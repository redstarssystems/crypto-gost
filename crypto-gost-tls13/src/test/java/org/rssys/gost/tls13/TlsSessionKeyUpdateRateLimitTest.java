package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.engine.HandshakeOutputs;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;

/**
 * Лимит KeyUpdate: чужие ограничены скользящим окном времени, собственные не считаются.
 *
 * <p>Общий счётчик на соединение (32) убивал долгоживущее соединение с периодической сменой ключа
 * (раз в час на 33-м обновлении), хотя защита от потока сообщений держится на окне и на лимите
 * подряд идущих сообщений в {@code read()}.
 */
@DisplayName("KeyUpdate: окно для чужих обновлений, собственные не считаются")
class TlsSessionKeyUpdateRateLimitTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    /** Заведомо больше любого общего счётчика на соединение, который был раньше (32). */
    private static final int MANY_UPDATES = 40;

    private static TlsHandshakeEngine engineOf(TlsSession session) throws Exception {
        java.lang.reflect.Field field = TlsSession.class.getDeclaredField("engine");
        field.setAccessible(true);
        return (TlsHandshakeEngine) field.get(session);
    }

    private static void useClock(TlsHandshakeEngine engine, LongSupplier clock) throws Exception {
        Method method =
                TlsHandshakeEngine.class.getDeclaredMethod(
                        "setNanoClockForTest", LongSupplier.class);
        method.setAccessible(true);
        method.invoke(engine, clock);
    }

    private static byte[] keyUpdateNotRequested() {
        return new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, new byte[] {0}).encode();
    }

    @Test
    @DisplayName("собственные KeyUpdate не считаются: сорок подряд без ошибок")
    void ownKeyUpdatesAreNotLimited() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.client());

        assertDoesNotThrow(
                () -> {
                    for (int i = 0; i < MANY_UPDATES; i++) {
                        engine.initiateKeyUpdate(false);
                        // Поток отдан: KeyUpdate и смена ключа за ним
                        HandshakeOutputs.drain(engine);
                    }
                },
                "Приложение с периодической сменой ключа не должно упираться в общий счётчик");
    }

    @Test
    @DisplayName("медленный поток чужих KeyUpdate (по одному за окно) не ограничивается")
    void slowPeerKeyUpdatesAreNotLimited() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.server());
        AtomicLong now = new AtomicLong();
        useClock(engine, now::get);

        assertDoesNotThrow(
                () -> {
                    for (int i = 0; i < MANY_UPDATES; i++) {
                        engine.receivePostHandshake(keyUpdateNotRequested());
                        engine.acknowledgeReadKeyChange();
                        // Следующее обновление приходит уже в новом окне
                        now.addAndGet(TlsConstants.KEY_UPDATE_RATE_WINDOW_NANOS + 1);
                    }
                },
                "Нормальный темп обновлений на долгом соединении не должен давать отказ");
    }

    @Test
    @DisplayName("поток чужих KeyUpdate быстрее окна: превышение даёт unexpected_message")
    void fastPeerKeyUpdateFloodIsRejected() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.server());
        AtomicLong now = new AtomicLong();
        useClock(engine, now::get);

        for (int i = 0; i < TlsConstants.MAX_PEER_KEY_UPDATES_PER_WINDOW; i++) {
            engine.receivePostHandshake(keyUpdateNotRequested());
            engine.acknowledgeReadKeyChange();
        }

        TlsException error =
                assertThrows(
                        TlsException.class,
                        () -> engine.receivePostHandshake(keyUpdateNotRequested()),
                        "Превышение числа обновлений за окно должно отвергаться");
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
    }

    @Test
    @DisplayName("реальное время: 11 чужих KeyUpdate подряд заведомо быстрее окна дают отказ")
    void fastPeerKeyUpdateFloodOnRealClockIsRejected() throws Exception {
        // Без подмены часов: десять обновлений в памяти занимают миллисекунды, окно в секунду не
        // успевает сброситься. На прежнем общем счётчике (32) одиннадцатое обновление проходило
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.server());
        for (int i = 0; i < TlsConstants.MAX_PEER_KEY_UPDATES_PER_WINDOW; i++) {
            engine.receivePostHandshake(keyUpdateNotRequested());
            engine.acknowledgeReadKeyChange();
        }

        TlsException error =
                assertThrows(
                        TlsException.class,
                        () -> engine.receivePostHandshake(keyUpdateNotRequested()),
                        "Одиннадцатое обновление за окно должно отвергаться");

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
    }

    @Test
    @DisplayName("окно сбрасывается: после паузы чужие KeyUpdate снова принимаются")
    void windowResetsAfterPause() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.server());
        AtomicLong now = new AtomicLong();
        useClock(engine, now::get);
        for (int i = 0; i < TlsConstants.MAX_PEER_KEY_UPDATES_PER_WINDOW; i++) {
            engine.receivePostHandshake(keyUpdateNotRequested());
            engine.acknowledgeReadKeyChange();
        }

        now.addAndGet(TlsConstants.KEY_UPDATE_RATE_WINDOW_NANOS + 1);

        assertDoesNotThrow(() -> engine.receivePostHandshake(keyUpdateNotRequested()));
    }
}
