package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.engine.HandshakeOutputs;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;

/**
 * Пока смена ключа записи не подтверждена, второе обновление недопустимо: оба ожидающих набора
 * выводятся из одного и того же ещё не сдвинутого секрета, а пир сдвинул бы ключ чтения дважды,
 * отправитель - один раз.
 */
@DisplayName("KeyUpdate: одно ожидающее обновление ключа записи за раз")
class TlsSessionKeyUpdateGuardTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static TlsHandshakeEngine engineOf(TlsSession session) throws Exception {
        Field field = TlsSession.class.getDeclaredField("engine");
        field.setAccessible(true);
        return (TlsHandshakeEngine) field.get(session);
    }

    private static byte[] keyUpdateRequested() {
        return new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, new byte[] {1}).encode();
    }

    @Test
    @DisplayName(
            "второй initiateKeyUpdate до отправки первого: одно обновление, запрос ответа сохранён")
    void secondInitiateBeforeSendIsMerged() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.client());
        byte[] clientReadKeyBefore = engine.getReadKeys().getKey();
        // Обновление стоит в потоке движка и ещё не отправлено
        engine.initiateKeyUpdate(false);

        // Второй вызов объединяется со стоящим: секрет сдвигается один раз, запрос ответа повышает
        // стоящее сообщение; сессия отправляет одно обновление
        connection.client().initiateKeyUpdate(true);

        assertFalse(connection.client().isClosed(), "Сессия не должна закрываться");
        byte[] toServer = "после объединённого обновления".getBytes(StandardCharsets.UTF_8);
        connection.client().write(toServer);
        assertArrayEquals(toServer, connection.server().read(), "ключи сторон согласованы");
        byte[] toClient = "ответ сервера".getBytes(StandardCharsets.UTF_8);
        connection.server().write(toClient);
        assertArrayEquals(
                toClient, connection.client().read(), "данные сервера читаются: ключи согласованы");
        assertFalse(
                java.util.Arrays.equals(clientReadKeyBefore, engine.getReadKeys().getKey()),
                "сервер ответил своим обновлением: запрос ответа не потерян");
    }

    @Test
    @DisplayName(
            "два update_requested пира до подтверждения: один ответ, ключи чтения сдвинуты дважды")
    void twoPeerRequestsGiveSingleResponse() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine engine = engineOf(connection.client());
        byte[] keyBefore = engine.getReadKeys().getKey();

        engine.receivePostHandshake(keyUpdateRequested());
        byte[] keyAfterFirst = engine.getReadKeys().getKey();
        engine.acknowledgeReadKeyChange();
        engine.receivePostHandshake(keyUpdateRequested());
        byte[] keyAfterSecond = engine.getReadKeys().getKey();
        engine.acknowledgeReadKeyChange();

        // Каждый запрос пира сдвигает наш ключ чтения: пир сдвинул свой ключ записи дважды
        assertFalse(java.util.Arrays.equals(keyBefore, keyAfterFirst), "Первый сдвиг ключа чтения");
        assertFalse(
                java.util.Arrays.equals(keyAfterFirst, keyAfterSecond),
                "Второй сдвиг ключа чтения");
        // А ответ нужен один: пока своё обновление стоит в потоке, оно и служит ответом
        assertEquals(
                "M24 K",
                HandshakeOutputs.layout(HandshakeOutputs.drain(engine)),
                "На два запроса подряд один KeyUpdate и одна смена ключа записи за ним");
    }
}
