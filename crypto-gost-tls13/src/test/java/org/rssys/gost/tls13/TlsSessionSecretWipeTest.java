package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * Прежние трафик-ключи затираются при смене ключа (RFC 8446 §7.2): {@code TlsRecord} получает
 * копии, поэтому уничтожение старой записи оригиналы в движке не затирает.
 */
@DisplayName("TlsSession: затирание прежних трафик-ключей при KeyUpdate")
class TlsSessionSecretWipeTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static TlsHandshakeEngine engineOf(TlsSession session) throws Exception {
        Field field = TlsSession.class.getDeclaredField("engine");
        field.setAccessible(true);
        return (TlsHandshakeEngine) field.get(session);
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static boolean isZero(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }

    @Test
    @DisplayName("собственный KeyUpdate: прежняя запись отправки уничтожена, новая рабочая")
    void initiatedKeyUpdateWipesOldWriteKeys() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        Object oldWriter = field(connection.client(), "writerRecord");
        // Ссылка на массив ключа прежней записи: после смены он обязан быть обнулён на месте
        byte[] oldKey = (byte[]) field(oldWriter, "startKey");
        byte[] oldIv = (byte[]) field(oldWriter, "startIv");
        assertFalse(isZero(oldKey), "До смены ключ должен быть ненулевым");

        connection.client().initiateKeyUpdate(false);

        Object newWriter = field(connection.client(), "writerRecord");
        assertNotSame(oldWriter, newWriter, "Запись отправки сменилась");
        assertTrue(isZero(oldKey), "Прежний ключ записи должен быть затёрт после смены");
        assertTrue(isZero(oldIv), "Прежний IV записи должен быть затёрт после смены");
        assertFalse(isZero((byte[]) field(newWriter, "startKey")), "Новый ключ записи ненулевой");
        byte[] message = "после смены ключа".getBytes(StandardCharsets.UTF_8);
        connection.client().write(message);
        assertArrayEquals(message, connection.server().read());
    }

    @Test
    @DisplayName("KeyUpdate пира: прежние ключи чтения затираются, новые рабочие")
    void peerKeyUpdateWipesOldReadKeys() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsHandshakeEngine serverEngine = engineOf(connection.server());
        TlsTrafficKeys oldReadKeys = serverEngine.getReadKeys();
        byte[] oldKey = oldReadKeys.getKey();
        assertFalse(isZero(oldKey), "До смены ключ должен быть ненулевым");

        connection.client().initiateKeyUpdate(false);
        byte[] message = "после смены ключа".getBytes(StandardCharsets.UTF_8);
        connection.client().write(message);
        // read() сначала обрабатывает KeyUpdate, затем отдаёт данные приложения
        assertArrayEquals(message, connection.server().read());

        assertFalse(
                Arrays.equals(oldKey, serverEngine.getReadKeys().getKey()),
                "Ключ чтения должен смениться");
        assertArrayEquals(
                new byte[oldKey.length],
                oldReadKeys.getKey(),
                "Прежний ключ чтения должен быть затёрт после смены");
    }

    @Test
    @DisplayName("после закрытия сессии экспорт ключевого материала недоступен")
    void exportIsUnavailableAfterClose() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        assertArrayEquals(
                connection.server().exportKeyingMaterial("label", null, 16),
                connection.client().exportKeyingMaterial("label", null, 16),
                "до закрытия стороны получают одинаковое значение");

        connection.client().close();

        assertThrows(
                IllegalStateException.class,
                () -> connection.client().exportKeyingMaterial("label", null, 16),
                "после закрытия секрет затёрт, экспорт обязан отказывать");
    }
}
