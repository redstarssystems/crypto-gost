package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.EOFException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/** Экспорт ключевого материала {@link TlsSession#exportKeyingMaterial} (RFC 8446 §7.5). */
@DisplayName("TlsSession: экспорт ключевого материала")
class TlsSessionKeyExportTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int HASH_LEN = SUITE.getHashLen();
    private static final String LABEL = "EXPORTER-Channel-Binding";
    private static final String HOST = "gost.example.com";
    private static final int TIMEOUT_SECONDS = 15;

    private static byte[] exporterSecretOf(TlsSession session) throws Exception {
        Field engineField = TlsSession.class.getDeclaredField("engine");
        engineField.setAccessible(true);
        TlsHandshakeEngine engine = (TlsHandshakeEngine) engineField.get(session);
        Field secretField = TlsHandshakeEngine.class.getDeclaredField("exporterMasterSecret");
        secretField.setAccessible(true);
        return ((byte[]) secretField.get(engine)).clone();
    }

    private static byte[] streebog(byte[] data) {
        Streebog256 digest = new Streebog256();
        digest.update(data, 0, data.length);
        byte[] out = new byte[HASH_LEN];
        digest.doFinal(out, 0);
        return out;
    }

    /** Структура HkdfLabel (RFC 8446 §7.1), собранная байтами вручную, без expandLabel. */
    private static byte[] hkdfLabel(int length, String label, byte[] context) {
        byte[] labelBytes = ("tls13 " + label).getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[2 + 1 + labelBytes.length + 1 + context.length];
        info[0] = (byte) (length >>> 8);
        info[1] = (byte) length;
        info[2] = (byte) labelBytes.length;
        System.arraycopy(labelBytes, 0, info, 3, labelBytes.length);
        info[3 + labelBytes.length] = (byte) context.length;
        System.arraycopy(context, 0, info, 4 + labelBytes.length, context.length);
        return info;
    }

    /** Независимый расчёт: чистый HKDF-Expand и Стрибог, структуры метки собраны в тесте. */
    private static byte[] reference(byte[] secret, String label, byte[] context, int length) {
        byte[] emptyHash = streebog(new byte[0]);
        byte[] derived =
                HkdfStreebog.expand(secret, hkdfLabel(HASH_LEN, label, emptyHash), HASH_LEN, 32);
        return HkdfStreebog.expand(
                derived, hkdfLabel(length, "exporter", streebog(context)), length, 32);
    }

    @Test
    @DisplayName("Значение совпадает с расчётом по формуле RFC 8446 §7.5, собранной в тесте")
    void matchesIndependentFormula() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        byte[] secret = exporterSecretOf(connection.client());
        byte[] context = {1, 2, 3, 4, 5};

        assertArrayEquals(
                reference(secret, LABEL, context, 32),
                connection.client().exportKeyingMaterial(LABEL, context, 32),
                "клиентское значение должно совпасть с эталоном");
        assertArrayEquals(
                reference(secret, LABEL, new byte[0], 77),
                connection.server().exportKeyingMaterial(LABEL, null, 77),
                "серверное значение с пустым контекстом и длиной больше хэша");
        assertArrayEquals(
                reference(secret, "метка", new byte[0], 16),
                connection.server().exportKeyingMaterial("метка", null, 16),
                "метка передаётся в UTF-8, а не в ASCII");
    }

    @Test
    @DisplayName("Клиент и сервер получают одинаковые байты, значение зависит от всех аргументов")
    void bothSidesAgreeAndArgumentsMatter() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        TlsSession client = connection.client();
        TlsSession server = connection.server();
        byte[] context = {9, 8, 7};

        byte[] base = client.exportKeyingMaterial(LABEL, context, 32);
        assertArrayEquals(base, server.exportKeyingMaterial(LABEL, context, 32), "стороны равны");
        assertArrayEquals(base, client.exportKeyingMaterial(LABEL, context, 32), "детерминизм");

        assertFalse(
                Arrays.equals(base, client.exportKeyingMaterial("other", context, 32)),
                "другая метка даёт другое значение");
        assertFalse(
                Arrays.equals(base, client.exportKeyingMaterial(LABEL, new byte[] {9, 8}, 32)),
                "другой контекст даёт другое значение");
        byte[] longer = client.exportKeyingMaterial(LABEL, context, 33);
        assertFalse(
                Arrays.equals(base, Arrays.copyOf(longer, 32)),
                "значение другой длины не является префиксом: длина входит в HkdfLabel");
        assertArrayEquals(
                client.exportKeyingMaterial(LABEL, null, 32),
                client.exportKeyingMaterial(LABEL, new byte[0], 32),
                "в TLS 1.3 null и пустой контекст равны");
    }

    @Test
    @DisplayName("Границы длины, метки и контекста")
    void boundsAreChecked() throws Exception {
        TlsSession client = TlsSessionConnection.establish(SUITE).client();
        int maxLength = TlsConstants.HKDF_EXPAND_MAX_BLOCKS * HASH_LEN;

        assertEquals(1, client.exportKeyingMaterial(LABEL, null, 1).length);
        assertEquals(maxLength, client.exportKeyingMaterial(LABEL, null, maxLength).length);
        assertThrows(
                IllegalArgumentException.class, () -> client.exportKeyingMaterial(LABEL, null, 0));
        assertThrows(
                IllegalArgumentException.class, () -> client.exportKeyingMaterial(LABEL, null, -1));
        assertThrows(
                IllegalArgumentException.class,
                () -> client.exportKeyingMaterial(LABEL, null, maxLength + 1));

        String longest = "a".repeat(TlsConstants.EXPORTER_LABEL_MAX_LENGTH);
        assertEquals(16, client.exportKeyingMaterial(longest, null, 16).length);
        assertThrows(
                IllegalArgumentException.class,
                () -> client.exportKeyingMaterial(longest + "a", null, 16));
        assertThrows(
                IllegalArgumentException.class, () -> client.exportKeyingMaterial("", null, 16));
        assertThrows(
                IllegalArgumentException.class, () -> client.exportKeyingMaterial(null, null, 16));

        byte[] maxContext = new byte[TlsConstants.EXPORTER_CONTEXT_MAX_LENGTH];
        assertEquals(16, client.exportKeyingMaterial(LABEL, maxContext, 16).length);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        client.exportKeyingMaterial(
                                LABEL, new byte[TlsConstants.EXPORTER_CONTEXT_MAX_LENGTH + 1], 16));
    }

    @Test
    @DisplayName("До завершения рукопожатия экспорт недоступен")
    void unavailableBeforeHandshake() {
        var pair = InMemoryTlsTransport.newPair();
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        pair.getClientTransport(), SUITE, null, null);
        assertThrows(
                IllegalStateException.class, () -> client.exportKeyingMaterial(LABEL, null, 32));
    }

    @Test
    @DisplayName(
            "Возобновление по PSK: стороны согласны, значение отличается от первого соединения")
    void resumedConnectionHasOwnValue() throws Exception {
        PkixCertTestHelper.CertBundle server =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST});
        PskStore serverStore = new InMemoryPskStore(100);
        PskStore clientStore = new InMemoryPskStore(100);

        byte[][] first = connect(server, serverStore, clientStore, false);
        byte[][] second = connect(server, serverStore, clientStore, true);

        assertArrayEquals(first[0], first[1], "полное рукопожатие: стороны согласны");
        assertArrayEquals(second[0], second[1], "возобновление: стороны согласны");
        assertFalse(
                Arrays.equals(first[0], second[0]),
                "экспорт привязан к соединению, а не к сессии: значения различаются");
    }

    /** Возвращает {клиентское значение, серверное значение}; на втором соединении ждёт PSK. */
    private static byte[][] connect(
            PkixCertTestHelper.CertBundle server,
            PskStore serverStore,
            PskStore clientStore,
            boolean expectResumed)
            throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession =
                TlsSession.createServer(
                        new TlsServerConfig(
                                SUITE, Collections.singletonList(server.cert), server.priv),
                        pair.getServerTransport());
        serverSession.setPskStore(serverStore);
        TlsSession clientSession =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert))
                                .withServerHostname(HOST),
                        pair.getClientTransport());
        clientSession.setPskStore(clientStore);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientDone =
                    exec.submit(
                            () -> {
                                clientSession.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverDone =
                    exec.submit(
                            () -> {
                                serverSession.handshakeAsServer();
                                return null;
                            });
            clientDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            exec.shutdownNow();
        }
        assertEquals(expectResumed, clientSession.wasResumed(), "клиент: режим соединения");
        assertEquals(expectResumed, serverSession.wasResumed(), "сервер: режим соединения");
        byte[][] values = {
            clientSession.exportKeyingMaterial(LABEL, null, 32),
            serverSession.exportKeyingMaterial(LABEL, null, 32)
        };
        // NewSessionTicket клиент обрабатывает в read(): закрываем сервер и дочитываем
        serverSession.close();
        assertThrows(EOFException.class, clientSession::read);
        clientSession.close();
        return values;
    }
}
