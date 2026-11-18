package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Экспорт ключевого материала через {@link GostSSLSession}: контракт совпадает с
 * {@code ExtendedSSLSession.exportKeyingMaterial*} JDK 25, а секрет живёт в движке соединения.
 */
@DisplayName("GostSSLSession: экспорт ключевого материала")
class GostSSLSessionKeyExportTest {

    private static final String LABEL = "EXPORTER-Channel-Binding";
    private static final int KEY_LENGTH = 32;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null,
                        null);
    }

    private record Connection(GostSSLEngine client, GostSSLEngine server) {}

    private static Connection establish() throws Exception {
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(
                                org.rssys.gost.tls13.TlsCiphersuite
                                        .TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
        // Записи, отправленные после завершения рукопожатия (билеты сервера), остаются в очередях:
        // без их приёма порядковые номера записей у сторон разойдутся
        deliverPending(pair.getServerToClientQueue(), client);
        deliverPending(pair.getClientToServerQueue(), server);
        return new Connection(client, server);
    }

    private static void deliverPending(
            java.util.concurrent.LinkedBlockingQueue<byte[]> queue, GostSSLEngine receiver)
            throws Exception {
        byte[] record;
        while ((record = queue.poll()) != null) {
            receiver.unwrap(
                    ByteBuffer.wrap(record),
                    ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        }
    }

    private static GostSSLSession sessionOf(GostSSLEngine engine) {
        return (GostSSLSession) engine.getSession();
    }

    /** Передаёт другой стороне close_notify, который отправляющий движок готов записать. */
    private static void pass(GostSSLEngine from, GostSSLEngine to) throws Exception {
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        SSLEngineResult result = from.wrap(ByteBuffer.allocate(0), net);
        assertTrue(result.bytesProduced() > 0, "close_notify должен быть отправлен");
        net.flip();
        // unwrap разбирает одну запись за вызов: читаем, пока байты потребляются
        while (net.hasRemaining()) {
            int before = net.remaining();
            to.unwrap(net, ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
            assertTrue(net.remaining() < before, "unwrap обязан потреблять входные байты");
        }
        assertTrue(to.isInboundDone(), "close_notify должен быть принят");
    }

    @Test
    @DisplayName("Клиент и сервер получают одинаковые значения; Key согласован с Data")
    void bothSidesAgree() throws Exception {
        Connection connection = establish();
        GostSSLSession client = sessionOf(connection.client());
        GostSSLSession server = sessionOf(connection.server());
        byte[] context = {1, 2, 3};

        byte[] clientValue = client.exportKeyingMaterialData(LABEL, context, KEY_LENGTH);
        assertArrayEquals(
                clientValue,
                server.exportKeyingMaterialData(LABEL, context, KEY_LENGTH),
                "стороны должны получить одинаковые байты");
        assertFalse(
                Arrays.equals(
                        clientValue, client.exportKeyingMaterialData(LABEL, null, KEY_LENGTH)),
                "другой контекст даёт другое значение");
        assertArrayEquals(
                client.exportKeyingMaterialData(LABEL, null, KEY_LENGTH),
                client.exportKeyingMaterialData(LABEL, new byte[0], KEY_LENGTH),
                "null и пустой контекст равны");

        SecretKey key = server.exportKeyingMaterialKey("HMAC", LABEL, context, KEY_LENGTH);
        assertEquals("HMAC", key.getAlgorithm());
        assertArrayEquals(clientValue, key.getEncoded(), "Key несёт те же байты, что и Data");
    }

    @Test
    @DisplayName("Контракт JDK: исключения и их порядок")
    void jdkContract() throws Exception {
        GostSSLSession session = sessionOf(establish().client());

        assertThrows(
                NullPointerException.class,
                () -> session.exportKeyingMaterialData(null, null, KEY_LENGTH));
        assertThrows(
                IllegalArgumentException.class,
                () -> session.exportKeyingMaterialData(LABEL, null, 0));
        assertThrows(
                IllegalArgumentException.class,
                () -> session.exportKeyingMaterialData("", null, KEY_LENGTH));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        session.exportKeyingMaterialData(
                                "a".repeat(TlsConstants.EXPORTER_LABEL_MAX_LENGTH + 1),
                                null,
                                KEY_LENGTH));
        assertEquals(
                KEY_LENGTH,
                session.exportKeyingMaterialData(LABEL, new byte[255], KEY_LENGTH).length,
                "контекст в 255 байт допустим");
        assertThrows(
                IllegalArgumentException.class,
                () -> session.exportKeyingMaterialData(LABEL, new byte[256], KEY_LENGTH),
                "JSSE принимает контекст не длиннее 255 байт, как JDK");
        assertThrows(
                IllegalArgumentException.class,
                () -> session.exportKeyingMaterialData(LABEL, null, 255 * 32 + 1));
        assertThrows(
                NullPointerException.class,
                () -> session.exportKeyingMaterialKey(null, LABEL, null, KEY_LENGTH));
        assertThrows(
                IllegalArgumentException.class,
                () -> session.exportKeyingMaterialKey("", LABEL, null, KEY_LENGTH));
    }

    @Test
    @DisplayName("До завершения рукопожатия: IllegalStateException")
    void unavailableBeforeHandshake() {
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
        GostSSLSession session = sessionOf(client);
        assertThrows(
                IllegalStateException.class,
                () -> session.exportKeyingMaterialData(LABEL, null, KEY_LENGTH));
    }

    @Test
    @DisplayName("invalidate() экспорт на живом соединении не отключает")
    void invalidateKeepsExportAvailable() throws Exception {
        Connection connection = establish();
        GostSSLSession session = sessionOf(connection.client());
        byte[] before = session.exportKeyingMaterialData(LABEL, null, KEY_LENGTH);

        session.invalidate();

        assertArrayEquals(
                before,
                session.exportKeyingMaterialData(LABEL, null, KEY_LENGTH),
                "invalidate() запрещает возобновление, но не закрывает текущее соединение");
    }

    @Test
    @DisplayName("После закрытия соединения сессия, оставшаяся в кэше, экспорт не отдаёт")
    void unavailableAfterClose() throws Exception {
        Connection connection = establish();
        GostSSLSession serverSession = sessionOf(connection.server());
        GostSSLSession clientSession = sessionOf(connection.client());
        assertEquals(
                KEY_LENGTH, serverSession.exportKeyingMaterialData(LABEL, null, KEY_LENGTH).length);

        // Обмен close_notify в обе стороны, после которого движки уничтожают ключи
        connection.client().closeOutbound();
        pass(connection.client(), connection.server());
        connection.server().closeOutbound();
        pass(connection.server(), connection.client());

        assertTrue(connection.server().isOutboundDone(), "сервер закрыт");
        assertThrows(
                IllegalStateException.class,
                () -> serverSession.exportKeyingMaterialData(LABEL, null, KEY_LENGTH),
                "серверная сессия после закрытия не должна отдавать экспорт");
        assertThrows(
                IllegalStateException.class,
                () -> clientSession.exportKeyingMaterialData(LABEL, null, KEY_LENGTH),
                "клиентская сессия после закрытия не должна отдавать экспорт");
    }
}
