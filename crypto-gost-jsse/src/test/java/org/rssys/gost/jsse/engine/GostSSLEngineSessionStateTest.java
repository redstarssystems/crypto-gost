package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Состояние сессии и буферов {@link GostSSLEngine} после рукопожатия и закрытия: привязка сессии
 * к контексту, затирание открытого текста, значения сессии из разных потоков.
 */
@DisplayName("GostSSLEngine: сессия и буфер открытого текста после рукопожатия и закрытия")
class GostSSLEngineSessionStateTest {

    private static final int BIG_BUFFER =
            4 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static TlsCiphersuite suite;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    private static GostSSLEngine server(GostSSLSessionContext context) {
        return GostSSLEngine.createForServer(
                serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, context);
    }

    private static GostSSLEngine client(GostSSLSessionContext context) {
        return GostSSLEngine.createForClientNoHostnameCheck(
                new GostX509KeyManager(),
                GostX509TrustManager.insecureTrustAll(),
                "localhost",
                0,
                context);
    }

    @Test
    @DisplayName("После рукопожатия сессия привязана к контексту и действительна")
    void sessionIsBoundToContextAfterHandshake() throws Exception {
        GostSSLSessionContext clientContext = new GostSSLSessionContext(suite);
        GostSSLEngine client = client(clientContext);
        GostSSLEngine server = server(new GostSSLSessionContext(suite));

        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        GostSSLSession session = (GostSSLSession) client.getSession();
        assertSame(
                clientContext,
                session.getSessionContext(),
                "сессия, видимая из движка, должна быть полностью собрана: с контекстом");
        assertTrue(session.isValid(), "сессия действительна");
        assertEquals(
                session,
                clientContext.getSession(session.getId()),
                "сессия лежит в кэше контекста");
    }

    @Test
    @DisplayName("Значения сессии: null вместо имени отвергается, как в JDK")
    void sessionValuesRejectNullName() throws Exception {
        GostSSLEngine client = client(new GostSSLSessionContext(suite));
        GostSSLEngine server = server(new GostSSLSessionContext(suite));
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
        GostSSLSession session = (GostSSLSession) client.getSession();

        session.putValue("ключ", "значение");
        assertEquals("значение", session.getValue("ключ"), "значение читается");
        assertThrows(IllegalArgumentException.class, () -> session.getValue(null));
        assertThrows(IllegalArgumentException.class, () -> session.removeValue(null));
        assertThrows(IllegalArgumentException.class, () -> session.putValue(null, "x"));
        assertEquals(
                session.getCreationTime(),
                session.getLastAccessedTime(),
                "время последнего обращения равно времени создания");
    }

    @Test
    @DisplayName("Закрытие движка затирает буфер расшифрованного открытого текста")
    void plaintextBufferIsWipedOnClose() throws Exception {
        GostSSLEngine client = client(new GostSSLSessionContext(suite));
        GostSSLEngine server = server(new GostSSLSessionContext(suite));
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        ByteBuffer network = ByteBuffer.allocate(BIG_BUFFER);
        byte[] secret = "секретные данные приложения".getBytes(StandardCharsets.UTF_8);
        client.wrap(ByteBuffer.wrap(secret), network);
        network.flip();
        ByteBuffer received = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult result = server.unwrap(network, received);
        assertEquals(secret.length, result.bytesProduced(), "данные клиента дошли до сервера");

        byte[] plaintextBuffer = plaintextBufferOf(server);
        assertFalse(isAllZero(plaintextBuffer), "предусловие: в буфере остался открытый текст");

        server.closeOutbound();
        server.closeInbound();

        assertTrue(
                isAllZero(plaintextBufferOf(server)),
                "после закрытия открытый текст не должен оставаться в буфере движка");
    }

    private static byte[] plaintextBufferOf(GostSSLEngine engine) throws Exception {
        Field field = GostSSLEngine.class.getDeclaredField("plaintextBuf");
        field.setAccessible(true);
        return ((ByteBuffer) field.get(engine)).array();
    }

    private static boolean isAllZero(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    @DisplayName("Сообщение больше предела: отказ по первой записи, в сообщении настоящий размер")
    void oversizedHandshakeMessageRejectedByHeader() {
        GostSSLEngine server = server(new GostSSLSessionContext(suite));
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        // ClientHello объявляет почти 16 МБ: длина сверяется с пределом по заголовку, поэтому
        // отказ приходит на первой же записи, без накопления тела
        byte[] fragment = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH];
        fragment[0] = TlsConstants.HT_CLIENT_HELLO;
        fragment[1] = (byte) 0xFF;
        fragment[2] = (byte) 0xFF;
        fragment[3] = (byte) 0xFF;
        ByteBuffer record = ByteBuffer.allocate(TlsConstants.RECORD_HEADER_SIZE + fragment.length);
        record.put(TlsConstants.CT_HANDSHAKE)
                .put(TlsConstants.LEGACY_VERSION_MAJOR)
                .put(TlsConstants.LEGACY_VERSION_MINOR)
                .putShort((short) fragment.length)
                .put(fragment);
        record.flip();

        SSLException failure =
                org.junit.jupiter.api.Assertions.assertThrows(
                        SSLException.class,
                        () -> server.unwrap(record, app),
                        "заявленная длина больше предела должна отвергаться сразу");
        assertTrue(
                failure.getMessage().contains("Handshake message too large: 16777219"),
                "в сообщении настоящий размер: " + failure.getMessage());
    }
}
