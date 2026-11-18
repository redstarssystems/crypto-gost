package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Контрактные проверки SSLEngineResult для каждого EngineState.
 * <p>
 * Фокус на DATA state — именно здесь были упущены проверки Status.CLOSED
 * и HandshakeStatus в существующих тестах.
 */
@DisplayName("GostSSLEngine: граф состояний")
class GostSSLEngineStateGraphTest {

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        EngineServerPki pki = EngineServerPki.create();
        rootCa = pki.rootCa();
        serverCert = pki.serverCert();
        serverKm = pki.serverKm();
    }

    // ========================================================================
    // DATA state
    // ========================================================================

    @Test
    @DisplayName("DATA: wrap() с app data возвращает OK, NOT_HANDSHAKING, bytesProduced>0")
    void testDataStateWrap() throws Exception {
        GostSSLEngine engine = dataStateEngine();
        ByteBuffer src = ByteBuffer.wrap(new byte[] {0x01, 0x02, 0x03});
        ByteBuffer dst =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        SSLEngineResult r = engine.wrap(src, dst);

        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "wrap в DATA должен вернуть OK");
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                r.getHandshakeStatus(),
                "handshakeStatus в DATA — NOT_HANDSHAKING");
        assertEquals(3, r.bytesConsumed(), "bytesConsumed = длина входных данных");
        assertTrue(r.bytesProduced() > 0, "bytesProduced > 0 — произведена TLS-запись");
    }

    @Test
    @DisplayName("DATA: unwrap() с app data возвращает OK, NOT_HANDSHAKING, bytesProduced>0")
    void testDataStateUnwrap() throws Exception {
        PairAndEncrypted pair = createPairAndEncrypt(new byte[] {0x42});

        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult r = pair.server.unwrap(pair.encrypted, appBuf);

        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "unwrap в DATA должен вернуть OK");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, r.getHandshakeStatus());
        assertTrue(r.bytesConsumed() > 0, "bytesConsumed > 0 — запись потреблена");
        assertTrue(r.bytesProduced() > 0, "bytesProduced > 0 — данные расшифрованы");

        appBuf.flip();
        assertEquals(0x42, appBuf.get(0), "расшифрованный байт должен совпадать");
    }

    @Test
    @DisplayName("DATA: unwrap с пустым буфером возвращает BUFFER_UNDERFLOW")
    void testDataStateUnwrapEmpty() throws Exception {
        GostSSLEngine server = dataStateEngineServer();
        ByteBuffer empty = ByteBuffer.allocate(0);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult r = server.unwrap(empty, appBuf);

        assertEquals(
                SSLEngineResult.Status.BUFFER_UNDERFLOW,
                r.getStatus(),
                "пустой unwrap — BUFFER_UNDERFLOW");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, r.getHandshakeStatus());
    }

    @Test
    @DisplayName("DATA: closeOutbound() -> wrap отдаёт close_notify со статусом CLOSED")
    void testDataStateCloseOutbound() throws Exception {
        GostSSLEngine server = dataStateEngineServer();
        ByteBuffer dst =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

        server.closeOutbound();
        assertFalse(
                server.isOutboundDone(),
                "close_notify собран, но не отдан: выходная сторона ещё не закрыта");
        SSLEngineResult r = server.wrap(ByteBuffer.allocate(0), dst);

        // Как в JDK: после отдачи закрывающей записи статус CLOSED
        assertEquals(
                SSLEngineResult.Status.CLOSED,
                r.getStatus(),
                "wrap после closeOutbound отдаёт close_notify со статусом CLOSED");
        assertTrue(r.bytesProduced() > 0, "close_notify запись должна быть произведена");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, r.getHandshakeStatus());
        assertTrue(server.isOutboundDone(), "isOutboundDone после отдачи close_notify");

        SSLEngineResult repeated = server.wrap(ByteBuffer.allocate(0), dst);
        assertEquals(SSLEngineResult.Status.CLOSED, repeated.getStatus(), "повторный wrap");
        assertEquals(0, repeated.bytesProduced(), "close_notify отдаётся ровно один раз");
    }

    @Test
    @DisplayName("DATA: closeInbound() завершает входную сторону, wrap() больше нечего отдавать")
    void testDataStateCloseInbound() throws Exception {
        GostSSLEngine server = dataStateEngineServer();

        server.closeInbound();
        assertTrue(server.isInboundDone(), "isInboundDone после closeInbound");
        // Инвариант: isOutboundDone истинно ровно тогда, когда wrap() нечего отдавать. После
        // closeInbound() ключи записи разрушены, wrap() возвращает CLOSED без байтов, поэтому
        // цикл «пока не isOutboundDone() - wrap()» завершается
        assertTrue(server.isOutboundDone(), "wrap() больше нечего отдавать");
        assertEquals(
                SSLEngineResult.Status.CLOSED,
                server.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(64)).getStatus());
    }

    @Test
    @DisplayName(
            "DATA: closeOutbound + closeInbound -> wrap/unwrap возвращают CLOSED (штатное закрытие)")
    void testDataStateBothClosed() throws Exception {
        GostSSLEngine server = dataStateEngineServer();
        ByteBuffer dst =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        server.closeOutbound();
        // Потребляем close_notify
        server.wrap(ByteBuffer.allocate(0), dst);
        server.closeInbound();

        // Штатное закрытие не ошибка: как в JDK, циклы контейнеров получают CLOSED. Исключение
        // остаётся только после отказа (см. GostSSLEngineFatalAlertTest).
        SSLEngineResult wrapped = server.wrap(ByteBuffer.allocate(0), dst);
        assertEquals(SSLEngineResult.Status.CLOSED, wrapped.getStatus(), "wrap при закрытии");
        assertEquals(0, wrapped.bytesProduced(), "писать нечего");
        SSLEngineResult unwrapped = server.unwrap(ByteBuffer.allocate(0), appBuf);
        assertEquals(SSLEngineResult.Status.CLOSED, unwrapped.getStatus(), "unwrap при закрытии");
    }

    @Test
    @DisplayName(
            "DATA: closeOutbound (closeReceived==false) не зануляет record-ключи; closeInbound — зануляет")
    void testCloseInboundWipesRecordKeys() throws Exception {
        GostSSLEngine server = dataStateEngineServer();

        // Штатная ветка «закрываем первыми»: closeOutbound() лишь ставит close_notify,
        // destroyHandshakeEngine() не вызывается — ключи ещё в памяти.
        server.closeOutbound();
        assertFalse(
                server.recordsDestroyedForTest(),
                "record-ключи не должны быть занулены до closeInbound");

        // closeInbound() -> destroyHandshakeEngine(): единая точка зачистки.
        server.closeInbound();
        assertTrue(
                server.recordsDestroyedForTest(),
                "record-ключи должны быть занулены после closeInbound");
    }

    // ========================================================================
    // CLOSED state
    // ========================================================================

    @Test
    @DisplayName("CLOSED: wrap и unwrap возвращают CLOSED")
    void testClosedState() throws Exception {
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        client.beginHandshake();
        client.closeOutbound();
        client.closeInbound();

        ByteBuffer dst =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        assertEquals(
                SSLEngineResult.Status.CLOSED,
                client.wrap(ByteBuffer.allocate(0), dst).getStatus(),
                "wrap в CLOSED возвращает CLOSED");
        assertEquals(
                SSLEngineResult.Status.CLOSED,
                client.unwrap(ByteBuffer.allocate(0), appBuf).getStatus(),
                "unwrap в CLOSED возвращает CLOSED");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private record PairAndEncrypted(GostSSLEngine server, ByteBuffer encrypted) {}

    /** Создаёт пару handshake + шифрует app data клиентом. */
    private static PairAndEncrypted createPairAndEncrypt(byte[] data) throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        doHandshake(client, server, pair);

        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.wrap(data), net);
        net.flip();
        return new PairAndEncrypted(server, net);
    }

    /** Создаёт серверный GostSSLEngine в DATA state (после полного handshake). */
    private static GostSSLEngine dataStateEngineServer() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        doHandshake(client, server, pair);
        return server;
    }

    /** Создаёт клиентский GostSSLEngine в DATA state. */
    private static GostSSLEngine dataStateEngine() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        doHandshake(client, server, pair);
        return client;
    }

    private static void doHandshake(
            GostSSLEngine client, GostSSLEngine server, InMemoryTlsTransport.Pair pair)
            throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
    }
}
