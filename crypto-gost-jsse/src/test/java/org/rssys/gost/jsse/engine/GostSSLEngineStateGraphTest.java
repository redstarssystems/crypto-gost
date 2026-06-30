package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Контрактные проверки SSLEngineResult для каждого EngineState.
 * <p>
 * Фокус на DATA state — именно здесь были упущены проверки Status.CLOSED
 * и HandshakeStatus в существующих тестах.
 */
class GostSSLEngineStateGraphTest {

    private static TlsTestHelper.CertBundle rootCa;
    private static TlsTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        serverCert =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
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
    @DisplayName("DATA: closeOutbound() -> wrap возвращает OK с close_notify")
    void testDataStateCloseOutbound() throws Exception {
        GostSSLEngine server = dataStateEngineServer();
        ByteBuffer dst =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

        server.closeOutbound();
        SSLEngineResult r = server.wrap(ByteBuffer.allocate(0), dst);

        // closeOutbound() только инициирует отправку close_notify.
        // wrap() возвращает OK с произведённым close_notify (bytesProduced > 0).
        // CLOSED возвращается только при closeReceived.
        assertEquals(
                SSLEngineResult.Status.OK,
                r.getStatus(),
                "wrap после closeOutbound возвращает OK (close_notify произведён)");
        assertTrue(r.bytesProduced() > 0, "close_notify запись должна быть произведена");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, r.getHandshakeStatus());
        assertTrue(server.isOutboundDone(), "isOutboundDone после closeOutbound");
    }

    @Test
    @DisplayName("DATA: closeInbound() — isInboundDone() = true")
    void testDataStateCloseInbound() throws Exception {
        GostSSLEngine server = dataStateEngineServer();

        server.closeInbound();
        assertTrue(server.isInboundDone(), "isInboundDone после closeInbound");
        assertFalse(server.isOutboundDone(), "isOutboundDone должен оставаться false");
    }

    @Test
    @DisplayName(
            "DATA: closeOutbound + closeInbound -> wrap/unwrap бросают SSLException (engine closed)")
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

        // Когда engineState = CLOSED, wrap выкидывает SSLException, а не CLOSED
        // (checkNotClosed срабатывает до формирования результата)
        assertThrows(
                javax.net.ssl.SSLException.class,
                () -> server.wrap(ByteBuffer.allocate(0), dst),
                "wrap при engine closed — SSLException");
        assertThrows(
                javax.net.ssl.SSLException.class,
                () -> server.unwrap(ByteBuffer.allocate(0), appBuf),
                "unwrap при engine closed — SSLException");
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
                        new GostX509TrustManager(null, false),
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

        assertThrows(
                javax.net.ssl.SSLException.class,
                () -> client.wrap(ByteBuffer.allocate(0), dst),
                "wrap в CLOSED — SSLException");
        assertThrows(
                javax.net.ssl.SSLException.class,
                () -> client.unwrap(ByteBuffer.allocate(0), appBuf),
                "unwrap в CLOSED — SSLException");
    }

    @Test
    @DisplayName("CLOSED: isInboundDone / isOutboundDone — true")
    void testClosedStateDone() throws Exception {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        engine.closeOutbound();
        engine.closeInbound();

        assertTrue(engine.isInboundDone());
        assertTrue(engine.isOutboundDone());
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
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);
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
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);
        doHandshake(client, server, pair);
        return server;
    }

    /** Создаёт клиентский GostSSLEngine в DATA state. */
    private static GostSSLEngine dataStateEngine() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);
        doHandshake(client, server, pair);
        return client;
    }

    private static void doHandshake(
            GostSSLEngine client, GostSSLEngine server, InMemoryTlsTransport.Pair pair)
            throws Exception {
        client.beginHandshake();
        server.beginHandshake();
        AtomicReference<Throwable> ce = new AtomicReference<>();
        AtomicReference<Throwable> se = new AtomicReference<>();

        Thread ct =
                new Thread(
                        () -> {
                            try {
                                hsLoop(client, pair.getClientTransport());
                            } catch (Exception e) {
                                ce.set(e);
                            }
                        });
        Thread st =
                new Thread(
                        () -> {
                            try {
                                hsLoop(server, pair.getServerTransport());
                            } catch (Exception e) {
                                se.set(e);
                            }
                        });
        ct.start();
        st.start();
        ct.join(10000);
        st.join(10000);
        if (ce.get() != null) throw new RuntimeException(ce.get());
        if (se.get() != null) throw new RuntimeException(se.get());
    }

    private static void hsLoop(GostSSLEngine engine, InMemoryTlsTransport transport)
            throws Exception {
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        for (int i = 0; i < 80; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;
            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] out = new byte[netBuf.remaining()];
                        netBuf.get(out);
                        transport.sendRecord(out);
                    }
                    break;
                case NEED_UNWRAP:
                    {
                        byte[] in = transport.receiveRecord();
                        if (in != null) {
                            netBuf.clear();
                            netBuf.put(in);
                            netBuf.flip();
                            appBuf.clear();
                            engine.unwrap(netBuf, appBuf);
                        } else Thread.sleep(10);
                        break;
                    }
                case NEED_TASK:
                    {
                        Runnable t = engine.getDelegatedTask();
                        if (t != null) t.run();
                        break;
                    }
            }
        }
        throw new RuntimeException("Тайм-аут рукопожатия " + engine.getHandshakeStatus());
    }
}
