package org.rssys.gost.netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import java.security.Security;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты GostSslContext через Netty EmbeddedChannel.
 * Избегает TCP — вся коммуникация в памяти, оба SslHandler
 * в одном потоке.
 */
class GostSslContextHandshakeTest {

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static GostSslContext serverMtlsCtx;
    private static GostSslContext clientMtlsCtx;
    private static GostSslContext serverAlpnCtx;
    private static GostSslContext clientAlpnCtx;

    private static TlsTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        rootCa = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        TlsTestHelper.CertBundle clientCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null,
                false, null);

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", toJcaChain(serverCert, rootCa), serverCert.priv);
        serverCtx = GostSslContextBuilder.forServer(serverKm).build();

        GostX509TrustManager trustAll = new GostX509TrustManager(rootCa.cert.getPublicKey(), false);
        clientCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .build();

        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("client", toJcaChain(clientCert, rootCa), clientCert.priv);

        serverMtlsCtx = GostSslContextBuilder.forServer(serverKm)
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .clientAuth(io.netty.handler.ssl.ClientAuth.REQUIRE)
                .build();
        clientMtlsCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .keyManager(clientKm)
                .build();

        serverAlpnCtx = GostSslContextBuilder.forServer(serverKm)
                .applicationProtocols("h2", "http/1.1")
                .build();
        clientAlpnCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .applicationProtocols("h2", "http/1.1")
                .build();
    }

    @Test
    @DisplayName("Embedded: send data after handshake")
    void testSendData() throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);

        // Send data from client
        clientCh.writeOutbound(Unpooled.wrappedBuffer("hello".getBytes()));
        ByteBuf encrypted = clientCh.readOutbound();
        assertNotNull(encrypted, "зашифрованные данные должны быть");

        // Feed to server
        serverCh.writeInbound(encrypted.retain());
        encrypted.release();
        ByteBuf decrypted = serverCh.readInbound();
        assertNotNull(decrypted, "расшифрованные данные должны быть");

        String received = decrypted.toString(java.nio.charset.StandardCharsets.UTF_8);
        assertEquals("hello", received);
        decrypted.release();
    }

    @Test
    @DisplayName("ALPN: h2 согласован между клиентом и сервером")
    void testAlpnNegotiation() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        TlsTestHelper.CertBundle sc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), rootCa.priv,
                rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        skm.addKeyEntry("default", toJcaChain(sc, rootCa), sc.priv);

        GostSslContext srv = GostSslContextBuilder.forServer(skm)
                .applicationProtocols("h2").build();
        GostSslContext cli = GostSslContextBuilder.forClient()
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .applicationProtocols("h2").build();

        SslHandler cs = cli.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler ss = srv.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        doHandshake(cs, ss);

        assertEquals("h2", cs.applicationProtocol(),
                "клиентский протокол должен быть h2");
        assertEquals("h2", ss.applicationProtocol(),
                "серверный протокол должен быть h2");
    }

    @Test
    @DisplayName("ALPN mismatch: Netty 4.2+ кидает SSLHandshakeException")
    void testAlpnMismatch() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        TlsTestHelper.CertBundle sc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), rootCa.priv,
                rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        skm.addKeyEntry("default", toJcaChain(sc, rootCa), sc.priv);

        GostSslContext srv = GostSslContextBuilder.forServer(skm)
                .applicationProtocols("http/1.1").build();
        GostSslContext cli = GostSslContextBuilder.forClient()
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .applicationProtocols("h2").build();

        SslHandler cs = cli.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler ss = srv.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        assertThrows(Exception.class, () -> doHandshake(cs, ss),
                "handshake при ALPN mismatch падает в Netty 4.2+");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static void doHandshake(GostSslContext serverCtx, GostSslContext clientCtx)
            throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        doHandshake(clientSsl, serverSsl);
    }

    private static void doHandshake(SslHandler clientSsl, SslHandler serverSsl)
            throws Exception {
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);
    }

    private static void doHandshake(SslHandler clientSsl, SslHandler serverSsl,
                                    EmbeddedChannel clientCh, EmbeddedChannel serverCh)
            throws Exception {
        // WHY: обмениваемся handshake-сообщениями, пока обе стороны не завершат.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);

        while (!clientSsl.handshakeFuture().isDone()
                || !serverSsl.handshakeFuture().isDone()) {
            if (System.nanoTime() > deadline) {
                fail("Handshake timed out");
            }

            boolean progressed = false;

            ByteBuf clientOut = clientCh.readOutbound();
            if (clientOut != null) {
                serverCh.writeInbound(clientOut.retain());
                clientOut.release();
                serverCh.runPendingTasks();
                progressed = true;
            }

            ByteBuf serverOut = serverCh.readOutbound();
            if (serverOut != null) {
                clientCh.writeInbound(serverOut.retain());
                serverOut.release();
                clientCh.runPendingTasks();
                progressed = true;
            }

            clientCh.runPendingTasks();
            serverCh.runPendingTasks();

            if (!progressed) {
                Thread.sleep(10);
            }
        }

        clientSsl.handshakeFuture().sync();
        serverSsl.handshakeFuture().sync();
    }

    private static java.security.cert.X509Certificate[] toJcaChain(
            TlsTestHelper.CertBundle leaf, TlsTestHelper.CertBundle... intermediates) throws Exception {
        java.security.cert.X509Certificate[] result =
                new java.security.cert.X509Certificate[1 + intermediates.length];
        result[0] = CertificateBridge.toJca(leaf.cert);
        for (int i = 0; i < intermediates.length; i++) {
            result[1 + i] = CertificateBridge.toJca(intermediates[i].cert);
        }
        return result;
    }
}
