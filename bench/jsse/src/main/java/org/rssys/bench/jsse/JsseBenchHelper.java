package org.rssys.bench.jsse;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.X509ExtendedKeyManager;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Helper для JMH-бенчмарков JSSE-модуля: генерация сертификатов,
 * создание SSLContext, loopback handshake.
 */
class JsseBenchHelper {

    static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null)
            Security.addProvider(new RssysGostProvider());
    }

    static class Bundle {
        final X509Certificate cert;
        final PrivateKey privateKey;
        final javax.net.ssl.X509ExtendedKeyManager keyManager;

        Bundle(X509Certificate cert, PrivateKey privateKey,
               javax.net.ssl.X509ExtendedKeyManager keyManager) {
            this.cert = cert;
            this.privateKey = privateKey;
            this.keyManager = keyManager;
        }
    }

    static Bundle createBundle() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert = PkixCertTestHelper.createCertSignedBy(
                params, root.priv,
                root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        X509Certificate jcaCert = CertificateBridge.toJca(serverCert.cert);
        PrivateKey jcaPriv = new GostECPrivateKey(serverCert.priv);

        org.rssys.gost.jsse.manager.GostX509KeyManager km = new org.rssys.gost.jsse.manager.GostX509KeyManager();
        km.addKeyEntry("default", new X509Certificate[]{jcaCert}, serverCert.priv);

        return new Bundle(jcaCert, jcaPriv, km);
    }

    static SSLContext createSslContext(Bundle serverBundle) throws Exception {
        SSLContext ctx = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, new org.rssys.gost.jsse.RssysGostJsseProvider());
        ctx.init(new javax.net.ssl.KeyManager[]{serverBundle.keyManager},
                 new javax.net.ssl.TrustManager[]{GostX509TrustManager.insecureTrustAll()},
                 null);
        return ctx;
    }

    /**
     * Loopback handshake: два SSLEngine обмениваются данными через InMemoryTlsTransport.
     * Серверная сторона — в CompletableFuture с executor, клиентская — в текущем потоке.
     * Pump — проверенный паттерн из GostSSLEngineLoopbackTest.
     */
    static void doHandshake(SSLEngine client, SSLEngine server, ExecutorService exec) throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        client.beginHandshake();
        server.beginHandshake();

        java.util.concurrent.CompletableFuture<Void> sf = java.util.concurrent.CompletableFuture.runAsync(() -> {
            try { pumpLoop(server, pair.getServerTransport()); }
            catch (Exception e) { throw new RuntimeException(e); }
        }, exec);

        pumpLoop(client, pair.getClientTransport());
        sf.get();
    }

    /** Switch-based SSLEngine handshake pump (один шаг на итерацию). */
    private static void pumpLoop(SSLEngine engine,
                                  org.rssys.gost.tls13.TlsTransport transport) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 200; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        transport.sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = transport.receiveRecord();
                    if (inData != null) {
                        netBuf.clear();
                        netBuf.put(inData);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    }
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Handshake did not complete after 200 iterations, status="
                + engine.getHandshakeStatus());
    }

    // createBundle заменён на PkixCertTestHelper.createRootCA() — DER-хелперы удалены
}
