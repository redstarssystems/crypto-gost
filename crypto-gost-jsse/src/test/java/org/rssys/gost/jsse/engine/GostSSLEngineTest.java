package org.rssys.gost.jsse.engine;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Интеграционные тесты GostSSLEngine.
 */
class GostSSLEngineTest {

    private static TlsCertificate serverCert;
    private static PrivateKeyParameters serverPriv;
    private static TlsCiphersuite cs;

    private static TlsCertificate caCert;
    private static PrivateKeyParameters caPriv;
    private static PublicKeyParameters caPub;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        serverCert = bundle.cert;
        serverPriv = bundle.priv;

        // WHY: собственный CA для теста цепочки — нужна подпись, которой мы доверяем
        TlsTestHelper.CertBundle caBundle = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        caCert = caBundle.cert;
        caPriv = caBundle.priv;
        caPub = caCert.getPublicKey();
    }

    @Test
    @DisplayName("GostSSLEngine после beginHandshake переходит в NEED_WRAP и генерирует ClientHello")
    void testEngineProducesClientHello() throws Exception {
        GostSSLEngine engine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
        engine.beginHandshake();
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_WRAP, engine.getHandshakeStatus());

        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        SSLEngineResult r = engine.wrap(ByteBuffer.allocate(0), dst);
        dst.flip();
        assertTrue(dst.hasRemaining(), "wrap should produce data");
    }

    @Test
    @DisplayName("Клиент GostSSLEngine → сервер TlsSession: handshake + app data + close")
    void testEngineClientToTlsSessionServer() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig = new TlsServerConfig(cs,
                Collections.singletonList(serverCert), serverPriv);
        TlsSession serverSession = TlsSession.createServer(serverConfig, pair.getServerTransport());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                serverSession.handshakeAsServer();
            } catch (Exception e) {
                serverError.set(e);
                throw new RuntimeException("Server handshake failed", e);
            }
        }, "tls-server");
        serverThread.start();

        GostX509TrustManager trustManager = new GostX509TrustManager(null, false);
        GostX509KeyManager keyManager = new GostX509KeyManager();
        GostSSLEngine clientEngine = new GostSSLEngine(keyManager, trustManager,
                "localhost", 0, true);

        clientEngine.beginHandshake();
        doHandshake(clientEngine, pair);

        // WHY: ждём серверный handshake — без него app data принять не сможем
        serverThread.join(5000);
        if (serverThread.isAlive()) {
            throw new RuntimeException("Server handshake did not complete");
        }
        if (serverError.get() != null) {
            Throwable se = serverError.get();
            throw new RuntimeException("Server handshake error: " + se.getMessage(), se);
        }

        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"),
                "Suite: " + clientEngine.getSession().getCipherSuite());
        assertEquals(GostJsseConstants.PROTOCOL_TLS_1_3, clientEngine.getSession().getProtocol());

        // WHY: отправляем app-данные, чтобы убедиться, что шифрование работает
        String msg = "Hello from GostSSLEngine!";
        byte[] msgBytes = msg.getBytes("UTF-8");
        ByteBuffer wrapBuf = ByteBuffer.wrap(msgBytes);
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        SSLEngineResult wr = clientEngine.wrap(wrapBuf, netBuf);
        netBuf.flip();
        byte[] enc = new byte[netBuf.remaining()];
        netBuf.get(enc);
        pair.getClientTransport().sendRecord(enc);

        byte[] received = serverSession.read();
        assertEquals(msg, new String(received, "UTF-8"));

        // WHY: ответные app-данные — двусторонняя проверка шифрования
        String resp = "Hello back!";
        serverSession.write(resp.getBytes("UTF-8"));

        // WHY: после handshake сервер мог прислать NST — читаем в цикле,
        // отбрасывая post-handshake сообщения, пока не получим app-данные
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        byte[] respData;
        outer:
        while (true) {
            byte[] serverRaw = pair.getClientTransport().receiveRecord();
            netBuf.clear();
            netBuf.put(serverRaw);
            netBuf.flip();
            appBuf.clear();
            SSLEngineResult rr = clientEngine.unwrap(netBuf, appBuf);
            appBuf.flip();
            respData = new byte[appBuf.remaining()];
            appBuf.get(respData);
            if (respData.length > 0) break;
        }
        assertEquals(resp, new String(respData, "UTF-8"));

        clientEngine.closeOutbound();
        serverSession.close();
        serverThread.join(5000);
    }

    /**
     * Выполняет handshake для клиентского engine до состояния FINISHED.
     *
     * @param engine клиентский GostSSLEngine
     * @param pair   пара in-memory транспортов для обмена данными
     * @throws Exception если handshake не завершился за 50 итераций
     *
     * Предусловие: engine.beginHandshake() уже вызван.
     * Постусловие: engine.getHandshakeStatus() == FINISHED или NOT_HANDSHAKING.
     */
    private void doHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 50; i++) {
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
                        pair.getClientTransport().sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = pair.getClientTransport().receiveRecord();
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
        throw new RuntimeException("Handshake did not complete after 50 iterations");
    }

    @Test
    @DisplayName("TrustManager валидирует цепочку с реальным CA")
    void testTrustManagerWithCA() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        // WHY: собственный CA — нужна независимая подпись для теста валидации
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle server = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        java.security.cert.X509Certificate[] jcaChain =
                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(
                        java.util.List.of(server.cert, rootCa.cert));
        GostX509TrustManager trustManager = new GostX509TrustManager(
                rootCa.cert.getPublicKey(), false);
        trustManager.checkServerTrusted(jcaChain, "ECGOST3410-2012-256");
    }

    @Test
    @DisplayName("OCSP staple через setOcspResponse")
    void testOcspStapleViaSetter() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        GostX509TrustManager tm = new GostX509TrustManager(caPub, true);

        GostSSLEngine engine = new GostSSLEngine(km, tm,
                "localhost", 0, false);
        engine.beginHandshake();

        byte[] dummyOcsp = TlsTestHelper.buildDummyOcspResponse();
        engine.setOcspResponse(dummyOcsp);

        assertNotNull(engine.getOcspResponseForTest(),
                "OCSP response должен быть установлен после setOcspResponse");
        assertSame(dummyOcsp, engine.getOcspResponseForTest(),
                "getOcspResponseForTest должен вернуть тот же массив (no clone)");
    }
}
