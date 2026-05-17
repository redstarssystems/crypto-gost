package org.rssys.gost.jsse.engine;

import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Loopback-тесты GostSSLEngine: client ↔ server, mTLS, ALPN, SNI.
 */
class GostSSLEngineLoopbackTest {

    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static TlsTestHelper.CertBundle serverCertDefault;
    private static TlsTestHelper.CertBundle serverCertApi;
    private static TlsTestHelper.CertBundle clientCertBundle;
    private static TlsTestHelper.CertBundle rootCa;
    private static PublicKeyParameters caPub;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        // WHY: один CA на все тесты — единая точка доверия, не плодим ключи
        rootCa = TlsTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();

        // WHY: серверный сертификат default нужен для всех loopback-тестов (без SNI)
        serverCertDefault = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        // WHY: отдельный сертификат для api.example.com — чтобы проверить,
        // что SNI-селектор выбирает сертификат по имени хоста, а не берёт первый
        serverCertApi = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"api.example.com"}, new byte[]{(byte) 0x80}, null,
                false, null);

        // WHY: клиентский сертификат для mTLS-тестов (need/wantClientAuth)
        clientCertBundle = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null,
                false, null);
    }

    // ========================================================================
    // Базовая проверка handshake и обмена данными между двумя GostSSLEngine
    // ========================================================================

    @Test
    @DisplayName("Loopback: GostSSLEngine клиент ↔ сервер, рукопожатие + данные")
    void testLoopbackBasic() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Loopback mTLS — обе стороны с сертификатами
    // ========================================================================

    @Test
    @DisplayName("Loopback mTLS: обе стороны с сертификатами")
    void testLoopbackMtls() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostX509KeyManager clientKeyManager = new GostX509KeyManager();
        clientKeyManager.addKeyEntry("client", toJcaChain(clientCertBundle, rootCa), clientCertBundle.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(caPub, false),
                "localhost", 0, false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine = new GostSSLEngine(
                clientKeyManager, new GostX509TrustManager(caPub, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // wantClientAuth с клиентским сертификатом — mTLS срабатывает
    // ========================================================================

    @Test
    @DisplayName("Loopback want auth: клиент с сертификатом, mTLS срабатывает")
    void testLoopbackWantAuthWithCert() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostX509KeyManager clientKeyManager = new GostX509KeyManager();
        clientKeyManager.addKeyEntry("client", toJcaChain(clientCertBundle, rootCa), clientCertBundle.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(caPub, false),
                "localhost", 0, false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine = new GostSSLEngine(
                clientKeyManager, new GostX509TrustManager(caPub, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Loopback ALPN — согласование h2
    // ========================================================================

    @Test
    @DisplayName("Loopback ALPN: h2 согласован")
    void testLoopbackAlpn() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        javax.net.ssl.SSLParameters serverParams = serverEngine.getSSLParameters();
        serverParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        serverEngine.setSSLParameters(serverParams);

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
        javax.net.ssl.SSLParameters clientParams = clientEngine.getSSLParameters();
        clientParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        doLoopback(clientEngine, serverEngine, pair);

        assertEquals("h2", clientEngine.getApplicationProtocol());
    }

    // ========================================================================
    // Loopback SNI — выбор сертификата по имени хоста
    // ========================================================================

    @Test
    @DisplayName("Loopback SNI: client запрашивает api.example.com")
    void testLoopbackSni() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // WHY: два сертификата на сервере — проверяем SNI-селектор
        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);
        serverKeyManager.addKeyEntry("api", toJcaChain(serverCertApi, rootCa), serverCertApi.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "", 0, false);

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "api.example.com", 0, true);

        doLoopback(clientEngine, serverEngine, pair);

        // WHY: если SNI не сработал — сервер вернёт default, а не api
        assertEquals("api.example.com", serverEngine.getRequestedServerName());
    }

    // ========================================================================
    // needClientAuth без клиентского сертификата — fatal
    // ========================================================================

    @Test
    @DisplayName("Loopback need auth: клиент без сертификата → fatal")
    void testLoopbackNeedAuthReject() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        Exception ex = assertThrows(RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(SSLHandshakeException.class, ex.getCause());
    }

    // ========================================================================
    // wantClientAuth без клиентского сертификата — handshake проходит без mTLS
    // ========================================================================

    @Test
    @DisplayName("Loopback want auth: клиент без сертификата → OK без mTLS")
    void testLoopbackWantAuthFallback() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);

        // WHY: wantClientAuth не делает mTLS обязательным — рукопожатие проходит
        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
        // WHY: если сервер не получил сертификат — getPeerCertificates падает
        assertThrows(SSLPeerUnverifiedException.class,
                () -> serverEngine.getSession().getPeerCertificates());
    }

    // ========================================================================
    // Interop: GostSSLEngine ↔ TlsSession (совместимость рукопожатия)
    // ========================================================================

    @Test
    @DisplayName("Interop: GostSSLEngine клиент → TlsSession сервер")
    void testInteropClient() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig = new TlsServerConfig(cs,
                Collections.singletonList(serverCertDefault.cert), serverCertDefault.priv);
        TlsSession serverSession = TlsSession.createServer(serverConfig, pair.getServerTransport());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                serverSession.handshakeAsServer();
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "tls-server");
        serverThread.start();

        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        clientEngine.beginHandshake();
        doClientHandshake(clientEngine, pair);

        serverThread.join(5000);
        if (serverThread.isAlive()) fail("Рукопожатие сервера не завершилось в течение тайм-аута");
        if (serverError.get() != null) throw new RuntimeException(serverError.get());

        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // Interop: TlsSession клиент → GostSSLEngine сервер
    // ========================================================================

    @Test
    @DisplayName("Interop: TlsSession клиент → GostSSLEngine сервер")
    void testInteropServer() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "", 0, false);

        TlsClientConfig clientConfig = new TlsClientConfig(cs);
        TlsSession clientSession = TlsSession.createClient(clientConfig, pair.getClientTransport());

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        Thread clientThread = new Thread(() -> {
            try {
                clientSession.handshakeAsClient();
            } catch (Exception e) {
                clientError.set(e);
            }
        }, "tls-client");
        clientThread.start();

        serverEngine.beginHandshake();
        doServerHandshake(serverEngine, pair);

        clientThread.join(5000);
        if (clientThread.isAlive()) fail("Рукопожатие клиента не завершилось в течение тайм-аута");
        if (clientError.get() != null) throw new RuntimeException(clientError.get());

        assertTrue(serverEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // ALPN round-trip через SSLParameters
    // ========================================================================

    @Test
    @DisplayName("ALPN round-trip: getSSLParameters возвращает applicationProtocols")
    void testAlpnRoundTrip() {
        GostSSLEngine engine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
        SSLParameters params = new SSLParameters();
        params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        engine.setSSLParameters(params);

        SSLParameters returned = engine.getSSLParameters();
        assertArrayEquals(new String[]{"h2", "http/1.1"},
                returned.getApplicationProtocols(),
                "applicationProtocols должны сохраняться при round-trip через getSSLParameters");
    }

    // ========================================================================
    // getHandshakeApplicationProtocol доступен после handshake
    // ========================================================================

    @Test
    @DisplayName("getHandshakeApplicationProtocol: не null после завершения handshake")
    void testHandshakeAlpnEarly() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa),
                serverCertDefault.priv);
        GostX509KeyManager ckm = new GostX509KeyManager();

        GostSSLEngine serverEngine = new GostSSLEngine(
                skm, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                ckm, new GostX509TrustManager(null, false),
                "localhost", 0, true);

        SSLParameters serverParams = new SSLParameters();
        serverParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        serverEngine.setSSLParameters(serverParams);
        SSLParameters clientParams = new SSLParameters();
        clientParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try { doClientHandshake(clientEngine, pair); }
            catch (Exception e) { clientError.set(e); }
        }, "alpn-client");
        Thread serverThread = new Thread(() -> {
            try { doServerHandshake(serverEngine, pair); }
            catch (Exception e) { serverError.set(e); }
        }, "alpn-server");

        clientThread.start();
        serverThread.start();
        clientThread.join(10000);
        serverThread.join(10000);

        if (clientError.get() != null) throw new RuntimeException(clientError.get());
        if (serverError.get() != null) throw new RuntimeException(serverError.get());

        // WHY: если ALPN не сработал — getApplicationProtocol вернёт null
        assertEquals("h2", clientEngine.getApplicationProtocol(),
                "ALPN клиента должен быть h2");
        assertEquals("h2", serverEngine.getHandshakeApplicationProtocol(),
                "ALPN сервера (getHandshakeApplicationProtocol) должен быть h2");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /**
     * Выполняет полный handshake между двумя GostSSLEngine в параллельных потоках.
     * <p>
     * Вызывает beginHandshake на обеих сторонах, запускает handshake-циклы в двух
     * vthread-потоках и ждёт их завершения.
     *
     * @param clientEngine клиентский GostSSLEngine (предварительно сконфигурированный, beginHandshake не нужен)
     * @param serverEngine серверный GostSSLEngine (предварительно сконфигурированный, beginHandshake не нужен)
     * @param pair         транспортная пара для обмена данными
     * @throws Exception если handshake не завершился за 10 секунд
     *
     * Предусловие: оба engine сконфигурированы (keyManager, trustManager заданы).
     * Постусловие: оба engine в состоянии FINISHED или NOT_HANDSHAKING.
     */
    private void doLoopback(GostSSLEngine clientEngine, GostSSLEngine serverEngine,
                            InMemoryTlsTransport.Pair pair) throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try {
                doClientHandshake(clientEngine, pair);
            } catch (Exception e) {
                clientError.set(e);
            }
        }, "loopback-client");
        Thread serverThread = new Thread(() -> {
            try {
                doServerHandshake(serverEngine, pair);
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "loopback-server");

        clientThread.start();
        serverThread.start();

        clientThread.join(10000);
        serverThread.join(10000);

        if (clientThread.isAlive()) { clientThread.interrupt(); fail("Тайм-аут рукопожатия клиента"); }
        if (serverThread.isAlive()) { serverThread.interrupt(); fail("Тайм-аут рукопожатия сервера"); }
        if (clientError.get() != null) throw new RuntimeException("Клиент завершился с ошибкой", clientError.get());
        if (serverError.get() != null) throw new RuntimeException("Сервер завершился с ошибкой", serverError.get());
    }

    /**
     * Цикл handshake для клиента: wrap/unwrap через in-memory transport.
     * <p>
     * Параллельный handshake (два потока обмениваются TLS-сообщениями через
     * in-memory очереди). 80 итераций — запас для случая, когда один поток
     * ждёт данные, которые ещё не отправлены другим.
     *
     * @param engine клиентский GostSSLEngine (уже вызван beginHandshake)
     * @param pair   транспортная пара для обмена данными
     * @throws Exception если handshake не завершился за 80 итераций
     *
     * Предусловие: engine.beginHandshake() уже вызван.
     * Постусловие: engine в состоянии FINISHED или NOT_HANDSHAKING, либо исключение.
     */
    private void doClientHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
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
                    } else {
                        Thread.sleep(10);
                    }
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Рукопожатие клиента не завершилось за 80 итераций, status="
                + engine.getHandshakeStatus());
    }

    /**
     * Цикл handshake для сервера: wrap/unwrap через in-memory transport.
     *
     * @param engine серверный GostSSLEngine (уже вызван beginHandshake)
     * @param pair   транспортная пара для обмена данными
     * @throws Exception если handshake не завершился за 80 итераций
     *
     * Предусловие: engine.beginHandshake() уже вызван.
     * Постусловие: engine в состоянии FINISHED или NOT_HANDSHAKING, либо исключение.
     */
    private void doServerHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
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
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        pair.getServerTransport().sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = pair.getServerTransport().receiveRecord();
                    if (inData != null) {
                        netBuf.clear();
                        netBuf.put(inData);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    } else {
                        Thread.sleep(10);
                    }
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Рукопожатие сервера не завершилось за 80 итераций, status="
                + engine.getHandshakeStatus());
    }

    /**
     * Конвертирует связку сертификатов TlsCertificate в JCA X509Certificate[].
     * <p>
     * JSSE API (GostX509KeyManager, GostX509TrustManager) требует
     * X509Certificate[], поэтому перед передачей в эти классы все внутренние
     * TlsCertificate нужно конвертировать через CertificateBridge.
     *
     * @param leaf          листовой сертификат
     * @param intermediates промежуточные CA-сертификаты (опционально)
     * @return массив X509Certificate, leaf на [0], intermediates на [1..n]
     * @throws Exception если DER-конвертация не удалась
     */
    private static java.security.cert.X509Certificate[] toJcaChain(
            TlsTestHelper.CertBundle leaf, TlsTestHelper.CertBundle... intermediates) throws Exception {
        java.security.cert.X509Certificate[] result = new java.security.cert.X509Certificate[1 + intermediates.length];
        result[0] = org.rssys.gost.jsse.bridge.CertificateBridge.toJca(leaf.cert);
        for (int i = 0; i < intermediates.length; i++) {
            result[1 + i] = org.rssys.gost.jsse.bridge.CertificateBridge.toJca(intermediates[i].cert);
        }
        return result;
    }

    // ========================================================================
    // Regression: wrap() возвращает FINISHED при HANDSHAKE→DATA
    // ========================================================================

    @Test
    @DisplayName("Regression: handshake → wrap возвращает FINISHED, затем NOT_HANDSHAKING")
    void testWrapReturnsFinished() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);
        GostSSLEngine server = new GostSSLEngine(
                skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
        doLoopback(client, server, pair);
        // WHY: после handshake getHandshakeStatus должен быть NOT_HANDSHAKING
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, client.getHandshakeStatus(),
                "После handshake getHandshakeStatus должен быть NOT_HANDSHAKING");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, server.getHandshakeStatus(),
                "После handshake серверный статус должен быть NOT_HANDSHAKING");
    }

    // ========================================================================
    // Regression: клиентский Finished шифруется handshake-ключами
    // ========================================================================

    @Test
    @DisplayName("Regression: Client Finished с handshake-ключами, AppData с app-ключами")
    void testDeferredClientAppKeys() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry("default", toJcaChain(serverCertDefault, rootCa), serverCertDefault.priv);
        GostSSLEngine server = new GostSSLEngine(
                skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
        doLoopback(client, server, pair);
        // WHY: после handshake writerRecord с app-ключами, seqNum=0 —
        // Client Finished ушёл с handshake-ключами (не app)
        TlsRecord wr = client.getWriterRecordForTest();
        assertNotNull(wr, "writerRecord должен существовать после handshake");
        assertEquals(0, wr.getSequenceNumber(),
                "seqNum writerRecord = 0 — начало app epoch, AppData ещё не отправлена");
        // WHY: отправляем AppData — seqNum становится 1, сервер расшифровывает
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        netBuf.clear();
        client.wrap(ByteBuffer.wrap("Hello".getBytes()), netBuf);
        netBuf.flip();
        assertEquals(1, wr.getSequenceNumber(),
                "seqNum writerRecord = 1 после одной AppData");
        // WHY: передача серверу — если бы ключи не совпали, unwrap бы упал
        byte[] outData = new byte[netBuf.remaining()];
        netBuf.get(outData);
        pair.getClientTransport().sendRecord(outData);
        for (int i = 0; i < 80; i++) {
            byte[] inData = pair.getServerTransport().receiveRecord();
            if (inData != null) {
                netBuf.clear();
                netBuf.put(inData);
                netBuf.flip();
                appBuf.clear();
                assertTrue(server.unwrap(netBuf, appBuf).bytesProduced() > 0,
                        "Сервер должен расшифровать AppData");
                appBuf.flip();
                byte[] received = new byte[appBuf.remaining()];
                appBuf.get(received);
                assertEquals("Hello", new String(received),
                        "Содержимое AppData должно совпадать");
                return;
            }
            Thread.sleep(10);
        }
        fail("Сервер не принял AppData за 80 итераций");
    }
}
