package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
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

/**
 * Loopback-тесты GostSSLEngine: client <-> server, mTLS, ALPN, SNI.
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

        // один CA на все тесты — единая точка доверия, не плодим ключи
        rootCa = TlsTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();

        // серверный сертификат default нужен для всех loopback-тестов (без SNI)
        serverCertDefault =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        // отдельный сертификат для api.example.com — чтобы проверить,
        // что SNI-селектор выбирает сертификат по имени хоста, а не берёт первый
        serverCertApi =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"api.example.com"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        // клиентский сертификат для mTLS-тестов (need/wantClientAuth)
        clientCertBundle =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    // ========================================================================
    // Базовая проверка handshake и обмена данными между двумя GostSSLEngine
    // ========================================================================

    @Test
    @DisplayName("Петля: GostSSLEngine клиент <-> сервер, рукопожатие + данные")
    void testLoopbackBasic() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        false);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Loopback mTLS — обе стороны с сертификатами
    // ========================================================================

    @Test
    @DisplayName("Петля mTLS: обе стороны с сертификатами")
    void testLoopbackMtls() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostX509KeyManager clientKeyManager = new GostX509KeyManager();
        clientKeyManager.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCertBundle.cert, rootCa.cert)),
                clientCertBundle.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(caPub, false),
                        "localhost",
                        0,
                        false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        clientKeyManager,
                        new GostX509TrustManager(caPub, false),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // wantClientAuth с клиентским сертификатом — mTLS срабатывает
    // ========================================================================

    @Test
    @DisplayName("Петля, опциональная аутентификация: клиент с сертификатом, mTLS срабатывает")
    void testLoopbackWantAuthWithCert() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostX509KeyManager clientKeyManager = new GostX509KeyManager();
        clientKeyManager.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCertBundle.cert, rootCa.cert)),
                clientCertBundle.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(caPub, false),
                        "localhost",
                        0,
                        false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        clientKeyManager,
                        new GostX509TrustManager(caPub, false),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Loopback ALPN — согласование h2
    // ========================================================================

    @Test
    @DisplayName("Петля ALPN: h2 согласован")
    void testLoopbackAlpn() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        false);
        javax.net.ssl.SSLParameters serverParams = serverEngine.getSSLParameters();
        serverParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        serverEngine.setSSLParameters(serverParams);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        javax.net.ssl.SSLParameters clientParams = clientEngine.getSSLParameters();
        clientParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        doLoopback(clientEngine, serverEngine, pair);

        assertEquals("h2", clientEngine.getApplicationProtocol());
    }

    // ========================================================================
    // Loopback SNI — выбор сертификата по имени хоста
    // ========================================================================

    @Test
    @DisplayName("Петля SNI: клиент запрашивает api.example.com")
    void testLoopbackSni() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // два сертификата на сервере — проверяем SNI-селектор
        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        serverKeyManager.addKeyEntry(
                "api",
                CertificateBridge.toJca(List.of(serverCertApi.cert, rootCa.cert)),
                serverCertApi.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager, new GostX509TrustManager(null, false), "", 0, false);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "api.example.com",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        // если SNI не сработал — сервер вернёт default, а не api
        assertEquals("api.example.com", serverEngine.getRequestedServerName());
    }

    // ========================================================================
    // needClientAuth без клиентского сертификата — fatal
    // ========================================================================

    @Test
    @DisplayName("Петля, обязательная аутентификация: клиент без сертификата -> критическая ошибка")
    void testLoopbackNeedAuthReject() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        Exception ex =
                assertThrows(
                        RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(SSLHandshakeException.class, ex.getCause());
    }

    // ========================================================================
    // wantClientAuth без клиентского сертификата — handshake проходит без mTLS
    // ========================================================================

    @Test
    @DisplayName("Петля, опциональная аутентификация: клиент без сертификата -> OK без mTLS")
    void testLoopbackWantAuthFallback() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        // wantClientAuth не делает mTLS обязательным — рукопожатие проходит
        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
        // если сервер не получил сертификат — getPeerCertificates падает
        assertThrows(
                SSLPeerUnverifiedException.class,
                () -> serverEngine.getSession().getPeerCertificates());
    }

    // ========================================================================
    // Interop: GostSSLEngine <-> TlsSession (совместимость рукопожатия)
    // ========================================================================

    @Test
    @DisplayName("Совместимость: GostSSLEngine клиент -> TlsSession сервер")
    void testInteropClient() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig =
                new TlsServerConfig(
                        cs,
                        Collections.singletonList(serverCertDefault.cert),
                        serverCertDefault.priv);
        TlsSession serverSession = TlsSession.createServer(serverConfig, pair.getServerTransport());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                serverSession.handshakeAsServer();
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "tls-server");
        serverThread.start();

        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        clientEngine.beginHandshake();
        doClientHandshake(clientEngine, pair);

        serverThread.join(5000);
        if (serverThread.isAlive()) fail("Рукопожатие сервера не завершилось в течение тайм-аута");
        if (serverError.get() != null) throw new RuntimeException(serverError.get());

        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // Interop: TlsSession клиент -> GostSSLEngine сервер
    // ========================================================================

    @Test
    @DisplayName("Совместимость: TlsSession клиент -> GostSSLEngine сервер")
    void testInteropServer() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager, new GostX509TrustManager(null, false), "", 0, false);

        TlsClientConfig clientConfig = new TlsClientConfig(cs);
        TlsSession clientSession = TlsSession.createClient(clientConfig, pair.getClientTransport());

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                clientSession.handshakeAsClient();
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "tls-client");
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
    @DisplayName("ALPN обратимость: getSSLParameters возвращает applicationProtocols")
    void testAlpnRoundTrip() {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        SSLParameters params = new SSLParameters();
        params.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        engine.setSSLParameters(params);

        SSLParameters returned = engine.getSSLParameters();
        assertArrayEquals(
                new String[] {"h2", "http/1.1"},
                returned.getApplicationProtocols(),
                "applicationProtocols должны сохраняться при обратимости через getSSLParameters");
    }

    // ========================================================================
    // getHandshakeApplicationProtocol доступен после handshake
    // ========================================================================

    @Test
    @DisplayName("getHandshakeApplicationProtocol: не null после завершения handshake")
    void testHandshakeAlpnEarly() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostX509KeyManager ckm = new GostX509KeyManager();

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(ckm, new GostX509TrustManager(null, false), "localhost", 0, true);

        SSLParameters serverParams = new SSLParameters();
        serverParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        serverEngine.setSSLParameters(serverParams);
        SSLParameters clientParams = new SSLParameters();
        clientParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                doClientHandshake(clientEngine, pair);
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "alpn-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                doServerHandshake(serverEngine, pair);
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "alpn-server");

        clientThread.start();
        serverThread.start();
        clientThread.join(10000);
        serverThread.join(10000);

        if (clientError.get() != null) throw new RuntimeException(clientError.get());
        if (serverError.get() != null) throw new RuntimeException(serverError.get());

        // если ALPN не сработал — getApplicationProtocol вернёт null
        assertEquals("h2", clientEngine.getApplicationProtocol(), "ALPN клиента должен быть h2");
        assertEquals(
                "h2",
                serverEngine.getHandshakeApplicationProtocol(),
                "ALPN сервера (getHandshakeApplicationProtocol) должен быть h2");
    }

    // ========================================================================
    // Multi-CA
    // ========================================================================

    @Test
    @DisplayName("Множественный CA: сертификат подписан вторым CA из двух — рукопожатие успешно")
    void testMultiCaPositiveSecondCa() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // Два независимых CA
        TlsTestHelper.CertBundle ca1 = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle ca2 = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub2 = ca2.cert.getPublicKey();

        // Серверный сертификат подписан CA #2
        TlsTestHelper.CertBundle serverCert =
                TlsTestHelper.createCertSignedBy(
                        params,
                        ca2.priv,
                        caPub2,
                        ca2.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, ca2.cert)),
                serverCert.priv);

        GostX509TrustManager tm =
                new GostX509TrustManager(
                        List.of(ca1.cert.getPublicKey(), caPub2), OcspPolicy.IF_PRESENT, null);

        GostSSLEngine serverEngine = new GostSSLEngine(serverKm, tm, "localhost", 0, false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(new GostX509KeyManager(), tm, "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);
    }

    @Test
    @DisplayName(
            "Множественный CA: сертификат подписан третьим CA (не в списке) — рукопожатие падает")
    void testMultiCaNegativeThirdCa() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsTestHelper.CertBundle ca1 = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle ca2 = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle ca3 = TlsTestHelper.createRootCA(params);
        PublicKeyParameters caPub3 = ca3.cert.getPublicKey();

        // Серверный сертификат подписан CA #3 (не в списке доверенных)
        TlsTestHelper.CertBundle serverCert =
                TlsTestHelper.createCertSignedBy(
                        params,
                        ca3.priv,
                        caPub3,
                        ca3.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, ca3.cert)),
                serverCert.priv);

        GostX509TrustManager tm =
                new GostX509TrustManager(
                        List.of(ca1.cert.getPublicKey(), ca2.cert.getPublicKey()),
                        OcspPolicy.IF_PRESENT,
                        null);

        GostSSLEngine serverEngine = new GostSSLEngine(serverKm, tm, "localhost", 0, false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(new GostX509KeyManager(), tm, "localhost", 0, true);

        RuntimeException ex =
                assertThrows(
                        RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(
                SSLException.class,
                ex.getCause(),
                "Причина должна быть SSLException, не " + ex.getCause());
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
    private void doLoopback(
            GostSSLEngine clientEngine, GostSSLEngine serverEngine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                doClientHandshake(clientEngine, pair);
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "loopback-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                doServerHandshake(serverEngine, pair);
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "loopback-server");

        clientThread.start();
        serverThread.start();

        clientThread.join(10000);
        serverThread.join(10000);

        if (clientThread.isAlive()) {
            clientThread.interrupt();
            fail("Тайм-аут рукопожатия клиента");
        }
        if (serverThread.isAlive()) {
            serverThread.interrupt();
            fail("Тайм-аут рукопожатия сервера");
        }
        if (clientError.get() != null)
            throw new RuntimeException("Клиент завершился с ошибкой", clientError.get());
        if (serverError.get() != null)
            throw new RuntimeException("Сервер завершился с ошибкой", serverError.get());
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
    private void doClientHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
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
        throw new RuntimeException(
                "Рукопожатие клиента не завершилось за 80 итераций, status="
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
    private void doServerHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
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
        throw new RuntimeException(
                "Рукопожатие сервера не завершилось за 80 итераций, status="
                        + engine.getHandshakeStatus());
    }

    // ========================================================================
    // Regression: wrap() возвращает FINISHED при HANDSHAKE->DATA
    // ========================================================================

    @Test
    @DisplayName("Регрессия: рукопожатие -> wrap возвращает FINISHED, затем NOT_HANDSHAKING")
    void testWrapReturnsFinished() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        doLoopback(client, server, pair);
        // после handshake getHandshakeStatus должен быть NOT_HANDSHAKING
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                client.getHandshakeStatus(),
                "После handshake getHandshakeStatus должен быть NOT_HANDSHAKING");
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                server.getHandshakeStatus(),
                "После handshake серверный статус должен быть NOT_HANDSHAKING");
    }

    // ========================================================================
    // Regression: клиентский Finished шифруется handshake-ключами
    // ========================================================================

    @Test
    @DisplayName("Регрессия: Client Finished с handshake-ключами, AppData с app-ключами")
    void testDeferredClientAppKeys() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        doLoopback(client, server, pair);
        // после handshake writerRecord с app-ключами, seqNum=0 —
        // Client Finished ушёл с handshake-ключами (не app)
        TlsRecord wr = client.getWriterRecordForTest();
        assertNotNull(wr, "writerRecord должен существовать после handshake");
        assertEquals(
                0,
                wr.getSequenceNumber(),
                "seqNum writerRecord = 0 — начало app epoch, AppData ещё не отправлена");
        // отправляем AppData — seqNum становится 1, сервер расшифровывает
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        netBuf.clear();
        client.wrap(ByteBuffer.wrap("Hello".getBytes()), netBuf);
        netBuf.flip();
        assertEquals(1, wr.getSequenceNumber(), "seqNum writerRecord = 1 после одной AppData");
        // передача серверу — если бы ключи не совпали, unwrap бы упал
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
                assertTrue(
                        server.unwrap(netBuf, appBuf).bytesProduced() > 0,
                        "Сервер должен расшифровать AppData");
                appBuf.flip();
                byte[] received = new byte[appBuf.remaining()];
                appBuf.get(received);
                assertEquals("Hello", new String(received), "Содержимое AppData должно совпадать");
                return;
            }
            Thread.sleep(10);
        }
        fail("Сервер не принял AppData за 80 итераций");
    }

    // ========================================================================
    // Regression: closeOutbound() -> wrap() не перешифровывает close_notify
    // ========================================================================

    @Test
    @DisplayName("Регрессия: closeOutbound() -> wrap() не перешифровывает close_notify")
    void testCloseOutboundWrapDoesNotDoubleEncrypt() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // Сервер с сертификатом
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);

        // Клиент без сертификата (чистый клиент)
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        doLoopback(client, server, pair);

        // Сервер закрывает исходящий канал (Undertow-сценарий: closeOutbound -> wrap)
        server.closeOutbound();
        assertTrue(server.isOutboundDone(), "isOutboundDone после closeOutbound");

        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        netBuf.clear();
        // именно этот wrap() перешифровывал close_notify до фикса
        SSLEngineResult wrapResult = server.wrap(ByteBuffer.allocate(0), netBuf);
        assertTrue(
                wrapResult.bytesProduced() > 0,
                "wrap() должен произвести байты (close_notify запись)");
        netBuf.flip();

        // Передаём клиенту — если двойное шифрование, unwrap() бросит SSLException
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        // assertDoesNotThrow — ключевая проверка регрессии
        assertDoesNotThrow(
                () -> client.unwrap(netBuf, appBuf),
                "unwrap() close_notify не должен бросать исключение (bad_record_mac)");
        assertTrue(client.isInboundDone(), "клиент должен зафиксировать получение close_notify");
    }

    // ========================================================================
    // Regression: unwrap() возвращает Status.CLOSED при получении close_notify
    // ========================================================================

    @Test
    @DisplayName("Регрессия: unwrap() close_notify возвращает Status.CLOSED, а не Status.OK")
    void testUnwrapCloseNotifyReturnsClosed() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);

        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        doLoopback(client, server, pair);

        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // отправляем app data перед close_notify, чтобы гарантировать,
        // что close_notify придёт отдельной TLS-записью, а не склеенной с данными.
        // Иначе тест был бы зелёным и без фикса (как маленькие файлы работали).
        ByteBuffer sendBuf = ByteBuffer.wrap(new byte[] {0x42});
        netBuf.clear();
        client.wrap(sendBuf, netBuf);
        netBuf.flip();

        appBuf.clear();
        server.unwrap(netBuf, appBuf);
        assertEquals(0x42, appBuf.get(0), "сервер должен получить отправленный байт app data");

        // Клиентское closeOutbound -> wrap -> close_notify в отдельной записи
        client.closeOutbound();
        netBuf.clear();
        SSLEngineResult wrapResult = client.wrap(ByteBuffer.allocate(0), netBuf);
        assertTrue(wrapResult.bytesProduced() > 0, "wrap() должен произвести close_notify запись");
        netBuf.flip();

        // Сервер принимает close_notify — баг: возвращал Status.OK
        appBuf.clear();
        SSLEngineResult unwrapResult = server.unwrap(netBuf, appBuf);
        assertEquals(
                SSLEngineResult.Status.CLOSED,
                unwrapResult.getStatus(),
                "unwrap() close_notify должен вернуть Status.CLOSED, а не Status.OK");
        assertTrue(server.isInboundDone(), "сервер должен зафиксировать получение close_notify");
    }

    // ========================================================================
    // Regression: bytesProduced корректен при нескольких AppData записях
    // ========================================================================

    @Test
    @DisplayName("Регрессия: unwrap bytesProduced совпадает с реальными байтами")
    void testMultiRecordUnwrapProducedCount() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        skm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);

        doLoopback(client, server, pair);

        byte[] data1 = new byte[100];
        byte[] data2 = new byte[200];
        // Заполняем тестовыми данными
        for (int i = 0; i < data1.length; i++) data1[i] = (byte) i;
        for (int i = 0; i < data2.length; i++) data2[i] = (byte) (i + 100);

        ByteBuffer tmp = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        ByteBuffer net1 =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer net2 =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

        // Шифруем две отдельные записи в раздельные буферы
        tmp.clear();
        tmp.put(data1);
        tmp.flip();
        client.wrap(tmp, net1);
        net1.flip();

        tmp.clear();
        tmp.put(data2);
        tmp.flip();
        client.wrap(tmp, net2);
        net2.flip();

        // подаём записи раздельно (а не склеенными), чтобы тест был
        // детерминирован — каждая unwrap обрабатывает одну запись,
        // без зависимости от внутренних оптимизаций обработки.
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Первая запись — отдельный буфер
        appBuf.clear();
        SSLEngineResult r1 = server.unwrap(net1, appBuf);
        assertTrue(
                r1.bytesProduced() > 0, "bytesProduced должен быть > 0 после unwrap первой записи");
        appBuf.flip();
        assertEquals(
                data1.length, appBuf.remaining(), "сервер должен получить 100 байт первой записи");
        assertEquals(
                data1.length,
                r1.bytesProduced(),
                "bytesProduced должен равняться реальному количеству байт в dst");

        // Вторая запись — отдельный буфер
        appBuf.clear();
        SSLEngineResult r2 = server.unwrap(net2, appBuf);
        assertTrue(
                r2.bytesProduced() > 0, "bytesProduced должен быть > 0 после unwrap второй записи");
        appBuf.flip();
        assertEquals(
                data2.length, appBuf.remaining(), "сервер должен получить 200 байт второй записи");
        assertEquals(
                data2.length,
                r2.bytesProduced(),
                "bytesProduced должен равняться реальному количеству байт в dst");
    }
}
