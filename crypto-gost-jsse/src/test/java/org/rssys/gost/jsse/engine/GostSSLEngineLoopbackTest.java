package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
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
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Loopback-тесты GostSSLEngine: client <-> server, mTLS, ALPN, SNI.
 */
@DisplayName("GostSSLEngine: рукопожатие и обмен данными в памяти")
class GostSSLEngineLoopbackTest {

    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle serverCertDefault;
    private static PkixCertTestHelper.CertBundle serverCertApi;
    private static PkixCertTestHelper.CertBundle clientCertBundle;
    private static PkixCertTestHelper.CertBundle rootCa;
    private static PublicKeyParameters caPub;
    private static GostCertificate caCert;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        // один CA на все тесты — единая точка доверия, не плодим ключи
        rootCa = PkixCertTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();
        caCert = rootCa.cert;

        // серверный сертификат default нужен для всех loopback-тестов (без SNI)
        serverCertDefault =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        // отдельный сертификат для api.example.com — чтобы проверить,
        // что SNI-селектор выбирает сертификат по имени хоста, а не берёт первый
        serverCertApi =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"api.example.com"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        // клиентский сертификат для mTLS-тестов (need/wantClientAuth)
        clientCertBundle =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    @Test
    @DisplayName("mTLS need/want: NewSessionTicket не выдаётся")
    void testClientAuthSuppressesNst() throws Exception {
        for (boolean want : new boolean[] {false, true}) {
            InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
            GostSSLSessionContext serverContext = new GostSSLSessionContext(cs);
            GostSSLSessionContext clientContext = new GostSSLSessionContext(cs);

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
                    GostSSLEngine.createForServer(
                            serverKeyManager,
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(caCert)),
                            "localhost",
                            0,
                            serverContext);
            if (want) {
                serverEngine.setWantClientAuth(true);
            } else {
                serverContext.setNeedClientAuth(true);
            }
            GostSSLEngine clientEngine =
                    GostSSLEngine.createForClient(
                            clientKeyManager,
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(caCert)),
                            "localhost",
                            0,
                            clientContext);

            doLoopback(clientEngine, serverEngine, pair);
            assertEquals(
                    0,
                    serverContext.getPskStore().size(),
                    "при client auth тикет не должен сохраняться в PskStore (want=" + want + ")");
        }
    }

    @Test
    @DisplayName("mTLS: STAPLING_REQUIRED у сервера не блокирует клиента без staple")
    void testMtlsWithServerStaplingRequired() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLSessionContext serverContext = new GostSSLSessionContext(cs);
        GostSSLSessionContext clientContext = new GostSSLSessionContext(cs);

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
                GostSSLEngine.createForServer(
                        serverKeyManager,
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(caCert),
                                OcspPolicy.STAPLING_REQUIRED,
                                null),
                        "localhost",
                        0,
                        serverContext);
        serverContext.setNeedClientAuth(true);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        clientKeyManager,
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        clientContext);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Базовая проверка handshake и обмена данными между двумя GostSSLEngine
    // ========================================================================

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
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        clientKeyManager,
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

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
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        clientKeyManager,
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

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
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        javax.net.ssl.SSLParameters serverParams = serverEngine.getSSLParameters();
        serverParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        serverEngine.setSSLParameters(serverParams);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
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
                        serverKeyManager, GostX509TrustManager.insecureTrustAll(), "", 0, false);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "api.example.com",
                        0,
                        null);

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
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        serverEngine.setNeedClientAuth(true);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);

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
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);

        doLoopback(clientEngine, serverEngine, pair);

        // wantClientAuth не делает mTLS обязательным — рукопожатие проходит
        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
        // если сервер не получил сертификат — getPeerCertificates падает
        assertThrows(
                SSLPeerUnverifiedException.class,
                () -> serverEngine.getSession().getPeerCertificates());
    }

    @Test
    @DisplayName(
            "Петля: want из контекста сессии (builder.wantClientAuth) -> клиент без сертификата принят")
    void testLoopbackWantAuthFromSessionContext() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);

        GostSSLSessionContext serverContext =
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        serverContext.setWantClientAuth(true);

        GostSSLEngine serverEngine =
                GostSSLEngine.createForServer(
                        serverKeyManager,
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        serverContext);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

        doLoopback(clientEngine, serverEngine, pair);

        assertThrows(
                SSLPeerUnverifiedException.class,
                () -> serverEngine.getSession().getPeerCertificates(),
                "Клиент без сертификата: у сервера нет сертификата пира");
    }

    // ========================================================================
    // Interop: GostSSLEngine <-> TlsSession (совместимость рукопожатия)
    // ========================================================================

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
                        serverKeyManager, GostX509TrustManager.insecureTrustAll(), "", 0, false);

        TlsClientConfig clientConfig =
                new TlsClientConfig(cs, TrustAnchors.ofCertificate(caCert))
                        .withoutHostnameVerification();
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
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
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
    @DisplayName(
            "ALPN: getApplicationProtocol после handshake, getHandshakeApplicationProtocol -> null")
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
                        skm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        ckm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, null);

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

        assertEquals("h2", clientEngine.getApplicationProtocol(), "ALPN клиента должен быть h2");
        assertEquals("h2", serverEngine.getApplicationProtocol(), "ALPN сервера должен быть h2");
        // Контракт JDK: после завершения рукопожатия handshake-значение уже не определено,
        // итог читается через getApplicationProtocol()
        assertNull(
                serverEngine.getHandshakeApplicationProtocol(),
                "после рукопожатия getHandshakeApplicationProtocol должен вернуть null");
    }

    // ========================================================================
    // Multi-CA
    // ========================================================================

    @Test
    @DisplayName("Множественный CA: сертификат подписан вторым CA из двух — рукопожатие успешно")
    void testMultiCaPositiveSecondCa() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // Два независимых CA
        PkixCertTestHelper.CertBundle ca1 = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle ca2 = PkixCertTestHelper.createRootCA(params);
        PublicKeyParameters caPub2 = ca2.cert.getPublicKey();

        // Серверный сертификат подписан CA #2
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca2.priv,
                        caPub2,
                        ca2.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
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
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(ca1.cert, ca2.cert)),
                        OcspPolicy.IF_PRESENT,
                        null);

        GostSSLEngine serverEngine = new GostSSLEngine(serverKm, tm, "localhost", 0, false);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(new GostX509KeyManager(), tm, "localhost", 0, null);

        doLoopback(clientEngine, serverEngine, pair);
    }

    @Test
    @DisplayName(
            "Множественный CA: сертификат подписан третьим CA (не в списке) — рукопожатие падает")
    void testMultiCaNegativeThirdCa() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        PkixCertTestHelper.CertBundle ca1 = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle ca2 = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle ca3 = PkixCertTestHelper.createRootCA(params);
        PublicKeyParameters caPub3 = ca3.cert.getPublicKey();

        // Серверный сертификат подписан CA #3 (не в списке доверенных)
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        ca3.priv,
                        caPub3,
                        ca3.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
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
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(ca1.cert, ca2.cert)),
                        OcspPolicy.IF_PRESENT,
                        null);

        GostSSLEngine serverEngine = new GostSSLEngine(serverKm, tm, "localhost", 0, false);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(new GostX509KeyManager(), tm, "localhost", 0, null);

        RuntimeException ex =
                assertThrows(
                        RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(
                SSLException.class,
                ex.getCause(),
                "Причина должна быть SSLException, не " + ex.getCause());
    }

    @Test
    @DisplayName("Клиент с null TrustManager не принимает сертификат сервера")
    void testClientWithoutTrustManagerFailsClosed() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(new GostX509KeyManager(), null, "localhost", 0, null);

        RuntimeException ex =
                assertThrows(
                        RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(SSLException.class, ex.getCause(), "ожидается отказ TLS-рукопожатия");
    }

    @Test
    @DisplayName("Сервер без mTLS с null TrustManager работает")
    void testServerWithoutClientAuthAllowsNullTrustManager() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(serverKeyManager, null, "localhost", 0, false);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

        doLoopback(clientEngine, serverEngine, pair);
    }

    @Test
    @DisplayName("wantClientAuth с null TrustManager и сертификатом клиента падает")
    void testServerWantClientAuthWithoutTrustManagerRejectsClientCert() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(serverKeyManager, null, "localhost", 0, false);
        serverEngine.setWantClientAuth(true);

        GostX509KeyManager clientKeyManager = new GostX509KeyManager();
        clientKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(clientCertBundle.cert, rootCa.cert)),
                clientCertBundle.priv);
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        clientKeyManager,
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

        RuntimeException ex =
                assertThrows(
                        RuntimeException.class, () -> doLoopback(clientEngine, serverEngine, pair));
        assertInstanceOf(
                SSLException.class, ex.getCause(), "ожидается отказ из-за отсутствия доверия");
    }

    @Test
    @DisplayName("wantClientAuth с null TrustManager без сертификата клиента работает")
    void testServerWantClientAuthWithoutTrustManagerNoClientCert() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertDefault.cert, rootCa.cert)),
                serverCertDefault.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(serverKeyManager, null, "localhost", 0, false);
        serverEngine.setWantClientAuth(true);

        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert)),
                        "localhost",
                        0,
                        null);

        doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /**
     * Выполняет полный handshake между двумя GostSSLEngine в параллельных потоках.
     * <p>
     * Вызывает beginHandshake на обеих сторонах, запускает handshake-циклы в двух
     * потоках и ждёт их завершения. Упавшая сторона закрывает свой транспорт, чтобы вторая не
     * ждала таймаут транспорта; причиной отказа считается первая записанная ошибка
     * ({@link HandshakeFailures}).
     *
     * @param clientEngine клиентский GostSSLEngine (предварительно сконфигурированный, beginHandshake не нужен)
     * @param serverEngine серверный GostSSLEngine (предварительно сконфигурированный, beginHandshake не нужен)
     * @param pair         транспортная пара для обмена данными
     * @throws Exception если handshake не завершился за 10 секунд
     *
     * Предусловие: оба engine сконфигурированы (keyManager, trustManager заданы).
     * Постусловие: оба engine в состоянии FINISHED или NOT_HANDSHAKING.
     */
    static void doLoopback(
            GostSSLEngine clientEngine, GostSSLEngine serverEngine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        HandshakeFailures failures = new HandshakeFailures();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                doClientHandshake(clientEngine, pair);
                            } catch (Exception e) {
                                failures.recordAndClose(
                                        HandshakeFailures.SIDE_CLIENT,
                                        e,
                                        pair.getClientTransport());
                            }
                        },
                        "loopback-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                doServerHandshake(serverEngine, pair);
                            } catch (Exception e) {
                                failures.recordAndClose(
                                        HandshakeFailures.SIDE_SERVER,
                                        e,
                                        pair.getServerTransport());
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
        failures.throwIfFailed();
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
    static void doClientHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
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
                    netBuf.clear();
                    netBuf.put(inData);
                    netBuf.flip();
                    appBuf.clear();
                    engine.unwrap(netBuf, appBuf);
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
    static void doServerHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
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
                    netBuf.clear();
                    netBuf.put(inData);
                    netBuf.flip();
                    appBuf.clear();
                    engine.unwrap(netBuf, appBuf);
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
                        skm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
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
        byte[] inData = pair.getServerTransport().receiveRecord();
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
    }

    // ========================================================================
    // Regression: closeOutbound() -> wrap() не перешифровывает close_notify
    // ========================================================================

    // ========================================================================
    // Regression: unwrap() возвращает Status.CLOSED при получении close_notify
    // ========================================================================

    // ========================================================================
    // Regression: bytesProduced корректен при нескольких AppData записях
    // ========================================================================
}
