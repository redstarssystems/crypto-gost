package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.net.Socket;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Проверяет hostname verification на engine-пути через SSLContext.createSSLEngine.
 * <p>
 * Ключевой инвариант: engine, созданный через {@code createSSLEngine(host, port)},
 * должен давать те же гарантии проверки имени, что socket-путь — иначе перенос кода
 * с сокетов на engine молча теряет проверку имени сервера.
 */
@DisplayName("GostSSLEngine: проверка имени сервера")
class GostSSLEngineHostnameVerificationTest {

    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle rootCa;
    private static PublicKeyParameters caPub;
    private static GostCertificate caCert;
    private static PkixCertTestHelper.CertBundle serverCertLocalhost;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();
        caCert = rootCa.cert;
        // сертификат сервера с SAN=localhost — по нему проверяется совпадение имени
        serverCertLocalhost =
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
    }

    // ========================================================================
    // Дефолт endpoint identification на engine-пути
    // ========================================================================

    @Test
    @DisplayName("createSSLEngine(host,port): endpointIdentificationAlgorithm=HTTPS по умолчанию")
    void engineWithHostDefaultsToHttps() throws Exception {
        SSLContext ctx = clientContext();
        javax.net.ssl.SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        assertEquals(
                "HTTPS",
                engine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "engine с непустым host должен по умолчанию проверять hostname (HTTPS)");
    }

    @Test
    @DisplayName("createSSLEngine() без host и без endpoint id — рукопожатие проходит")
    void engineWithoutHostAndEndpointIdSucceeds() throws Exception {
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine();
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("Socket-путь: некорректный непустой host даёт SSLException при startHandshake")
    void socketInvalidHostThrowsSslException() throws Exception {
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0);
                Socket underlying = new Socket("127.0.0.1", listener.getLocalPort())) {
            GostSSLSocket socket =
                    new GostSSLSocket(
                            underlying,
                            "a..b",
                            0,
                            false,
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            new GostSSLSessionContext(
                                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));

            assertThrows(
                    SSLException.class,
                    socket::startHandshake,
                    "некорректный host на socket-пути должен давать SSLException");
        }
    }

    @Test
    @DisplayName("Socket-перегрузка: HTTPS без peerHost -> CertificateException")
    void socketOverloadWithoutHostFails() throws Exception {
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0);
                Socket underlying = new Socket("127.0.0.1", listener.getLocalPort())) {
            GostSSLSocket socket =
                    new GostSSLSocket(
                            underlying,
                            "",
                            0,
                            false,
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            new GostSSLSessionContext(
                                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
            SSLParameters params = socket.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);

            assertThrows(
                    CertificateException.class,
                    () -> GostX509TrustManager.requireHostnameForEndpointId((Socket) socket));
        }
    }

    @Test
    @DisplayName("createSSLEngine() без host + HTTPS — отказ, а не молчаливый пропуск")
    void engineWithoutHostWithHttpsFails() throws Exception {
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine();
        SSLParameters params = client.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(params);

        RuntimeException ex =
                assertThrows(RuntimeException.class, () -> doLoopback(client, newServerEngine()));
        assertInstanceOf(
                SSLException.class,
                ex.getCause(),
                "включённая проверка имени без адреса должна завершаться SSLException");
    }

    // ========================================================================
    // Реальный handshake: совпадение и несовпадение имени
    // ========================================================================

    @Test
    @DisplayName("Engine-путь: host=localhost совпадает с SAN — рукопожатие успешно")
    void engineHandshakeMatchingHostSucceeds() throws Exception {
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine("localhost", 0);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("Engine-путь: кириллический host -> A-label SNI и успешное рукопожатие")
    void engineIdnHostUsesPunycodeSni() throws Exception {
        PkixCertTestHelper.CertBundle idnBundle =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"www.xn--e1afmkfd.xn--p1ai"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        GostSSLEngine server = newServerEngine(idnBundle);
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine("www.пример.рф", 0);

        doLoopback(client, server);

        assertEquals(
                "www.xn--e1afmkfd.xn--p1ai",
                server.getRequestedServerName(),
                "JSSE-путь должен отправить SNI в A-label");
    }

    @Test
    @DisplayName("Engine-путь: IP-литералы не уходят в SNI")
    void engineIpLiteralsNoSni() throws Exception {
        assertIpEngineHandshake("192.168.1.10", "192.168.1.10");
        assertIpEngineHandshake("::1", "::1");
        assertIpEngineHandshake("[::1]", "::1");
        assertIpEngineHandshake("fe80::1%eth0", "fe80::1");
    }

    @Test
    @DisplayName("Engine-путь: некорректный непустой host даёт SSLException, а не IAE")
    void engineInvalidHostThrowsSslException() throws Exception {
        for (String invalidHost : new String[] {"a..b", "*.example.com", "exa mple.com"}) {
            GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine(invalidHost, 0);
            SSLException ex =
                    assertThrows(
                            SSLException.class,
                            client::beginHandshake,
                            "некорректный host '" + invalidHost + "' должен давать SSLException");
            assertFalse(
                    ex.getMessage().contains(invalidHost),
                    "сообщение не должно содержать имя пира");
            assertNotNull(ex.getCause(), "причина должна сохраняться");
        }
    }

    @Test
    @DisplayName("Engine-путь: host длиннее 253 символов даёт SSLException, а не IAE в рукопожатии")
    void engineTooLongHostThrowsSslException() throws Exception {
        // Метки по 60 символов допустимы для GostDnsName, но общая длина больше предела SNI:
        // отказ даёт проверка tls13, и он должен остаться SSLException при beginHandshake
        String tooLongHost = ("a".repeat(60) + ".").repeat(5) + "com";
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine(tooLongHost, 0);
        SSLException ex =
                assertThrows(
                        SSLException.class,
                        client::beginHandshake,
                        "слишком длинный host должен давать SSLException");
        assertFalse(
                ex.getMessage().contains(tooLongHost), "сообщение не должно содержать имя пира");
        assertNotNull(ex.getCause(), "причина должна сохраняться");
    }

    private void assertIpEngineHandshake(String hostname, String sanIp) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new String[] {sanIp},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null,
                        null);
        GostSSLEngine server = newServerEngine(bundle);
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine(hostname, 0);

        doLoopback(client, server);

        assertNull(
                server.getRequestedServerName(),
                "IP-литерал " + hostname + " не должен уходить в SNI");
    }

    @Test
    @DisplayName("Engine-путь: host не совпадает с SAN — fatal (проверка имени сервера)")
    void engineHandshakeWrongHostFails() throws Exception {
        GostSSLEngine client =
                (GostSSLEngine) clientContext().createSSLEngine("wronghost.invalid", 0);
        RuntimeException ex =
                assertThrows(RuntimeException.class, () -> doLoopback(client, newServerEngine()));
        assertInstanceOf(
                SSLException.class,
                ex.getCause(),
                "несовпадение hostname должно приводить к SSLException, причина: " + ex.getCause());
    }

    // ========================================================================
    // Opt-out через session context флаг (endpointIdentificationDisabled)
    // ========================================================================

    @Test
    @DisplayName(
            "SessionContext флаг: wrong host проходит (аналог trustAllNoHostnameCheckInsecure)")
    void disabledFlagOnSessionContextAllowsWrongHost() throws Exception {
        SSLContext ctx = clientContext();
        ((GostSSLSessionContext) ctx.getClientSessionContext())
                .setEndpointIdentificationMode(EndpointIdentificationMode.DISABLED);
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine("wronghost.invalid", 0);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // Opt-out по контракту SSLParameters: null и "" отключают проверку
    // ========================================================================

    // ========================================================================
    // Утилиты
    // ========================================================================

    /** Клиентский SSLContext с доверием к rootCa и без клиентского сертификата. */
    private SSLContext clientContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(
                new KeyManager[] {new GostX509KeyManager()},
                new TrustManager[] {
                    GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert))
                },
                null);
        return ctx;
    }

    /** Серверный engine с сертификатом SAN=localhost, подписанным rootCa. */
    private GostSSLEngine newServerEngine() throws Exception {
        return newServerEngine(serverCertLocalhost);
    }

    private GostSSLEngine newServerEngine(PkixCertTestHelper.CertBundle bundle) throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(bundle.cert, rootCa.cert)), bundle.priv);
        return new GostSSLEngine(
                skm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    private void doLoopback(GostSSLEngine client, GostSSLEngine server) throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }
}
