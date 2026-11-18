package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * OCSP-staple клиентского сертификата в JSSE (RFC 8446 §4.4.2.1): политика сервера
 * {@link ClientOcspPolicy} в {@link GostSSLSessionContext}, staple клиента через
 * {@link GostSSLEngine#setOcspResponse(byte[])}, прямая проверка по {@code GostCertificate}.
 */
@DisplayName("GostSSLEngine: OCSP-staple клиента (ClientOcspPolicy) и staple сервера до handshake")
class GostSSLEngineClientOcspTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static PkixCertTestHelper.CertBundle clientLeaf;
    private static PkixCertTestHelper.CertBundle otherLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf = leaf(new String[] {"localhost"});
        clientLeaf = leaf(null);
        otherLeaf = leaf(null);
    }

    private static PkixCertTestHelper.CertBundle leaf(String[] san) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                san,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static byte[] ocspFor(GostCertificate cert, Instant thisUpdate) throws Exception {
        return GostOcspResponseBuilder.create(cert.getSerialNumber())
                .issuerDn(root.subjectDn)
                .thisUpdate(thisUpdate)
                .noNextUpdate()
                .sign(root.priv);
    }

    private static byte[] clientStaple() throws Exception {
        return ocspFor(clientLeaf.cert, Instant.now());
    }

    private static GostX509KeyManager keyManager(String alias, PkixCertTestHelper.CertBundle bundle)
            throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                alias, CertificateBridge.toJca(List.of(bundle.cert, root.cert)), bundle.priv);
        return km;
    }

    private static GostX509TrustManager trust() {
        return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(root.cert));
    }

    private enum Auth {
        NEED,
        WANT
    }

    /** Пара engine: сервер с политикой и режимом аутентификации, клиент со staple и без. */
    private record Pair(GostSSLEngine client, GostSSLEngine server) {}

    private static Pair pair(
            ClientOcspPolicy policy, Auth auth, boolean clientHasCert, byte[] clientStaple)
            throws Exception {
        GostSSLSessionContext serverContext = new GostSSLSessionContext(CS);
        GostSSLSessionContext clientContext = new GostSSLSessionContext(CS);
        serverContext.setClientOcspPolicy(policy);
        if (auth == Auth.NEED) {
            serverContext.setNeedClientAuth(true);
        }
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager("default", serverLeaf), trust(), "localhost", 0, serverContext);
        if (auth == Auth.WANT) {
            server.setWantClientAuth(true);
        }
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        clientHasCert ? keyManager("client", clientLeaf) : new GostX509KeyManager(),
                        trust(),
                        "localhost",
                        0,
                        clientContext);
        if (clientStaple != null) {
            client.setOcspResponse(clientStaple);
        }
        return new Pair(client, server);
    }

    private static void run(Pair p) throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(
                p.client(), p.server(), InMemoryTlsTransport.newPair());
    }

    /**
     * Отказ по OCSP-политике. Тип исключения сервера здесь не несёт кода alert'а: после
     * отказа engine уже в состоянии ERROR. Конкретный alert {@code bad_certificate} проверяется
     * на уровне {@code GostX509TrustManagerClientOcspTest}.
     */
    private static void assertRejected(Pair p) {
        assertThrows(
                RuntimeException.class,
                () -> run(p),
                "сервер должен отвергнуть клиента по политике OCSP");
    }

    // ------------------------------------------------------------------ REQUIRE

    @Test
    @DisplayName("REQUIRE, need: валидный staple клиента принимается (JSSE <-> JSSE)")
    void requireAcceptsValidStaple() throws Exception {
        run(pair(ClientOcspPolicy.REQUIRE, Auth.NEED, true, clientStaple()));
    }

    @Test
    @DisplayName("REQUIRE, need: клиент без staple -> отказ")
    void requireRejectsMissingStaple() throws Exception {
        assertRejected(pair(ClientOcspPolicy.REQUIRE, Auth.NEED, true, null));
    }

    @Test
    @DisplayName("REQUIRE, want: клиент без сертификата (анонимный) проходит")
    void requireWithWantAllowsAnonymousClient() throws Exception {
        run(pair(ClientOcspPolicy.REQUIRE, Auth.WANT, false, null));
    }

    @Test
    @DisplayName("REQUIRE, want: сертификат предъявлен без staple -> отказ")
    // Доказывает, что политика применяется к предъявленному сертификату, а не только к need.
    void requireWithWantRejectsPresentedCertificateWithoutStaple() throws Exception {
        assertRejected(pair(ClientOcspPolicy.REQUIRE, Auth.WANT, true, null));
    }

    // ------------------------------------------------------------------ REQUEST

    @Test
    @DisplayName("REQUEST, need: клиент без staple допустим")
    void requestAllowsMissingStaple() throws Exception {
        run(pair(ClientOcspPolicy.REQUEST, Auth.NEED, true, null));
    }

    @Test
    @DisplayName("REQUEST, want: клиент со staple проходит")
    void requestWithWantAcceptsStaple() throws Exception {
        run(pair(ClientOcspPolicy.REQUEST, Auth.WANT, true, clientStaple()));
    }

    @Test
    @DisplayName("REQUEST: просроченный staple -> отказ")
    void requestRejectsStaleStaple() throws Exception {
        byte[] stale = ocspFor(clientLeaf.cert, Instant.now().minus(3, ChronoUnit.DAYS));
        assertRejected(pair(ClientOcspPolicy.REQUEST, Auth.NEED, true, stale));
    }

    @Test
    @DisplayName("REQUIRE: staple другого сертификата не прикладывается -> отказ как без staple")
    // Клиент выбирает лист по запросу сервера, поэтому чужой staple не отправляется (иначе сервер
    // отверг бы рукопожатие по CertID): при обязательном staple остаётся отказ «staple нет»
    void requireRejectsForeignStaple() throws Exception {
        assertRejected(
                pair(
                        ClientOcspPolicy.REQUIRE,
                        Auth.NEED,
                        true,
                        ocspFor(otherLeaf.cert, Instant.now())));
    }

    @Test
    @DisplayName("REQUEST: staple другого сертификата не прикладывается, рукопожатие проходит")
    void requestDropsForeignStaple() throws Exception {
        run(
                pair(
                        ClientOcspPolicy.REQUEST,
                        Auth.NEED,
                        true,
                        ocspFor(otherLeaf.cert, Instant.now())));
    }

    @Test
    @DisplayName("REQUEST: staple со статусом revoked -> отказ")
    void requestRejectsRevokedStaple() throws Exception {
        byte[] revoked =
                GostOcspResponseBuilder.create(clientLeaf.cert.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(Instant.now())
                        .noNextUpdate()
                        .revoked("20250101000000Z")
                        .sign(root.priv);
        assertRejected(pair(ClientOcspPolicy.REQUEST, Auth.NEED, true, revoked));
    }

    // ------------------------------------------------------------------ OFF и контракты

    @Test
    @DisplayName("OFF: staple клиента не запрашивается и не отправляется, handshake проходит")
    void offDoesNotSendStaple() throws Exception {
        run(pair(ClientOcspPolicy.OFF, Auth.NEED, true, clientStaple()));
    }

    @Test
    @DisplayName("getStatusResponses() клиентской сессии не возвращает собственный staple клиента")
    void clientSessionDoesNotExposeOwnStaple() throws Exception {
        Pair p = pair(ClientOcspPolicy.REQUIRE, Auth.NEED, true, clientStaple());
        run(p);
        ExtendedSSLSession session = (ExtendedSSLSession) p.client().getSession();
        assertTrue(
                session.getStatusResponses().isEmpty(),
                "собственный staple клиента не относится к ответам сервера");
    }

    // ------------------------------------------------------------------ fail-fast

    @Test
    @DisplayName("Политика не OFF без need/want -> SSLException при beginHandshake")
    void policyWithoutClientAuthFailsFast() throws Exception {
        GostSSLSessionContext serverContext = new GostSSLSessionContext(CS);
        serverContext.setClientOcspPolicy(ClientOcspPolicy.REQUEST);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager("default", serverLeaf), trust(), "localhost", 0, serverContext);
        assertThrows(SSLException.class, server::beginHandshake);
    }

    @Test
    @DisplayName("setClientOcspPolicy(null) и пустой staple -> IllegalArgumentException")
    void invalidArgumentsRejected() {
        GostSSLSessionContext ctx = new GostSSLSessionContext(CS);
        assertThrows(IllegalArgumentException.class, () -> ctx.setClientOcspPolicy(null));
        GostSSLEngine engine =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(), trust(), "localhost", 0, ctx);
        assertThrows(IllegalArgumentException.class, () -> engine.setOcspResponse(new byte[0]));
    }

    @Test
    @DisplayName("GostSslBuilder: политика не OFF вместе с trustAll() -> IllegalStateException")
    void builderPolicyWithTrustAllRejected() {
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustAll()
                                .clientOcspPolicy(ClientOcspPolicy.REQUEST)
                                .buildServerContext());
        assertDoesNotThrow(() -> GostSsl.builder().clientOcspPolicy(ClientOcspPolicy.OFF));
    }

    // ------------------------------------------------------------------ staple сервера

    @Test
    @DisplayName(
            "Staple сервера, заданный до beginHandshake, доходит до клиента (в том числе с SNI)")
    void serverStapleSetBeforeHandshakeReachesClient() throws Exception {
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager("default", serverLeaf),
                        trust(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        server.setOcspResponse(ocspFor(serverLeaf.cert, Instant.now()));
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(root.cert),
                                OcspPolicy.STAPLING_REQUIRED,
                                null),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        // STAPLING_REQUIRED: без доставленного staple клиент отвергнет сервер.
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }

    @Test
    @DisplayName(
            "SNI выбрал другой сертификат: staple сертификата по умолчанию к нему не подставляется")
    void serverStapleNotAttachedToOtherSniCertificate() throws Exception {
        PkixCertTestHelper.CertBundle apiLeaf = leaf(new String[] {"api.example.com"});
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverLeaf.cert, root.cert)),
                serverLeaf.priv);
        km.addKeyEntry(
                "api", CertificateBridge.toJca(List.of(apiLeaf.cert, root.cert)), apiLeaf.priv);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        km, trust(), "localhost", 0, new GostSSLSessionContext(CS));
        // staple относится к сертификату по умолчанию, а клиент придёт с SNI api.example.com
        server.setOcspResponse(ocspFor(serverLeaf.cert, Instant.now()));
        // IF_PRESENT: отсутствующий staple допустим, а присланный проверяется. Подставь обёртка
        // чужой staple к api-сертификату - клиент отверг бы несовпадение серийного номера.
        // Успех также подтверждает, что SNI выбрал именно api-сертификат (hostname совпал).
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        trust(),
                        "api.example.com",
                        0,
                        new GostSSLSessionContext(CS));
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }

    @Test
    @DisplayName("Контроль: сервер без staple отвергается клиентом со STAPLING_REQUIRED")
    void controlWithoutServerStapleRejected() throws Exception {
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager("default", serverLeaf),
                        trust(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(root.cert),
                                OcspPolicy.STAPLING_REQUIRED,
                                null),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        RuntimeException ex =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                GostSSLEngineLoopbackTest.doLoopback(
                                        client, server, InMemoryTlsTransport.newPair()));
        // отказ должен быть именно TLS-отказом, а не истёкшим сроком или закрытым транспортом
        assertInstanceOf(SSLException.class, ex.getCause(), "ожидается отказ TLS-рукопожатия");
    }

    // ------------------------------------------------------------------ interop с tls13

    @Test
    @DisplayName("JSSE-сервер REQUIRE <- клиент tls13 TlsSession со staple")
    void jsseServerAcceptsTls13ClientStaple() throws Exception {
        InMemoryTlsTransport.Pair transports = InMemoryTlsTransport.newPair();
        GostSSLSessionContext serverContext = new GostSSLSessionContext(CS);
        serverContext.setClientOcspPolicy(ClientOcspPolicy.REQUIRE);
        serverContext.setNeedClientAuth(true);
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        keyManager("default", serverLeaf), trust(), "localhost", 0, serverContext);

        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withOcspStaplingResponse(clientStaple())
                                .withoutHostnameVerification(),
                        transports.getClientTransport());
        AtomicReference<Throwable> clientError = new AtomicReference<>();
        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                client.handshakeAsClient();
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "tls13-client");
        clientThread.start();

        server.beginHandshake();
        GostSSLEngineLoopbackTest.doServerHandshake(server, transports);
        clientThread.join(5000);
        assertEquals(null, clientError.get(), "клиент tls13 должен завершить handshake");
    }

    @Test
    @DisplayName("Сервер tls13 REQUIRE <- JSSE-клиент со staple")
    void tls13ServerAcceptsJsseClientStaple() throws Exception {
        InMemoryTlsTransport.Pair transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        CS,
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert))
                                .withClientOcspPolicy(ClientOcspPolicy.REQUIRE),
                        transports.getServerTransport());
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                server.handshakeAsServer();
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "tls13-server");
        serverThread.start();

        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        keyManager("client", clientLeaf),
                        trust(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(CS));
        client.setOcspResponse(clientStaple());
        client.beginHandshake();
        GostSSLEngineLoopbackTest.doClientHandshake(client, transports);
        serverThread.join(5000);
        assertEquals(null, serverError.get(), "сервер tls13 должен принять staple JSSE-клиента");
    }
}
