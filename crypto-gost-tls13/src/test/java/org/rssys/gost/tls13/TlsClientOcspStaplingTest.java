package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * OCSP-staple клиентского сертификата при mTLS (RFC 8446 §4.4.2.1): сервер запрашивает его
 * расширением status_request в CertificateRequest, клиент прикладывает ответ к leaf.
 */
@DisplayName("TlsSession: OCSP-staple клиентского сертификата (ClientOcspPolicy)")
class TlsClientOcspStaplingTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static PkixCertTestHelper.CertBundle clientLeaf;
    private static PkixCertTestHelper.CertBundle otherLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf = leaf(new String[] {"gost.example.com"}, GostOids.EXT_SERVER_AUTH);
        clientLeaf = leaf(null, GostOids.EXT_CLIENT_AUTH);
        otherLeaf = leaf(null, GostOids.EXT_CLIENT_AUTH);
    }

    private static PkixCertTestHelper.CertBundle leaf(String[] san, String eku) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                san,
                new byte[] {(byte) 0x80},
                new String[] {eku},
                false,
                null);
    }

    /** OCSP-ответ CA о статусе good для сертификата с заданным серийным номером. */
    private static byte[] ocspFor(GostCertificate cert, Instant thisUpdate) throws Exception {
        return GostOcspResponseBuilder.create(cert.getSerialNumber())
                .issuerDn(root.subjectDn)
                .thisUpdate(thisUpdate)
                .noNextUpdate()
                .sign(root.priv);
    }

    private static byte[] freshOcsp() throws Exception {
        return ocspFor(clientLeaf.cert, Instant.now());
    }

    private static TlsServerConfig serverConfig(ClientOcspPolicy policy) {
        return new TlsServerConfig(CS, Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .needClientAuth(TrustAnchors.ofCertificate(root.cert))
                .withClientOcspPolicy(policy);
    }

    private static TlsClientConfig clientConfig(byte[] staple) {
        TlsClientConfig cc =
                new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert))
                        .withClientCertificateChain(clientLeaf.cert)
                        .withClientPrivateKey(clientLeaf.priv)
                        .withServerHostname("gost.example.com");
        return staple == null ? cc : cc.withOcspStaplingResponse(staple);
    }

    /** Итог рукопожатия: ошибка сервера (null = успех) и цепочка клиента, увиденная сервером. */
    private record Outcome(Throwable serverError, List<GostCertificate> clientChainSeen) {
        byte[] stapleSeen() {
            return clientChainSeen == null ? null : clientChainSeen.get(0).getOcspResponse();
        }

        int serverAlert() {
            return ((TlsException) serverError).getAlertCode();
        }
    }

    private static Outcome handshake(TlsServerConfig sc, TlsClientConfig cc) throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(sc, tp.getServerTransport());
        TlsSession client = TlsSession.createClient(cc, tp.getClientTransport());
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> cf =
                    exec.submit(
                            () -> {
                                try {
                                    client.handshakeAsClient();
                                } catch (Exception ignored) {
                                    // Ошибку сервера читаем с его стороны; клиент может
                                    // получить alert или разрыв транспорта.
                                }
                                return null;
                            });
            Future<Void> sf =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Throwable serverError = null;
            try {
                sf.get(15, TimeUnit.SECONDS);
            } catch (ExecutionException e) {
                serverError = e.getCause();
            }
            cf.get(15, TimeUnit.SECONDS);
            return new Outcome(
                    serverError, serverError == null ? server.getPeerCertificates() : null);
        } finally {
            exec.shutdownNow();
            server.close();
            client.close();
        }
    }

    private static void assertOk(Outcome o) {
        assertNull(o.serverError(), "рукопожатие должно пройти: " + o.serverError());
    }

    private static void assertRejected(Outcome o, int alert) {
        assertNotNull(o.serverError(), "сервер должен отвергнуть рукопожатие");
        assertInstanceOf(TlsException.class, o.serverError());
        assertEquals(alert, o.serverAlert(), "неожиданный alert сервера");
    }

    // ------------------------------------------------------------------ политика OFF

    @Test
    @DisplayName("OFF: staple не запрашивается, клиент его не шлёт, рукопожатие проходит")
    void offDoesNotRequestStaple() throws Exception {
        Outcome o = handshake(serverConfig(ClientOcspPolicy.OFF), clientConfig(freshOcsp()));
        assertOk(o);
        assertNull(o.stapleSeen(), "без запроса сервера клиент не должен слать staple");
    }

    @Test
    @DisplayName("Политика по умолчанию - OFF")
    void defaultPolicyIsOff() {
        assertEquals(
                ClientOcspPolicy.OFF,
                new TlsServerConfig(CS, Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                        .getClientOcspPolicy());
    }

    // ------------------------------------------------------------------ REQUEST

    @Test
    @DisplayName("REQUEST: валидный staple клиента доходит до сервера и проверяется")
    void requestAcceptsValidStaple() throws Exception {
        byte[] staple = freshOcsp();
        Outcome o = handshake(serverConfig(ClientOcspPolicy.REQUEST), clientConfig(staple));
        assertOk(o);
        assertArrayEquals(staple, o.stapleSeen(), "сервер должен получить staple клиента");
    }

    @Test
    @DisplayName("REQUEST: клиент без staple допустим")
    void requestAllowsMissingStaple() throws Exception {
        Outcome o = handshake(serverConfig(ClientOcspPolicy.REQUEST), clientConfig(null));
        assertOk(o);
        assertNull(o.stapleSeen());
    }

    @Test
    @DisplayName("REQUEST: просроченный staple -> bad_certificate")
    void requestRejectsStaleStaple() throws Exception {
        byte[] stale = ocspFor(clientLeaf.cert, Instant.now().minus(3, ChronoUnit.DAYS));
        assertRejected(
                handshake(serverConfig(ClientOcspPolicy.REQUEST), clientConfig(stale)),
                TlsConstants.ALERT_BAD_CERTIFICATE);
    }

    @Test
    @DisplayName("REQUEST: staple со статусом revoked -> certificate_revoked, причина сохранена")
    void requestRejectsRevokedStaple() throws Exception {
        byte[] revoked =
                GostOcspResponseBuilder.create(clientLeaf.cert.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(Instant.now())
                        .noNextUpdate()
                        .revoked("20250101000000Z")
                        .sign(root.priv);
        Outcome outcome = handshake(serverConfig(ClientOcspPolicy.REQUEST), clientConfig(revoked));
        assertRejected(outcome, TlsConstants.ALERT_CERTIFICATE_REVOKED);
        assertInstanceOf(
                PkixException.class,
                outcome.serverError().getCause(),
                "причина отзыва должна остаться в исключении");
        assertEquals(
                PkixException.Reason.REVOKED,
                ((PkixException) outcome.serverError().getCause()).reason(),
                "причина отказа - отзыв");
    }

    @Test
    @DisplayName("REQUEST: staple другого сертификата -> bad_certificate")
    void requestRejectsStapleOfOtherCertificate() throws Exception {
        byte[] foreign = ocspFor(otherLeaf.cert, Instant.now());
        assertRejected(
                handshake(serverConfig(ClientOcspPolicy.REQUEST), clientConfig(foreign)),
                TlsConstants.ALERT_BAD_CERTIFICATE);
    }

    // ------------------------------------------------------------------ REQUIRE

    @Test
    @DisplayName("REQUIRE: клиент без staple -> bad_certificate")
    void requireRejectsMissingStaple() throws Exception {
        assertRejected(
                handshake(serverConfig(ClientOcspPolicy.REQUIRE), clientConfig(null)),
                TlsConstants.ALERT_BAD_CERTIFICATE);
    }

    @Test
    @DisplayName("REQUIRE: валидный staple принимается")
    void requireAcceptsValidStaple() throws Exception {
        byte[] staple = freshOcsp();
        Outcome o = handshake(serverConfig(ClientOcspPolicy.REQUIRE), clientConfig(staple));
        assertOk(o);
        assertArrayEquals(staple, o.stapleSeen());
    }

    // ------------------------------------------------------------------ селектор

    /** Фильтр нужен только для того, чтобы сервер отправил oid_filters и сработал селектор. */
    private static TlsServerConfig serverConfigWithFilters(ClientOcspPolicy policy) {
        return serverConfig(policy)
                .withOidFilters(List.of(new OIDFilter(new byte[] {0x55, 0x1D, 0x0F}, new byte[0])));
    }

    private static TlsClientConfig selectorOnlyConfig(TlsClientCredentials creds) {
        return new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert))
                .withServerHostname("gost.example.com")
                .withClientCertificateSelector(request -> creds);
    }

    @Test
    @DisplayName("Селектор: staple берётся из выбранных учётных данных")
    void selectorCredentialsCarryOwnStaple() throws Exception {
        byte[] staple = freshOcsp();
        TlsClientCredentials creds =
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv, staple);
        Outcome o =
                handshake(
                        serverConfigWithFilters(ClientOcspPolicy.REQUIRE),
                        selectorOnlyConfig(creds));
        assertOk(o);
        assertArrayEquals(staple, o.stapleSeen());
    }

    @Test
    @DisplayName("Селектор: staple из конфигурации не подставляется к выбранным учётным данным")
    void selectorDoesNotFallBackToConfigStaple() throws Exception {
        // Конфигурация содержит валидный staple, но селектор выбрал учётные данные без него:
        // staple принадлежит другому leaf и отправляться не должен (REQUIRE -> отказ).
        TlsClientCredentials creds =
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv);
        TlsClientConfig cc =
                clientConfig(freshOcsp()).withClientCertificateSelector(request -> creds);
        assertRejected(
                handshake(serverConfigWithFilters(ClientOcspPolicy.REQUIRE), cc),
                TlsConstants.ALERT_BAD_CERTIFICATE);
    }

    @Test
    @DisplayName(
            "Селектор вернул null: пустой certificate_list и никакого staple -> certificate_required")
    void selectorReturningNullSendsNoCertificate() throws Exception {
        // Конфигурация содержит цепочку и валидный staple, но селектор отказался выбирать:
        // клиент обязан отправить пустой certificate_list, а чужой staple не должен уйти.
        TlsClientConfig cc =
                clientConfig(freshOcsp()).withClientCertificateSelector(request -> null);
        assertRejected(
                handshake(serverConfigWithFilters(ClientOcspPolicy.REQUIRE), cc),
                TlsConstants.ALERT_CERTIFICATE_REQUIRED);
    }

    @Test
    @DisplayName(
            "Селектор вызывается и без oid_filters: источник учётных данных - селектор, не конфигурация")
    void selectorIsCalledWithoutFilters() throws Exception {
        byte[] configStaple = freshOcsp();
        byte[] selectorStaple = ocspFor(clientLeaf.cert, Instant.now().minusSeconds(60));
        TlsClientCredentials creds =
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv, selectorStaple);
        java.util.concurrent.atomic.AtomicInteger calls =
                new java.util.concurrent.atomic.AtomicInteger();
        TlsClientConfig cc =
                clientConfig(configStaple)
                        .withClientCertificateSelector(
                                request -> {
                                    calls.incrementAndGet();
                                    return creds;
                                });
        Outcome o = handshake(serverConfig(ClientOcspPolicy.REQUIRE), cc);
        assertOk(o);
        assertEquals(1, calls.get(), "селектор вызывается на каждый CertificateRequest");
        assertArrayEquals(
                selectorStaple,
                o.stapleSeen(),
                "staple из конфигурации не должен подменять выбор селектора");
    }

    @Test
    @DisplayName("Селектор вернул null без oid_filters: цепочка из конфигурации не подставляется")
    void selectorNullWithoutFiltersSendsNoCertificate() throws Exception {
        // Раньше без фильтров селектор не вызывался и уходила цепочка из конфигурации; теперь
        // заданный селектор единственный источник, null - пустой Certificate
        TlsClientConfig cc =
                clientConfig(freshOcsp()).withClientCertificateSelector(request -> null);
        assertRejected(
                handshake(serverConfig(ClientOcspPolicy.REQUIRE), cc),
                TlsConstants.ALERT_CERTIFICATE_REQUIRED);
    }

    @Test
    @DisplayName("Исключение селектора: пир получает internal_error, а не decode_error")
    void selectorFailureSendsInternalError() throws Exception {
        TlsClientConfig cc =
                clientConfig(freshOcsp())
                        .withClientCertificateSelector(
                                request -> {
                                    throw new IllegalArgumentException("selector bug");
                                });
        assertRejected(
                handshake(serverConfig(ClientOcspPolicy.REQUIRE), cc),
                TlsConstants.ALERT_INTERNAL_ERROR);
    }

    @Test
    @DisplayName("Селектор получает запрос целиком: фильтры, запрос staple и схемы сервера")
    void selectorReceivesWholeRequest() throws Exception {
        java.util.concurrent.atomic.AtomicReference<ClientCertificateRequest> seen =
                new java.util.concurrent.atomic.AtomicReference<>();
        TlsClientCredentials creds =
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv, freshOcsp());
        TlsClientConfig cc =
                clientConfig(null)
                        .withClientCertificateSelector(
                                request -> {
                                    seen.set(request);
                                    return creds;
                                });
        assertOk(handshake(serverConfigWithFilters(ClientOcspPolicy.REQUEST), cc));

        ClientCertificateRequest request = seen.get();
        assertNotNull(request, "селектор должен получить запрос");
        assertEquals(1, request.oidFilters().size(), "OID-фильтр сервера");
        assertTrue(request.ocspRequested(), "политика REQUEST запрашивает staple клиента");
        assertTrue(request.caDns().isEmpty(), "сервер не присылал certificate_authorities");
        int[] schemes = request.signatureSchemes();
        assertTrue(
                java.util.Arrays.stream(schemes)
                        .anyMatch(x -> x == TlsConstants.SIG_GOST_TC26_A_256),
                "схемы сервера должны дойти до селектора");
        assertArrayEquals(
                schemes,
                request.certificateSignatureSchemes(),
                "без signature_algorithms_cert список схем сертификатов тот же");
    }

    // ------------------------------------------------------------------ fail-fast и конфиг

    @Test
    @DisplayName(
            "createServer: политика не OFF без needClientAuth/wantClientAuth -> IllegalArgumentException")
    void policyWithoutAnchorsFailsFast() {
        for (ClientOcspPolicy policy :
                List.of(ClientOcspPolicy.REQUEST, ClientOcspPolicy.REQUIRE)) {
            TlsServerConfig sc =
                    new TlsServerConfig(
                                    CS, Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                            .withClientOcspPolicy(policy);
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            TlsSession.createServer(
                                    sc, InMemoryTlsTransport.newPair().getServerTransport()),
                    "политика "
                            + policy
                            + " без режима аутентификации клиента должна отвергаться сразу");
        }
    }

    @Test
    @DisplayName("withClientOcspPolicy(null) -> IllegalArgumentException")
    void nullPolicyRejected() {
        TlsServerConfig sc =
                new TlsServerConfig(
                        CS, Collections.singletonList(serverLeaf.cert), serverLeaf.priv);
        assertThrows(IllegalArgumentException.class, () -> sc.withClientOcspPolicy(null));
    }

    @Test
    @DisplayName(
            "createClient: staple в конфигурации без клиентской цепочки -> IllegalArgumentException")
    void stapleWithoutChainFailsFast() throws Exception {
        TlsClientConfig cc =
                new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert))
                        .withServerHostname("gost.example.com")
                        .withOcspStaplingResponse(freshOcsp());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsSession.createClient(
                                cc, InMemoryTlsTransport.newPair().getClientTransport()));
    }

    @Test
    @DisplayName("Пустой staple отвергается конфигурацией клиента и учётными данными")
    void emptyStapleRejected() {
        TlsClientConfig cc = new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert));
        assertThrows(
                IllegalArgumentException.class, () -> cc.withOcspStaplingResponse(new byte[0]));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsClientCredentials(
                                List.of(clientLeaf.cert), clientLeaf.priv, new byte[0]));
        assertFalse(
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv)
                        .toString()
                        .contains("ocspResponse"),
                "без staple toString не упоминает его");
        assertTrue(
                new TlsClientCredentials(List.of(clientLeaf.cert), clientLeaf.priv, new byte[] {1})
                        .toString()
                        .contains("1 bytes"),
                "toString печатает только длину staple");
    }
}
