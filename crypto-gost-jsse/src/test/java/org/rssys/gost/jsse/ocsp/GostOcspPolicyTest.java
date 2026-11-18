package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.CertIdHasher;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Тесты OcspPolicy и кэша.
 */
@DisplayName("GostX509TrustManager: политики OCSP")
class GostOcspPolicyTest {

    private static PkixCertTestHelper.CertBundle root;
    private static ECParameters params;

    private HttpServer mockServer;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) mockServer.stop(0);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH + fetcher=null + нет OCSP -> fail-closed")
    void testStaplingOrFetchNoFetcher() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeaf();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_OR_FETCH, null);

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "STAPLING_OR_FETCH без staple и без fetcher должен отклоняться");
        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, true),
                "явный requireOcsp без staple должен отклоняться");
    }

    @Test
    @DisplayName("IF_PRESENT + нет OCSP -> success (OCSP не обязателен)")
    void testIfPresentNoOcsp() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeaf();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.IF_PRESENT, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH с приложенным OCSP-ответом: успех")
    void testStaplingOrFetchStapled() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeaf();

        byte[] ocspResp =
                PkixCertTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        leaf.cert.setOcspResponse(ocspResp);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_OR_FETCH, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH + AIA OCSP URI + mock HTTP -> успешный fetch")
    void testStaplingOrFetchViaAia() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();

        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension(ocspUri);

        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        java.util.concurrent.atomic.AtomicReference<byte[]> recordedBody =
                new java.util.concurrent.atomic.AtomicReference<>();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    byte[] req = ex.getRequestBody().readAllBytes();
                    recordedBody.set(req);
                    byte[] ocspResp = buildOcspResponseEchoingNonce(req, leaf, root);
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        tm.validateChainWithOcsp(chain, null, false);

        assertNotNull(recordedBody.get(), "Mock-сервер должен был получить запрос");
        assertTrue(recordedBody.get().length > 0, "Тело запроса не должно быть пустым");
    }

    // ========================================================================
    // OCSP cache
    // ========================================================================

    @Test
    @DisplayName("OCSP cache hit — повторный fetch не делает HTTP")
    void testOcspCacheHit() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();

        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension(ocspUri);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        AtomicInteger counter = new AtomicInteger(0);
        byte[] leafDer = leaf.cert.getEncoded();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    counter.incrementAndGet();
                    byte[] req = ex.getRequestBody().readAllBytes();
                    byte[] ocspResp = buildOcspResponseEchoingNonce(req, leaf, root);
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);
        tm.setOcspCacheTtlMs(60_000);

        // Первый вызов — новый объект сертификата, fetch сходит на сервер
        List<GostCertificate> chain1 = List.of(new GostCertificate(leafDer), root.cert);
        tm.validateChainWithOcsp(chain1, null, false);
        assertEquals(1, counter.get(), "Первый вызов должен сделать HTTP-запрос");

        // Второй вызов — новый объект сертификата (симулирует новый handshake)
        // hasOcspResponse=false -> cache lookup -> hit -> setOcspResponse
        List<GostCertificate> chain2 = List.of(new GostCertificate(leafDer), root.cert);
        tm.validateChainWithOcsp(chain2, null, false);
        assertEquals(1, counter.get(), "Второй вызов должен попасть в кэш, без HTTP");
        assertTrue(
                chain2.get(0).hasOcspResponse(),
                "Кэш должен установить OCSP-ответ во втором сертификате");
    }

    @Test
    @DisplayName("Клиентский OCSP: два checkClientTrusted из одного DER -> один HTTP fetch")
    void testClientOcspCacheSingleFetch() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();
        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension(ocspUri);
        PkixCertTestHelper.CertBundle client =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x80},
                        new String[] {org.rssys.gost.pkix.GostOids.EXT_CLIENT_AUTH},
                        false,
                        null,
                        aiaExt);

        AtomicInteger counter = new AtomicInteger();
        byte[] clientDer = client.cert.getEncoded();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    counter.incrementAndGet();
                    byte[] req = ex.getRequestBody().readAllBytes();
                    byte[] ocspResp = buildOcspResponseEchoingNonce(req, client, root);
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);
        tm.setOcspCacheTtlMs(60_000);

        // Клиентский fetch включается явно: при ClientOcspPolicy.OFF исходящих запросов нет.
        tm.validateClientChain(
                List.of(new GostCertificate(clientDer), root.cert), ClientOcspPolicy.REQUEST);
        assertEquals(1, counter.get(), "первый клиентский вызов должен сделать HTTP-запрос");

        tm.validateClientChain(
                List.of(new GostCertificate(clientDer), root.cert), ClientOcspPolicy.REQUEST);
        assertEquals(1, counter.get(), "повторный клиентский вызов должен попасть в кэш");
    }

    @Test
    @DisplayName("OCSP cache expiry — fetch повторяется после TTL")
    void testOcspCacheExpiry() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();

        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension(ocspUri);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        AtomicInteger counter = new AtomicInteger(0);
        byte[] leafDer = leaf.cert.getEncoded();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    counter.incrementAndGet();
                    byte[] req = ex.getRequestBody().readAllBytes();
                    byte[] ocspResp = buildOcspResponseEchoingNonce(req, leaf, root);
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);
        tm.setOcspCacheTtlMs(100);

        List<GostCertificate> chain1 = List.of(new GostCertificate(leafDer), root.cert);
        tm.validateChainWithOcsp(chain1, null, false);
        assertEquals(1, counter.get(), "Первый вызов должен fetch'ить");

        // Ждём истечения кэша
        Thread.sleep(200);

        // Кэш истёк — новый сертификат, refetch
        List<GostCertificate> chain2 = List.of(new GostCertificate(leafDer), root.cert);
        tm.validateChainWithOcsp(chain2, null, false);
        assertEquals(2, counter.get(), "После истечения TTL должен перезапросить");
    }

    // ========================================================================
    // OCSP для промежуточных сертификатов
    // ========================================================================

    @Test
    @DisplayName("Полная цепочка 3-deep, OCSP на leaf и промежуточный")
    void testIntermediateChainFull() throws Exception {
        // Создаём промежуточный CA, подписанный root
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x04},
                        (String[]) null,
                        true,
                        null);

        // Создаём leaf, подписанный промежуточным
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);

        // DN издателя промежуточного совпадает с subject DN корневого
        assertArrayEquals(
                intermediate.cert.getIssuerDnBytes(),
                root.subjectDn,
                "DN издателя промежуточного должен совпадать с subject DN корневого");
        // hashIssuerName(root) == digest(getIssuerDnBytes(intermediate))
        assertArrayEquals(
                CertIdHasher.hashIssuerName(root.cert.getEncoded()),
                Digest.digest256(intermediate.cert.getIssuerDnBytes()),
                "хэш имени издателя корневого должен совпадать с хэшем DN издателя промежуточного");

        // Стаплинг для leaf: OCSP-ответ, подписанный промежуточным
        byte[] leafOcsp =
                PkixCertTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), intermediate.priv,
                        intermediate.cert.getPublicKey(), intermediate.subjectDn);
        leaf.cert.setOcspResponse(leafOcsp);

        // Стаплинг для промежуточного: OCSP-ответ, подписанный корневым
        byte[] intOcsp =
                PkixCertTestHelper.buildOcspResponse(
                        intermediate.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        intermediate.cert.setOcspResponse(intOcsp);

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert), OcspPolicy.STAPLING_OR_FETCH, null);
        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Промежуточный без OCSP — best-effort не падает")
    void testIntermediateOcspMissing() throws Exception {
        // Создаём промежуточный CA без OCSP (нет stapling, нет AIA)
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x04},
                        (String[]) null,
                        true,
                        null);

        // Создаём leaf с AIA, подписанный промежуточным
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();
        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension(ocspUri);

        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        mockServer.createContext(
                "/ocsp",
                ex -> {
                    byte[] req = ex.getRequestBody().readAllBytes();
                    byte[] ocspResp = buildOcspResponseEchoingNonce(req, leaf, intermediate);
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        tm.validateChainWithOcsp(chain, null, false);

        // Убеждаемся, что промежуточный не имеет OCSP (нет AIA, нет stapling)
        assertFalse(
                intermediate.cert.hasOcspResponse(),
                "Промежуточный сертификат не должен иметь OCSP (нет AIA, нет stapling)");
    }

    @Test
    @DisplayName("OCSP-ответ с чужой подписью не попадает в кэш: следующий handshake идёт в сеть")
    void testOcspResponseWithForeignSignatureIsNotCached() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();
        byte[] aiaExt =
                PkixCertTestHelper.buildAiaOcspExtension("http://localhost:" + port + "/ocsp");
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);
        // Ответ подписан чужим ключом: подпись не сойдётся с ключом доверенного издателя.
        PkixCertTestHelper.CertBundle foreignRoot = PkixCertTestHelper.createRootCA(params);

        AtomicInteger requests = new AtomicInteger();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    // Первый ответ подписан чужим ключом, дальше - легитимный responder.
                    boolean foreignSigned = requests.getAndIncrement() == 0;
                    byte[] req = ex.getRequestBody().readAllBytes();
                    byte[] resp =
                            buildOcspResponseEchoingNonce(
                                    req, leaf, foreignSigned ? foreignRoot : root);
                    ex.sendResponseHeaders(200, resp.length);
                    ex.getResponseBody().write(resp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);
        tm.setOcspCacheTtlMs(60_000);
        byte[] leafDer = leaf.cert.getEncoded();

        assertThrows(
                CertificateException.class,
                () ->
                        tm.validateChainWithOcsp(
                                List.of(new GostCertificate(leafDer), root.cert), null, false),
                "ответ с неверной подписью должен отклоняться");

        // Свежий объект сертификата: иначе hasOcspResponse() сам замкнёт fetch, и тест не
        // отличил бы отравленный кэш от чистого.
        tm.validateChainWithOcsp(List.of(new GostCertificate(leafDer), root.cert), null, false);
        assertEquals(
                2,
                requests.get(),
                "после отказа ответ с чужой подписью не должен попасть в кэш: второй handshake идёт в сеть");
    }

    @Test
    @DisplayName(
            "Клиентский OCSP: OFF не делает исходящих запросов, REQUIRE без staple - отказ до сети")
    void testClientFetchGatedByClientOcspPolicy() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();
        PkixCertTestHelper.CertBundle client =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x80},
                        new String[] {org.rssys.gost.pkix.GostOids.EXT_CLIENT_AUTH},
                        false,
                        null,
                        PkixCertTestHelper.buildAiaOcspExtension(
                                "http://localhost:" + port + "/ocsp"));
        AtomicInteger requests = new AtomicInteger();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    requests.incrementAndGet();
                    ex.sendResponseHeaders(500, -1);
                    ex.close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536, true);
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher);
        byte[] clientDer = client.cert.getEncoded();

        // OFF: сертификат принимается без OCSP, сервер по AIA клиента не ходит.
        tm.validateClientChain(
                List.of(new GostCertificate(clientDer), root.cert), ClientOcspPolicy.OFF);
        assertEquals(0, requests.get(), "при OFF исходящих OCSP-запросов быть не должно");

        // REQUIRE без staple: отказ происходит до сетевого запроса.
        assertThrows(
                CertificateException.class,
                () ->
                        tm.validateClientChain(
                                List.of(new GostCertificate(clientDer), root.cert),
                                ClientOcspPolicy.REQUIRE),
                "REQUIRE без присланного staple должен отклонять сертификат");
        assertEquals(0, requests.get(), "отказ по REQUIRE не должен доходить до сети");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    /**
     * Строит OCSP-ответ, эхируя nonce из полученного запроса (RFC 8954). Имитирует
     * реальный responder: без эха nonce fail-closed верификатор отклонит ответ.
     *
     * @param requestDer сырой DER OCSP-запроса из мок-сервера
     * @param target     сертификат, чей статус подтверждаем (источник serialNumber)
     * @param signer     bundle подписанта ответа (ключ + issuer DN)
     */
    private static byte[] buildOcspResponseEchoingNonce(
            byte[] requestDer,
            PkixCertTestHelper.CertBundle target,
            PkixCertTestHelper.CertBundle signer)
            throws java.io.IOException {
        byte[] nonce = PkixCertTestHelper.extractOcspRequestNonce(requestDer);
        try {
            return PkixCertTestHelper.buildOcspResponseWithNonce(
                    target.cert.getSerialNumber(),
                    signer.priv,
                    signer.cert.getPublicKey(),
                    signer.subjectDn,
                    nonce);
        } catch (Exception e) {
            throw new java.io.IOException("Failed to build OCSP response", e);
        }
    }

    private static PkixCertTestHelper.CertBundle createLeaf() throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                new String[] {"localhost"},
                null,
                (String[]) null,
                false,
                null);
    }
}
