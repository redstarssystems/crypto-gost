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
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTestHelper;

/**
 * Тесты OcspPolicy и кэша.
 */
class GostOcspPolicyTest {

    private static TlsTestHelper.CertBundle root;
    private static ECParameters params;
    private static TlsCiphersuite cs;

    private HttpServer mockServer;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) mockServer.stop(0);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH + fetcher=null + нет OCSP -> fail-closed")
    void testStaplingOrFetchNoFetcher() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeaf();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, null);

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "STAPLING_OR_FETCH без fetcher и без OCSP должно падать");
    }

    @Test
    @DisplayName("IF_PRESENT + нет OCSP -> success (OCSP не обязателен)")
    void testIfPresentNoOcsp() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeaf();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                new GostX509TrustManager(root.cert.getPublicKey(), OcspPolicy.IF_PRESENT, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH + stapled OCSP -> success")
    void testStaplingOrFetchStapled() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeaf();

        byte[] ocspResp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        leaf.cert.setOcspResponse(ocspResp);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("STAPLING_OR_FETCH + AIA OCSP URI + mock HTTP -> успешный fetch")
    void testStaplingOrFetchViaAia() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();

        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = TlsTestHelper.buildAiaOcspExtension(ocspUri);

        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        byte[] ocspResp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        java.util.concurrent.atomic.AtomicReference<byte[]> recordedBody =
                new java.util.concurrent.atomic.AtomicReference<>();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    recordedBody.set(ex.getRequestBody().readAllBytes());
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, fetcher);

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
        byte[] aiaExt = TlsTestHelper.buildAiaOcspExtension(ocspUri);
        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        byte[] ocspResp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        AtomicInteger counter = new AtomicInteger(0);
        byte[] leafDer = leaf.cert.getEncoded();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    counter.incrementAndGet();
                    ex.getRequestBody().readAllBytes();
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, fetcher);
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
    @DisplayName("OCSP cache expiry — fetch повторяется после TTL")
    void testOcspCacheExpiry() throws Exception {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        int port = mockServer.getAddress().getPort();

        String ocspUri = "http://localhost:" + port + "/ocsp";
        byte[] aiaExt = TlsTestHelper.buildAiaOcspExtension(ocspUri);
        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        byte[] ocspResp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        AtomicInteger counter = new AtomicInteger(0);
        byte[] leafDer = leaf.cert.getEncoded();
        mockServer.createContext(
                "/ocsp",
                ex -> {
                    counter.incrementAndGet();
                    ex.getRequestBody().readAllBytes();
                    ex.sendResponseHeaders(200, ocspResp.length);
                    ex.getResponseBody().write(ocspResp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, fetcher);
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
        TlsTestHelper.CertBundle intermediate =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        (String[]) null,
                        (String[]) null,
                        new byte[] {(byte) 0x04},
                        (String[]) null,
                        true,
                        null);

        // Создаём leaf, подписанный промежуточным
        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);

        // Diagnostic assertions (P1-P2)
        // DN издателя промежуточного совпадает с subject DN корневого
        assertArrayEquals(
                intermediate.cert.getIssuerDnBytes(),
                root.subjectDn,
                "getIssuerDnBytes(intermediate) != subjectDN(root)");
        // hashIssuerName(root) == digest(getIssuerDnBytes(intermediate))
        assertArrayEquals(
                CertIdHasher.hashIssuerName(root.cert.getEncoded()),
                Digest.digest256(intermediate.cert.getIssuerDnBytes()),
                "hashIssuerName(root) != digest(getIssuerDnBytes(intermediate))");

        // Стаплинг для leaf: OCSP-ответ, подписанный промежуточным
        byte[] leafOcsp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), intermediate.priv,
                        intermediate.cert.getPublicKey(), intermediate.subjectDn);
        leaf.cert.setOcspResponse(leafOcsp);

        // Стаплинг для промежуточного: OCSP-ответ, подписанный корневым
        byte[] intOcsp =
                TlsTestHelper.buildOcspResponse(
                        intermediate.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        intermediate.cert.setOcspResponse(intOcsp);

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, null);
        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Промежуточный без OCSP — best-effort не падает")
    void testIntermediateOcspMissing() throws Exception {
        // Создаём промежуточный CA без OCSP (нет stapling, нет AIA)
        TlsTestHelper.CertBundle intermediate =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
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
        byte[] aiaExt = TlsTestHelper.buildAiaOcspExtension(ocspUri);

        TlsTestHelper.CertBundle leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aiaExt);

        byte[] leafOcsp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), intermediate.priv,
                        intermediate.cert.getPublicKey(), intermediate.subjectDn);

        mockServer.createContext(
                "/ocsp",
                ex -> {
                    ex.getRequestBody().readAllBytes();
                    ex.sendResponseHeaders(200, leafOcsp.length);
                    ex.getResponseBody().write(leafOcsp);
                    ex.getResponseBody().close();
                });
        mockServer.start();

        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        GostX509TrustManager tm =
                new GostX509TrustManager(
                        root.cert.getPublicKey(), OcspPolicy.STAPLING_OR_FETCH, fetcher);

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        tm.validateChainWithOcsp(chain, null, false);

        // Убеждаемся, что промежуточный не имеет OCSP (нет AIA, нет stapling)
        assertFalse(
                intermediate.cert.hasOcspResponse(),
                "Промежуточный сертификат не должен иметь OCSP (нет AIA, нет stapling)");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    private static TlsTestHelper.CertBundle createLeaf() throws Exception {
        return TlsTestHelper.createCertSignedBy(
                params,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "290501120000Z",
                new String[] {"localhost"},
                null,
                (String[]) null,
                false,
                null);
    }
}
