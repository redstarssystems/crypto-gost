package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Интеграционные тесты CRL-проверки через GostX509TrustManager.
 */
@DisplayName("GostX509TrustManager: CRL-проверка")
class GostX509TrustManagerCrlTest {

    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle root;
    private static byte[] testCrl;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
        // CRL без отозванных, действительный до 2030
        testCrl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);
    }

    private PkixCertTestHelper.CertBundle createLeafWithCdp(String... cdpUris) throws Exception {
        byte[] cdpExt = PkixCertTestHelper.buildCdpExtension(cdpUris);
        return PkixCertTestHelper.createCertSignedBy(
                params,
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                new String[] {"gost.example.com"},
                (String[]) null,
                (byte[]) null,
                (String[]) null,
                false,
                null,
                cdpExt);
    }

    private static TrustAnchors caAnchors() {
        return TrustAnchors.ofCertificate(root.cert);
    }

    @Test
    @DisplayName("Чистый CRL при IF_CDP_PRESENT с загрузчиком: проверка проходит")
    void testCrlClean() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        assertNotNull(leaf.cert.getCdpUris(), "CDP должен парситься из leaf-сертификата");
        assertTrue(leaf.cert.getCdpUris().length > 0, "CDP URI не должен быть пустым");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Отзыв по CRL при IF_CDP_PRESENT: CertificateException")
    void testCrlRevoked() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");

        // CRL с отозванным leaf
        byte[] revokedCrl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {leaf.cert.getSerialNumber()},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> revokedCrl.clone();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        mockFetcher);

        CertificateException ex;
        List<String> warnings;
        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            ex =
                    assertThrows(
                            CertificateException.class,
                            () -> tm.validateChainWithOcsp(chain, null, false));
            warnings = log.messages(Level.WARNING);
        }
        assertTrue(
                ex.getMessage().contains("revoked"),
                "Ожидается revoked, получено: " + ex.getMessage());
        // Оператору нужно знать, чей сертификат отозван и по какому списку
        String serialHex = HexFormat.of().formatHex(leaf.cert.getSerialNumber());
        assertEquals(1, warnings.size(), "одна запись на отзыв: " + warnings);
        assertTrue(
                warnings.get(0).contains("serial=0x" + serialHex), "серийный номер: " + warnings);
        assertTrue(
                warnings.get(0).contains("http://crl.example.com/root.crl"),
                "адрес списка: " + warnings);
    }

    @Test
    @DisplayName("CRL: отозванный промежуточный CA в клиентской цепочке -> отказ")
    void testClientChainIntermediateRevoked() throws Exception {
        byte[] intermediateCdp =
                PkixCertTestHelper.buildCdpExtension("http://crl.example.com/root.crl");
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        0,
                        intermediateCdp);
        PkixCertTestHelper.CertBundle clientLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);
        assertNotNull(clientLeaf.cert);

        byte[] revokedIntermediateCrl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {intermediate.cert.getSerialNumber()},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> revokedIntermediateCrl.clone());

        X509Certificate[] chain =
                CertificateBridge.toJca(List.of(clientLeaf.cert, intermediate.cert, root.cert));

        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () -> tm.checkClientTrusted(chain, "EC"),
                        "отзыв промежуточного CA должен проверяться в клиентской цепочке");
        assertTrue(
                ex.getMessage().contains("revoked"),
                "Ожидается revoked, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL REQUIRE + нет CDP -> CertificateException")
    void testRequireNoCdp() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.REQUIRE, mockFetcher);

        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("CRL IF_CDP_PRESENT + нет CDP -> OK")
    void testIfPresentNoCdp() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.IF_CDP_PRESENT, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL DISABLED + CDP есть: загрузчик запрещён конфигурацией, CRL не загружается")
    void testDisabledWithCdp() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        // Загрузчик при DISABLED запрещён конфигурацией: он не использовался бы
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostX509TrustManager.fromTrustAnchors(
                                caAnchors(),
                                OcspPolicy.IF_PRESENT,
                                null,
                                CrlPolicy.DISABLED,
                                uri -> testCrl.clone()));
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.DISABLED, null);

        // При DISABLED цепочка с CDP принимается без загрузки CRL
        assertDoesNotThrow(() -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName(
            "CRL IF_CDP_PRESENT + CDP есть -> CRL загружается ровно один раз (контроль к DISABLED)")
    void testIfCdpPresentFetchesCrl() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return testCrl.clone();
                        });

        tm.validateChainWithOcsp(chain, null, false);

        assertEquals(1, fetches.get(), "при IF_CDP_PRESENT CRL загружается");
    }

    @Test
    @DisplayName("CRL IF_CDP_PRESENT + fetcher=null + CDP есть -> pass (fetch skipped)")
    void testIfPresentNoFetcher() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.IF_CDP_PRESENT, null);

        // fetcher=null -> checkCrl пропускается, валидация OCSP проходит
        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL REQUIRE + fetcher=null + CDP есть -> CertificateException")
    void testRequireNoFetcher() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.REQUIRE, null);

        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("Первый CDP mirror недоступен, второй отвечает clean -> OK")
    void testFirstMirrorDownSecondServes() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl.example.com/fail.crl", "http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        List<String> requested = new java.util.concurrent.CopyOnWriteArrayList<>();
        CrlFetcher mockFetcher =
                uri -> {
                    requested.add(uri);
                    if (uri.contains("fail")) throw new IOException("CDP down");
                    return testCrl.clone();
                };

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.REQUIRE, mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);

        assertEquals(
                List.of("http://crl.example.com/fail.crl", "http://crl.example.com/root.crl"),
                requested,
                "первый адрес пропущен, второй запрошен следом");
    }

    @Test
    @DisplayName("Все CDP mirror недоступны, REQUIRE -> CertificateException")
    void testAllMirrorsDownRequire() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl.example.com/fail1.crl", "http://crl.example.com/fail2.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher =
                uri -> {
                    throw new IOException("down");
                };

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.REQUIRE, mockFetcher);

        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("Все CDP mirror недоступны, IF_CDP_PRESENT -> OK (fallback)")
    void testAllMirrorsDownIfPresent() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl.example.com/fail1.crl", "http://crl.example.com/fail2.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher =
                uri -> {
                    throw new IOException("down");
                };

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("TrustManager с кастомным maxCrlSize отвергает валидный CRL при превышении лимита")
    void testCustomMaxCrlSizeRejected() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        mockFetcher,
                        testCrl.length - 1,
                        GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                        CrlCache.DEFAULT_MAX_BYTES,
                        CrlCache.DEFAULT_MAX_AGE,
                        GostOids.MAX_OCSP_AGE_MS,
                        null);

        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false));
        assertTrue(
                ex.getMessage().contains("exceeds size limit"),
                "Ожидается явная ошибка лимита размера, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("TrustManager с кастомным maxCrlSize=10000 принимает валидный CRL")
    void testCustomMaxCrlSizeWithinLimit() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        mockFetcher,
                        10_000,
                        GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                        CrlCache.DEFAULT_MAX_BYTES,
                        CrlCache.DEFAULT_MAX_AGE,
                        GostOids.MAX_OCSP_AGE_MS,
                        null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL с чужой подписью не отравляет кэш: следующий легитимный CRL принимается")
    void testCrlWithForeignSignatureDoesNotPoisonCache() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        // Чужая подпись: имя издателя верное, но подпись чужим ключом, огромный cRLNumber и срок.
        PkixCertTestHelper.CertBundle foreignRoot = PkixCertTestHelper.createRootCA(params);
        byte[] foreignSignedCrl =
                PkixCertTestHelper.buildCrlWithCrlNumber(
                        null,
                        foreignRoot.priv,
                        foreignRoot.cert.getPublicKey(),
                        root.subjectDn,
                        "99991231235959Z",
                        1_000_000);
        byte[] legitCrl =
                PkixCertTestHelper.buildCrlWithCrlNumber(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        5);

        AtomicInteger fetches = new AtomicInteger();
        CrlFetcher fetcher =
                uri -> (fetches.getAndIncrement() == 0 ? foreignSignedCrl : legitCrl).clone();
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        caAnchors(),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        fetcher);

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "CRL с неверной подписью должен отклоняться");

        // Если бы CRL с чужой подписью осел в кэше, здесь ушёл бы он же (и baseline 1_000_000
        // отверг бы легитимный номер 5), а fetcher не был бы вызван повторно.
        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(2, fetches.get(), "после отказа CRL не кэшируется: нужен повторный fetch");

        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(2, fetches.get(), "проверенный CRL должен браться из кэша без fetch");
    }

    // ------------------------------------------------------------------------
    // CRL, который использовать нельзя (неизвестное critical-расширение), и ошибки разбора
    // ------------------------------------------------------------------------

    /**
     * Подписанный УЦ CRL из «сырых» частей: tbsCertList собирается вручную, потому что
     * построитель не умеет выпускать неизвестные critical-расширения и битые записи.
     */
    private static byte[] rawCrl(byte[]... tbsTail) {
        java.io.ByteArrayOutputStream tbs = new java.io.ByteArrayOutputStream();
        byte[] algId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_WITH_DIGEST_256));
        tbs.writeBytes(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
        tbs.writeBytes(algId);
        tbs.writeBytes(root.subjectDn);
        tbs.writeBytes(DerCodec.encodeTime("260101000000Z"));
        tbs.writeBytes(DerCodec.encodeTime("21060101120000Z"));
        for (byte[] part : tbsTail) {
            tbs.writeBytes(part);
        }
        byte[] tbsDer = DerCodec.encodeSequence(tbs.toByteArray());
        byte[] signature = Signature.signHash(Digest.digest256(tbsDer), root.priv);
        return DerCodec.encodeSequence(tbsDer, algId, DerCodec.encodeBitString(signature));
    }

    private static byte[] crlWithUnknownCritical() {
        byte[] extension =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("1.2.3.4.5"),
                        DerCodec.encodeBoolean(true),
                        DerCodec.encodeOctetString(DerCodec.encodeNull()));
        return rawCrl(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(extension)));
    }

    private GostX509TrustManager trustManager(CrlPolicy policy, CrlFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                caAnchors(), OcspPolicy.IF_PRESENT, null, policy, fetcher);
    }

    @Test
    @DisplayName(
            "CRL с неизвестным critical + IF_CDP_PRESENT: зеркало пропущено, соединение проходит")
    void testUnknownCriticalCrlSkippedIfCdpPresent() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] unusable = crlWithUnknownCritical();
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return unusable.clone();
                        });

        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(1, fetches.get(), "CRL запрошен один раз");
    }

    @Test
    @DisplayName("CRL с неизвестным critical + REQUIRE: нет пригодного CRL -> отказ")
    void testUnknownCriticalCrlRejectedWhenRequired() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] unusable = crlWithUnknownCritical();

        GostX509TrustManager tm = trustManager(CrlPolicy.REQUIRE, uri -> unusable.clone());

        CertificateException e =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false),
                        "При REQUIRE непригодный CRL не заменяет проверку отзыва");
        assertTrue(
                e.getMessage().contains("no usable CRL"),
                "Сообщение должно говорить о непригодном CRL, а не о недоступности: "
                        + e.getMessage());
    }

    @Test
    @DisplayName("Первое зеркало с неизвестным critical, второе чистое: проходит и при REQUIRE")
    void testUnknownCriticalFirstMirrorThenCleanSecond() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl1.example.com/root.crl", "http://crl2.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] unusable = crlWithUnknownCritical();
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.REQUIRE,
                        uri -> (fetches.getAndIncrement() == 0 ? unusable : testCrl).clone());

        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(2, fetches.get(), "после непригодного зеркала запрошено второе");
    }

    @Test
    @DisplayName("Ошибка разбора записей не выдаётся за «сертификат отозван»")
    void testParseErrorIsNotReportedAsRevoked() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        // Запись без serialNumber: "Failed to parse CRL revoked entries" содержит "revoked"
        byte[] brokenEntry = DerCodec.encodeSequence(DerCodec.encodeNull());
        byte[] malformed = rawCrl(DerCodec.encodeSequence(brokenEntry));

        GostX509TrustManager tm = trustManager(CrlPolicy.IF_CDP_PRESENT, uri -> malformed.clone());

        CertificateException e =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false),
                        "Битый CRL при проверке отзыва — ошибка проверки");
        assertTrue(
                e.getMessage().contains("CRL validation failed"),
                "Это ошибка проверки, а не отзыв: " + e.getMessage());
        assertFalse(
                e.getMessage().contains("revoked per CRL"),
                "Ложное «сертификат отозван» недопустимо: " + e.getMessage());
    }

    // ------------------------------------------------------------------------
    // Область CRL (IssuingDistributionPoint): TLS-матрица политик
    // ------------------------------------------------------------------------

    private static byte[] idpExtension(byte... fieldTlvs) {
        return DerCodec.encodeSequence(
                DerCodec.encodeOid("2.5.29.28"),
                DerCodec.encodeBoolean(true),
                DerCodec.encodeOctetString(DerCodec.encodeSequence(fieldTlvs)));
    }

    /** CRL, подписанный УЦ, с onlyContainsCACerts: конечный сертификат он не покрывает. */
    private static byte[] caOnlyCrl(byte[]... revokedEntries) {
        byte[] idp = idpExtension(DerCodec.encodeTlv(0x82, new byte[] {(byte) 0xFF}));
        byte[] tail = DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idp));
        if (revokedEntries.length > 0) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.writeBytes(DerCodec.encodeSequence(concatAll(revokedEntries)));
            out.writeBytes(tail);
            return rawCrl(out.toByteArray());
        }
        return rawCrl(tail);
    }

    private static byte[] concatAll(byte[]... parts) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    @Test
    @DisplayName(
            "CRL не покрывает сертификат + IF_CDP_PRESENT: равносилен недоступному зеркалу, проходит")
    void testNonCoveringCrlSkippedIfCdpPresent() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] nonCovering = caOnlyCrl();
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return nonCovering.clone();
                        });

        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(1, fetches.get(), "CRL запрошен один раз");
    }

    @Test
    @DisplayName("CRL не покрывает сертификат + REQUIRE: отказ «нет пригодного CRL»")
    void testNonCoveringCrlRejectedWhenRequired() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] nonCovering = caOnlyCrl();

        GostX509TrustManager tm = trustManager(CrlPolicy.REQUIRE, uri -> nonCovering.clone());

        CertificateException e =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false),
                        "При REQUIRE не покрывающий CRL не заменяет проверку отзыва");
        assertTrue(
                e.getMessage().contains("no usable CRL"),
                "Сообщение должно говорить о непригодном CRL: " + e.getMessage());
    }

    @Test
    @DisplayName("Первое зеркало не покрывает сертификат, второе чистое: проходит и при REQUIRE")
    void testNonCoveringFirstMirrorThenCleanSecond() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl1.example.com/root.crl", "http://crl2.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] nonCovering = caOnlyCrl();
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.REQUIRE,
                        uri -> (fetches.getAndIncrement() == 0 ? nonCovering : testCrl).clone());

        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(2, fetches.get(), "после не покрывающего зеркала запрошено второе");
    }

    @Test
    @DisplayName("Запись об отзыве в не покрывающем CRL по-прежнему даёт отзыв")
    void testNonCoveringCrlWithSerialStillRevoked() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] entry =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(
                                new java.math.BigInteger(1, leaf.cert.getSerialNumber())),
                        DerCodec.encodeTime("260601000000Z"));
        byte[] revoking = caOnlyCrl(entry);

        GostX509TrustManager tm = trustManager(CrlPolicy.IF_CDP_PRESENT, uri -> revoking.clone());

        CertificateException e =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false),
                        "Отзыв нельзя потерять из-за области CRL");
        assertTrue(
                e.getMessage().contains("revoked per CRL"),
                "Должен быть отзыв, а не пропуск зеркала: " + e.getMessage());
    }

    @Test
    @DisplayName("Подлинный, но не покрывающий лист CRL кэшируется: повторной загрузки нет")
    void testNonCoveringCrlIsCached() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] nonCovering = caOnlyCrl();
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return nonCovering.clone();
                        });

        tm.validateChainWithOcsp(chain, null, false);
        tm.validateChainWithOcsp(chain, null, false);
        // Подпись CRL проверена и годится другим сертификатам, поэтому он кэшируется; область
        // проверяется на каждом соединении по готовому объекту, без повторной загрузки
        assertEquals(1, fetches.get(), "Подлинный CRL берётся из кэша без повторного fetch");
    }

    @Test
    @DisplayName("Покрывающий partial CRL (onlyContainsUserCerts) принимается и кэшируется")
    void testCoveringPartialCrlIsCached() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] idp = idpExtension(DerCodec.encodeTlv(0x81, new byte[] {(byte) 0xFF}));
        byte[] covering = rawCrl(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idp)));
        AtomicInteger fetches = new AtomicInteger();

        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.REQUIRE,
                        uri -> {
                            fetches.incrementAndGet();
                            return covering.clone();
                        });

        tm.validateChainWithOcsp(chain, null, false);
        tm.validateChainWithOcsp(chain, null, false);
        assertEquals(1, fetches.get(), "Покрывающий CRL берётся из кэша без повторного fetch");
    }

    @Test
    @DisplayName("Delta CRL по адресу CDP остаётся фатальной ошибкой при любой политике")
    void testDeltaCrlIsFatal() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] number =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.20"),
                        DerCodec.encodeOctetString(DerCodec.encodeInteger(2)));
        byte[] delta =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.27"),
                        DerCodec.encodeBoolean(true),
                        DerCodec.encodeOctetString(DerCodec.encodeInteger(1)));
        byte[] deltaCrl = rawCrl(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(number, delta)));

        GostX509TrustManager tm = trustManager(CrlPolicy.IF_CDP_PRESENT, uri -> deltaCrl.clone());

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "Delta CRL по CDP — неверная настройка, а не неподходящий CRL");
    }

    @Test
    @DisplayName("Пустой IDP принимается как полный CRL")
    void testEmptyIdpAccepted() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] emptyIdp = rawCrl(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idpExtension())));

        GostX509TrustManager tm = trustManager(CrlPolicy.REQUIRE, uri -> emptyIdp.clone());

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Indirect CRL: IF_CDP_PRESENT проходит с предупреждением, REQUIRE отказ")
    void testIndirectCrlSkippedUnlessRequired() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] idp = idpExtension(DerCodec.encodeTlv(0x84, new byte[] {(byte) 0xFF}));
        byte[] indirect = rawCrl(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idp)));

        // Раньше indirect CRL был фатальной ошибкой при любой политике; теперь это CRL, который
        // использовать нельзя, и он равносилен недоступному зеркалу
        trustManager(CrlPolicy.IF_CDP_PRESENT, uri -> indirect.clone())
                .validateChainWithOcsp(chain, null, false);

        assertThrows(
                CertificateException.class,
                () ->
                        trustManager(CrlPolicy.REQUIRE, uri -> indirect.clone())
                                .validateChainWithOcsp(chain, null, false),
                "При REQUIRE indirect CRL не заменяет проверку отзыва");
    }

    @Test
    @DisplayName("CRL с неизвестным critical не используется, даже если в нём указан сертификат")
    void testUnknownCriticalCrlWithSerialIsNotUsed() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] entry =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(
                                new java.math.BigInteger(1, leaf.cert.getSerialNumber())),
                        DerCodec.encodeTime("260601000000Z"));
        byte[] unknownCritical =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("1.2.3.4.5"),
                        DerCodec.encodeBoolean(true),
                        DerCodec.encodeOctetString(DerCodec.encodeNull()));
        byte[] crl =
                rawCrl(
                        DerCodec.encodeSequence(entry),
                        DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(unknownCritical)));

        // RFC 5280 §5.2 запрещает использовать такой CRL; отзыв из него не учитывается.
        // Поведение зафиксировано тестом, потому что раньше здесь был REVOKED.
        trustManager(CrlPolicy.IF_CDP_PRESENT, uri -> crl.clone())
                .validateChainWithOcsp(chain, null, false);
        assertThrows(
                CertificateException.class,
                () ->
                        trustManager(CrlPolicy.REQUIRE, uri -> crl.clone())
                                .validateChainWithOcsp(chain, null, false),
                "При REQUIRE такой CRL не заменяет проверку отзыва");
    }

    // ------------------------------------------------------------------------
    // Слишком большой ответ: ошибка, а не «адрес недоступен»
    // ------------------------------------------------------------------------

    private GostX509TrustManager sizedTrustManager(
            CrlPolicy policy, CrlFetcher fetcher, int maxCrlSize) {
        return GostX509TrustManager.fromTrustAnchors(
                caAnchors(),
                OcspPolicy.IF_PRESENT,
                null,
                policy,
                fetcher,
                maxCrlSize,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                CrlCache.DEFAULT_MAX_BYTES,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                null);
    }

    @Test
    @DisplayName("CrlSizeLimitException от загрузчика: отказ при IF_CDP_PRESENT и REQUIRE")
    void testFetcherSizeLimitIsFatalForAllPolicies() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        CrlFetcher tooLarge =
                uri -> {
                    throw new CrlSizeLimitException("too large", 100, 200);
                };

        for (CrlPolicy policy : new CrlPolicy[] {CrlPolicy.IF_CDP_PRESENT, CrlPolicy.REQUIRE}) {
            CertificateException e =
                    assertThrows(
                            CertificateException.class,
                            () ->
                                    sizedTrustManager(policy, tooLarge, 100)
                                            .validateChainWithOcsp(chain, null, false),
                            "Большой CRL не должен молча отключать проверку отзыва: " + policy);
            assertTrue(e.getMessage().contains("exceeds size limit"), e.getMessage());
        }
    }

    @Test
    @DisplayName("Большой ответ первого адреса даёт отказ сразу, второй адрес не опрашивается")
    void testSizeLimitDoesNotFallBackToNextMirror() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                createLeafWithCdp(
                        "http://crl1.example.com/root.crl", "http://crl2.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        AtomicInteger fetches = new AtomicInteger();
        CrlFetcher fetcher =
                uri -> {
                    if (fetches.getAndIncrement() == 0) {
                        throw new CrlSizeLimitException("too large", 100, 200);
                    }
                    return testCrl.clone();
                };

        assertThrows(
                CertificateException.class,
                () ->
                        sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, fetcher, 10_000)
                                .validateChainWithOcsp(chain, null, false));
        assertEquals(1, fetches.get(), "Как и прочие ошибки CRL: без перехода к другому адресу");
    }

    @Test
    @DisplayName("Прочий IOException по-прежнему только пропускает адрес")
    void testOtherIoExceptionStillSkipsMirror() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        CrlFetcher failing =
                uri -> {
                    throw new java.io.IOException("connection refused");
                };

        assertDoesNotThrow(
                () ->
                        sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, failing, 10_000)
                                .validateChainWithOcsp(chain, null, false),
                "сетевая ошибка при IF_CDP_PRESENT только пропускает адрес");
    }

    @Test
    @DisplayName(
            "RuntimeException загрузчика не выдаётся за отказ собеседника: уходит наверх как сбой")
    void testFetcherRuntimeFailureIsNotPeerRejection() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        CrlFetcher failing =
                uri -> {
                    throw new IllegalStateException("boom http://u:p@host/");
                };

        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            IllegalStateException failure =
                    assertThrows(
                            IllegalStateException.class,
                            () ->
                                    sizedTrustManager(CrlPolicy.REQUIRE, failing, 10_000)
                                            .validateChainWithOcsp(chain, null, false));
            assertEquals("boom http://u:p@host/", failure.getMessage(), "причина сохранена");

            // Классификация сбоя и WARNING с типом - на движке, у менеджера записи нет:
            // иначе один сбой записывался бы дважды
            assertEquals(
                    List.of(),
                    log.allMessages("GostX509TrustManager"),
                    "менеджер не путает сбой загрузчика с отказом собеседника");
        }
    }

    @Test
    @DisplayName("Собственный загрузчик вернул CRL ровно по maxCrlSize: принимается")
    void testCustomFetcherResponseExactlyAtLimitAccepted() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, uri -> testCrl.clone(), testCrl.length)
                .validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Собственный загрузчик вернул CRL длиннее maxCrlSize: понятная ошибка")
    void testCustomFetcherOversizeResponseIsRejected() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);

        CertificateException e =
                assertThrows(
                        CertificateException.class,
                        () ->
                                sizedTrustManager(
                                                CrlPolicy.IF_CDP_PRESENT,
                                                uri -> testCrl.clone(),
                                                testCrl.length - 1)
                                        .validateChainWithOcsp(chain, null, false));
        assertTrue(e.getMessage().contains("exceeds size limit"), e.getMessage());
    }

    @Test
    @DisplayName("Конструктор: загрузчик с меньшим пределом отвергается, DISABLED и лямбда нет")
    void testFetcherLimitCheckInConstructor() {
        CrlFetcher small =
                new CrlFetcher() {
                    @Override
                    public byte[] fetch(String crlUri) {
                        return null;
                    }

                    @Override
                    public int maxResponseSize() {
                        return 1000;
                    }
                };

        assertThrows(
                IllegalArgumentException.class,
                () -> sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, small, 2000),
                "Загрузчик оборвал бы большой CRL раньше разбора");
        assertThrows(
                IllegalArgumentException.class,
                () -> sizedTrustManager(CrlPolicy.REQUIRE, small, 2000));
        sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, small, 1000);
        assertThrows(
                IllegalArgumentException.class,
                () -> sizedTrustManager(CrlPolicy.DISABLED, small, 2000),
                "загрузчик без политики CRL - ошибка конфигурации");
        sizedTrustManager(CrlPolicy.IF_CDP_PRESENT, uri -> null, 2000);
    }

    // ------------------------------------------------------------------------
    // Кэш проверенных CRL: бюджет, отзыв из кэша, параллельные соединения, прерывание
    // ------------------------------------------------------------------------

    private GostX509TrustManager budgetTrustManager(
            CrlPolicy policy, CrlFetcher fetcher, long crlCacheMaxBytes) {
        return GostX509TrustManager.fromTrustAnchors(
                caAnchors(),
                OcspPolicy.IF_PRESENT,
                null,
                policy,
                fetcher,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                crlCacheMaxBytes,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                null);
    }

    @Test
    @DisplayName("Отозванный сертификат отвергается и при втором соединении, CRL из кэша")
    void testRevokedCertRejectedFromCache() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] revokedCrl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {leaf.cert.getSerialNumber()},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);
        AtomicInteger fetches = new AtomicInteger();
        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return revokedCrl.clone();
                        });

        for (int i = 0; i < 2; i++) {
            CertificateException ex =
                    assertThrows(
                            CertificateException.class,
                            () -> tm.validateChainWithOcsp(chain, null, false));
            assertTrue(ex.getMessage().contains("revoked"), "Отзыв виден и из кэша: " + ex);
        }
        assertEquals(1, fetches.get(), "Второе соединение берёт проверенный CRL из кэша");
    }

    @Test
    @DisplayName("Бюджет кэша 0: CRL грузится на каждом соединении, отзыв по-прежнему проверяется")
    void testZeroBudgetFetchesEveryConnection() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        AtomicInteger fetches = new AtomicInteger();
        GostX509TrustManager tm =
                budgetTrustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return testCrl.clone();
                        },
                        0);

        tm.validateChainWithOcsp(chain, null, false);
        tm.validateChainWithOcsp(chain, null, false);

        assertEquals(2, fetches.get(), "При нулевом бюджете записи не хранятся");
    }

    @Test
    @DisplayName("CRL не помещается как разобранный: сырой DER хранится, сеть один раз")
    void testRawDerKeptWhenParsedExceedsBudget() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        AtomicInteger fetches = new AtomicInteger();
        // Бюджет между длиной DER и оценкой удержания разобранного объекта
        GostX509TrustManager tm =
                budgetTrustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            fetches.incrementAndGet();
                            return testCrl.clone();
                        },
                        testCrl.length + 10);

        tm.validateChainWithOcsp(chain, null, false);
        tm.validateChainWithOcsp(chain, null, false);

        assertEquals(1, fetches.get(), "Сырой DER сохраняет главное: CRL берётся по сети один раз");
    }

    @Test
    @DisplayName("Прерванная загрузка даёт отказ и при IF_CDP_PRESENT, а не пропуск проверки")
    void testInterruptedFetchRejects() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        GostX509TrustManager tm =
                trustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> {
                            Thread.currentThread().interrupt();
                            throw new IOException("CRL fetch interrupted");
                        });
        try {
            CertificateException ex =
                    assertThrows(
                            CertificateException.class,
                            () -> tm.validateChainWithOcsp(chain, null, false),
                            "Прерывание не должно молча отключать проверку отзыва");
            assertTrue(ex.getMessage().contains("interrupted"), "Причина - прерывание: " + ex);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    @DisplayName("Откат cRLNumber на втором соединении -> жёсткий отказ даже при IF_CDP_PRESENT")
    void testCrlNumberRollbackRejectedEvenIfCdpPresent() throws Exception {
        PkixCertTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        byte[] newer = numberedCrl(10);
        byte[] older = numberedCrl(3);
        AtomicInteger fetches = new AtomicInteger();
        // Бюджет 0: CRL между соединениями не хранится, но номер для защиты от отката остаётся
        GostX509TrustManager tm =
                budgetTrustManager(
                        CrlPolicy.IF_CDP_PRESENT,
                        uri -> (fetches.incrementAndGet() == 1 ? newer : older).clone(),
                        0);

        tm.validateChainWithOcsp(chain, null, false);
        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain, null, false),
                        "Откат номера CRL - не недоступный адрес: отказ при любой политике");
        assertTrue(
                ex.getMessage().contains("CRL validation failed"),
                "Ожидается отказ проверки CRL, получено: " + ex.getMessage());
        assertEquals(2, fetches.get(), "Второй CRL загружен и отвергнут как откат");
    }

    private static byte[] numberedCrl(int number) {
        return GostCrlBuilder.create(root.subjectDn)
                .thisUpdate(Instant.now().minus(Duration.ofDays(1)))
                .nextUpdate(Instant.now().plus(Duration.ofDays(30)))
                .withCrlNumber(number)
                .sign(root.priv);
    }

    @Test
    @DisplayName("Отрицательный бюджет кэша CRL -> IllegalArgumentException")
    void testNegativeCacheBudgetRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> budgetTrustManager(CrlPolicy.IF_CDP_PRESENT, uri -> null, -1),
                "Бюджет не может быть отрицательным");
    }
}
