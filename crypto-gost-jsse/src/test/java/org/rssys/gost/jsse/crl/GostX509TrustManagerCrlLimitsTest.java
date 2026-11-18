package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostTrustManagerParameters;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Пределы CRL в менеджере доверия: превышение - отказ при любой политике, а не пропуск проверки
 * отзыва; нулевые и отрицательные значения отвергаются сразу.
 */
@DisplayName("GostX509TrustManager: пределы CRL")
class GostX509TrustManagerCrlLimitsTest {

    private static final int ENTRIES = 11;
    private static final int ENTRIES_LIMIT = 10;

    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle leaf;
    private static byte[] crlWithManyEntries;
    private static byte[] cleanCrl;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
        leaf =
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
                        null,
                        PkixCertTestHelper.buildCdpExtension(
                                "http://crl1.example.com/root.crl",
                                "http://crl2.example.com/root.crl"));
        byte[][] serials = new byte[ENTRIES][];
        for (int i = 0; i < ENTRIES; i++) {
            serials[i] = new byte[] {(byte) (i + 1)};
        }
        crlWithManyEntries =
                PkixCertTestHelper.buildCrl(
                        serials,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);
        cleanCrl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);
    }

    private static GostX509TrustManager manager(
            CrlPolicy policy, CrlFetcher fetcher, int maxCrlSize, int maxRevokedEntries) {
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificate(root.cert),
                OcspPolicy.IF_PRESENT,
                null,
                policy,
                fetcher,
                maxCrlSize,
                maxRevokedEntries,
                CrlCache.DEFAULT_MAX_BYTES,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                null);
    }

    private static List<GostCertificate> chain() {
        return List.of(leaf.cert, root.cert);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(
            value = CrlPolicy.class,
            names = {"IF_CDP_PRESENT", "REQUIRE"})
    @DisplayName("Превышение числа записей - отказ при любой включённой политике")
    void entriesLimitExceededIsRefused(CrlPolicy policy) {
        GostX509TrustManager tm =
                manager(
                        policy,
                        uri -> crlWithManyEntries.clone(),
                        GostCrl.DEFAULT_MAX_CRL_SIZE,
                        ENTRIES_LIMIT);

        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () -> tm.validateChainWithOcsp(chain(), null, false),
                        "превышение предела не должно превращаться в пропуск проверки отзыва");

        assertTrue(
                ex.getMessage().contains("revoked entries exceed maximum"),
                "сообщение называет предел записей: " + ex.getMessage());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(
            value = CrlPolicy.class,
            names = {"IF_CDP_PRESENT", "REQUIRE"})
    @DisplayName("Первое зеркало превышает предел, второе чистое: отказ, второе не запрашивается")
    void exceededMirrorIsNotSkipped(CrlPolicy policy) {
        AtomicInteger fetches = new AtomicInteger();
        CrlFetcher fetcher =
                uri -> {
                    fetches.incrementAndGet();
                    return uri.startsWith("http://crl1.")
                            ? crlWithManyEntries.clone()
                            : cleanCrl.clone();
                };
        GostX509TrustManager tm =
                manager(policy, fetcher, GostCrl.DEFAULT_MAX_CRL_SIZE, ENTRIES_LIMIT);

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain(), null, false),
                "CRL, не поместившийся в предел, не равносилен недоступному зеркалу");

        assertEquals(1, fetches.get(), "второе зеркало не должно запрашиваться");
    }

    @Test
    @DisplayName("Поднятый предел записей пропускает тот же CRL")
    void raisedLimitAcceptsCrl() throws Exception {
        GostX509TrustManager tm =
                manager(
                        CrlPolicy.REQUIRE,
                        uri -> crlWithManyEntries.clone(),
                        GostCrl.DEFAULT_MAX_CRL_SIZE,
                        ENTRIES);

        tm.validateChainWithOcsp(chain(), null, false);
    }

    @Test
    @DisplayName("Пределы CRL по умолчанию: CRL с большим числом записей принимается")
    void managerDefaultsUnchanged() throws Exception {
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.REQUIRE,
                        uri -> crlWithManyEntries.clone());

        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(chain(), null, false),
                "CRL в пределах значений по умолчанию должен приниматься");
    }

    // ------------------------------------------------------------------------
    // Проверка значений при создании
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "Конструктор менеджера: нулевые и отрицательные пределы -> IllegalArgumentException")
    void managerRejectsNonPositiveLimits() {
        assertThrows(
                IllegalArgumentException.class,
                () -> manager(CrlPolicy.DISABLED, null, 0, ENTRIES_LIMIT));
        assertThrows(
                IllegalArgumentException.class, () -> manager(CrlPolicy.DISABLED, null, 1024, 0));
        assertThrows(
                IllegalArgumentException.class,
                () -> manager(CrlPolicy.REQUIRE, uri -> cleanCrl.clone(), 1024, -1));
    }

    @Test
    @DisplayName(
            "GostTrustManagerParameters.Builder.build: нулевые пределы -> IllegalArgumentException")
    void parametersBuilderRejectsNonPositiveLimits() {
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostTrustManagerParameters.builder()
                                .trustAnchors(anchors)
                                .crlPolicy(CrlPolicy.DISABLED)
                                .maxRevokedEntries(0)
                                .build());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostTrustManagerParameters.builder()
                                .trustAnchors(anchors)
                                .crlPolicy(CrlPolicy.DISABLED)
                                .maxCrlSize(0)
                                .build());
    }

    @Test
    @DisplayName("GostSslBuilder: нулевые пределы -> IllegalStateException при сборке")
    void sslBuilderRejectsNonPositiveLimits() throws Exception {
        byte[] pem = root.cert.toPem().getBytes(StandardCharsets.US_ASCII);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustCa(pem)
                                .crlPolicy(CrlPolicy.DISABLED)
                                .maxRevokedEntries(0)
                                .buildClientContext());
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustCa(pem)
                                .crlPolicy(CrlPolicy.DISABLED)
                                .maxCrlSize(-1)
                                .buildClientContext());
    }
}
