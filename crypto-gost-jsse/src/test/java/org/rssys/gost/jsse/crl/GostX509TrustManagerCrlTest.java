package org.rssys.gost.jsse.crl;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Интеграционные тесты CRL-проверки через GostX509TrustManager.
 */
@DisplayName("GostX509TrustManager: CRL-проверка")
class GostX509TrustManagerCrlTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle root;
    private static byte[] testCrl;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        // CRL без отозванных, действительный до 2030
        testCrl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
    }

    private TlsTestHelper.CertBundle createLeafWithCdp(String... cdpUris) throws Exception {
        byte[] cdpExt = TlsTestHelper.buildCdpExtension(cdpUris);
        return TlsTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, (String[]) null,
                (byte[]) null, (String[]) null,
                false, null, cdpExt);
    }

    private static List<PublicKeyParameters> caKeys() {
        return Collections.singletonList(root.cert.getPublicKey());
    }

    @Test
    @DisplayName("CRL clean + IF_CDP_PRESENT + fetcher → OK")
    void testCrlClean() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        assertNotNull(leaf.cert.getCdpUris(), "CDP должен парситься из leaf-сертификата");
        assertTrue(leaf.cert.getCdpUris().length > 0, "CDP URI не должен быть пустым");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.IF_CDP_PRESENT, mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL revoked + IF_CDP_PRESENT → CertificateException")
    void testCrlRevoked() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");

        // CRL с отозванным leaf
        byte[] revokedCrl = TlsTestHelper.buildCrl(
                new byte[][]{leaf.cert.getSerialNumber()}, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);

        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> revokedCrl.clone();

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.IF_CDP_PRESENT, mockFetcher);

        CertificateException ex = assertThrows(CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false));
        assertTrue(ex.getMessage().contains("revoked"),
                "Ожидается revoked, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL REQUIRE + нет CDP → CertificateException")
    void testRequireNoCdp() throws Exception {
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, (String[]) null,
                (byte[]) null, (String[]) null,
                false, null);
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> testCrl.clone();

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.REQUIRE, mockFetcher);

        assertThrows(CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("CRL IF_CDP_PRESENT + нет CDP → OK")
    void testIfPresentNoCdp() throws Exception {
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, (String[]) null,
                (byte[]) null, (String[]) null,
                false, null);
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.IF_CDP_PRESENT, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL DISABLED + CDP есть → CRL не проверяется, OK")
    void testDisabledWithCdp() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.DISABLED, null);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL IF_CDP_PRESENT + fetcher=null + CDP есть → pass (fetch skipped)")
    void testIfPresentNoFetcher() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.IF_CDP_PRESENT, null);

        // fetcher=null → checkCrl пропускается, валидация OCSP проходит
        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("CRL REQUIRE + fetcher=null + CDP есть → CertificateException")
    void testRequireNoFetcher() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp("http://crl.example.com/root.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.REQUIRE, null);

        assertThrows(CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("Первый CDP mirror недоступен, второй отвечает clean → OK")
    void testFirstMirrorDownSecondServes() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp(
                "http://crl.example.com/fail.crl",
                "http://crl.example.com/root.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> {
            if (uri.contains("fail")) throw new IOException("CDP down");
            return testCrl.clone();
        };

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.REQUIRE, mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);
    }

    @Test
    @DisplayName("Все CDP mirror недоступны, REQUIRE → CertificateException")
    void testAllMirrorsDownRequire() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp(
                "http://crl.example.com/fail1.crl",
                "http://crl.example.com/fail2.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> { throw new IOException("down"); };

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.REQUIRE, mockFetcher);

        assertThrows(CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false));
    }

    @Test
    @DisplayName("Все CDP mirror недоступны, IF_CDP_PRESENT → OK (fallback)")
    void testAllMirrorsDownIfPresent() throws Exception {
        TlsTestHelper.CertBundle leaf = createLeafWithCdp(
                "http://crl.example.com/fail1.crl",
                "http://crl.example.com/fail2.crl");
        List<TlsCertificate> chain = List.of(leaf.cert, root.cert);

        CrlFetcher mockFetcher = uri -> { throw new IOException("down"); };

        GostX509TrustManager tm = new GostX509TrustManager(
                caKeys(), OcspPolicy.IF_PRESENT, null,
                CrlPolicy.IF_CDP_PRESENT, mockFetcher);

        tm.validateChainWithOcsp(chain, null, false);
    }
}
