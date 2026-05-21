package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsTestHelper;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit-тесты для {@link TlsCrlVerifier}.
 */
@DisplayName("TlsCrlVerifier: верификация CRL")
class TlsCrlVerifierTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        leaf = TlsTestHelper.createCertSignedBy(params, root.priv,
                root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, (byte[]) null, (String[]) null,
                false, null);
    }

    @Test
    @DisplayName("CRL без отозванных → OK")
    void testEmptyCrl() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertDoesNotThrow(() ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("CRL с отозванным серийником → revoked")
    void testRevokedCert() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(
                new byte[][]{leaf.cert.getSerialNumber()}, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("revoked"),
                "Ожидается revoked в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с чужим серийником (неотозванным) → OK")
    void testNotRevokedCert() throws Exception {
        byte[] otherSerial = new byte[]{0x01, 0x02, 0x03};
        byte[] crl = TlsTestHelper.buildCrl(
                new byte[][]{otherSerial}, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertDoesNotThrow(() ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("CRL с битой подписью → TlsException")
    void testBadSignature() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        // Мутируем подпись: проверяем fail-closed — битая подпись не должна пропустить
        crl[crl.length - 1] ^= 0xFF;
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("signature"),
                "Ожидается signature error, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с nextUpdate в прошлом → TlsException")
    void testExpiredCrl() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "200101120000Z", false);
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("expired"),
                "Ожидается expired в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с issuingDistributionPoint → TlsException")
    void testIdpExtension() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", true);
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("issuingDistributionPoint"),
                "Ожидается issuingDistributionPoint error, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("null CRL → TlsException")
    void testNullCrl() {
        TlsException ex = assertThrows(TlsException.class, () ->
                TlsCrlVerifier.verify(null, new byte[]{0x01}, root.cert.getPublicKey()));
        assertTrue(ex.getMessage().contains("null"),
                "Ожидается null в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate есть → возвращает Date")
    void testExtractNextUpdatePresent() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        java.util.Date nu = TlsCrlVerifier.extractNextUpdate(crl);
        assertNotNull(nu, "nextUpdate должен быть распарсен");
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate отсутствует → null")
    void testExtractNextUpdateAbsent() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, null, false);
        java.util.Date nu = TlsCrlVerifier.extractNextUpdate(crl);
        assertNull(nu, "Без nextUpdate вернётся null");
    }

    @Test
    @DisplayName("extractNextUpdate: null → null")
    void testExtractNextUpdateNull() throws Exception {
        assertNull(TlsCrlVerifier.extractNextUpdate(null), "На null входе → null");
    }

    @Test
    @DisplayName("extractNextUpdate: битый DER → null (no exception)")
    void testExtractNextUpdateMalformed() throws Exception {
        assertNull(TlsCrlVerifier.extractNextUpdate(new byte[]{0x01, 0x02, 0x03}),
                "Битый DER не должен кидать исключение");
    }

    // ========================================================================
    // Версия CRL: голый INTEGER (RFC 5280) vs [0] EXPLICIT (ошибочная совместимость)
    // ========================================================================

    @Test
    @DisplayName("verify: v2 CRL с голым INTEGER version (RFC 5280)")
    void testVerifyV2RfcVersion() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertDoesNotThrow(() ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("verify: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testVerifyV2LegacyVersion() throws Exception {
        byte[] crl = TlsTestHelper.buildCrlLegacyVersion(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertDoesNotThrow(() ->
                TlsCrlVerifier.verify(crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("extractNextUpdate: v2 CRL с голым INTEGER version (RFC 5280)")
    void testExtractNextUpdateV2RfcVersion() throws Exception {
        byte[] crl = TlsTestHelper.buildCrl(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertNotNull(TlsCrlVerifier.extractNextUpdate(crl),
                "nextUpdate должен быть распарсен с голым INTEGER version");
    }

    @Test
    @DisplayName("extractNextUpdate: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testExtractNextUpdateV2LegacyVersion() throws Exception {
        byte[] crl = TlsTestHelper.buildCrlLegacyVersion(null, root.priv,
                root.cert.getPublicKey(), root.subjectDn, "300101120000Z", false);
        assertNotNull(TlsCrlVerifier.extractNextUpdate(crl),
                "nextUpdate должен быть распарсен с [0] EXPLICIT version");
    }
}
