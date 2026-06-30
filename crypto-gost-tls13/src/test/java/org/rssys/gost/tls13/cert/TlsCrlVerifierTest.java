package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

/**
 * Unit-тесты для {@link CrlVerifier}.
 */
@DisplayName("CrlVerifier: верификация CRL")
class TlsCrlVerifierTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
    }

    @Test
    @DisplayName("CRL без отозванных -> OK")
    void testEmptyCrl() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("CRL с отозванным серийником -> revoked")
    void testRevokedCert() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        new byte[][] {leaf.cert.getSerialNumber()},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crl,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.REVOKED,
                ex.reason(),
                "Причина исключения должна быть REVOKED");
        assertTrue(
                ex.getMessage().contains("revoked"),
                "Ожидается revoked в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с чужим серийником (неотозванным) -> OK")
    void testNotRevokedCert() throws Exception {
        byte[] otherSerial = new byte[] {0x01, 0x02, 0x03};
        byte[] crl =
                TlsTestHelper.buildCrl(
                        new byte[][] {otherSerial},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("CRL с битой подписью -> TlsException")
    void testBadSignature() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        // Мутируем подпись: проверяем fail-closed — битая подпись не должна пропустить
        crl[crl.length - 1] ^= 0xFF;
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crl,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.SIGNATURE_INVALID,
                ex.reason(),
                "Причина исключения должна быть SIGNATURE_INVALID, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с nextUpdate в прошлом -> TlsException")
    void testExpiredCrl() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "200101120000Z",
                        false);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crl,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.EXPIRED,
                ex.reason(),
                "Причина исключения должна быть EXPIRED, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с issuingDistributionPoint -> TlsException")
    void testIdpExtension() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        true);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crl,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                ex.reason(),
                "Причина исключения должна быть IDP_NOT_SUPPORTED, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL равен null -> TlsException")
    void testNullCrl() {
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        null, new byte[] {0x01}, root.cert.getPublicKey()));
        assertTrue(
                ex.getMessage().contains("null"),
                "Ожидается null в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate есть -> возвращает Date")
    void testExtractNextUpdatePresent() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        java.time.Instant nu = CrlVerifier.extractNextUpdate(crl);
        assertNotNull(nu, "nextUpdate должен быть распарсен");
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate отсутствует -> null")
    void testExtractNextUpdateAbsent() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null, root.priv, root.cert.getPublicKey(), root.subjectDn, null, false);
        java.time.Instant nu = CrlVerifier.extractNextUpdate(crl);
        assertNull(nu, "Без nextUpdate вернётся null");
    }

    @Test
    @DisplayName("извлечение nextUpdate из null -> null")
    void testExtractNextUpdateNull() throws Exception {
        assertNull(CrlVerifier.extractNextUpdate(null), "На null входе -> null");
    }

    @Test
    @DisplayName("extractNextUpdate: битый DER -> null (no exception)")
    void testExtractNextUpdateMalformed() throws Exception {
        assertNull(
                CrlVerifier.extractNextUpdate(new byte[] {0x01, 0x02, 0x03}),
                "Битый DER не должен кидать исключение");
    }

    // ========================================================================
    // Версия CRL: голый INTEGER (RFC 5280) vs [0] EXPLICIT (ошибочная совместимость)
    // ========================================================================

    @Test
    @DisplayName("verify: v2 CRL с голым INTEGER version (RFC 5280)")
    void testVerifyV2RfcVersion() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("verify: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testVerifyV2LegacyVersion() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrlLegacyVersion(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("extractNextUpdate: v2 CRL с голым INTEGER version (RFC 5280)")
    void testExtractNextUpdateV2RfcVersion() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertNotNull(
                CrlVerifier.extractNextUpdate(crl),
                "nextUpdate должен быть распарсен с голым INTEGER version");
    }

    @Test
    @DisplayName("extractNextUpdate: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testExtractNextUpdateV2LegacyVersion() throws Exception {
        byte[] crl =
                TlsTestHelper.buildCrlLegacyVersion(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20300101120000Z",
                        false);
        assertNotNull(
                CrlVerifier.extractNextUpdate(crl),
                "nextUpdate должен быть распарсен с [0] EXPLICIT version");
    }

    @Test
    @DisplayName("thisUpdate в будущем -> отказ")
    void testThisUpdateInFuture() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(root.priv, root.subjectDn)
                        .thisUpdate("21000101120000Z") // thisUpdate = далёкое будущее
                        .nextUpdate("21000201120000Z") // nextUpdate = ещё дальше
                        .build();
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crl,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.THIS_UPDATE_FUTURE,
                ex.reason(),
                "Причина исключения должна быть THIS_UPDATE_FUTURE, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("thisUpdate в рамках clock skew (3 мин) -> OK")
    void testThisUpdateWithinClockSkew() throws Exception {
        // thisUpdate = сейчас + 3 минуты (в пределах 5-минутного допуска)
        java.time.Instant future = java.time.Instant.now().plusMillis(3 * 60 * 1000L);
        java.time.format.DateTimeFormatter fmt =
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
                        .withZone(java.time.ZoneOffset.UTC);
        String thisUpdate3minFuture = fmt.format(future);

        byte[] crl =
                GostCrlBuilder.create(root.priv, root.subjectDn)
                        .thisUpdate(thisUpdate3minFuture)
                        .nextUpdate("20300101120000Z")
                        .build();
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }

    @Test
    @DisplayName("thisUpdate в прошлом -> OK (нормальный CRL)")
    void testThisUpdateInPast() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(root.priv, root.subjectDn)
                        .thisUpdate("20200101120000Z") // thisUpdate в прошлом
                        .nextUpdate("20300101120000Z") // nextUpdate в будущем
                        .build();
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                crl, leaf.cert.getSerialNumber(), root.cert.getPublicKey()));
    }
}
