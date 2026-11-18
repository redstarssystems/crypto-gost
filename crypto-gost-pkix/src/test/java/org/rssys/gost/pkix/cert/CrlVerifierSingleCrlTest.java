package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;

/**
 * Unit-тесты для {@link CrlVerifier}.
 */
@DisplayName("CrlVerifier: проверка одного CRL, nextUpdate, версия, thisUpdate")
class CrlVerifierSingleCrlTest {

    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle leaf;

    /** Срок следующего выпуска CRL: далеко в будущем, как notAfter тестовых сертификатов. */
    private static final String NEXT_UPDATE = "21060101120000Z";

    @BeforeAll
    static void setUp() throws Exception {
        params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
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
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        assertDoesNotThrow(() -> CrlVerifier.verify(crl, leaf.cert, root.cert));
    }

    @Test
    @DisplayName("CRL с отозванным серийником -> revoked")
    void testRevokedCert() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {leaf.cert.getSerialNumber()},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CrlVerifier.verify(crl, leaf.cert, root.cert));
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
                PkixCertTestHelper.buildCrl(
                        new byte[][] {otherSerial},
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        assertDoesNotThrow(() -> CrlVerifier.verify(crl, leaf.cert, root.cert));
    }

    @Test
    @DisplayName("CRL с битой подписью -> PkixException")
    void testBadSignature() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        // Мутируем подпись: проверяем fail-closed — битая подпись не должна пропустить
        crl[crl.length - 1] ^= 0xFF;
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CrlVerifier.verify(crl, leaf.cert, root.cert));
        assertEquals(
                PkixException.Reason.SIGNATURE_INVALID,
                ex.reason(),
                "Причина исключения должна быть SIGNATURE_INVALID, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CRL с nextUpdate в прошлом -> PkixException")
    void testExpiredCrl() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "200101120000Z",
                        false);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CrlVerifier.verify(crl, leaf.cert, root.cert));
        assertEquals(
                PkixException.Reason.EXPIRED,
                ex.reason(),
                "Причина исключения должна быть EXPIRED, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName(
            "CRL с пустым IDP (indirectCRL=false) — принимается, reject только indirectCRL=true")
    void testIdpExtension() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        true);
        // Пустой IDP (все флаги false, indirectCRL=false) больше не реджектится
        GostCrl parsed = GostCrl.fromDer(crl);
        parsed.verify(root.cert.getPublicKey());
        assertTrue(parsed.isIdp(), "IDP расширение должно присутствовать");
        assertFalse(parsed.isIndirectCrl(), "indirectCRL должен быть false");
    }

    @Test
    @DisplayName("CRL равен null -> PkixException")
    void testNullCrl() {
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        null,
                                        CrlTestCerts.certFor(new byte[] {0x01}, root.subjectDn),
                                        root.cert));
        assertTrue(
                ex.getMessage().contains("null"),
                "Ожидается null в сообщении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate есть -> возвращает Date")
    void testExtractNextUpdatePresent() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        java.time.Instant nu = CrlVerifier.extractNextUpdate(crl);
        assertEquals(
                java.time.Instant.parse("2106-01-01T12:00:00Z"),
                nu,
                "nextUpdate должен совпадать с заданным при выпуске CRL");
    }

    @Test
    @DisplayName("extractNextUpdate: nextUpdate отсутствует -> null")
    void testExtractNextUpdateAbsent() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrl(
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
    @DisplayName("verify: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testVerifyV2LegacyVersion() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrlLegacyVersion(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        assertDoesNotThrow(() -> CrlVerifier.verify(crl, leaf.cert, root.cert));
    }

    @Test
    @DisplayName("extractNextUpdate: v2 CRL с [0] EXPLICIT version (legacy fallback)")
    void testExtractNextUpdateV2LegacyVersion() throws Exception {
        byte[] crl =
                PkixCertTestHelper.buildCrlLegacyVersion(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NEXT_UPDATE,
                        false);
        assertNotNull(
                CrlVerifier.extractNextUpdate(crl),
                "nextUpdate должен быть распарсен с [0] EXPLICIT version");
    }

    @Test
    @DisplayName("thisUpdate в будущем -> отказ")
    void testThisUpdateInFuture() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(root.subjectDn)
                        .thisUpdate("21000101120000Z") // thisUpdate = далёкое будущее
                        .nextUpdate("21000201120000Z") // nextUpdate = ещё дальше
                        .sign(root.priv);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CrlVerifier.verify(crl, leaf.cert, root.cert));
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
                GostCrlBuilder.create(root.subjectDn)
                        .thisUpdate(thisUpdate3minFuture)
                        .nextUpdate(NEXT_UPDATE)
                        .sign(root.priv);
        assertDoesNotThrow(() -> CrlVerifier.verify(crl, leaf.cert, root.cert));
    }

    @Test
    @DisplayName("thisUpdate в прошлом -> OK (нормальный CRL)")
    void testThisUpdateInPast() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(root.subjectDn)
                        .thisUpdate("20200101120000Z") // thisUpdate в прошлом
                        .nextUpdate(NEXT_UPDATE) // nextUpdate в будущем
                        .sign(root.priv);
        assertDoesNotThrow(() -> CrlVerifier.verify(crl, leaf.cert, root.cert));
    }
}
