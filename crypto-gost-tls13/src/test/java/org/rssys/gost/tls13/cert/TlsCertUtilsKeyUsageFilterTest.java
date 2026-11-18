package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Фильтр KeyUsage в {@code oid_filters} (RFC 8446 §4.2.5): сертификат подходит, если в его
 * KeyUsage установлены все биты запроса. Значение фильтра, как и у остальных расширений, - DER
 * значения расширения, то есть BIT STRING целиком, с тегом и длиной.
 */
@DisplayName("TlsCertUtils.matchesOidFilter: фильтр KeyUsage")
class TlsCertUtilsKeyUsageFilterTest {

    /** OID расширения KeyUsage в DER (без тега и длины, как его хранит фильтр). */
    private static final byte[] KU_EXTENSION_OID = {0x55, 0x1D, 0x0F};

    private static GostCertificate signatureAndNonRepudiation;
    private static GostCertificate withoutKeyUsage;

    @BeforeAll
    static void setUp() {
        ECParameters params = ECParameters.tc26a256();
        signatureAndNonRepudiation =
                PkixCertTestHelper.createCertWithKey(
                                params,
                                "20240501120000Z",
                                "21060101120000Z",
                                null,
                                GostCertificateBuilder.keyUsageFlags(
                                        KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION),
                                null)
                        .cert;
        withoutKeyUsage = PkixCertTestHelper.createCertWithKey(params).cert;
    }

    /** DER BIT STRING: тег 0x03, длина, число неиспользуемых бит, затем байты битов. */
    private static byte[] bitString(int unusedBits, int... bytes) {
        byte[] der = new byte[3 + bytes.length];
        der[0] = 0x03;
        der[1] = (byte) (1 + bytes.length);
        der[2] = (byte) unusedBits;
        for (int i = 0; i < bytes.length; i++) {
            der[3 + i] = (byte) bytes[i];
        }
        return der;
    }

    private static boolean matches(GostCertificate cert, byte[] filterValue) {
        return TlsCertUtils.matchesOidFilter(cert, new OIDFilter(KU_EXTENSION_OID, filterValue));
    }

    @Test
    @DisplayName("KeyUsage: все биты запроса есть в сертификате -> подходит")
    void allRequestedBitsPresent() {
        assertTrue(matches(signatureAndNonRepudiation, bitString(7, 0x80)), "digitalSignature");
        assertTrue(matches(signatureAndNonRepudiation, bitString(6, 0x40)), "nonRepudiation");
        assertTrue(matches(signatureAndNonRepudiation, bitString(6, 0xC0)), "оба бита");
    }

    @Test
    @DisplayName("KeyUsage: хотя бы одного бита запроса нет в сертификате -> не подходит")
    void requestedBitMissing() {
        assertFalse(matches(signatureAndNonRepudiation, bitString(2, 0x04)), "keyCertSign");
        assertFalse(
                matches(signatureAndNonRepudiation, bitString(2, 0xC4)),
                "оба бита есть, но keyCertSign нет");
    }

    @Test
    @DisplayName("KeyUsage: неиспользуемые биты запроса не учитываются")
    void unusedBitsAreIgnored() {
        // Запрошен только digitalSignature (бит 0x80); младшие биты байта объявлены
        // неиспользуемыми и несут мусор, который в запрос не входит
        assertTrue(matches(signatureAndNonRepudiation, bitString(7, 0x81)));
    }

    @Test
    @DisplayName("KeyUsage: пустое значение фильтра требует лишь наличия расширения")
    void emptyValueRequiresPresenceOnly() {
        assertTrue(matches(signatureAndNonRepudiation, new byte[0]));
        assertFalse(
                matches(withoutKeyUsage, new byte[0]),
                "Без расширения KeyUsage пустой фильтр не подходит, как у EKU и CertificatePolicies");
    }

    @Test
    @DisplayName("KeyUsage: сертификат без расширения не подходит под непустой фильтр")
    void absentExtension() {
        assertFalse(matches(withoutKeyUsage, bitString(7, 0x80)));
    }

    @Test
    @DisplayName("KeyUsage: значение фильтра не BIT STRING или искажено -> не подходит")
    void malformedFilterValue() {
        assertFalse(matches(signatureAndNonRepudiation, new byte[] {0x04, 0x00}), "Не BIT STRING");
        assertFalse(matches(signatureAndNonRepudiation, new byte[] {0x03}), "Короче заголовка");
        assertFalse(
                matches(signatureAndNonRepudiation, new byte[] {0x03, 0x05, 0x07, (byte) 0x80}),
                "Длина больше тела");
        assertFalse(
                matches(
                        signatureAndNonRepudiation,
                        new byte[] {0x03, 0x02, 0x07, (byte) 0x80, 0x00}),
                "Лишние байты после BIT STRING");
        assertFalse(
                matches(signatureAndNonRepudiation, new byte[] {0x03, 0x02, 0x08, (byte) 0x80}),
                "Неиспользуемых бит больше семи");
        assertFalse(matches(signatureAndNonRepudiation, new byte[] {0x03, 0x00}), "Пустое тело");
    }
}
