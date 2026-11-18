package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Смысл фильтров ExtendedKeyUsage и CertificatePolicies в {@code oid_filters} (RFC 8446 §4.2.5):
 * сертификат подходит, если содержит каждое значение из списка фильтра. Ветки реализованы
 * общим кодом, поэтому оба расширения проверяются одинаковыми сценариями.
 */
@DisplayName("TlsCertUtils.matchesOidFilter: фильтры ExtendedKeyUsage и CertificatePolicies")
class TlsCertUtilsOidFilterTest {

    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    private static final String CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    private static final String ANY_EKU = "2.5.29.37.0";
    private static final String POLICY_A = "1.2.3.4.5";
    private static final String POLICY_B = "1.2.3.4.6";
    private static final String POLICY_C = "1.2.3.4.7";

    /** OID расширений в DER (без тега и длины, как их хранит фильтр). */
    private static final byte[] EKU_EXTENSION_OID = {0x55, 0x1D, 0x25};

    private static final byte[] POLICIES_EXTENSION_OID = {0x55, 0x1D, 0x20};

    private static GostCertificate withEku;
    private static GostCertificate withAnyEku;
    private static GostCertificate withPolicies;
    private static GostCertificate withoutExtensions;

    @BeforeAll
    static void setUp() {
        ECParameters params = ECParameters.tc26a256();
        withEku =
                PkixCertTestHelper.createCertWithKey(
                                params,
                                "20240501120000Z",
                                "21060101120000Z",
                                null,
                                null,
                                new String[] {CLIENT_AUTH, SERVER_AUTH})
                        .cert;
        withAnyEku =
                PkixCertTestHelper.createCertWithKey(
                                params,
                                "20240501120000Z",
                                "21060101120000Z",
                                null,
                                null,
                                new String[] {CLIENT_AUTH, ANY_EKU})
                        .cert;
        withPolicies =
                PkixCertTestHelper.createCertWithKey(
                                params,
                                "20240501120000Z",
                                "21060101120000Z",
                                null,
                                null,
                                null,
                                null,
                                new String[] {POLICY_A, POLICY_B})
                        .cert;
        withoutExtensions = PkixCertTestHelper.createCertWithKey(params).cert;
    }

    private static byte[] oidList(String... oids) {
        byte[][] elements = new byte[oids.length][];
        for (int i = 0; i < oids.length; i++) {
            elements[i] = PkixCertTestHelper.derOid(oids[i]);
        }
        return PkixCertTestHelper.derSequence(elements);
    }

    private static boolean matches(GostCertificate cert, byte[] extensionOid, byte[] values) {
        return TlsCertUtils.matchesOidFilter(cert, new OIDFilter(extensionOid, values));
    }

    // ---- ExtendedKeyUsage ----

    @Test
    @DisplayName("EKU: все OID фильтра есть в сертификате -> подходит")
    void ekuAllPresent() {
        assertTrue(
                matches(withEku, EKU_EXTENSION_OID, oidList(CLIENT_AUTH)),
                "Один из двух EKU сертификата");
        assertTrue(
                matches(withEku, EKU_EXTENSION_OID, oidList(CLIENT_AUTH, SERVER_AUTH)),
                "Оба EKU сертификата");
    }

    @Test
    @DisplayName("EKU: хотя бы одного OID фильтра нет в сертификате -> не подходит")
    void ekuOneMissing() {
        assertFalse(matches(withEku, EKU_EXTENSION_OID, oidList(CODE_SIGNING)));
        assertFalse(
                matches(withEku, EKU_EXTENSION_OID, oidList(CLIENT_AUTH, CODE_SIGNING)),
                "Один есть, второго нет");
    }

    @Test
    @DisplayName("EKU: пустое значение фильтра требует лишь наличия расширения")
    void ekuEmptyValueRequiresPresenceOnly() {
        assertTrue(matches(withEku, EKU_EXTENSION_OID, new byte[0]));
        assertFalse(matches(withoutExtensions, EKU_EXTENSION_OID, new byte[0]));
    }

    @Test
    @DisplayName("EKU: сертификат без расширения не подходит под непустой фильтр")
    void ekuAbsentExtension() {
        assertFalse(matches(withoutExtensions, EKU_EXTENSION_OID, oidList(CLIENT_AUTH)));
    }

    @Test
    @DisplayName("EKU: anyExtendedKeyUsage в сертификате не принимается за совпадение")
    void ekuAnyExtendedKeyUsageIsNotAWildcard() {
        assertFalse(
                matches(withAnyEku, EKU_EXTENSION_OID, oidList(CLIENT_AUTH)),
                "Сертификат с anyEKU под фильтр EKU не подходит: подстановки нет");
    }

    @Test
    @DisplayName("EKU: значение фильтра не SEQUENCE или обрезано -> не подходит")
    void ekuMalformedFilterValue() {
        assertFalse(matches(withEku, EKU_EXTENSION_OID, new byte[] {0x04, 0x00}), "Не SEQUENCE");
        assertFalse(matches(withEku, EKU_EXTENSION_OID, new byte[] {0x30}), "Короче заголовка");
    }

    // ---- CertificatePolicies ----

    @Test
    @DisplayName("Политики: все OID фильтра есть в сертификате -> подходит")
    void policiesAllPresent() {
        assertTrue(matches(withPolicies, POLICIES_EXTENSION_OID, oidList(POLICY_A)));
        assertTrue(matches(withPolicies, POLICIES_EXTENSION_OID, oidList(POLICY_A, POLICY_B)));
    }

    @Test
    @DisplayName("Политики: хотя бы одного OID фильтра нет в сертификате -> не подходит")
    void policiesOneMissing() {
        assertFalse(matches(withPolicies, POLICIES_EXTENSION_OID, oidList(POLICY_C)));
        assertFalse(matches(withPolicies, POLICIES_EXTENSION_OID, oidList(POLICY_A, POLICY_C)));
    }

    @Test
    @DisplayName("Политики: пустое значение фильтра требует лишь наличия расширения")
    void policiesEmptyValueRequiresPresenceOnly() {
        assertTrue(matches(withPolicies, POLICIES_EXTENSION_OID, new byte[0]));
        assertFalse(matches(withoutExtensions, POLICIES_EXTENSION_OID, new byte[0]));
    }

    @Test
    @DisplayName("Политики: сертификат без расширения не подходит под непустой фильтр")
    void policiesAbsentExtension() {
        assertFalse(matches(withoutExtensions, POLICIES_EXTENSION_OID, oidList(POLICY_A)));
    }

    @Test
    @DisplayName("Политики: значение фильтра не SEQUENCE -> не подходит")
    void policiesMalformedFilterValue() {
        assertFalse(matches(withPolicies, POLICIES_EXTENSION_OID, new byte[] {0x04, 0x00}));
    }
}
