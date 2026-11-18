package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Фильтр {@code oid_filters} для расширений без особых правил (RFC 8446 §4.2.5): значение фильтра
 * сравнивается побайтно со значением расширения (extnValue) сертификата, пустое значение требует
 * лишь наличия расширения, а OID неизвестного расширения не мешает выбору сертификата.
 */
@DisplayName("TlsCertUtils.matchesOidFilter: значение произвольного расширения")
class TlsCertUtilsExtensionValueFilterTest {

    /** OID SubjectAltName в DER (без тега и длины). */
    private static final byte[] SAN_OID = {0x55, 0x1D, 0x11};

    /** OID BasicConstraints: в сертификате теста его нет. */
    private static final byte[] BASIC_CONSTRAINTS_OID = {0x55, 0x1D, 0x13};

    private static final byte[] UNKNOWN_OID = {0x2A, 0x03, 0x04, 0x05, 0x06};

    private static GostCertificate withSan;

    @BeforeAll
    static void setUp() {
        withSan =
                PkixCertTestHelper.createCertWithKey(
                                ECParameters.tc26a256(),
                                "20240501120000Z",
                                "21060101120000Z",
                                new String[] {"example.org"})
                        .cert;
    }

    private static boolean matches(byte[] extensionOid, byte[] value) {
        return TlsCertUtils.matchesOidFilter(withSan, new OIDFilter(extensionOid, value));
    }

    @Test
    @DisplayName("значение фильтра совпало со значением расширения -> подходит")
    void equalValueMatches() {
        byte[] sanValue = withSan.getExtensionValue(GostOids.EXT_SAN);
        assertNotNull(sanValue, "в сертификате теста есть SubjectAltName");

        assertTrue(matches(SAN_OID, sanValue));
    }

    @Test
    @DisplayName("значение фильтра отличается (в любом байте, длиной) -> не подходит")
    void differentValueDoesNotMatch() {
        byte[] sanValue = withSan.getExtensionValue(GostOids.EXT_SAN);

        byte[] changed = sanValue.clone();
        changed[changed.length - 1] ^= 0x01;
        assertFalse(matches(SAN_OID, changed), "изменён последний байт");

        byte[] shorter = java.util.Arrays.copyOf(sanValue, sanValue.length - 1);
        assertFalse(matches(SAN_OID, shorter), "значение короче");

        byte[] longer = java.util.Arrays.copyOf(sanValue, sanValue.length + 1);
        assertFalse(matches(SAN_OID, longer), "значение длиннее");
    }

    @Test
    @DisplayName("пустое значение фильтра: достаточно наличия расширения")
    void emptyValueRequiresPresenceOnly() {
        assertTrue(matches(SAN_OID, new byte[0]));
        assertFalse(
                matches(BASIC_CONSTRAINTS_OID, new byte[0]),
                "известного расширения в сертификате нет");
    }

    @Test
    @DisplayName("известное расширение отсутствует -> не подходит, неизвестное -> не мешает")
    void absentKnownAndUnknownExtension() {
        assertFalse(matches(BASIC_CONSTRAINTS_OID, new byte[] {0x30, 0x00}));
        assertTrue(
                matches(UNKNOWN_OID, new byte[] {0x05, 0x00}),
                "RFC 8446 §4.2.5: фильтр с неизвестным OID игнорируется");
    }
}
