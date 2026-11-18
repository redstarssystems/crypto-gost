package org.rssys.gost.tls13.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

@DisplayName("TlsClientConfig: IDN hostname")
class TlsClientConfigTest {

    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    private static TlsClientConfig newConfig() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        return new TlsClientConfig(CS, TrustAnchors.ofCertificate(root.cert));
    }

    @Test
    @DisplayName("Кириллический hostname хранится как A-label")
    void testCyrillicHostnameConverted() throws Exception {
        TlsClientConfig config = newConfig();
        config.withServerHostname("пример.рф");
        assertEquals("xn--e1afmkfd.xn--p1ai", config.getServerHostname());
    }

    @Test
    @DisplayName("ASCII-имена с подчёркиванием и IP-литералы принимаются")
    void testAsciiAndIpHostnames() throws Exception {
        TlsClientConfig config = newConfig();
        assertEquals(
                "project_service_1",
                config.withServerHostname("project_service_1").getServerHostname());
        assertEquals("192.168.1.10", config.withServerHostname("192.168.1.10").getServerHostname());
        assertEquals("::1", config.withServerHostname("::1").getServerHostname());
        assertEquals("[::1]", config.withServerHostname("[::1]").getServerHostname());
        assertEquals("fe80::1%eth0", config.withServerHostname("fe80::1%eth0").getServerHostname());
    }

    @Test
    @DisplayName("Числовые формы IPv4 и NUL не принимаются как hostname")
    void testNumericIpv4FormsAndControlCharactersRejected() throws Exception {
        TlsClientConfig config = newConfig();
        for (String hostname :
                new String[] {
                    "2130706433", "0x7f000001", "127.1", "0177.0.0.1", "example.com\0", "a..b"
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> config.withServerHostname(hostname),
                    "hostname " + hostname + " нельзя принимать: он дошёл бы до SNI как имя");
        }
    }

    @Test
    @DisplayName("null отключает проверку, пустая строка и IDNA2003-омоним отклоняются")
    void testInvalidHostnames() throws Exception {
        TlsClientConfig config = newConfig();
        assertNull(config.withServerHostname(null).getServerHostname());
        assertThrows(IllegalArgumentException.class, () -> config.withServerHostname(""));
        assertThrows(
                IllegalArgumentException.class, () -> config.withServerHostname("fa\u00DF.de"));
    }
}
