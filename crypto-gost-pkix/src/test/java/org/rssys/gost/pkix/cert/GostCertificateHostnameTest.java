package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;

/**
 * Проверка hostname и IP по SAN: единая нормализация в {@link GostDnsName}, никаких обращений
 * к DNS и никакого расхождения в границах случаев между разными разборщиками.
 */
@DisplayName("GostCertificate: verifyHostname/verifyAddress, единая нормализация")
class GostCertificateHostnameTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate cert;
    private static GostCertificate ipv4OnlyCert;

    @BeforeAll
    static void setUp() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        cert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Host Cert"))
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .sanDns("example.com", "*.example.com", "xn--e1afmkfd.xn--p1ai")
                        .sanIp("127.0.0.1", "::1", "2001:db8::1")
                        .sign(kp.getPrivate());
        KeyPair kp2 = KeyGenerator.generateKeyPair(PARAMS);
        ipv4OnlyCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Ipv4 Cert"))
                        .publicKey(kp2.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .sanIp("1.2.3.4")
                        .sign(kp2.getPrivate());
    }

    @Test
    @DisplayName("Штатные имена: точное, wildcard, IDN, регистр, одна завершающая точка")
    void regularNamesMatch() {
        assertTrue(cert.verifyHostname("example.com"));
        assertTrue(cert.verifyHostname("EXAMPLE.com."));
        assertTrue(cert.verifyHostname("www.example.com"));
        assertTrue(cert.verifyHostname("пример.рф"));
        assertFalse(cert.verifyHostname("other.com"));
        assertFalse(cert.verifyHostname("a.b.example.com"), "wildcard покрывает одну метку");
    }

    @Test
    @DisplayName("NUL, лишние точки и управляющие символы не дают совпадения")
    void malformedNamesDoNotMatch() {
        assertFalse(cert.verifyHostname("example.com\0"), "NUL не срезается");
        assertFalse(cert.verifyHostname("example.com.."), "две завершающие точки - пустая метка");
        assertFalse(cert.verifyHostname("exam­ple.com"), "soft hyphen");
        assertFalse(cert.verifyHostname("ｅxample.com"), "fullwidth e");
        assertFalse(cert.verifyHostname("   "));
    }

    @Test
    @DisplayName("IP-литералы сверяются с iPAddress SAN: IPv4, IPv6, скобки, зона")
    void ipLiteralsMatchIpSan() {
        assertTrue(cert.verifyHostname("127.0.0.1"));
        assertTrue(cert.verifyHostname("::1"));
        assertTrue(cert.verifyHostname("[::1]"));
        assertTrue(cert.verifyHostname("2001:db8::1"));
        assertTrue(cert.verifyHostname("[2001:DB8:0:0:0:0:0:1]"));
        assertFalse(cert.verifyHostname("127.0.0.2"));
        assertFalse(cert.verifyHostname("::2"));
    }

    @Test
    @DisplayName("Числовые формы IPv4 не совпадают ни с IP SAN, ни с dNSName")
    void numericIpv4FormsNeverMatch() {
        assertFalse(cert.verifyHostname("2130706433"), "127.0.0.1 в десятичной записи");
        assertFalse(cert.verifyHostname("0x7f000001"));
        assertFalse(cert.verifyHostname("127.1"));
        assertFalse(cert.verifyHostname("0177.0.0.1"));
        assertFalse(cert.verifyHostname("127.0.0.+1"));
    }

    @Test
    @DisplayName("verifyAddress(String) принимает только литералы и не резолвит имена")
    void verifyAddressAcceptsLiteralsOnly() {
        assertTrue(cert.verifyAddress("127.0.0.1"));
        assertTrue(cert.verifyAddress("[::1]"), "скобки допустимы и при прямом вызове");
        assertFalse(cert.verifyAddress("[127.0.0.1]"), "скобки допустимы только у IPv6");
        assertFalse(cert.verifyHostname("[127.0.0.1]"), "скобки допустимы только у IPv6");
        assertFalse(cert.verifyAddress("localhost"), "имя не резолвится");
        assertFalse(cert.verifyAddress("abc:1"), "не IP-литерал");
        assertFalse(cert.verifyAddress("example.com"));
        assertFalse(cert.verifyAddress((String) null));
    }

    @Test
    @DisplayName("IPv4-mapped IPv6 совпадает с IPv4 SAN в любой записи, IPv4-compatible - нет")
    void ipv4MappedMatchesIpv4San() {
        assertTrue(ipv4OnlyCert.verifyAddress("1.2.3.4"));
        assertTrue(ipv4OnlyCert.verifyAddress("::ffff:1.2.3.4"));
        assertTrue(ipv4OnlyCert.verifyAddress("0:0:0:0:0:ffff:1.2.3.4"));
        assertTrue(ipv4OnlyCert.verifyAddress("[::ffff:102:304]"));
        assertTrue(ipv4OnlyCert.verifyHostname("::ffff:1.2.3.4"));
        assertFalse(ipv4OnlyCert.verifyAddress("::1.2.3.4"), "IPv4-compatible не mapped");
        assertFalse(ipv4OnlyCert.verifyAddress("1.2.3.5"));
    }
}
