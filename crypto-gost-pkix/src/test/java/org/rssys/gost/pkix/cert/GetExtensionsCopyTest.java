package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;

/**
 * {@code getExtensions()} отдаёт независимую копию: правка возвращённых публичных массивов не
 * должна менять ни сам объект, ни результат проверки цепочки, которая читает те же поля.
 */
@DisplayName("getExtensions(): независимая копия, а не внутренние массивы")
class GetExtensionsCopyTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate cert;
    private static GostCsrParser csr;

    @BeforeAll
    static void setUp() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        cert =
                GostCertificateBuilder.create(PARAMS, "CN=Copy Test,O=Test,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .basicConstraints(true, 2)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sanDns("example.com", "www.example.com")
                        .sanIp("10.0.0.1")
                        .sanUri("https://example.com/")
                        .nameConstraints(
                                new String[] {"example.com"},
                                new String[] {"10.0.0.0/8"},
                                new String[] {"evil.example.com"},
                                null)
                        .sign(kp.getPrivate());
        csr =
                new GostCsrParser(
                        GostCsrBuilder.create("CN=Copy Csr", kp.getPublic())
                                .sanDns("csr.example.com")
                                .sign(kp.getPrivate()));
    }

    @Test
    @DisplayName("Правка массивов копии не меняет SAN, IP и ограничения самого сертификата")
    void modifyingCopyDoesNotAffectCertificate() {
        GostExtensionParser.ExtensionsResult first = cert.getExtensions();
        first.sanDnsNames[0] = "evil.com";
        first.sanIpAddresses[0][0] = 99;
        first.sanUris[0] = "https://evil.com/";
        first.nameConstraints.permittedDnsNames[0] = "evil.com";
        first.nameConstraints.permittedIps[0][0] = 99;
        first.nameConstraints.excludedDnsNames[0] = "other.org";

        assertEquals("example.com", cert.getSanDnsNames()[0], "SAN dNSName сертификата");
        assertEquals(10, cert.getSanIpAddresses()[0][0] & 0xFF, "SAN iPAddress сертификата");
        assertEquals("https://example.com/", cert.getSanUris()[0], "SAN URI сертификата");

        GostExtensionParser.ExtensionsResult second = cert.getExtensions();
        assertEquals("example.com", second.sanDnsNames[0], "вторая копия не видит правок первой");
        assertEquals("example.com", second.nameConstraints.permittedDnsNames[0]);
        assertEquals(10, second.nameConstraints.permittedIps[0][0] & 0xFF);
        assertEquals("evil.example.com", second.nameConstraints.excludedDnsNames[0]);
    }

    @Test
    @DisplayName("Каждый вызов возвращает новый объект с теми же значениями")
    void everyCallReturnsEqualButDistinctCopy() {
        GostExtensionParser.ExtensionsResult a = cert.getExtensions();
        GostExtensionParser.ExtensionsResult b = cert.getExtensions();

        assertNotSame(a, b, "объекты разные");
        assertNotSame(a.sanDnsNames, b.sanDnsNames, "массивы разные");
        assertArrayEquals(a.sanDnsNames, b.sanDnsNames);
        assertArrayEquals(a.sanIpAddresses[0], b.sanIpAddresses[0]);
        assertEquals(a.isCA, b.isCA);
        assertEquals(2, b.pathLen);
        assertEquals(a.presentExtensionOids, b.presentExtensionOids);
    }

    @Test
    @DisplayName("Канонический empty() возвращается как есть: сравнение == сохраняется")
    void emptyResultKeepsIdentity() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate bare =
                GostCertificateBuilder.create(PARAMS, "CN=Bare,O=Test,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .sign(kp.getPrivate());
        assertSame(GostExtensionParser.ExtensionsResult.empty(), bare.getExtensions());
    }

    @Test
    @DisplayName("GostCsrParser.getExtensions(): тоже копия")
    void csrExtensionsAreCopy() {
        GostExtensionParser.ExtensionsResult first = csr.getExtensions();
        first.sanDnsNames[0] = "evil.com";

        assertEquals("csr.example.com", csr.getExtensions().sanDnsNames[0]);
        assertNotSame(csr.getExtensions(), csr.getExtensions());
    }

    @Test
    @DisplayName(
            "getNameConstraints(): правка копии не меняет ограничения, на которых строится проверка")
    void nameConstraintsGetterReturnsCopy() {
        NameConstraintsData first = cert.getNameConstraints();
        first.excludedDnsNames[0] = "changed.example";
        first.permittedIps[0][0] = 99;

        NameConstraintsData second = cert.getNameConstraints();
        assertEquals("evil.example.com", second.excludedDnsNames[0], "excluded dNSName");
        assertEquals(10, second.permittedIps[0][0] & 0xFF, "permitted iPAddress");
        assertNotSame(first, second, "каждый вызов даёт новый объект");
        assertSame(
                NameConstraintsData.EMPTY,
                csrlessCertificateWithoutConstraints().getNameConstraints(),
                "отсутствие ограничений - канонический EMPTY");
    }

    private static GostCertificate csrlessCertificateWithoutConstraints() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        return GostCertificateBuilder.create(PARAMS, "CN=No NC,O=Test,C=RU")
                .publicKey(kp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForDays(30)
                .sign(kp.getPrivate());
    }
}
