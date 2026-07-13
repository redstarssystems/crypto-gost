package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("ExtensionsAccumulator: fluent-накопитель и статические строители")
class ExtensionsAccumulatorTest {

    @Test
    @DisplayName("writeExtensions: пустой аккумулятор — hasAnyExtensions() = false, вывод пуст")
    void testEmptyAccumulator() throws Exception {
        ExtensionsAccumulator ext = new ExtensionsAccumulator();
        assertFalse(ext.hasAnyExtensions());
        assertFalse(ext.hasAnySanNames());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ext.writeExtensions(out);
        assertEquals(0, out.size());
    }

    @Test
    @DisplayName("fluent-сеттеры: все типы + writeExtensions дают непустой вывод")
    void testAllFluentSetters() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] skiBytes = Digest.digest256(GostDerCodec.subjectPublicKeyPointBytes(kp.getPublic()));

        ExtensionsAccumulator ext = new ExtensionsAccumulator();
        ext.sanDns("example.com")
                .sanIp("192.168.1.1")
                .sanRfc822Name("test@example.com")
                .sanUri("https://example.com")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                .basicConstraints(false, null)
                .certificatePolicies("1.2.643.100.113.1")
                .ski(skiBytes)
                .additionalExtensions(DerCodec.encodeSequence(new byte[0]));

        assertTrue(ext.hasAnyExtensions());
        assertTrue(ext.hasAnySanNames());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ext.writeExtensions(out);
        assertTrue(out.size() > 0, "Вывод должен быть непустым после сеттеров");
    }

    @Test
    @DisplayName("buildKeyUsageExtension(KeyUsage...): кодирование битовой маски")
    void testBuildKeyUsageExtensionEnum() {
        byte[] ext =
                ExtensionsAccumulator.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                        GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT);
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildKeyUsageExtension(byte[], boolean): кодирование сырых битов")
    void testBuildKeyUsageExtensionBytes() {
        byte[] kuBits = new byte[] {(byte) 0xA0};
        byte[] ext = ExtensionsAccumulator.buildKeyUsageExtension(kuBits, true);
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildEkuExtension: кодирование EKU с critical флагом")
    void testBuildEkuExtension() {
        byte[] ext =
                ExtensionsAccumulator.buildEkuExtension(
                        new String[] {GostOids.EXT_SERVER_AUTH, GostOids.EXT_CLIENT_AUTH}, true);
        assertNotNull(ext);
        assertTrue(ext.length > 30);
    }

    @Test
    @DisplayName("buildSanExtension: все 6 типов GeneralName")
    void testBuildSanExtensionAllTypes() {
        byte[] ext =
                ExtensionsAccumulator.buildSanExtension(
                        new String[] {"example.com"},
                        new String[] {"192.168.1.1"},
                        new String[] {"user@example.com"},
                        new String[] {"https://example.com"},
                        null,
                        null);
        assertNotNull(ext);
        assertTrue(ext.length > 30);
    }

    @Test
    @DisplayName("buildIssuerAltNameExtension: структура как SAN, OID разный")
    void testBuildIssuerAltNameExtension() {
        byte[] ext =
                ExtensionsAccumulator.buildIssuerAltNameExtension(
                        new String[] {"issuer.example.com"}, null, null, null, null, null);
        assertNotNull(ext);
        assertTrue(ext.length > 5);

        byte[] oidDer = DerCodec.encodeOid(GostOids.EXT_IAN);
        boolean foundIanOid = false;
        for (int i = 0; i <= ext.length - oidDer.length; i++) {
            boolean match = true;
            for (int j = 0; j < oidDer.length; j++) {
                if (ext[i + j] != oidDer[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                foundIanOid = true;
                break;
            }
        }
        assertTrue(foundIanOid, "Расширение должно содержать OID IssuerAltName");
    }

    @Test
    @DisplayName("buildBasicConstraintsExtension: CA=true с pathLen")
    void testBuildBasicConstraintsCaWithPathLen() {
        byte[] ext = ExtensionsAccumulator.buildBasicConstraintsExtension(true, 0);
        assertNotNull(ext);
        assertTrue(ext.length > 15);
    }

    @Test
    @DisplayName("buildBasicConstraintsExtension: CA=false без pathLen")
    void testBuildBasicConstraintsNonCa() {
        byte[] ext = ExtensionsAccumulator.buildBasicConstraintsExtension(false, null);
        assertNotNull(ext);
        assertTrue(ext.length > 10);
    }

    @Test
    @DisplayName("buildBasicConstraintsExtension: pathLen без isCA — исключение")
    void testPathLenWithoutCaThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ExtensionsAccumulator.buildBasicConstraintsExtension(false, 0));
    }

    @Test
    @DisplayName("buildCertificatePoliciesExtension: из CertificatePolicy[]")
    void testBuildCertificatePoliciesExtension() {
        CertificatePolicy[] policies = CertificatePolicy.fromOids("1.2.643.100.113.1");
        byte[] ext = ExtensionsAccumulator.buildCertificatePoliciesExtension(policies);
        assertNotNull(ext);
        assertTrue(ext.length > 15);
    }

    @Test
    @DisplayName("buildAiaExtension: только OCSP")
    void testBuildAiaOcspOnly() {
        byte[] ext = ExtensionsAccumulator.buildAiaExtension("http://ocsp.example.com", null);
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildAiaExtension: оба параметра null — исключение")
    void testBuildAiaBothNullThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ExtensionsAccumulator.buildAiaExtension(null, null));
    }

    @Test
    @DisplayName("buildSkiExtension: SKI как Streebog-256 от точки ключа")
    void testBuildSkiExtension() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] ext = ExtensionsAccumulator.buildSkiExtension(kp.getPublic());
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildAkiExtension: кодирование из сырых байт SKI")
    void testBuildAkiExtensionFromBytes() {
        byte[] ski = new byte[32];
        byte[] ext = ExtensionsAccumulator.buildAkiExtension(ski);
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildCdpExtension: кодирование CRL Distribution Points")
    void testBuildCdpExtension() {
        byte[] ext = ExtensionsAccumulator.buildCdpExtension("http://crl.example.com/crl.crl");
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildFreshestCrlExtension: кодирование Freshest CRL")
    void testBuildFreshestCrlExtension() {
        byte[] ext =
                ExtensionsAccumulator.buildFreshestCrlExtension("http://crl.example.com/delta.crl");
        assertNotNull(ext);
        assertTrue(ext.length > 5);
    }

    @Test
    @DisplayName("buildOcspNoCheckExtension: кодирование id-pkix-ocsp-nocheck")
    void testBuildOcspNoCheckExtension() {
        byte[] ext = ExtensionsAccumulator.buildOcspNoCheckExtension();
        assertNotNull(ext);
        assertTrue(ext.length > 10);
    }

    @Test
    @DisplayName("buildNameConstraintsExtension: кодирование с DNS и IP")
    void testBuildNameConstraintsExtension() {
        byte[] ext =
                ExtensionsAccumulator.buildNameConstraintsExtension(
                        new String[] {"example.com"},
                        new String[] {"10.0.0.0/8"},
                        new String[] {"forbidden.com"},
                        null);
        assertNotNull(ext);
        assertTrue(ext.length > 30);

        byte[] oidDer = DerCodec.encodeOid(GostOids.EXT_NAME_CONSTRAINTS);
        boolean foundNcOid = false;
        for (int i = 0; i <= ext.length - oidDer.length; i++) {
            boolean match = true;
            for (int j = 0; j < oidDer.length; j++) {
                if (ext[i + j] != oidDer[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                foundNcOid = true;
                break;
            }
        }
        assertTrue(foundNcOid, "Расширение должно содержать OID NameConstraints");
    }

    @Test
    @DisplayName("buildNameConstraintsExtension: все списки пусты — исключение")
    void testNameConstraintsEmptyThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ExtensionsAccumulator.buildNameConstraintsExtension(null, null, null, null));
    }

    @Test
    @DisplayName("hasAnySanNames: только dnsName")
    void testHasAnySanNamesDnsOnly() {
        ExtensionsAccumulator ext = new ExtensionsAccumulator();
        ext.sanDns("example.com");
        assertTrue(ext.hasAnySanNames());
        assertTrue(ext.hasAnyExtensions());
    }

    @Test
    @DisplayName("CertificatePolicy.fromOids: лёгкая фабрика")
    void testCertificatePolicyFromOids() {
        CertificatePolicy[] policies =
                CertificatePolicy.fromOids("1.2.643.100.113.1", GostOids.POLICY_KC1);
        assertEquals(2, policies.length);
        assertEquals("1.2.643.100.113.1", policies[0].policyOid());
        assertNull(policies[0].cpsUri());
    }
}
