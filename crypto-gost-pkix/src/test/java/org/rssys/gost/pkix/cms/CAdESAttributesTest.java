package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESAttributes: signingCertificateV2")
class CAdESAttributesTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26c512();
    private static GostCertificate signerCert256;
    private static GostCertificate signerCert512;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPair kp256 = KeyGenerator.generateKeyPair(PARAMS_256);
        signerCert256 =
                GostCertificateBuilder.create(PARAMS_256, "CN=Test Signer 256")
                        .basicConstraints(false, null)
                        .notBefore("250101000000Z")
                        .notAfter("260101000000Z")
                        .publicKey(kp256.getPublic())
                        .assembleCert(kp256.getPrivate());

        KeyPair kp512 = KeyGenerator.generateKeyPair(PARAMS_512);
        signerCert512 =
                GostCertificateBuilder.create(PARAMS_512, "CN=Test Signer 512")
                        .basicConstraints(false, null)
                        .notBefore("250101000000Z")
                        .notAfter("260101000000Z")
                        .publicKey(kp512.getPublic())
                        .assembleCert(kp512.getPrivate());
    }

    @Test
    @DisplayName("signingCertificateV2 строится без ошибок (256-бит)")
    void buildSigningCertV2_256() {
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert256);
        assertTrue(attr.length > 0);
    }

    @Test
    @DisplayName("signingCertificateV2 строится без ошибок (512-бит)")
    void buildSigningCertV2_512() {
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert512);
        assertTrue(attr.length > 0);
    }

    @Test
    @DisplayName("verifySigningCertificateV2 проходит для валидного атрибута")
    void verifyValidAttr() {
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert256);
        assertDoesNotThrow(() -> CAdESAttributes.verifySigningCertificateV2(attr, signerCert256));
    }

    @Test
    @DisplayName("verifySigningCertificateV2 падает при несовпадении хэша (чужой сертификат)")
    void verifyMismatchedCert() {
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert256);
        assertThrows(
                PkixException.class,
                () -> CAdESAttributes.verifySigningCertificateV2(attr, signerCert512));
    }

    @Test
    @DisplayName("signingCertificateV2 падает при null-сертификате")
    void nullCertThrows() {
        assertThrows(NullPointerException.class, () -> CAdESAttributes.signingCertificateV2(null));
    }

    @Test
    @DisplayName("verifySigningCertificateV2 падает при null-параметрах")
    void nullVerifyParamsThrows() {
        assertThrows(
                NullPointerException.class,
                () -> CAdESAttributes.verifySigningCertificateV2(null, signerCert256));
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert256);
        assertThrows(
                NullPointerException.class,
                () -> CAdESAttributes.verifySigningCertificateV2(attr, null));
    }

    // ========================================================================
    // hashAlgorithm без NULL-параметров (RFC 9215 §4.2)
    // ========================================================================

    @Test
    @DisplayName("signingCertificateV2 кодирует hashAlgorithm без NULL-параметров для ГОСТ")
    void signingCertificateV2HashAlgorithmNoNullParam() throws Exception {
        byte[] attr = CAdESAttributes.signingCertificateV2(signerCert256);
        // SigningCertificateV2 -> certs -> ESSCertIDv2 -> hashAlgorithm
        byte[][] signingCertV2Parts = DerCodec.parseSequenceContents(attr, 0);
        byte[][] certsParts = DerCodec.parseSequenceContents(signingCertV2Parts[0], 0);
        byte[][] essParts = DerCodec.parseSequenceContents(certsParts[0], 0);
        // hashAlgorithm: AlgorithmIdentifier = SEQUENCE { OID } (без NULL)
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(essParts[0], 0);
        assertEquals(
                1,
                hashAlgParts.length,
                "hashAlgorithm должен содержать только OID, без NULL-параметров");
    }

    // ========================================================================
    // hashAlgorithm OID из атрибута
    // ========================================================================

    @Test
    @DisplayName("verifySigningCertificateV2 использует OID хэш-алгоритма из атрибута")
    void verifySigningCertificateV2UsesOidFromAttr() throws Exception {
        byte[] attr256 = CAdESAttributes.signingCertificateV2(signerCert256);
        // проверка должна пройти — OID в атрибуте Стрибог-256, сертификат 256-бит
        assertDoesNotThrow(
                () -> CAdESAttributes.verifySigningCertificateV2(attr256, signerCert256));

        byte[] attr512 = CAdESAttributes.signingCertificateV2(signerCert512);
        // проверка должна пройти — OID в атрибуте Стрибог-512, сертификат 512-бит
        assertDoesNotThrow(
                () -> CAdESAttributes.verifySigningCertificateV2(attr512, signerCert512));
    }

    @Test
    @DisplayName(
            "verifySigningCertificateV2 бросает PkixException при неизвестном OID hashAlgorithm")
    void verifySigningCertificateV2RejectsUnknownOid() throws Exception {
        byte[] certDer = signerCert256.getEncoded();
        byte[] certHash = Digest.digest256(certDer);

        byte[] unknownHashAlg = DerCodec.encodeSequence(DerCodec.encodeOid("1.3.6.1.4.1.99999.1"));
        byte[] certHashOctet = DerCodec.encodeOctetString(certHash);
        byte[] issuerSerial = buildIssuerSerial(signerCert256);
        byte[] essCertIdV2 = DerCodec.encodeSequence(unknownHashAlg, certHashOctet, issuerSerial);
        byte[] certs = DerCodec.encodeSequence(essCertIdV2);
        byte[] attrValue = DerCodec.encodeSequence(certs);

        assertThrows(
                PkixException.class,
                () -> CAdESAttributes.verifySigningCertificateV2(attrValue, signerCert256),
                "Неизвестный OID hashAlgorithm должен вызывать исключение");
    }

    private static byte[] buildIssuerSerial(GostCertificate cert) {
        byte[] issuerDn = cert.getIssuerDnBytes();
        byte[] generalName = DerCodec.encodeContextConstructed(4, issuerDn);
        byte[] generalNames = DerCodec.encodeSequence(generalName);
        byte[] serialInt = DerCodec.encodeInteger(cert.getSerialNumberBigInt());
        return DerCodec.encodeSequence(generalNames, serialInt);
    }
}
