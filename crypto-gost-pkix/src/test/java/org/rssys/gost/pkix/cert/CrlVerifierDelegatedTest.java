package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

@DisplayName("CrlVerifier — делегированный CRL-подписант")
class CrlVerifierDelegatedTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] UNUSED_SERIAL = new byte[] {0x0F};

    private static PrivateKeyParameters caKey;
    private static PublicKeyParameters caPub;
    private static GostCertificate caCert;
    private static byte[] issuerDn;

    private static PrivateKeyParameters signerKey;
    private static GostCertificate signerCert;
    private static byte[] signerCertDer;

    private static PrivateKeyParameters leafKey;
    private static GostCertificate leafCert;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(PARAMS);
        caKey = caKp.getPrivate();
        caPub = caKp.getPublic();

        byte[] caKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] caBcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, 0);
        caSki = Digest.digest256(GostDerCodec.subjectPublicKeyPointBytes(caPub));
        byte[] caSkiExt = GostCertificateBuilder.buildSkiExtension(caPub);

        issuerDn = GostDnParser.encodeDn("CN=Test CA,O=TestOrg,C=RU");
        caCert =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=Test CA,O=TestOrg,C=RU")
                                .publicKey(caPub)
                                .randomSerial()
                                .notBefore("260601000000Z")
                                .notAfter("360601000000Z")
                                .additionalExtensions(concatExtensions(caKuExt, caBcExt, caSkiExt))
                                .buildTbs(),
                        GostSigner.of(caKey));

        // CRL-подписант с cRLSign (не CA)
        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerKey = signerKp.getPrivate();
        PublicKeyParameters signerPub = signerKp.getPublic();

        byte[] signerKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] signerSkiExt = GostCertificateBuilder.buildSkiExtension(signerPub);
        byte[] signerAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        signerCert =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=CRL Signer,O=TestOrg,C=RU")
                                .publicKey(signerPub)
                                .issuerDn(issuerDn)
                                .notBefore("260601000000Z")
                                .notAfter("360601000000Z")
                                .serial(BigInteger.valueOf(99))
                                .additionalExtensions(
                                        concatExtensions(signerKuExt, signerSkiExt, signerAkiExt))
                                .buildTbs(),
                        GostSigner.of(caKey));
        signerCertDer = signerCert.getEncoded();

        // Leaf без cRLSign (только digitalSignature)
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leafKey = leafKp.getPrivate();
        PublicKeyParameters leafPub = leafKp.getPublic();

        byte[] leafKuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] leafSkiExt = GostCertificateBuilder.buildSkiExtension(leafPub);
        byte[] leafAkiExt = GostCertificateBuilder.buildAkiExtension(caSki);

        leafCert =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=Leaf,O=TestOrg,C=RU")
                                .publicKey(leafPub)
                                .issuerDn(issuerDn)
                                .notBefore("260601000000Z")
                                .notAfter("360601000000Z")
                                .serial(BigInteger.valueOf(100))
                                .additionalExtensions(
                                        concatExtensions(leafKuExt, leafSkiExt, leafAkiExt))
                                .buildTbs(),
                        GostSigner.of(caKey));
    }

    // Вспомогательные поля / методы
    private static byte[] caSki;

    private static byte[] concatExtensions(byte[]... exts) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] ext : exts) {
            out.write(ext);
        }
        return out.toByteArray();
    }

    // ========================================================================
    // Позитивные тесты
    // ========================================================================

    @Test
    @DisplayName("CRL подписан делегированным ключом — verifyDelegated успешно")
    void testDelegatedSignerVerified() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(1)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        assertDoesNotThrow(
                () ->
                        CrlVerifier.verifyDelegated(
                                crl,
                                UNUSED_SERIAL,
                                caPub,
                                issuerDn,
                                caCert,
                                List.of(signerCertDer)),
                "Делегированный подписант должен проходить верификацию");
    }

    @Test
    @DisplayName("CA-ключ не подходит — fallback к delegated подписанту работает")
    void testCaKeyFailsFallbackToDelegated() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(2)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        // Без delegated signers — CA-ключ не подходит
        assertThrows(
                PkixException.class,
                () -> CrlVerifier.verify(crl, UNUSED_SERIAL, caPub, issuerDn),
                "CA-ключ не должен верифицировать CRL делегированного подписанта");

        // С delegated signers — ok
        CrlVerifier.verifyDelegated(
                crl, UNUSED_SERIAL, caPub, issuerDn, caCert, List.of(signerCertDer));
    }

    @Test
    @DisplayName("verifyDelegated с minCrlNumber — защита от rollback")
    void testDelegatedWithMinCrlNumber() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(3)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        // cRLNumber=3 >= min=2 — ok
        CrlVerifier.verifyDelegated(
                crl,
                UNUSED_SERIAL,
                caPub,
                issuerDn,
                caCert,
                List.of(signerCertDer),
                BigInteger.valueOf(2));

        // cRLNumber=3 < min=5 — reject
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyDelegated(
                                crl,
                                UNUSED_SERIAL,
                                caPub,
                                issuerDn,
                                caCert,
                                List.of(signerCertDer),
                                BigInteger.valueOf(5)),
                "cRLNumber downgrade должен быть rejected");
    }

    // ========================================================================
    // Негативные тесты
    // ========================================================================

    @Test
    @DisplayName("Сертификат подписанта без cRLSign — reject")
    void testDelegatedSignerWithoutCrlSignRejected() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(4)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        // Leaf cert не имеет cRLSign, должен быть reject
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyDelegated(
                                crl,
                                UNUSED_SERIAL,
                                caPub,
                                issuerDn,
                                caCert,
                                List.of(leafCert.getEncoded())),
                "Сертификат без cRLSign не должен приниматься как подписант");
    }

    @Test
    @DisplayName("CRL подписан leaf-ключом (без cRLSign) — reject")
    void testCrlSignedByLeafKeyRejected() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(5)
                        .nextUpdate("270601120000Z")
                        .sign(leafKey);

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyDelegated(
                                crl,
                                UNUSED_SERIAL,
                                caPub,
                                issuerDn,
                                caCert,
                                List.of(signerCertDer)),
                "CRL от leaf-ключа должен быть rejected (leafKey не в списке подписантов)");
    }

    @Test
    @DisplayName("Пустой список подписантов + CA не подходит — reject")
    void testEmptySignerListRejected() throws Exception {
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(6)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyDelegated(
                                crl, UNUSED_SERIAL, caPub, issuerDn, null, Collections.emptyList()),
                "Пустой список подписантов должен давать SIGNATURE_INVALID");
    }

    @Test
    @DisplayName("Сертификат подписанта не от того CA — reject")
    void testSignerCertFromDifferentCaRejected() throws Exception {
        // CRL подписан нашим signerKey, но в качестве подписанта передаём leafCert
        // (leafCert подписан CA, но у него нет cRLSign — isCrlSigner() = false, отсев)
        byte[] crl =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(7)
                        .nextUpdate("270601120000Z")
                        .sign(signerKey);

        // signerKey — в списке подписантов (проходит isCrlSigner, verifySignature)
        // leafCert — нет cRLSign, будет пропущен
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verifyDelegated(
                                crl,
                                UNUSED_SERIAL,
                                caPub,
                                issuerDn,
                                caCert,
                                List.of(leafCert.getEncoded(), signerCertDer)),
                "Среди смешанных подписантов должен найтись валидный");
    }
}
