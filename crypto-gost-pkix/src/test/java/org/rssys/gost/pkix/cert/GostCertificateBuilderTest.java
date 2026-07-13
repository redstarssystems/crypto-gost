package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostCertificateBuilder}: сборка сертификата через buildTbs + sign.
 * Генерация ключей — в тесте (не в builder'е).
 */
@DisplayName("GostCertificateBuilder: построение и верификация")
class GostCertificateBuilderTest {

    @Test
    @DisplayName("buildTbs + sign: обратимость — собираем сертификат, парсим, проверяем поля")
    void testBuildAndAssembleRoundtrip() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Cert 1");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertNotNull(cert);
        assertFalse(cert.isExpired(), "Сертификат не должен быть просрочен");
        assertTrue(cert.isSelfSigned(), "Самоподписанный сертификат должен быть self-signed");
        assertEquals(
                cert.getPublicKey().getParams(),
                ECParameters.tc26a256(),
                "Кривая должна совпадать");
    }

    @Test
    @DisplayName("P1-T1: сертификат без KeyUsage — isKeyCertSignSet() = true (RFC 5280 §4.2.1.3)")
    void testKeyCertSignWithoutKeyUsage() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CA Without KU");
        // Без расширений (additionalExtensions = null) — KU отсутствует
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertTrue(
                cert.isKeyCertSignSet(),
                "При отсутствии KeyUsage все использования разрешены по RFC 5280 §4.2.1.3");
    }

    @Test
    @DisplayName("buildTbs с SAN: dNSName читается обратно")
    void testBuildTbsWithSanDns() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Cert 2");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .sanDns("example.com")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        String[] names = cert.getSanDnsNames();
        assertNotNull(names, "SAN dNSName не null");
        assertEquals(1, names.length);
        assertEquals("example.com", names[0]);
        assertTrue(cert.verifyHostname("example.com"));
        assertFalse(cert.verifyHostname("other.com"));
    }

    @Test
    @DisplayName("buildTbs с IAN: dNSName читается обратно")
    void testBuildTbsWithIanDns() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Cert IAN");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .ianDns("issuer.example.com")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        String[] names = cert.getIssuerAltNameDnsNames();
        assertNotNull(names, "IAN dNSName не null");
        assertEquals(1, names.length);
        assertEquals("issuer.example.com", names[0]);
    }

    @Test
    @DisplayName("verifyHostname не использует IAN — только SAN")
    void testVerifyHostnameDoesNotUseIan() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=IAN Check");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .sanDns("subject.example.com")
                        .ianDns("issuer.example.com")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertTrue(
                cert.verifyHostname("subject.example.com"),
                "SAN dNSName должен проходить hostname-верификацию");
        assertFalse(
                cert.verifyHostname("issuer.example.com"),
                "IAN dNSName не должен проходить hostname-верификацию");
    }

    @Test
    @DisplayName("buildTbs с KeyUsage и EKU")
    void testBuildTbsWithKuEku() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Cert 3");
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE));
        extBuf.write(
                GostCertificateBuilder.buildEkuExtension(
                        new String[] {"1.3.6.1.5.5.7.3.1"}, false));
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertTrue(cert.isKeyUsageValid());
        assertTrue(cert.isEkuValidForServer());
    }

    @Test
    @DisplayName("Root CA: buildTbs с BasicConstraints + KeyUsage -> алгебра ключей")
    void testRootCaViaBuildTbs() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Root CA 1");
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        extBuf.write(bcExt);
        extBuf.write(kuExt);
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertTrue(cert.isSelfSigned(), "Root CA должен быть self-signed");
        assertEquals(-1, cert.getPathLen(), "Root CA должен иметь pathLen -1 (none)");
    }

    @Test
    @DisplayName("Цепочка CA -> leaf: buildTbs + sign через issuer-ключ")
    void testChainViaBuildTbs() throws Exception {
        ECParameters params = ECParameters.tc26a256();

        // Root CA
        KeyPair rootKp = KeyGenerator.generateKeyPair(params);
        byte[] rootDn = GostDnParser.encodeDn("CN=Test Root CA 2");
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        ByteArrayOutputStream rootExtBuf = new ByteArrayOutputStream();
        rootExtBuf.write(bcExt);
        rootExtBuf.write(kuExt);
        byte[] rootTbs =
                GostCertificateBuilder.create(params, rootDn)
                        .publicKey(rootKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(rootExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.sign(rootTbs, GostSigner.of(rootKp.getPrivate()));

        // Leaf
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf");
        byte[] leafTbs =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.sign(leafTbs, GostSigner.of(rootKp.getPrivate()));

        assertTrue(
                leafCert.verifySignature(rootCert.getPublicKey()),
                "leaf должен верифицироваться ключом root");
        assertFalse(leafCert.isSelfSigned());
    }

    @Test
    @DisplayName("buildCert с SAN, extraExtensions (CDP), KU и EKU")
    void testBuildCertWithSanAndExtra() throws Exception {
        ECParameters params = ECParameters.tc26a256();

        // Root CA
        KeyPair rootKp = KeyGenerator.generateKeyPair(params);
        byte[] rootDn = GostDnParser.encodeDn("CN=Test Root CA 3");
        ByteArrayOutputStream rootExtBuf = new ByteArrayOutputStream();
        rootExtBuf.write(GostCertificateBuilder.buildBasicConstraintsExtension(true, null));
        rootExtBuf.write(
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN));
        byte[] rootTbs =
                GostCertificateBuilder.create(params, rootDn)
                        .publicKey(rootKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(rootExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.sign(rootTbs, GostSigner.of(rootKp.getPrivate()));

        // Leaf with SAN + CDP + KU + EKU
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf 2");
        byte[] cdpExt = GostCertificateBuilder.buildCdpExtension("http://crl.example.com/crl.der");
        ByteArrayOutputStream leafExtBuf = new ByteArrayOutputStream();
        leafExtBuf.write(
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE));
        leafExtBuf.write(
                GostCertificateBuilder.buildEkuExtension(
                        new String[] {"1.3.6.1.5.5.7.3.1"}, false));
        leafExtBuf.write(cdpExt);
        byte[] leafTbs =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("server.com")
                        .additionalExtensions(leafExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.sign(leafTbs, GostSigner.of(rootKp.getPrivate()));

        assertTrue(leafCert.verifyHostname("server.com"));
        assertTrue(leafCert.isKeyUsageValid());
    }

    @Test
    @DisplayName("buildCdpExtension: возвращает валидное расширение")
    void testBuildCdpExtension() {
        byte[] ext = GostCertificateBuilder.buildCdpExtension("http://pki.example.com/crl.crl");
        assertNotNull(ext);
        assertTrue(ext.length > 30, "Расширение должно быть ненулевой длины");
    }

    @Test
    @DisplayName("Подпись самоподписанного сертификата (sign) валидна")
    void testSelfSignedSignatureValid() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Self-Signed");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertTrue(
                cert.verifySignature(cert.getPublicKey()),
                "Подпись самоподписанного сертификата должна быть валидна");
    }

    // ========================================================================
    // SKI / AKI extensions
    // ========================================================================

    @Test
    @DisplayName("buildSkiExtension: SKI не null и длина 32 байта (256-битная кривая)")
    void testBuildSkiExtensionNotNull32() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] skiExt = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        assertNotNull(skiExt);
        assertTrue(skiExt.length > 0);

        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(kp.getPublic());
        byte[] expectedSki = Digest.digest256(pointBytes);
        assertEquals(32, expectedSki.length, "SKI должен быть 32 байта (Streebog-256)");

        byte[][] extParts = DerCodec.parseSequenceContents(skiExt, 0);
        byte[] skiOctetStr = DerCodec.parseOctetString(extParts[1], 0);
        byte[] actualSki = DerCodec.parseOctetString(skiOctetStr, 0);
        assertArrayEquals(expectedSki, actualSki, "SKI должен совпадать с хешем от точки ключа");
    }

    @Test
    @DisplayName("buildSkiExtension: один и тот же ключ -> одинаковый SKI")
    void testBuildSkiExtensionSameKeySameSki() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] ski1 = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] ski2 = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        assertArrayEquals(ski1, ski2, "Один и тот же ключ должен давать одинаковый SKI");
    }

    @Test
    @DisplayName("buildSkiExtension: разные ключи -> разные SKI")
    void testBuildSkiExtensionDifferentKeysDifferentSki() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp1 = KeyGenerator.generateKeyPair(params);
        KeyPair kp2 = KeyGenerator.generateKeyPair(params);
        byte[] ski1 = GostCertificateBuilder.buildSkiExtension(kp1.getPublic());
        byte[] ski2 = GostCertificateBuilder.buildSkiExtension(kp2.getPublic());
        assertFalse(java.util.Arrays.equals(ski1, ski2), "Разные ключи должны давать разные SKI");
    }

    @Test
    @DisplayName("buildSkiExtension: 512-битная кривая -> SKI 32 байта")
    void testBuildSkiExtension512Bit() {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] skiExt = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        assertNotNull(skiExt);
        byte[] pointBytes = GostDerCodec.subjectPublicKeyPointBytes(kp.getPublic());
        byte[] expectedSki = Digest.digest256(pointBytes);
        assertEquals(32, expectedSki.length, "SKI для 512-битной кривой — 32 байта (Streebog-256)");

        byte[][] extParts = DerCodec.parseSequenceContents(skiExt, 0);
        byte[] skiOctetStr = DerCodec.parseOctetString(extParts[1], 0);
        byte[] actualSki = DerCodec.parseOctetString(skiOctetStr, 0);
        assertArrayEquals(expectedSki, actualSki, "SKI должен совпадать с хешем от точки ключа");
    }

    @Test
    @DisplayName("buildAkiExtension: валидный DER с OID EXT_AKI")
    void testBuildAkiExtensionValidDer() {
        byte[] fakeSki = new byte[32];
        java.util.Arrays.fill(fakeSki, (byte) 0xAA);
        byte[] akiExt = GostCertificateBuilder.buildAkiExtension(fakeSki);
        assertNotNull(akiExt);
        assertTrue(akiExt.length > 0);

        byte[] akiOid = DerCodec.encodeOid(GostOids.EXT_AKI);
        byte[] akiOidDer = java.util.Arrays.copyOfRange(akiExt, 2, 2 + akiOid.length);
        assertArrayEquals(akiOid, akiOidDer, "Расширение должно содержать OID AKI (2.5.29.35)");
    }

    @Test
    @DisplayName("buildAkiExtension: keyIdentifier [0] IMPLICIT tag 0x80 присутствует")
    void testBuildAkiExtensionKeyIdentifierTag() {
        byte[] fakeSki = new byte[32];
        java.util.Arrays.fill(fakeSki, (byte) 0xBB);
        byte[] akiExt = GostCertificateBuilder.buildAkiExtension(fakeSki);
        assertNotNull(akiExt);

        // Разбираем: Extension SEQUENCE -> OID + OCTET STRING -> AKI SEQUENCE -> keyIdentifier
        byte[][] extParts = DerCodec.parseSequenceContents(akiExt, 0);
        byte[] akiOctetStr = DerCodec.parseOctetString(extParts[1], 0);
        byte[][] akiParts = DerCodec.parseSequenceContents(akiOctetStr, 0);
        assertTrue(akiParts.length >= 1, "AKI должен содержать keyIdentifier");
        assertEquals(0x80, akiParts[0][0] & 0xFF, "keyIdentifier: [0] IMPLICIT (0x80)");
    }

    @Test
    @DisplayName("buildSkiExtension + buildAkiExtension: обратимость CA -> дочерний")
    void testSkiAkiRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();

        // Root CA
        KeyPair rootKp = KeyGenerator.generateKeyPair(params);
        byte[] rootDn = GostDnParser.encodeDn("CN=Test Root CA SKI");

        byte[] rootSkiExt = GostCertificateBuilder.buildSkiExtension(rootKp.getPublic());
        byte[] bcExt = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] kuExt =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        ByteArrayOutputStream rootExtBuf = new ByteArrayOutputStream();
        rootExtBuf.write(rootSkiExt);
        rootExtBuf.write(bcExt);
        rootExtBuf.write(kuExt);
        byte[] rootTbs =
                GostCertificateBuilder.create(params, rootDn)
                        .publicKey(rootKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(rootExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.sign(rootTbs, GostSigner.of(rootKp.getPrivate()));
        assertTrue(
                rootCert.verifySignature(rootKp.getPublic()),
                "Root CA должен верифицироваться своим ключом");

        // Leaf с AKI = SKI Root CA (через перегрузку buildAkiExtension(PublicKeyParameters))
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf SKI");
        byte[] akiExt = GostCertificateBuilder.buildAkiExtension(rootKp.getPublic());

        ByteArrayOutputStream leafExtBuf = new ByteArrayOutputStream();
        leafExtBuf.write(akiExt);
        byte[] leafTbs =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(leafExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .randomSerial()
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.sign(leafTbs, GostSigner.of(rootKp.getPrivate()));

        assertTrue(
                leafCert.verifySignature(rootCert.getPublicKey()),
                "Дочерний сертификат должен верифицироваться ключом root CA");
    }

    @Test
    @DisplayName("buildBasicConstraintsExtension(false, pathLen) -> IllegalArgumentException")
    void testBuildBasicConstraints_pathLenWithoutCA_throws() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.buildBasicConstraintsExtension(false, 5),
                "pathLen без isCA=true должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("basicConstraints(false, pathLen) fluent setter -> IllegalArgumentException")
    void testBasicConstraintsFluent_pathLenWithoutCA_throws() {
        ECParameters params = ECParameters.tc26a256();
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.create(params, "CN=Test").basicConstraints(false, 5),
                "fluent setter с pathLen без isCA=true должен бросать IllegalArgumentException");
    }

    // ========================================================================
    // Валидация notBefore/notAfter
    // ========================================================================

    @Test
    @DisplayName("buildTbs() с notBefore=null -> IllegalStateException")
    void testBuildTbs_nullNotBefore_throws() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .publicKey(kp.getPublic())
                                .notAfter("21060101120000Z")
                                .buildTbs(),
                "notBefore=null должен давать IllegalStateException");
    }

    @Test
    @DisplayName("buildTbs() с notAfter=null -> IllegalStateException")
    void testBuildTbs_nullNotAfter_throws() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .publicKey(kp.getPublic())
                                .notBefore("20240501120000Z")
                                .buildTbs(),
                "notAfter=null должен давать IllegalStateException");
    }

    @Test
    @DisplayName("buildTbs() с notAfter раньше notBefore -> IllegalArgumentException")
    void testBuildTbs_notAfterBeforeNotBefore_throws() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .publicKey(kp.getPublic())
                                .notBefore("21060101120000Z")
                                .notAfter("20240501120000Z")
                                .serial(BigInteger.ONE)
                                .buildTbs(),
                "notAfter раньше notBefore должен давать IllegalArgumentException");
    }

    // ========================================================================
    // Whitelist OID в verifySignature
    // ========================================================================

    /**
     * Сертификат с подменённым OID алгоритма подписи (не ГОСТ)
     * должен давать false в verifySignature().
     */
    @Test
    @DisplayName("verifySignature с не-ГОСТ OID -> false")
    void testVerifySignature_nonGostOid_returnsFalse() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Cert M3");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        byte[] signedDer =
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();

        // Портим OID алгоритма подписи в сигнатуре:
        // buildAlgId использует GostOids.SIGN_WITH_DIGEST_256 = 1.2.643.7.1.1.3.2
        // DER OID bytes = {2A, 85, 03, 07, 01, 01, 03, 02}
        // Этот OID встречается дважды: внутри TBS (inner) и вне (outer).
        // Портим внешний (второе вхождение), заменяя 0x02 -> 0x13.
        byte[] corrupted = signedDer.clone();
        byte[] oidTlv =
                new byte[] {
                    0x06, 0x08, (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02
                };
        int first = findBytes(corrupted, oidTlv, 0);
        int second = -1;
        if (first >= 0) {
            second = findBytes(corrupted, oidTlv, first + oidTlv.length);
            if (second >= 0) {
                // Меняем последний байт значения OID (0x02 -> 0x13):
                // TLV = тег(1) + длина(1) + 8 байт значения; последний байт = offset + 9
                corrupted[second + 9] = 0x13;
            }
        }

        assertTrue(
                second >= 0,
                "Второе вхождение OID не найдено — коррупция AlgorithmIdentifier не сработала");
        GostCertificate cert = new GostCertificate(corrupted);
        assertFalse(
                cert.verifySignature(kp.getPublic()),
                "Подпись с не-ГОСТ OID должна возвращать false");
    }

    /** Поиск подмассива байтов. */
    private static int findBytes(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    // ========================================================================
    // Валидация серийного номера
    // ========================================================================

    @Test
    @DisplayName("buildTbs() без serial -> IllegalStateException (fail-closed)")
    void testBuildTbs_noSerial_throws() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        IllegalStateException ex =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                GostCertificateBuilder.create(params, "CN=Test")
                                        .publicKey(kp.getPublic())
                                        .notBefore("20240501120000Z")
                                        .notAfter("21060101120000Z")
                                        .issuerDn("CN=Test")
                                        .buildTbs(),
                        "Сборка без явного serial должна отвергаться fail-closed");
        assertTrue(
                ex.getMessage().contains("serial"),
                "Сообщение должно указывать на отсутствие serial: " + ex.getMessage());
    }

    @Test
    @DisplayName("serial(BigInteger.ZERO) -> IllegalArgumentException")
    void testSerialZeroThrows() {
        ECParameters params = ECParameters.tc26a256();
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.create(params, "CN=Test").serial(BigInteger.ZERO),
                "Нулевой serial должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("serial(отрицательный) -> IllegalArgumentException")
    void testSerialNegativeThrows() {
        ECParameters params = ECParameters.tc26a256();
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .serial(BigInteger.valueOf(-1)),
                "Отрицательный serial должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("serial(21 байт) -> IllegalArgumentException")
    void testSerialTooLongThrows() {
        ECParameters params = ECParameters.tc26a256();
        BigInteger longSerial = new BigInteger("ff".repeat(21), 16);
        assertEquals(
                21, (longSerial.bitLength() + 7) / 8, "Предусловие: serial должен быть 21 байт");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.create(params, "CN=Test").serial(longSerial),
                "Serial > 20 октетов должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("serial(20 байт, MSB=1) — не бросает исключение (регрессия toByteArray)")
    void testSerial20BytesMsb1Passes() {
        ECParameters params = ECParameters.tc26a256();
        // 20-байтный serial с MSB=1: BigInteger.toByteArray() = 21 байт (ведущий 0x00),
        // но bitLength() корректно даёт 160 бит -> (160+7)/8 = 20 -> проходит.
        BigInteger serial20Msb1 = new BigInteger("ff".repeat(20), 16);
        assertEquals(
                21,
                serial20Msb1.toByteArray().length,
                "Предусловие: toByteArray для 20-байтного serial с MSB=1 = 21 байт");
        assertEquals(
                20, (serial20Msb1.bitLength() + 7) / 8, "Но bitLength показывает 20 байт значения");
        // Не должно бросать исключение
        GostCertificateBuilder.create(params, "CN=Test").serial(serial20Msb1);
    }

    // ========================================================================
    // generateSerial / randomSerial
    // ========================================================================

    @Test
    @DisplayName("generateSerial: положительный BigInteger")
    void testGenerateSerialPositive() {
        BigInteger s = GostCertificateBuilder.generateSerial();
        assertTrue(s.signum() > 0, "Серийный номер должен быть положительным");
    }

    @Test
    @DisplayName("generateSerial: bitLength == 128 (детерминированно, не флаки)")
    void testGenerateSerialBitLength() {
        BigInteger s = GostCertificateBuilder.generateSerial();
        assertEquals(128, s.bitLength(), "bitLength должен быть ровно 128");
    }

    @Test
    @DisplayName("generateSerial: не более 20 октетов (RFC 5280 §4.1.2.2)")
    void testGenerateSerialMaxOctets() {
        BigInteger s = GostCertificateBuilder.generateSerial();
        int valueLen = (s.bitLength() + 7) / 8;
        assertTrue(valueLen <= GostOids.MAX_SERIAL_OCTETS, "должен укладываться в 20 октетов");
    }

    @Test
    @DisplayName("generateSerial: два последовательных вызова дают разные значения")
    void testGenerateSerialUniqueness() {
        BigInteger s1 = GostCertificateBuilder.generateSerial();
        BigInteger s2 = GostCertificateBuilder.generateSerial();
        assertNotEquals(s1, s2, "Два вызова должны дать разные серийные номера");
    }

    @Test
    @DisplayName("generateSerial: результат проходит через serial() без исключений")
    void testGenerateSerialPassesSerialSetter() {
        ECParameters params = ECParameters.tc26a256();
        BigInteger s = GostCertificateBuilder.generateSerial();
        assertDoesNotThrow(
                () -> GostCertificateBuilder.create(params, "CN=Test").serial(s),
                "generateSerial() должен давать валидный для serial() результат");
    }

    @Test
    @DisplayName("randomSerial: fluent-метод устанавливает серийный номер")
    void testRandomSerialSucceeds() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        GostCertificate cert =
                GostCertificateBuilder.create(params, "CN=Test")
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .randomSerial()
                        .sign(kp.getPrivate());
        assertNotNull(cert);
        assertNotEquals(
                BigInteger.ONE,
                cert.getSerialNumberBigInt(),
                "randomSerial() не должен давать дефолтный BigInteger.ONE");
    }

    @Test
    @DisplayName("Instant-перегрузки notBefore/notAfter: валидность сертификата")
    void testInstantNotBeforeNotAfter() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test");
        Instant now = Instant.now();
        Instant future = now.plusSeconds(3600L * 24 * 365); // +1 год

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore(now)
                        .notAfter(future)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertNotNull(cert);
        Instant actualNotBefore = cert.getNotBefore();
        assertTrue(
                actualNotBefore.toEpochMilli() >= now.toEpochMilli() - 1000,
                "notBefore должен быть >= now - 1с (допуск на округление)");
    }

    @Test
    @DisplayName("BasicConstraints pathLen INTEGER длиннее 4 байт -> IllegalArgumentException")
    void testPathLenIntegerOverflowRejected() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] dn = GostDnParser.encodeDn("CN=Test CA Overflow");

        byte[] malformedBcExt =
                new byte[] {
                    0x30,
                    0x16, // SEQUENCE (22 байта)
                    0x06,
                    0x03,
                    0x55,
                    0x1D,
                    0x13, // OID 2.5.29.19 (BC)
                    0x01,
                    0x01,
                    (byte) 0xFF, // BOOLEAN TRUE (critical)
                    0x04,
                    0x0C, // OCTET STRING (12 байт)
                    0x30,
                    0x0A, // SEQUENCE (10 байт)
                    0x01,
                    0x01,
                    (byte) 0xFF, // BOOLEAN TRUE (isCA)
                    0x02,
                    0x05, // INTEGER (5 байт — malformed)
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x64 // value 4294967396
                };

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(params, dn)
                                .publicKey(kp.getPublic())
                                .notBefore("20250101000000Z")
                                .notAfter("20351231235959Z")
                                .additionalExtensions(malformedBcExt)
                                .issuerDn(dn)
                                .randomSerial()
                                .sign(kp.getPrivate()));
    }

    @Test
    @DisplayName("GostCertificate(byte[]): массив > MAX_CERT_SIZE -> IllegalArgumentException")
    void testGostCertificateOversizedRejected() {
        byte[] oversizedDer = new byte[262_145]; // на 1 больше MAX_CERT_SIZE = 262_144
        IllegalArgumentException ex =
                assertThrows(
                        IllegalArgumentException.class, () -> new GostCertificate(oversizedDer));
        assertTrue(
                ex.getMessage().contains("exceeds maximum size"),
                "должен быть reject по превышению размера: " + ex.getMessage());
    }

    // ========================================================================
    // NameConstraints: round-trip тесты построителя
    // ========================================================================

    @Test
    @DisplayName("NameConstraints: buildNameConstraintsExtension — permitted dNSName")
    void testBuildNcPermittedDns() {
        byte[] ext =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        new String[] {"example.com"}, null, null, null);
        GostExtensionParser.ExtensionsResult r = parseExt(ext);
        assertEquals(1, r.nameConstraints.permittedDnsNames.length);
        assertEquals("example.com", r.nameConstraints.permittedDnsNames[0]);
        assertNull(r.nameConstraints.permittedIps);
        assertNull(r.nameConstraints.excludedDnsNames);
        assertNull(r.nameConstraints.excludedIps);
        assertFalse(r.nameConstraints.nonCritical);
    }

    @Test
    @DisplayName("NameConstraints: buildNameConstraintsExtension — permitted iPAddress CIDR")
    void testBuildNcPermittedIp() {
        byte[] ext =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        null, new String[] {"192.168.1.0/28"}, null, null);
        GostExtensionParser.ExtensionsResult r = parseExt(ext);
        assertNotNull(r.nameConstraints.permittedIps);
        assertEquals(1, r.nameConstraints.permittedIps.length);
        assertEquals(8, r.nameConstraints.permittedIps[0].length, "IPv4 constraint = 8 байт");
        assertNull(r.nameConstraints.permittedDnsNames);
        assertFalse(r.nameConstraints.nonCritical);
    }

    @Test
    @DisplayName("NameConstraints: buildNameConstraintsExtension — excluded dNSName")
    void testBuildNcExcludedDns() {
        byte[] ext =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        null, null, new String[] {"evil.com"}, null);
        GostExtensionParser.ExtensionsResult r = parseExt(ext);
        assertEquals(1, r.nameConstraints.excludedDnsNames.length);
        assertEquals("evil.com", r.nameConstraints.excludedDnsNames[0]);
        assertNull(r.nameConstraints.permittedDnsNames);
        assertNull(r.nameConstraints.permittedIps);
        assertNull(r.nameConstraints.excludedIps);
    }

    @Test
    @DisplayName("NameConstraints: buildNameConstraintsExtension — permitted + excluded, DNS + IP")
    void testBuildNcBoth() {
        byte[] ext =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        new String[] {"example.com"},
                        new String[] {"192.168.1.0/28"},
                        new String[] {"evil.com"},
                        new String[] {"10.0.0.0/8"});
        GostExtensionParser.ExtensionsResult r = parseExt(ext);
        assertEquals(1, r.nameConstraints.permittedDnsNames.length);
        assertEquals("example.com", r.nameConstraints.permittedDnsNames[0]);
        assertEquals(1, r.nameConstraints.permittedIps.length);
        assertEquals(8, r.nameConstraints.permittedIps[0].length);
        assertEquals(1, r.nameConstraints.excludedDnsNames.length);
        assertEquals("evil.com", r.nameConstraints.excludedDnsNames[0]);
        assertEquals(1, r.nameConstraints.excludedIps.length);
        assertEquals(8, r.nameConstraints.excludedIps[0].length);
        assertFalse(r.nameConstraints.hasUnsupportedNameType);
        assertFalse(r.nameConstraints.hasInvalidMinMax);
    }

    @Test
    @DisplayName("NameConstraints: расширение всегда critical")
    void testBuildNcCriticalAlways() {
        byte[] ext =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        new String[] {"example.com"}, null, null, null);
        GostExtensionParser.ExtensionsResult r = parseExt(ext);
        assertFalse(r.nameConstraints.nonCritical, "Расширение должно быть critical");
    }

    @Test
    @DisplayName("NameConstraints: все списки null -> IllegalArgumentException")
    void testBuildNcNullSafety() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.buildNameConstraintsExtension(null, null, null, null));
    }

    @Test
    @DisplayName("NameConstraints: все списки пусты -> IllegalArgumentException")
    void testBuildNcEmptyArrays() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.buildNameConstraintsExtension(
                                new String[0], new String[0], new String[0], new String[0]));
    }

    @Test
    @DisplayName("NameConstraints: полный round-trip через fluent API")
    void testBuildNcRoundtripViaFluent() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=NC CA");
        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .nameConstraints(
                                new String[] {"example.com"},
                                new String[] {"192.168.1.0/28"},
                                new String[] {"evil.com"},
                                null)
                        .randomSerial()
                        .sign(kp.getPrivate());

        NameConstraintsData nc = cert.getNameConstraints();
        assertNotNull(nc);
        assertFalse(nc.isEmpty());
        assertEquals(1, nc.permittedDnsNames.length);
        assertEquals("example.com", nc.permittedDnsNames[0]);
        assertEquals(1, nc.permittedIps.length);
        assertEquals(1, nc.excludedDnsNames.length);
        assertEquals("evil.com", nc.excludedDnsNames[0]);
        assertNull(nc.excludedIps);
        assertFalse(nc.nonCritical);
    }

    @Test
    @DisplayName("NameConstraints: некорректный CIDR -> IllegalArgumentException")
    void testBuildNcInvalidCidr() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.buildNameConstraintsExtension(
                                null, new String[] {"not-a-cidr"}, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.buildNameConstraintsExtension(
                                null, new String[] {"192.168.1.0/999"}, null, null));
    }

    @Test
    @DisplayName("AIA buildAiaExtension: только OCSP — round-trip через GostExtensionParser")
    void testBuildAiaOcspRoundtrip() {
        byte[] aiaExt = GostCertificateBuilder.buildAiaExtension("http://ocsp.example.com", null);
        GostExtensionParser.ExtensionsResult r = parseExt(aiaExt);

        assertNotNull(r.ocspUris, "OCSP URI должен быть");
        assertEquals(1, r.ocspUris.length);
        assertEquals("http://ocsp.example.com", r.ocspUris[0]);
        assertNull(r.caIssuersUris, "caIssuers должен быть null");
        assertNotNull(r.aiaUris);
        assertEquals(1, r.aiaUris.length);
    }

    @Test
    @DisplayName("AIA buildAiaExtension: только caIssuers — round-trip через GostExtensionParser")
    void testBuildAiaCaIssuersRoundtrip() {
        byte[] aiaExt =
                GostCertificateBuilder.buildAiaExtension(null, "http://ca.example.com/cert.p7c");
        GostExtensionParser.ExtensionsResult r = parseExt(aiaExt);

        assertNotNull(r.caIssuersUris, "caIssuers URI должен быть");
        assertEquals(1, r.caIssuersUris.length);
        assertEquals("http://ca.example.com/cert.p7c", r.caIssuersUris[0]);
        assertNull(r.ocspUris, "OCSP должен быть null");
        assertNotNull(r.aiaUris);
        assertEquals(1, r.aiaUris.length);
    }

    @Test
    @DisplayName("AIA buildAiaExtension: OCSP + caIssuers в одном расширении — round-trip")
    void testBuildAiaBothRoundtrip() {
        byte[] aiaExt =
                GostCertificateBuilder.buildAiaExtension(
                        "http://ocsp.example.com", "http://ca.example.com/cert.p7c");
        GostExtensionParser.ExtensionsResult r = parseExt(aiaExt);

        assertNotNull(r.ocspUris);
        assertEquals(1, r.ocspUris.length);
        assertEquals("http://ocsp.example.com", r.ocspUris[0]);
        assertNotNull(r.caIssuersUris);
        assertEquals(1, r.caIssuersUris.length);
        assertEquals("http://ca.example.com/cert.p7c", r.caIssuersUris[0]);
        assertNotNull(r.aiaUris);
        assertEquals(2, r.aiaUris.length);
    }

    @Test
    @DisplayName("AIA buildAiaExtension: оба null -> IllegalArgumentException")
    void testBuildAiaBothNullThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificateBuilder.buildAiaExtension(null, null));
    }

    /** Парсит одиночное Extension SEQUENCE через GostExtensionParser. */
    private static GostExtensionParser.ExtensionsResult parseExt(byte[] extensionDer) {
        byte[] seq = DerCodec.encodeSequence(extensionDer);
        return GostExtensionParser.parseExtensionsFromSequence(seq, 0);
    }

    @Test
    @DisplayName("freshestCrl fluent + round-trip: build -> parse -> verify URI")
    void testFreshestCrlFluentRoundtrip() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=FreshestCRL Test");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240601120000Z")
                        .notAfter("21060101120000Z")
                        .freshestCrl("http://ca.example/delta.crl")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));
        String[] uris = cert.getFreshestCrlUris();
        assertNotNull(uris, "freshestCrlUris не null после round-trip");
        assertEquals(1, uris.length);
        assertEquals("http://ca.example/delta.crl", uris[0]);
    }

    @Test
    @DisplayName("freshestCrl: без вызова -> getFreshestCrlUris() == null")
    void testFreshestCrlNotSet() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=No FreshestCRL");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240601120000Z")
                        .notAfter("21060101120000Z")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));
        assertNull(cert.getFreshestCrlUris(), "без freshestCrl() — null");
    }

    @Test
    @DisplayName("SAN: round-trip rfc822Name, URI, directoryName, otherName (UPN)")
    void testSanRoundTripNewTypes() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=MultiAltName");
        byte[] dnDer = GostDnParser.encodeDn("CN=AltDirName");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240601120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("example.com")
                        .sanIp("127.0.0.1")
                        .sanRfc822Name("user@example.com")
                        .sanUri("https://example.com")
                        .sanDirectoryName(dnDer)
                        .sanUpn("user@domain.ru")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        // DNS и IP — уже было
        String[] dns = cert.getSanDnsNames();
        assertNotNull(dns);
        assertEquals(1, dns.length);
        assertEquals("example.com", dns[0]);

        // Новые типы
        String[] emails = cert.getSanRfc822Names();
        assertNotNull(emails);
        assertEquals(1, emails.length);
        assertEquals("user@example.com", emails[0]);

        String[] uris = cert.getSanUris();
        assertNotNull(uris);
        assertEquals(1, uris.length);
        assertEquals("https://example.com", uris[0]);

        byte[][] dirNames = cert.getSanDirectoryNames();
        assertNotNull(dirNames);
        assertEquals(1, dirNames.length);
        assertArrayEquals(dnDer, dirNames[0]);

        OtherNameEntry[] otherNames = cert.getSanOtherNames();
        assertNotNull(otherNames);
        assertEquals(1, otherNames.length);
        assertEquals(GostOids.ID_MS_UPN, otherNames[0].oid(), "OID должен быть UPN");

        // Проверяем, что verifyHostname по-прежнему работает только с DNS
        assertTrue(cert.verifyHostname("example.com"));
        assertFalse(cert.verifyHostname("user@domain.ru"));
    }

    @Test
    @DisplayName("IAN: round-trip с новыми типами в IssuerAltName")
    void testIanRoundTripNewTypes() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=SelfSigned");
        byte[] dnDer = GostDnParser.encodeDn("CN=IssuerDirName");
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240601120000Z")
                        .notAfter("21060101120000Z")
                        .ianRfc822Name("issuer@example.com")
                        .ianUri("https://issuer.example.com")
                        .ianDirectoryName(dnDer)
                        .ianUpn("issuer@domain.ru")
                        .randomSerial()
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate()));

        assertNotNull(cert.getIssuerAltNameRfc822Names());
        assertEquals(1, cert.getIssuerAltNameRfc822Names().length);
        assertEquals("issuer@example.com", cert.getIssuerAltNameRfc822Names()[0]);

        assertNotNull(cert.getIssuerAltNameUris());
        assertEquals(1, cert.getIssuerAltNameUris().length);
        assertEquals("https://issuer.example.com", cert.getIssuerAltNameUris()[0]);

        assertNotNull(cert.getIssuerAltNameDirectoryNames());
        assertEquals(1, cert.getIssuerAltNameDirectoryNames().length);
        assertArrayEquals(dnDer, cert.getIssuerAltNameDirectoryNames()[0]);

        assertNotNull(cert.getIssuerAltNameOtherNames());
        assertEquals(1, cert.getIssuerAltNameOtherNames().length);
    }

    // ========================================================================
    // CertificatePolicies — fluent-сеттеры
    // ========================================================================

    @Test
    @DisplayName("certificatePolicies(String...): OID политик без CPS — round-trip")
    void testCertificatePoliciesFluentOidsOnly() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CertPolicies Test");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250601000000Z")
                        .notAfter("21070101000000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .certificatePolicies(GostOids.POLICY_KC1, GostOids.POLICY_KC2)
                        .sign(kp.getPrivate());

        String[] policies = cert.getCertificatePolicies();
        assertNotNull(policies);
        assertEquals(2, policies.length);
        assertEquals(GostOids.POLICY_KC1, policies[0]);
        assertEquals(GostOids.POLICY_KC2, policies[1]);

        CertificatePolicy[] infos = cert.getCertificatePolicyInfos();
        assertNotNull(infos);
        assertEquals(2, infos.length);
        assertEquals(GostOids.POLICY_KC1, infos[0].policyOid());
        assertNull(infos[0].cpsUri(), "CPS URI должен быть null без квалификаторов");
        assertNull(infos[1].cpsUri());
    }

    @Test
    @DisplayName(
            "certificatePolicyInfos(CertificatePolicy...): политики с CPS-квалификатором — round-trip")
    void testCertificatePolicyInfosWithCps() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CertPolicyCps Test");

        String cpsUri = "https://ca.example.com/cps/russian-ca.html";
        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250601000000Z")
                        .notAfter("21070101000000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .certificatePolicyInfos(
                                new CertificatePolicy(GostOids.POLICY_KC1, cpsUri),
                                new CertificatePolicy(GostOids.POLICY_KC2))
                        .sign(kp.getPrivate());

        CertificatePolicy[] infos = cert.getCertificatePolicyInfos();
        assertNotNull(infos);
        assertEquals(2, infos.length);
        assertEquals(GostOids.POLICY_KC1, infos[0].policyOid());
        assertEquals(cpsUri, infos[0].cpsUri());
        assertEquals(GostOids.POLICY_KC2, infos[1].policyOid());
        assertNull(infos[1].cpsUri());

        String[] policies = cert.getCertificatePolicies();
        assertNotNull(policies);
        assertEquals(2, policies.length);
    }

    @Test
    @DisplayName("certificatePolicyInfos: mix политик с/без CPS")
    void testCertificatePolicyInfosMixed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CertPolicyMix Test");

        String cpsUri = "https://ca.example.com/cps.html";
        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250601000000Z")
                        .notAfter("21070101000000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .certificatePolicyInfos(
                                new CertificatePolicy(GostOids.POLICY_KC1),
                                new CertificatePolicy(GostOids.POLICY_KC2, cpsUri),
                                new CertificatePolicy(GostOids.ANY_POLICY))
                        .sign(kp.getPrivate());

        CertificatePolicy[] infos = cert.getCertificatePolicyInfos();
        assertNotNull(infos);
        assertEquals(3, infos.length);
        assertNull(infos[0].cpsUri());
        assertEquals(cpsUri, infos[1].cpsUri());
        assertNull(infos[2].cpsUri());

        assertEquals(3, cert.getCertificatePolicies().length);
    }

    @Test
    @DisplayName("certificatePolicies: без расширения — getters возвращают null")
    void testCertificatePoliciesNotSet() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=NoPolicies Test");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250601000000Z")
                        .notAfter("21070101000000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertNull(cert.getCertificatePolicies());
        assertNull(cert.getCertificatePolicyInfos());
    }

    @Test
    @DisplayName("buildCertificatePoliciesExtension: старый API без CPS — обратная совместимость")
    void testBuildCertificatePoliciesExtensionLegacyApi() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=LegacyCp Test");

        byte[] cpExt =
                GostCertificateBuilder.buildCertificatePoliciesExtension(
                        new String[] {GostOids.POLICY_KC1, GostOids.POLICY_KC2});

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250601000000Z")
                        .notAfter("21070101000000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .additionalExtensions(cpExt)
                        .sign(kp.getPrivate());

        String[] policies = cert.getCertificatePolicies();
        assertNotNull(policies);
        assertEquals(2, policies.length);

        CertificatePolicy[] infos = cert.getCertificatePolicyInfos();
        assertNotNull(infos);
        assertEquals(2, infos.length);
        assertNull(infos[0].cpsUri());
    }

    // ========================================================================
    // fromCsrIdentity
    // ========================================================================

    @Test
    @DisplayName("fromCsrIdentity: успешное создание билдера, DN и ключ из CSR сохранены")
    void testFromCsrIdentitySuccess() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create("CN=FromCsr,O=TestOrg", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);

        GostCertificateBuilder b = GostCertificateBuilder.fromCsrIdentity(csr, params);
        assertNotNull(b);

        GostCertificate cert =
                b.issuerDn("CN=TestCA")
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(42))
                        .sign(kp.getPrivate());

        assertNotNull(cert);
        assertTrue(cert.getSubjectDn().contains("CN=FromCsr"));
        assertTrue(cert.getSubjectDn().contains("O=TestOrg"));
        assertArrayEquals(
                GostDerCodec.subjectPublicKeyPointBytes(csr.getPublicKey()),
                GostDerCodec.subjectPublicKeyPointBytes(cert.getPublicKey()),
                "Публичный ключ в сертификате должен побайтово совпадать с ключом из CSR");
    }

    @Test
    @DisplayName("fromCsrIdentity: PkixException при тамперинге подписи CSR")
    void testFromCsrIdentityPkixExceptionOnTamperedCsr() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=Tampered", kp.getPublic()).sign(kp.getPrivate());
        byte[] tampered = csrDer.clone();
        tampered[tampered.length - 1] ^= 0x01;

        GostCsrParser csr = GostCsrParser.fromDer(tampered);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> GostCertificateBuilder.fromCsrIdentity(csr, params));
        assertEquals(
                PkixException.Reason.SIGNATURE_INVALID,
                ex.reason(),
                "Причина должна быть SIGNATURE_INVALID");
    }

    @Test
    @DisplayName("fromCsrIdentity: расширения из CSR не попадают в сертификат автоматически")
    void testFromCsrIdentityExtensionsNotCopied() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        // CSR с расширениями
        byte[] csrDer =
                GostCsrBuilder.create("CN=WithExt,O=Org", kp.getPublic())
                        .sanDns("example.com")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(kp.getPrivate());
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);
        assertTrue(csr.hasExtensions(), "CSR должен содержать расширения");

        GostCertificateBuilder b = GostCertificateBuilder.fromCsrIdentity(csr, params);
        GostCertificate cert =
                b.issuerDn("CN=TestCA")
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(99))
                        .sign(kp.getPrivate());

        assertNotNull(cert);
        // Расширения не копируются: SAN должен отсутствовать
        assertNull(cert.getSanDnsNames(), "SAN не должен быть скопирован из CSR автоматически");
    }

    @Test
    @DisplayName("fromCsrIdentity: null csr → NullPointerException")
    void testFromCsrIdentityNullCsr() {
        ECParameters params = ECParameters.tc26a256();
        assertThrows(
                NullPointerException.class,
                () -> GostCertificateBuilder.fromCsrIdentity(null, params));
    }

    @Test
    @DisplayName("fromCsrIdentity: null params → NullPointerException")
    void testFromCsrIdentityNullParams() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create("CN=NullParams", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);

        assertThrows(
                NullPointerException.class,
                () -> GostCertificateBuilder.fromCsrIdentity(csr, null));
    }

    // ========================================================================
    // Удобные методы срока действия
    // ========================================================================

    @Test
    @DisplayName("notBeforeNow() + validForYears(10): сертификат не просрочен")
    void testNotBeforeNowAndValidForYears() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Now");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForYears(10)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertNotNull(cert);
        assertFalse(cert.isExpired(), "Сертификат не должен быть просрочен");
        Instant nb = cert.getNotBefore();
        Instant na = cert.getNotAfter();
        assertTrue(na.isAfter(nb), "notAfter должен быть после notBefore");
    }

    @Test
    @DisplayName("validForDays(1) с явным notBefore: разница ровно 24 часа")
    void testValidForDaysExact() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Days");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20260101120000Z")
                        .validForDays(1)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        Instant nb = cert.getNotBefore();
        Instant na = cert.getNotAfter();
        long diffSeconds = na.getEpochSecond() - nb.getEpochSecond();
        assertEquals(24L * 3600L, diffSeconds, "разница должна быть ровно 24 часа");
    }

    @Test
    @DisplayName("validForDays() без notBefore → IllegalStateException")
    void testValidForDaysWithoutNotBefore() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=NoNotBefore");

        assertThrows(
                IllegalStateException.class,
                () ->
                        GostCertificateBuilder.create(params, subjectDn)
                                .publicKey(kp.getPublic())
                                .validForDays(365)
                                .issuerDn(subjectDn)
                                .randomSerial()
                                .buildTbs(),
                "validForDays() без notBefore должен бросать IllegalStateException");
    }

    @Test
    @DisplayName("validForMonths(12): календарные месяцы, не 365×24 часа")
    void testValidForMonthsCalendar() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Months");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20260101120000Z")
                        .validForMonths(12)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        Instant nb = cert.getNotBefore();
        Instant na = cert.getNotAfter();
        // 2026-01-01 + 12 месяцев = 2027-01-01 (календарный)
        long diffSeconds = na.getEpochSecond() - nb.getEpochSecond();
        long expectedCalendar = 365L * 24L * 3600L;
        assertEquals(
                expectedCalendar,
                diffSeconds,
                "календарный год без leap-year должен быть 365×24×3600");
    }

    @Test
    @DisplayName("validForMonths(1) от 31 января → 28 февраля (календарная арифметика)")
    void testValidForMonthsJan31() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Jan31");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20260131235959Z")
                        .validForMonths(1)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        Instant na = cert.getNotAfter();
        java.time.ZonedDateTime zdt = na.atZone(java.time.ZoneOffset.UTC);
        assertEquals(2, zdt.getMonthValue(), "месяц должен быть февраль (2)");
        assertEquals(28, zdt.getDayOfMonth(), "день должен быть 28 (2026 — не високосный)");
    }

    @Test
    @DisplayName(
            "notBeforeNow() проверяет буфер clock skew: notBefore ≤ now ∧ notBefore ≥ now - CLOCK_SKEW_MS - 1с")
    void testNotBeforeNowClockSkewBuffer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Skew");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForYears(1)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        Instant now = Instant.now();
        Instant nb = cert.getNotBefore();
        assertFalse(
                nb.isAfter(now), "notBefore не должен быть в будущем: nb=" + nb + " now=" + now);
        assertTrue(
                nb.toEpochMilli() >= now.toEpochMilli() - GostOids.CLOCK_SKEW_MS - 1000L,
                "notBefore должен быть >= now - CLOCK_SKEW_MS - 1с (допуск): nb="
                        + nb
                        + " now="
                        + now);
    }

    // ====================================================================
    // Тесты getExtensions() / hasExtensions()
    // ====================================================================

    @Test
    @DisplayName("getExtensions: сертификат без расширений → ExtensionsResult.empty()")
    void testGetExtensionsNoExtensions() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=No Extensions");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        GostExtensionParser.ExtensionsResult ext = cert.getExtensions();
        assertNotNull(ext);
        assertTrue(ext.presentExtensionOids.isEmpty(), "presentExtensionOids должен быть пуст");
        assertFalse(cert.hasExtensions(), "hasExtensions должно быть false");
    }

    @Test
    @DisplayName("getExtensions: сертификат с SAN, KU, EKU — поля читаются из ExtensionsResult")
    void testGetExtensionsWithSanKuEku() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=With San Ku Eku");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sanDns("example.com")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .sign(kp.getPrivate());

        GostExtensionParser.ExtensionsResult ext = cert.getExtensions();
        assertNotNull(ext.sanDnsNames, "SAN dNSName не null");
        assertEquals(1, ext.sanDnsNames.length);
        assertEquals("example.com", ext.sanDnsNames[0]);

        assertTrue(
                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.isSetIn(ext.keyUsageBits),
                "KeyUsage: бит DIGITAL_SIGNATURE установлен");

        assertNotNull(ext.ekuOids, "EKU OID не null");
        assertEquals(1, ext.ekuOids.length, "Должен быть ровно 1 EKU OID");

        assertTrue(cert.hasExtensions(), "hasExtensions должно быть true");
    }

    @Test
    @DisplayName("getExtensions: presentExtensionOids содержит OID всех присутствующих расширений")
    void testGetExtensionsPresentOids() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Oid Coverage");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sanDns("example.org")
                        .basicConstraints(true, null)
                        .sign(kp.getPrivate());

        GostExtensionParser.ExtensionsResult ext = cert.getExtensions();
        Set<String> oids = ext.presentExtensionOids;

        assertTrue(oids.contains("2.5.29.17"), "Должен содержать OID SubjectAltName (2.5.29.17)");
        assertTrue(oids.contains("2.5.29.19"), "Должен содержать OID BasicConstraints (2.5.29.19)");
        assertFalse(
                oids.contains("2.5.29.15"),
                "Не должен содержать OID KeyUsage (2.5.29.15) — не задан");
        assertFalse(
                oids.contains("2.5.29.37"), "Не должен содержать OID EKU (2.5.29.37) — не задан");
    }

    @Test
    @DisplayName("getExtensions: presentExtensionOids.add() бросает UnsupportedOperationException")
    void testGetExtensionsPresentOidsImmutable() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Immutable");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sanDns("example.net")
                        .sign(kp.getPrivate());

        Set<String> oids = cert.getExtensions().presentExtensionOids;
        assertThrows(
                UnsupportedOperationException.class,
                () -> oids.add("1.2.3.4"),
                "presentExtensionOids должен быть неизменяемым");
    }

    // ====================================================================
    // Тесты fromCertificate()
    // ====================================================================

    @Test
    @DisplayName("fromCertificate: identity-копия — DN и ключ совпадают с оригиналом")
    void testFromCertificateIdentityCopy() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Original");

        GostCertificate original =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sanDns("original.example.com")
                        .sign(kp.getPrivate());

        GostCertificate reissued =
                GostCertificateBuilder.fromCertificate(original, params)
                        .notBeforeNow()
                        .validForDays(60)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertEquals(
                original.getSubjectDn(), reissued.getSubjectDn(), "Subject DN должен совпадать");
        assertArrayEquals(
                original.getSubjectDnBytes(),
                reissued.getSubjectDnBytes(),
                "Subject DN DER должен байтово совпадать");
        assertArrayEquals(
                GostDerCodec.subjectPublicKeyPointBytes(original.getPublicKey()),
                GostDerCodec.subjectPublicKeyPointBytes(reissued.getPublicKey()),
                "Публичный ключ должен совпадать (побайтово)");
    }

    @Test
    @DisplayName("fromCertificate: расширения НЕ копируются автоматически")
    void testFromCertificateExtensionsNotCopied() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=With Extensions");

        GostCertificate original =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sanDns("keep.example.com")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .basicConstraints(false, null)
                        .sign(kp.getPrivate());

        GostCertificate reissued =
                GostCertificateBuilder.fromCertificate(original, params)
                        .notBeforeNow()
                        .validForDays(60)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        GostExtensionParser.ExtensionsResult ext = reissued.getExtensions();
        assertNull(ext.sanDnsNames, "SAN dNSName не должен быть скопирован автоматически");
        assertEquals(0, ext.keyUsageBits, "KeyUsage не должен быть скопирован автоматически");
        assertNull(ext.ekuOids, "EKU не должен быть скопирован автоматически");
        assertFalse(
                reissued.hasExtensions(),
                "hasExtensions должно быть false при отсутствии расширений");
    }

    @Test
    @DisplayName("fromCertificate: null cert/params → NullPointerException")
    void testFromCertificateNullArgs() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Null Test");

        GostCertificate cert =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBeforeNow()
                        .validForDays(30)
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .sign(kp.getPrivate());

        assertThrows(
                NullPointerException.class,
                () -> GostCertificateBuilder.fromCertificate(null, params),
                "null cert → NPE");

        assertThrows(
                NullPointerException.class,
                () -> GostCertificateBuilder.fromCertificate(cert, null),
                "null params → NPE");
    }
}
