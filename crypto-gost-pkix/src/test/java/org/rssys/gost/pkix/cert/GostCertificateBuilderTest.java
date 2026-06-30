package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostCertificateBuilder}: сборка сертификата через buildTbs + assembleCert.
 * Генерация ключей — в тесте (не в builder'е).
 */
@DisplayName("GostCertificateBuilder: построение и верификация")
class GostCertificateBuilderTest {

    @Test
    @DisplayName(
            "buildTbs + assembleCert: обратимость — собираем сертификат, парсим, проверяем поля")
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
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

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
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

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
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

        String[] names = cert.getSanDnsNames();
        assertNotNull(names, "SAN dNSName не null");
        assertEquals(1, names.length);
        assertEquals("example.com", names[0]);
        assertTrue(cert.verifyHostname("example.com"));
        assertFalse(cert.verifyHostname("other.com"));
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
        extBuf.write(GostCertificateBuilder.buildEkuExtension(new String[] {"1.3.6.1.5.5.7.3.1"}));
        byte[] tbs =
                GostCertificateBuilder.create(params, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(extBuf.toByteArray())
                        .issuerDn(subjectDn)
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

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
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

        assertTrue(cert.isSelfSigned(), "Root CA должен быть self-signed");
        assertEquals(-1, cert.getPathLen(), "Root CA должен иметь pathLen -1 (none)");
    }

    @Test
    @DisplayName("Цепочка CA -> leaf: buildTbs + assembleCert через issuer-ключ")
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
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.assembleCert(rootTbs, rootKp.getPrivate(), params);

        // Leaf
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf");
        byte[] leafTbs =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(rootDn)
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.assembleCert(leafTbs, rootKp.getPrivate(), params);

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
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.assembleCert(rootTbs, rootKp.getPrivate(), params);

        // Leaf with SAN + CDP + KU + EKU
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);
        byte[] leafDn = GostDnParser.encodeDn("CN=Test Leaf 2");
        byte[] cdpExt = GostCertificateBuilder.buildCdpExtension("http://crl.example.com/crl.der");
        ByteArrayOutputStream leafExtBuf = new ByteArrayOutputStream();
        leafExtBuf.write(
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE));
        leafExtBuf.write(
                GostCertificateBuilder.buildEkuExtension(new String[] {"1.3.6.1.5.5.7.3.1"}));
        leafExtBuf.write(cdpExt);
        byte[] leafTbs =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("server.com")
                        .additionalExtensions(leafExtBuf.toByteArray())
                        .issuerDn(rootDn)
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.assembleCert(leafTbs, rootKp.getPrivate(), params);

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
    @DisplayName("Подпись самоподписанного сертификата (assembleCert) валидна")
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
                        .buildTbs();
        GostCertificate cert = GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params);

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
                        .buildTbs();
        GostCertificate rootCert =
                GostCertificateBuilder.assembleCert(rootTbs, rootKp.getPrivate(), params);
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
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.assembleCert(leafTbs, rootKp.getPrivate(), params);

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
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .basicConstraints(false, 5),
                "fluent setter с pathLen без isCA=true должен бросать IllegalArgumentException");
    }

    // ========================================================================
    // Валидация notBefore/notAfter
    // ========================================================================

    @Test
    @DisplayName("buildTbs() с notBefore=null → IllegalStateException")
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
    @DisplayName("buildTbs() с notAfter=null → IllegalStateException")
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
    @DisplayName("buildTbs() с notAfter раньше notBefore → IllegalArgumentException")
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
    @DisplayName("verifySignature с не-ГОСТ OID → false")
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
                        .buildTbs();
        byte[] signedDer =
                GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), params).getEncoded();

        // Портим OID алгоритма подписи в сигнатуре:
        // buildAlgId использует GostOids.SIGN_ALG_256 = 1.2.643.7.1.1.3.2
        // DER OID bytes = {2A, 85, 03, 07, 01, 01, 03, 02}
        // Этот OID встречается дважды: внутри TBS (inner) и вне (outer).
        // Портим внешний (второе вхождение), заменяя 0x02 -> 0x13.
        byte[] corrupted = signedDer.clone();
        byte[] oidTlv = new byte[] {
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
    @DisplayName("serial(BigInteger.ZERO) → IllegalArgumentException")
    void testSerialZeroThrows() {
        ECParameters params = ECParameters.tc26a256();
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .serial(BigInteger.ZERO),
                "Нулевой serial должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("serial(отрицательный) → IllegalArgumentException")
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
    @DisplayName("serial(21 байт) → IllegalArgumentException")
    void testSerialTooLongThrows() {
        ECParameters params = ECParameters.tc26a256();
        BigInteger longSerial = new BigInteger("ff".repeat(21), 16);
        assertEquals(21, (longSerial.bitLength() + 7) / 8,
                "Предусловие: serial должен быть 21 байт");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(params, "CN=Test")
                                .serial(longSerial),
                "Serial > 20 октетов должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("serial(20 байт, MSB=1) — не бросает исключение (регрессия toByteArray)")
    void testSerial20BytesMsb1Passes() {
        ECParameters params = ECParameters.tc26a256();
        // 20-байтный serial с MSB=1: BigInteger.toByteArray() = 21 байт (ведущий 0x00),
        // но bitLength() корректно даёт 160 бит → (160+7)/8 = 20 → проходит.
        BigInteger serial20Msb1 = new BigInteger("ff".repeat(20), 16);
        assertEquals(21, serial20Msb1.toByteArray().length,
                "Предусловие: toByteArray для 20-байтного serial с MSB=1 = 21 байт");
        assertEquals(20, (serial20Msb1.bitLength() + 7) / 8,
                "Но bitLength показывает 20 байт значения");
        // Не должно бросать исключение
        GostCertificateBuilder.create(params, "CN=Test").serial(serial20Msb1);
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
                        .assembleCert(kp.getPrivate());

        assertNotNull(cert);
        Instant actualNotBefore = cert.getNotBefore();
        assertTrue(
                actualNotBefore.toEpochMilli() >= now.toEpochMilli() - 1000,
                "notBefore должен быть >= now - 1с (допуск на округление)");
    }
}
