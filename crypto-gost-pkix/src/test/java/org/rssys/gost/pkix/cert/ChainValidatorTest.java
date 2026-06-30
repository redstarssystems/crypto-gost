package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("ChainValidator: валидация pathLenConstraint и edge cases")
class ChainValidatorTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    // ========================================================================
    // Нарушение pathLen
    // ========================================================================

    /**
     * Цепочка: leaf ← ca1(CA) ← ca2(CA, pathLen=0) ← root(CA).
     * ca2 с pathLen=0 запрещает следующие CA — но ca1 является CA → нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: ca2.pathLen=0, под ним есть CA → PATH_LEN_EXCEEDED")
    void testPathLenExceeded() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca2 = createIntermediateCa(root, 0);
        CertBundle ca1 = createIntermediateCa(ca2, null);
        CertBundle leaf = createLeaf(ca1);

        List<GostCertificate> chain = List.of(leaf.cert, ca1.cert, ca2.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Граничный валидный случай — pathLen=1, под ним 0 CA (только leaf)
    // ========================================================================

    /**
     * Цепочка: leaf ← ca1(CA, pathLen=1) ← ca2(CA) ← root(CA).
     * ca1 с pathLen=1: разрешён 1 CA, но под ca1 — 0 CA (только leaf). Валидно.
     */
    @Test
    @DisplayName("pathLenConstraint: ca1.pathLen=1, под ним 0 CA → валидно")
    void testPathLenBoundaryValid() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca2 = createIntermediateCa(root, null);
        CertBundle ca1 = createIntermediateCa(ca2, 1);
        CertBundle leaf = createLeaf(ca1);

        List<GostCertificate> chain = List.of(leaf.cert, ca1.cert, ca2.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // pathLen=0 с leaf напрямую — допустимо
    // ========================================================================

    /**
     * Цепочка: leaf ← intermediate(CA, pathLen=0) ← root(CA).
     * pathLen=0: разрешён только end-entity под этим CA. leaf не является CA → валидно.
     */
    @Test
    @DisplayName("pathLenConstraint: intermediate.pathLen=0, под ним только leaf → валидно")
    void testPathLenZeroWithLeafOnly() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, 0);
        CertBundle leaf = createLeaf(intermediate);

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // pathLen на root-сертификате (RFC 5280 §6.1)
    // ========================================================================

    /**
     * Цепочка: leaf ← ca(CA) ← root(CA, pathLen=0).
     * root с pathLen=0 разрешает только end-entity под собой — но ca является CA → нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: root.pathLen=0, под ним есть CA → PATH_LEN_EXCEEDED")
    void testPathLenExceededRoot() throws Exception {
        CertBundle root = createRootCa(0);
        CertBundle ca = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(ca);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Цепочка: leaf ← ca(CA) ← root(CA, pathLen=1).
     * root с pathLen=1: разрешён 1 CA — ca удовлетворяет ограничению.
     */
    @Test
    @DisplayName("pathLenConstraint: root.pathLen=1, под ним 1 CA → валидно")
    void testPathLenBoundaryValidRoot() throws Exception {
        CertBundle root = createRootCa(1);
        CertBundle ca = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(ca);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Self-issued сертификаты не считаются в pathLen (RFC 5280 §6.1)
    // ========================================================================

    /**
     * Цепочка: leaf ← caSelf(CA, DN=intermediate) ← intermediate(CA, pathLen=0) ← root(CA).
     * caSelf — self-issued (subjectDN == issuerDN == intermediate.subjectDN) → не считается.
     * intermediate с pathLen=0: разрешён 0 не-self-issued CA, условие выполнено → валидно.
     */
    @Test
    @DisplayName(
            "pathLenConstraint: int.pathLen=0, под ним self-issued CA → не считается → валидно")
    void testSelfIssuedNotCountedPathLen() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, 0);
        CertBundle caSelf = createSelfIssuedIntermediateCa(intermediate);
        CertBundle leaf = createLeaf(caSelf);

        List<GostCertificate> chain = List.of(leaf.cert, caSelf.cert, intermediate.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Цепочка: leaf ← ca(CA, DN≠intermediate) ← intermediate(CA, pathLen=0) ← root(CA).
     * ca — НЕ self-issued → считается. intermediate с pathLen=0: разрешён 0 CA, но ca — 1 → нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: int.pathLen=0, под ним НЕ self-issued CA → PATH_LEN_EXCEEDED")
    void testSelfIssuedPathLenExceeded() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, 0);
        CertBundle ca = createIntermediateCa(intermediate, null);
        CertBundle leaf = createLeaf(ca);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, intermediate.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    @Test
    @DisplayName("Пустая цепочка → PkixException")
    void testEmptyChain() throws Exception {
        var unusedKey = KeyGenerator.generateKeyPair(PARAMS).getPublic();
        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChain(List.of(), List.of(unusedKey)));
    }

    // ========================================================================
    // Algorithm consistency
    // ========================================================================

    /**
     * Сертификат, у которого внешний AlgorithmIdentifier не совпадает
     * с внутренним (TBSCertificate.signature) — нарушение RFC 5280 §4.1.1.2.
     */
    @Test
    @DisplayName("algorithm mismatch: внешний ≠ внутренний AlgId → ALG_MISMATCH")
    void testAlgorithmMismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] corruptedDer = corruptAlgConsistency(leaf.cert.getEncoded());
        GostCertificate brokenLeaf = new GostCertificate(corruptedDer);

        List<GostCertificate> chain = List.of(brokenLeaf, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChain(chain, trustedKeys));
        assertEquals(
                PkixException.Reason.ALG_MISMATCH,
                ex.reason(),
                "Ожидалась ошибка ALG_MISMATCH, а не SIGNATURE_INVALID");
    }

    // ========================================================================
    // Unknown critical extension
    // ========================================================================

    /**
     * Сертификат с неизвестным critical-расширением должен быть отвергнут
     * по RFC 5280 §4.2: «A certificate-using system MUST reject the certificate
     * if it encounters a critical extension it does not recognize».
     */
    @Test
    @DisplayName("unknown critical extension → UNKNOWN_CRITICAL_EXTENSION")
    void testUnknownCriticalExtension() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithUnknownCriticalExt(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Root not signed by any trusted CA
    // ========================================================================

    @Test
    @DisplayName("root не подписан ни одним trusted CA → ROOT_NOT_SIGNED")
    void testRootNotSigned() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(wrongKp.getPublic());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static CertBundle createRootCa() throws Exception {
        return createRootCa(null);
    }

    private static CertBundle createRootCa(Integer pathLen) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn =
                GostDnParser.encodeDn(
                        pathLen != null ? "CN=Root CA pathLen=" + pathLen : "CN=Root CA");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, pathLen);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] additional = concatExtensions(bc, ku, ski);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(dn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, kp.getPrivate(), PARAMS),
                dn);
    }

    private static CertBundle createIntermediateCa(CertBundle issuer, Integer pathLen)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn =
                GostDnParser.encodeDn(
                        "CN=Intermediate CA "
                                + (pathLen != null ? "pathLen=" + pathLen : "no-limit"));
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, pathLen);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(bc, ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                subjectDn);
    }

    /**
     * Создаёт self-issued intermediate CA: subjectDN == issuerDN.
     * Используется для проверки, что self-issued сертификаты не считаются против pathLen.
     */
    private static CertBundle createSelfIssuedIntermediateCa(CertBundle issuer) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(bc, ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, issuer.dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                issuer.dn);
    }

    private static CertBundle createLeaf(CertBundle issuer) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("gost.example.com")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                subjectDn);
    }

    /**
     * Создаёт leaf-сертификат с неизвестным critical-расширением.
     * Расширение: SEQUENCE { OID 1.2.3.4.5.6.7.8.9, BOOLEAN TRUE, OCTET STRING { 0x00 } }.
     */
    private static CertBundle createLeafWithUnknownCriticalExt(CertBundle issuer) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf Critical");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] unknownCrit = buildUnknownCriticalExtension();
        byte[] additional = concatExtensions(ku, ski, aki, unknownCrit);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("gost.example.com")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.TWO)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.assembleCert(tbs, issuer.priv, PARAMS),
                subjectDn);
    }

    /**
     * Строит сырое DER-расширение с неизвестным OID и critical=true.
     * Парсер GostExtensionParser при unknown OID + critical выставляет hasUnknownCritical = true.
     */
    private static byte[] buildUnknownCriticalExtension() {
        try {
            java.io.ByteArrayOutputStream ext = new java.io.ByteArrayOutputStream();
            ext.write(DerCodec.encodeOid("1.2.3.4.5.6.7.8.9"));
            ext.write(new byte[] {0x01, 0x01, (byte) 0xFF}); // BOOLEAN TRUE (critical)
            ext.write(DerCodec.encodeOctetString(new byte[] {0x00})); // пустое значение
            return DerCodec.encodeSequence(ext.toByteArray());
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Порча внешнего AlgorithmIdentifier сертификата — внутренний (в TBS) и внешний
     * перестают совпадать → isAlgConsistent() == false.
     * <p>
     * Ищет второе вхождение байт AlgorithmIdentifier в DER (первое — внутри TBS,
     * второе — внешний AlgId) и портит байт в OID внешнего.
     */
    private static byte[] corruptAlgConsistency(byte[] certData) {
        byte[] algId = GostSignatureHelper.buildAlgId(PARAMS);
        byte[] corrupted = certData.clone();
        int first = findBytes(corrupted, algId, 0);
        if (first >= 0) {
            int second = findBytes(corrupted, algId, first + algId.length);
            if (second >= 0) {
                // Портим первый байт содержимого OID внешнего AlgorithmIdentifier
                // AlgId = SEQUENCE(30 LL) { OID(06 LL content...) }
                // second+0=30, +1=LL, +2=06(OID tag), +3=OIDlen(8), +4=first OID byte
                corrupted[second + 4] ^= 0xFF;
            }
        }
        return corrupted;
    }

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

    private static byte[] concatExtensions(byte[]... exts) {
        if (exts.length == 0) return null;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            for (byte[] ext : exts) {
                out.write(ext);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    private static class CertBundle {
        final PrivateKeyParameters priv;
        final PublicKeyParameters pub;
        final GostCertificate cert;
        final byte[] dn;

        CertBundle(
                PrivateKeyParameters priv,
                PublicKeyParameters pub,
                GostCertificate cert,
                byte[] dn) {
            this.priv = priv;
            this.pub = pub;
            this.cert = cert;
            this.dn = dn;
        }
    }
}
