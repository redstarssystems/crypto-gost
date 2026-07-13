package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
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
     * ca2 с pathLen=0 запрещает следующие CA — но ca1 является CA -> нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: ca2.pathLen=0, под ним есть CA -> PATH_LEN_EXCEEDED")
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
    @DisplayName("pathLenConstraint: ca1.pathLen=1, под ним 0 CA -> валидно")
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
     * pathLen=0: разрешён только end-entity под этим CA. leaf не является CA -> валидно.
     */
    @Test
    @DisplayName("pathLenConstraint: intermediate.pathLen=0, под ним только leaf -> валидно")
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
     * root с pathLen=0 разрешает только end-entity под собой — но ca является CA -> нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: root.pathLen=0, под ним есть CA -> PATH_LEN_EXCEEDED")
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
    @DisplayName("pathLenConstraint: root.pathLen=1, под ним 1 CA -> валидно")
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
     * caSelf — self-issued (subjectDN == issuerDN == intermediate.subjectDN) -> не считается.
     * intermediate с pathLen=0: разрешён 0 не-self-issued CA, условие выполнено -> валидно.
     */
    @Test
    @DisplayName(
            "pathLenConstraint: int.pathLen=0, под ним self-issued CA -> не считается -> валидно")
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
     * ca — НЕ self-issued -> считается. intermediate с pathLen=0: разрешён 0 CA, но ca — 1 -> нарушение.
     */
    @Test
    @DisplayName("pathLenConstraint: int.pathLen=0, под ним НЕ self-issued CA -> PATH_LEN_EXCEEDED")
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
    @DisplayName("Пустая цепочка -> PkixException")
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
    @DisplayName("algorithm mismatch: внешний ≠ внутренний AlgId -> ALG_MISMATCH")
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
    @DisplayName("unknown critical extension -> UNKNOWN_CRITICAL_EXTENSION")
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
    @DisplayName("root не подписан ни одним trusted CA — ROOT_NOT_SIGNED")
    void testRootNotSigned() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(wrongKp.getPublic());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Name Constraints (RFC 5280 §4.2.1.10) — enforcement
    // ========================================================================

    /**
     * CA: NC permitted=example.com, leaf SAN=host.example.com — OK.
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — поддомен матчит")
    void testNameConstraintsPermittedDnsMatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC permitted=example.com, leaf SAN=example.com — точное совпадение.
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — точное совпадение")
    void testNameConstraintsPermittedDnsExact() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC permitted=example.com, leaf SAN=evil.com — не матчит.
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — SAN вне namespace")
    void testNameConstraintsPermittedDnsMismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "evil.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC permitted=example.com, leaf SAN=notexample.com — нет точки-границы.
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — label-aware, частичное не матчит")
    void testNameConstraintsPermittedDnsNoPartial() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "notexample.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC excluded=bad.example.com, leaf SAN=bad.example.com — reject.
     */
    @Test
    @DisplayName("NameConstraints: excluded dNSName — reject")
    void testNameConstraintsExcludedDns() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("bad.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "bad.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC excluded=example.com, leaf SAN=sub.example.com — excluded subtree включает поддомены.
     */
    @Test
    @DisplayName("NameConstraints: excluded dNSName — поддомен тоже excluded")
    void testNameConstraintsExcludedSubdomain() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "sub.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC non-critical — reject по RFC 5280 §4.2.1.10 MUST.
     */
    @Test
    @DisplayName("NameConstraints: non-critical — reject")
    void testNameConstraintsNonCritical() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedDns("example.com", false));
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC с rfc822Name (unsupported type), leaf только с dNSName.
     * Неподдерживаемый тип ограничения игнорируется — цепочка проходит.
     */
    @Test
    @DisplayName("NameConstraints: unsupported тип игнорируется")
    void testNameConstraintsUnsupportedType() throws Exception {
        CertBundle root = createRootCa();
        byte[] rfc822 =
                DerCodec.encodeTlv(0x81, "user@example.com".getBytes(StandardCharsets.US_ASCII));
        byte[] nc =
                buildNameConstraintsExtension(
                        permittedSubtrees(generalSubtreesNc(generalSubtreeNc(rfc822, null, null))),
                        null,
                        true);
        CertBundle ca = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC с rfc822Name И dNSName permitted, leaf только с dNSName.
     * Реальный сценарий: государственный УЦ, выпускающий email- и TLS-сертификаты
     * одним промежуточным CA. rfc822Name-ограничения игнорируются,
     * dNSName-ограничения продолжают enforced.
     */
    @Test
    @DisplayName("NameConstraints: rfc822Name + dNSName, leaf только dNSName — OK")
    void testNameConstraintsRfc822NameAndDnsName() throws Exception {
        CertBundle root = createRootCa();
        byte[] rfc822Subtree =
                generalSubtreeNc(
                        DerCodec.encodeTlv(
                                0x81, "user@example.com".getBytes(StandardCharsets.US_ASCII)),
                        null,
                        null);
        byte[] dnsSubtree =
                generalSubtreeNc(
                        DerCodec.encodeTlv(0x82, "example.com".getBytes(StandardCharsets.US_ASCII)),
                        null,
                        null);
        byte[] gs = generalSubtreesNc(rfc822Subtree, dnsSubtree);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        byte[] nc = buildNameConstraintsExtension(ps, null, true);
        CertBundle ca = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Self-issued CA не проверяется накопленными ограничениями (RFC 5280 §6.1.4(k)).
     * intermediate (pathLen=0, NC permitted=example.com) — под ним self-issued CA.
     * Self-issued не проверяется, leaf проверяется — leaf должен матчить.
     */
    @Test
    @DisplayName("NameConstraints: self-issued CA не проверяется ограничениями")
    void testNameConstraintsSelfIssuedNotChecked() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle caSelf = createSelfIssuedIntermediateCa(intermediate);
        CertBundle leaf = createLeafWithSan(caSelf, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, caSelf.cert, intermediate.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Два уровня: subCA NC=example.com, leaf удовлетворяет обоим — OK.
     */
    @Test
    @DisplayName("NameConstraints: два уровня, leaf матчит оба — OK")
    void testNameConstraintsMultipleLevels() throws Exception {
        CertBundle root = createRootCa();
        CertBundle subCa =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(subCa, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, subCa.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Root с NC permitted=example.com, leaf host.example.com — OK.
     */
    @Test
    @DisplayName("NameConstraints: trust anchor с NC — ограничения применяются")
    void testNameConstraintsOnTrustAnchor() throws Exception {
        CertBundle root = createRootCaWithNameConstraints(buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(root, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Root с NC permitted=example.com, leaf evil.com — reject.
     */
    @Test
    @DisplayName("NameConstraints: trust anchor с NC — SAN вне namespace -> reject")
    void testNameConstraintsOnTrustAnchorFail() throws Exception {
        CertBundle root = createRootCaWithNameConstraints(buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(root, "evil.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * Цепочка без NameConstraints — регрессия.
     */
    @Test
    @DisplayName("NameConstraints: цепочка без NC — OK (регрессия)")
    void testNameConstraintsNoConstraints() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC permitted=192.168.1.0/28, leaf SAN ip=192.168.1.5 — валидно.
     */
    @Test
    @DisplayName("NameConstraints: permitted iPAddress — адрес в префиксе")
    void testNameConstraintsPermittedIp() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root,
                        buildNcPermittedIp(
                                new byte[] {
                                    (byte) 0xC0,
                                    (byte) 0xA8,
                                    0x01,
                                    0x00,
                                    (byte) 0xFF,
                                    (byte) 0xFF,
                                    (byte) 0xFF,
                                    (byte) 0xF0
                                }));
        CertBundle leaf = createLeafWithSan(ca, null, "192.168.1.5");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    /**
     * CA: NC permitted=example.com, leaf без DNS SAN — vacuously satisfied (RFC 5280).
     */
    @Test
    @DisplayName("NameConstraints: permitted DNS, leaf без DNS SAN — vacuously satisfied")
    void testNameConstraintsPermittedDnsNoSan() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        // Leaf без SAN dNSName — vacuous-true
        CertBundle leaf = createLeafWithSan(ca, null, null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // CertificatePolicies — проверка политик leaf-сертификата
    // ========================================================================

    /**
     * Leaf с POLICY_KC1, required = KC1 -> успех.
     */
    @Test
    @DisplayName("CertificatePolicies: leaf с требуемой политикой -> валидно")
    void testPolicyCheckLeafHasMatchingPolicy() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithPolicy(root, GostOids.POLICY_KC1);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(
                () -> ChainValidator.validateChain(chain, trustedKeys, GostOids.POLICY_KC1));
    }

    /**
     * Leaf с anyPolicy, required = KC1 -> успех (anyPolicy удовлетворяет любой политике).
     */
    @Test
    @DisplayName("CertificatePolicies: leaf с anyPolicy, required=KC1 -> валидно")
    void testPolicyCheckLeafHasAnyPolicy() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithPolicy(root, GostOids.ANY_POLICY);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(
                () -> ChainValidator.validateChain(chain, trustedKeys, GostOids.POLICY_KC1));
    }

    /**
     * Leaf с POLICY_KC2, required = KC1 -> POLICY_VIOLATION.
     */
    @Test
    @DisplayName("CertificatePolicies: leaf с KC2, required=KC1 -> POLICY_VIOLATION")
    void testPolicyCheckLeafPolicyMismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithPolicy(root, GostOids.POLICY_KC2);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        chain, trustedKeys, GostOids.POLICY_KC1));
        assertEquals(
                PkixException.Reason.POLICY_VIOLATION,
                ex.reason(),
                "Ожидалась POLICY_VIOLATION при несовпадении политик");
    }

    /**
     * Leaf без расширения CertificatePolicies, required = KC1 -> POLICY_VIOLATION.
     */
    @Test
    @DisplayName("CertificatePolicies: leaf без расширения, required=KC1 -> POLICY_VIOLATION")
    void testPolicyCheckLeafNoExtension() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        chain, trustedKeys, GostOids.POLICY_KC1));
        assertEquals(
                PkixException.Reason.POLICY_VIOLATION,
                ex.reason(),
                "Ожидалась POLICY_VIOLATION при отсутствии расширения CertificatePolicies");
    }

    /**
     * Несколько required OID, leaf содержит один из них -> успех.
     */
    @Test
    @DisplayName("CertificatePolicies: несколько required, один совпадает -> валидно")
    void testPolicyCheckMultipleRequiredOneMatches() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithPolicy(root, GostOids.POLICY_KC1);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                chain, trustedKeys, GostOids.POLICY_KC1, GostOids.POLICY_KC2));
    }

    /**
     * requiredPolicyOids = null -> без проверки политик, обратная совместимость.
     */
    @Test
    @DisplayName("CertificatePolicies: requiredPolicyOids=null -> без проверки политик")
    void testPolicyCheckNoRequiredPolicies() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeafWithPolicy(root, GostOids.POLICY_KC1);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys, (String[]) null));
    }

    // ========================================================================
    // validateChainWithRevocation — проверка отзыва (CRL/OCSP)
    // ========================================================================

    @Test
    @DisplayName("validateChainWithRevocation: CRL, leaf не отозван -> успех")
    void testRevocationCrlNotRevoked() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] crlDer =
                GostCrlBuilder.create(root.dn).nextUpdate("21000101000000Z").sign(root.priv);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd =
                Arrays.asList(
                        new CertRevocationData(null, crlDer), null); // leaf, root (не проверяется)

        assertDoesNotThrow(
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: OCSP good -> успех")
    void testRevocationOcspGood() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] ocspGood =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(root.dn)
                        .nextUpdate("21000101000000Z")
                        .good()
                        .sign(root.priv);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(ocspGood, null), null);

        assertDoesNotThrow(
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: OCSP+CRL, OCSP приоритет -> успех")
    void testRevocationOcspOverCrl() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] ocspGood =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(root.dn)
                        .nextUpdate("21000101000000Z")
                        .good()
                        .sign(root.priv);
        byte[] crlDer =
                GostCrlBuilder.create(root.dn)
                        .nextUpdate("21000101000000Z")
                        .addRevoked(leaf.cert.getSerialNumber(), "20250101000000Z")
                        .sign(root.priv);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(ocspGood, crlDer), null);

        assertDoesNotThrow(
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: leaf отозван по CRL -> PkixException")
    void testRevocationCrlRevoked() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] crlDer =
                GostCrlBuilder.create(root.dn)
                        .nextUpdate("21000101000000Z")
                        .addRevoked(leaf.cert.getSerialNumber(), "20250101000000Z")
                        .sign(root.priv);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(null, crlDer), null);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: leaf отозван по OCSP -> PkixException")
    void testRevocationOcspRevoked() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] ocspRevoked =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(root.dn)
                        .nextUpdate("21000101000000Z")
                        .revoked("20250101000000Z")
                        .sign(root.priv);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd =
                Arrays.asList(new CertRevocationData(ocspRevoked, null), null);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: цепочка невалидна -> ошибка до проверки отзыва")
    void testRevocationChainInvalidFirst() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] crlDer =
                GostCrlBuilder.create(root.dn).nextUpdate("21000101000000Z").sign(root.priv);

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(wrongKp.getPublic());
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(null, crlDer), null);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
        assertEquals(
                PkixException.Reason.ROOT_NOT_SIGNED,
                ex.reason(),
                "Ошибка валидации цепочки должна возникнуть до проверки отзыва");
    }

    @Test
    @DisplayName("validateChainWithRevocation: null в revocationData -> пропуск, успех")
    void testRevocationNullEntry() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd = Arrays.asList(null, null);

        assertDoesNotThrow(
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: все null -> вырождается в validateChain")
    void testRevocationAllNull() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd =
                new ArrayList<>(Collections.nCopies(chain.size(), (CertRevocationData) null));

        assertDoesNotThrow(
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    @Test
    @DisplayName(
            "validateChainWithRevocation: размер revocationData != chain.size() -> IllegalArgumentException")
    void testRevocationSizeMismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());
        List<CertRevocationData> rd = List.of(); // пустой список при chain.size()=2

        assertThrows(
                IllegalArgumentException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, trustedKeys, rd));
    }

    // ========================================================================
    // NameConstraints: rfc822Name, URI, otherName enforcement
    // ========================================================================

    @Test
    @DisplayName("NameConstraints: permitted rfc822Name — leaf входит")
    void testNcPermittedRfc822Match() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle leaf = createLeafWithRfc822(ca, "user@example.com");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: permitted rfc822Name — leaf вне permitted -> REJECT")
    void testNcPermittedRfc822Mismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle leaf = createLeafWithRfc822(ca, "user@evil.com");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: otherName + leaf имеет otherName -> REJECT (fail-closed)")
    void testNcOtherNameLeafHasOtherName() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca = createIntermediateCaWithNameConstraints(root, buildNcWithOtherName());
        CertBundle leaf = createLeafWithUpn(ca, "user@domain.ru");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: otherName + leaf без otherName — WARNING (безопасно)")
    void testNcOtherNameLeafNoOtherName() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca = createIntermediateCaWithNameConstraints(root, buildNcWithOtherName());
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: многоуровневое накопление rfc822Name (дедушка->внук->leaf)")
    void testNcRfc822MultiLevelAccumulation() throws Exception {
        CertBundle root = createRootCaWithNameConstraints(buildNcPermittedRfc822("example.com"));
        CertBundle subCa = createIntermediateCa(root, null);
        CertBundle leaf = createLeafWithRfc822(subCa, "user@example.com");

        List<GostCertificate> chain = List.of(leaf.cert, subCa.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName(
            "NameConstraints: excluded rfc822Name mailbox-form + leaf с этим адресом -> REJECT")
    void testNcRfc822MailboxFormExcluded() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithMailboxExcluded("admin@example.com"));
        CertBundle leaf = createLeafWithRfc822(ca, "admin@example.com");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName(
            "NameConstraints: rfc822Name mailbox-form + leaf без rfc822Name -> WARNING (безопасно)")
    void testNcRfc822MailboxFormNoLeafMatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithMailboxExcluded("admin@example.com"));
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: URI с ведущей точкой — матчит поддомен, не матчит голый хост")
    void testNcUriDotPrefixMatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri(".example.com"));
        CertBundle leafMatch = createLeafWithUri(ca, "https://host.example.com/path");
        CertBundle leafExact = createLeafWithUri(ca, "https://example.com/path");

        List<GostCertificate> chainMatch = List.of(leafMatch.cert, ca.cert, root.cert);
        List<GostCertificate> chainExact = List.of(leafExact.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chainMatch, trustedKeys));
        assertThrows(
                PkixException.class, () -> ChainValidator.validateChain(chainExact, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: URI без точки — точное совпадение хоста")
    void testNcUriExactMatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri("example.com"));
        CertBundle leafMatch = createLeafWithUri(ca, "https://example.com/path");
        CertBundle leafSub = createLeafWithUri(ca, "https://host.example.com/path");

        List<GostCertificate> chainMatch = List.of(leafMatch.cert, ca.cert, root.cert);
        List<GostCertificate> chainSub = List.of(leafSub.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertDoesNotThrow(() -> ChainValidator.validateChain(chainMatch, trustedKeys));
        assertThrows(
                PkixException.class, () -> ChainValidator.validateChain(chainSub, trustedKeys));
    }

    @Test
    @DisplayName("NameConstraints: URI с IP-хостом под активным ограничением -> REJECT")
    void testNcUriIpHostReject() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri("example.com"));
        CertBundle leaf = createLeafWithUri(ca, "https://1.2.3.4/path");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        List<PublicKeyParameters> trustedKeys = List.of(root.cert.getPublicKey());

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, trustedKeys));
    }

    // ========================================================================
    // Name Constraints helpers
    // ========================================================================

    private static final byte[] NC_OID_BYTES = {0x55, 0x1D, 0x1E};

    /** Сборка одного Extension: SEQUENCE { OID [BOOLEAN] OCTET STRING { value } }. */
    private static byte[] buildNcExtension(byte[] oidBytes, boolean critical, byte[] extValue) {
        byte[] oidDer = DerCodec.encodeTlv(0x06, oidBytes);
        byte[] extInner;
        if (critical) {
            extInner =
                    DerCodec.encodeSequence(
                            oidDer,
                            new byte[] {0x01, 0x01, (byte) 0xFF},
                            DerCodec.encodeOctetString(extValue));
        } else {
            extInner = DerCodec.encodeSequence(oidDer, DerCodec.encodeOctetString(extValue));
        }
        return extInner;
    }

    /** Сборка NameConstraints SEQUENCE. */
    private static byte[] buildNameConstraintsExtension(
            byte[] permitted, byte[] excluded, boolean critical) {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        try {
            if (permitted != null) bos.write(permitted);
            if (excluded != null) bos.write(excluded);
        } catch (java.io.IOException impossible) {
            throw new RuntimeException(impossible);
        }
        byte[] ncSeq = DerCodec.encodeSequence(bos.toByteArray());
        return buildNcExtension(NC_OID_BYTES, critical, ncSeq);
    }

    /** Сборка NameConstraints: только permitted dNSName. */
    private static byte[] buildNcPermittedDns(String dnsName) {
        return buildNcPermittedDns(dnsName, true);
    }

    /** Сборка NameConstraints: только permitted dNSName с указанным critical. */
    private static byte[] buildNcPermittedDns(String dnsName, boolean critical) {
        byte[] dns = DerCodec.encodeTlv(0x82, dnsName.getBytes(StandardCharsets.US_ASCII));
        byte[] st = generalSubtreeNc(dns, null, null);
        byte[] gs = generalSubtreesNc(st);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        return buildNameConstraintsExtension(ps, null, critical);
    }

    /** Сборка NameConstraints: только excluded dNSName. */
    private static byte[] buildNcExcludedDns(String dnsName) {
        byte[] dns = DerCodec.encodeTlv(0x82, dnsName.getBytes(StandardCharsets.US_ASCII));
        byte[] st = generalSubtreeNc(dns, null, null);
        byte[] gs = generalSubtreesNc(st);
        byte[] es = DerCodec.encodeContextConstructed(1, gs);
        return buildNameConstraintsExtension(null, es, true);
    }

    /** Сборка NameConstraints: только permitted iPAddress. */
    private static byte[] buildNcPermittedIp(byte[] ipConstraint) {
        byte[] ip = DerCodec.encodeTlv(0x87, ipConstraint);
        byte[] st = generalSubtreeNc(ip, null, null);
        byte[] gs = generalSubtreesNc(st);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        return buildNameConstraintsExtension(ps, null, true);
    }

    /** Сборка NameConstraints: только permitted rfc822Name. */
    private static byte[] buildNcPermittedRfc822(String... names) {
        byte[][] subs = new byte[names.length][];
        for (int i = 0; i < names.length; i++) {
            byte[] base = DerCodec.encodeTlv(0x81, names[i].getBytes(StandardCharsets.US_ASCII));
            subs[i] = generalSubtreeNc(base, null, null);
        }
        byte[] gs = generalSubtreesNc(subs);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        return buildNameConstraintsExtension(ps, null, true);
    }

    /** Сборка NameConstraints: только permitted URI. */
    private static byte[] buildNcPermittedUri(String... uris) {
        byte[][] subs = new byte[uris.length][];
        for (int i = 0; i < uris.length; i++) {
            byte[] base = DerCodec.encodeTlv(0x86, uris[i].getBytes(StandardCharsets.US_ASCII));
            subs[i] = generalSubtreeNc(base, null, null);
        }
        byte[] gs = generalSubtreesNc(subs);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        return buildNameConstraintsExtension(ps, null, true);
    }

    /**
     * Сборка NameConstraints с otherName-записью (тег 0xA0) —
     * парсер не распознаёт otherName и ставит hasUnsupportedNameType=true.
     */
    private static byte[] buildNcWithOtherName() {
        byte[] otherBase = DerCodec.encodeTlv(0xA0, new byte[] {0x06, 0x00});
        byte[] sub = generalSubtreeNc(otherBase, null, null);
        byte[] gs = generalSubtreesNc(sub);
        byte[] ps = DerCodec.encodeContextConstructed(0, gs);
        return buildNameConstraintsExtension(ps, null, true);
    }

    /**
     * Сборка NameConstraints с rfc822Name исключением в mailbox-форме
     * (содержит '@') — парсер должен взвести hasUnsupportedRfc822Form.
     */
    private static byte[] buildNcWithMailboxExcluded(String email) {
        byte[] base = DerCodec.encodeTlv(0x81, email.getBytes(StandardCharsets.US_ASCII));
        byte[] sub = generalSubtreeNc(base, null, null);
        byte[] gs = generalSubtreesNc(sub);
        byte[] es = DerCodec.encodeContextConstructed(1, gs);
        return buildNameConstraintsExtension(null, es, true);
    }

    /**
     * Создаёт leaf с rfc822Name в SAN.
     */
    private static CertBundle createLeafWithRfc822(CertBundle issuer, String... emails)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf RFC822");
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
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .sanRfc822Name(emails)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /**
     * Создаёт leaf с URI в SAN.
     */
    private static CertBundle createLeafWithUri(CertBundle issuer, String... uris)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf URI");
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
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .sanUri(uris)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /**
     * Создаёт leaf с otherName (UPN) в SAN.
     */
    private static CertBundle createLeafWithUpn(CertBundle issuer, String upn) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf UPN");
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
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE)
                        .sanUpn(upn)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /** GeneralSubtree SEQUENCE. */
    private static byte[] generalSubtreeNc(byte[] base, Integer min, Integer max) {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        try {
            bos.write(base);
            if (min != null) {
                bos.write(
                        DerCodec.encodeContextConstructed(
                                0, DerCodec.encodeInteger(BigInteger.valueOf(min))));
            }
            if (max != null) {
                bos.write(
                        DerCodec.encodeContextConstructed(
                                1, DerCodec.encodeInteger(BigInteger.valueOf(max))));
            }
        } catch (java.io.IOException impossible) {
            throw new RuntimeException(impossible);
        }
        return DerCodec.encodeSequence(bos.toByteArray());
    }

    /** GeneralSubtrees SEQUENCE. */
    private static byte[] generalSubtreesNc(byte[]... subtrees) {
        return DerCodec.encodeSequence(subtrees);
    }

    /** [0] permittedSubtrees. */
    private static byte[] permittedSubtrees(byte[] generalSubtreesDer) {
        return DerCodec.encodeContextConstructed(0, generalSubtreesDer);
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static CertBundle createRootCa() throws Exception {
        return createRootCa(null);
    }

    /**
     * Создаёт intermediate CA с расширением NameConstraints.
     */
    private static CertBundle createIntermediateCaWithNameConstraints(
            CertBundle issuer, byte[] ncExtension) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=NC Intermediate CA");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(bc, ku, ski, aki, ncExtension);
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /**
     * Создаёт root CA с расширением NameConstraints.
     */
    private static CertBundle createRootCaWithNameConstraints(byte[] ncExtension) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Root CA NC");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] additional = concatExtensions(bc, ku, ski, ncExtension);
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())),
                dn);
    }

    /**
     * Создаёт leaf-сертификат с указанным SAN dNSName и/или iPAddress.
     */
    private static CertBundle createLeafWithSan(CertBundle issuer, String dnsName, String ipAddress)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf NC");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.ONE);
        if (dnsName != null) {
            builder.sanDns(dnsName);
        }
        if (ipAddress != null) {
            builder.sanIp(ipAddress);
        }
        byte[] tbs = builder.buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())),
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
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
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
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
     * перестают совпадать -> isAlgConsistent() == false.
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

    private static CertBundle createLeafWithPolicy(CertBundle issuer, String... policyOids)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf Policy");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] cp = GostCertificateBuilder.buildCertificatePoliciesExtension(policyOids);
        byte[] additional = concatExtensions(ku, ski, aki, cp);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("gost.example.com")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .serial(BigInteger.valueOf(42))
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
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
