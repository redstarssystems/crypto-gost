package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    @Test
    @DisplayName("Пустая цепочка -> PkixException")
    void testEmptyChain() throws Exception {
        CertBundle root = createRootCa();
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(), TrustAnchors.ofCertificate(root.cert)));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    // ========================================================================
    // Root not signed by any trusted CA
    // ========================================================================

    @Test
    @DisplayName("root не подписан ни одним trusted CA — ROOT_NOT_SIGNED")
    void testRootNotSigned() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        CertBundle wrongRoot = createRootCa();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(wrongRoot.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    /**
     * CA: NC permitted=example.com, leaf SAN=[host.example.com, bank.ru].
     * Второе имя вне permitted — цепочка должна быть отклонена (RFC 5280 §4.2.1.10).
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — любой SAN вне namespace -> REJECT")
    void testNameConstraintsPermittedDnsRejectsAnySanOutside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf =
                createLeafWithSans(
                        ca, new String[] {"host.example.com", "bank.ru"}, null, null, null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    /**
     * Все DNS-имена SAN входят в permitted — цепочка валидна.
     */
    @Test
    @DisplayName("NameConstraints: permitted dNSName — все SAN внутри namespace -> OK")
    void testNameConstraintsPermittedDnsAllSansInside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf =
                createLeafWithSans(
                        ca, new String[] {"host.example.com", "api.example.com"}, null, null, null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    /**
     * Default locale не должен влиять на нормализацию имён: под tr-TR
     * toLowerCase("I") даёт "ı", из-за чего excluded-ограничение могло не сработать.
     */
    @Test
    @DisplayName("NameConstraints: excluded dNSName срабатывает под tr-TR")
    void testNameConstraintsExcludedDnsIsLocaleIndependent() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("istanbul.example"));
        CertBundle leaf = createLeafWithSan(ca, "ISTANBUL.EXAMPLE", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
        } finally {
            Locale.setDefault(previous);
        }
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName — wildcard-SAN не обходит запрет")
    void testNameConstraintsExcludedDnsRejectsWildcardCoveringExcludedName() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("pay.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName — регистр wildcard-SAN не обходит запрет")
    void testNameConstraintsExcludedDnsWildcardCaseInsensitive() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("pay.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.EXAMPLE.COM", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName — wildcard вне зоны запрета разрешён")
    void testNameConstraintsExcludedDnsAllowsWildcardOutsideExcludedSubtree() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("a.pay.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName — wildcard внутри namespace разрешён")
    void testNameConstraintsPermittedDnsWildcardInside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName — wildcard вне namespace отклоняется")
    void testNameConstraintsPermittedDnsWildcardOutside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedDns("foo.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: wildcard в самом NC отклоняется")
    void testNameConstraintsWildcardInConstraintRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("*.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName с ведущей точкой — поддомен запрещён")
    void testNameConstraintsExcludedDnsLeadingDotRejectsSubdomain() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "pay.example.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName с ведущей точкой — apex разрешён")
    void testNameConstraintsExcludedDnsLeadingDotAllowsApex() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName с ведущей точкой — apex отклоняется")
    void testNameConstraintsPermittedDnsLeadingDotRejectsApex() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "example.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName с ведущей точкой — поддомен разрешён")
    void testNameConstraintsPermittedDnsLeadingDotAllowsSubdomain() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "pay.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName с ведущей точкой — wildcard внутри разрешён")
    void testNameConstraintsPermittedDnsWildcardInsideLeadingDot() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: permitted dNSName с ведущей точкой — wildcard вне отклоняется")
    void testNameConstraintsPermittedDnsWildcardOutsideLeadingDot() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedDns(".pay.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: excluded dNSName с завершающей точкой нормализуется")
    void testNameConstraintsExcludedDnsTrailingDot() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns("pay.example.com."));
        CertBundle leaf = createLeafWithSan(ca, "pay.example.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: excluded .example.com — wildcard поддомена не обходит")
    void testNameConstraintsExcludedDnsWildcardUnderLeadingDotAncestor() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedDns(".example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.pay.example.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: excluded .pay.example.com не пересекается с *.example.com")
    void testNameConstraintsExcludedDnsLeadingDotNoOverlap() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedDns(".pay.example.com"));
        CertBundle leaf = createLeafWithSan(ca, "*.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: self-issued leaf с SAN вне permitted -> отказ")
    void testNameConstraintsSelfIssuedLeafPermittedRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf = createSelfIssuedLeaf(intermediate, "evil.com");

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: self-issued leaf с SAN в excluded -> отказ")
    void testNameConstraintsSelfIssuedLeafExcludedRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedDns("evil.com"));
        CertBundle leaf = createSelfIssuedLeaf(intermediate, "evil.com");

        List<GostCertificate> chain = List.of(leaf.cert, intermediate.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    /**
     * CA: NC permitted=192.168.1.0/28, leaf SAN=[192.168.1.5, 8.8.8.8].
     * Второй iPAddress вне permitted — цепочка должна быть отклонена.
     */
    @Test
    @DisplayName("NameConstraints: permitted iPAddress — любой SAN вне префикса -> REJECT")
    void testNameConstraintsPermittedIpRejectsAnySanOutside() throws Exception {
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
        CertBundle leaf =
                createLeafWithSans(ca, null, new String[] {"192.168.1.5", "8.8.8.8"}, null, null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    /**
     * Все iPAddress SAN входят в permitted-префикс — цепочка валидна.
     */
    @Test
    @DisplayName("NameConstraints: permitted iPAddress — все SAN внутри префикса -> OK")
    void testNameConstraintsPermittedIpAllSansInside() throws Exception {
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
        CertBundle leaf =
                createLeafWithSans(
                        ca, null, new String[] {"192.168.1.5", "192.168.1.6"}, null, null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChain(chain, anchors, GostOids.POLICY_KC1));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                chain, anchors, GostOids.POLICY_KC1, GostOids.POLICY_KC2));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors, (String[]) null));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd =
                Arrays.asList(
                        new CertRevocationData(null, crlDer), null); // leaf, root (не проверяется)

        assertDoesNotThrow(() -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
    }

    @Test
    @DisplayName(
            "validateChainWithRevocation: partial CRL не покрывает leaf -> фатальный IDP_NOT_SUPPORTED")
    void testRevocationPartialCrlNotCoveringLeafIsFatal() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        // onlyContainsCACerts: CRL подписан УЦ, но листовой сертификат не покрывает
        byte[] idp =
                RawCrlTestSupport.extension(
                        RawCrlTestSupport.OID_IDP,
                        true,
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(0x82, new byte[] {(byte) 0xFF})));
        byte[] crlDer =
                RawCrlTestSupport.crl(
                        root.priv,
                        ECParameters.tc26a256(),
                        root.dn,
                        RawCrlTestSupport.crlExtensions(idp));

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(null, crlDer), null);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChainWithRevocation(chain, anchors, rd),
                        "Один CRL на сертификат: не покрывающий CRL не доказывает «не отозван»");
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, e.reason());
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(ocspGood, null), null);

        assertDoesNotThrow(() -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(ocspGood, crlDer), null);

        assertDoesNotThrow(() -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(null, crlDer), null);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd =
                Arrays.asList(new CertRevocationData(ocspRevoked, null), null);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: цепочка невалидна -> ошибка до проверки отзыва")
    void testRevocationChainInvalidFirst() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        byte[] crlDer =
                GostCrlBuilder.create(root.dn).nextUpdate("21000101000000Z").sign(root.priv);

        CertBundle wrongRoot = createRootCa();
        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(wrongRoot.cert);
        List<CertRevocationData> rd = Arrays.asList(new CertRevocationData(null, crlDer), null);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = Arrays.asList(null, null);

        assertDoesNotThrow(() -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
    }

    @Test
    @DisplayName("validateChainWithRevocation: все null -> вырождается в validateChain")
    void testRevocationAllNull() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd =
                new ArrayList<>(Collections.nCopies(chain.size(), (CertRevocationData) null));

        assertDoesNotThrow(() -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
    }

    @Test
    @DisplayName(
            "validateChainWithRevocation: размер revocationData != chain.size() -> IllegalArgumentException")
    void testRevocationSizeMismatch() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> rd = List.of(); // пустой список при chain.size()=2

        assertThrows(
                IllegalArgumentException.class,
                () -> ChainValidator.validateChainWithRevocation(chain, anchors, rd));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: permitted rfc822Name — любой адрес вне permitted -> REJECT")
    void testNcPermittedRfc822RejectsAnyNameOutside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle leaf = createLeafWithRfc822(ca, "user@example.com", "user@bank.ru");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: excluded rfc822Name — wildcard-домен не обходит запрет")
    void testNcExcludedRfc822RejectsWildcardCoveringExcludedDomain() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedRfc822("pay.example.com"));
        CertBundle leaf = createLeafWithRfc822(ca, "user@*.example.com");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName(
            "NameConstraints: excluded rfc822 с ведущей точкой — поддомен запрещён, apex разрешён")
    void testNcExcludedRfc822LeadingDot() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExcludedRfc822(".example.com"));
        CertBundle sub = createLeafWithRfc822(ca, "u@pay.example.com");
        CertBundle apex = createLeafWithRfc822(ca, "u@example.com");
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(sub.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(apex.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: permitted rfc822 bare — только сам хост, не поддомены")
    void testNcPermittedRfc822BareHostOnly() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle apex = createLeafWithRfc822(ca, "u@example.com");
        CertBundle sub = createLeafWithRfc822(ca, "u@pay.example.com");
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(apex.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(sub.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: excluded rfc822 bare — поддомен разрешён, apex запрещён")
    void testNcExcludedRfc822BareHostOnly() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedRfc822("example.com"));
        CertBundle sub = createLeafWithRfc822(ca, "u@pay.example.com");
        CertBundle apex = createLeafWithRfc822(ca, "u@example.com");
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(sub.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(apex.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: rfc822 SAN без @ или с пустым доменом отклоняется")
    void testNcRfc822InvalidMailboxFormRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle noAt = createLeafWithRfc822(ca, "user");
        CertBundle emptyDomain = createLeafWithRfc822(ca, "user@");
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(noAt.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(emptyDomain.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: otherName + leaf имеет otherName -> REJECT (fail-closed)")
    void testNcOtherNameLeafHasOtherName() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca = createIntermediateCaWithNameConstraints(root, buildNcWithOtherName());
        CertBundle leaf = createLeafWithUpn(ca, "user@domain.ru");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName(
            "NameConstraints: otherName + leaf без otherName -> принят, запись только на DEBUG")
    void testNcOtherNameLeafNoOtherName() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca = createIntermediateCaWithNameConstraints(root, buildNcWithOtherName());
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));

            // Ограничение на форму, которой в сертификате нет, не применяется: это штатный
            // исход, оператору вмешиваться не нужно
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "неприменимое ограничение не должно давать WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(m -> m.contains("constraints not applicable")),
                    "причина должна быть видна на DEBUG: " + log.messages(Level.FINE));
        }
    }

    @Test
    @DisplayName("Отзыв: данных нет у двух сертификатов -> одна запись WARNING и две DEBUG")
    void testMissingRevocationDataIsWarnedOncePerValidation() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithDn(root, "CN=Int", "20240101000000Z", "21060101000000Z");
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        List<CertRevocationData> noData = Arrays.asList(null, null, null);

        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            assertDoesNotThrow(
                    () -> ChainValidator.validateChainWithRevocation(chain, anchors, noData));

            List<String> warnings = log.messagesAtOrAbove(Level.WARNING);
            assertEquals(
                    1, warnings.size(), "одна запись на проверку, а не на сертификат: " + warnings);
            assertTrue(
                    warnings.get(0).contains("Revocation not checked for 2 of 2"),
                    "число пропущенных и всего: " + warnings.get(0));
            assertTrue(
                    warnings.get(0).contains(leaf.cert.getSerialNumberBigInt().toString(16)),
                    "серийный номер листа: " + warnings.get(0));
            assertEquals(
                    2,
                    log.messages(Level.FINE).stream()
                            .filter(m -> m.contains("No revocation data"))
                            .count(),
                    "по сертификату запись на DEBUG");
        }
    }

    @Test
    @DisplayName("NameConstraints: registeredID + leaf с registeredID в SAN -> отказ")
    void testNcRegisteredIdLeafHasRegisteredId() throws Exception {
        assertNcFormChain(
                buildNcWithForm(TAG_REGISTERED_ID, new byte[] {0x2B, 0x06, 0x01}),
                TAG_REGISTERED_ID,
                new byte[] {0x2B, 0x06, 0x01, 0x04},
                false);
    }

    @Test
    @DisplayName("NameConstraints: x400Address + leaf с x400Address в SAN -> отказ")
    void testNcX400LeafHasX400() throws Exception {
        assertNcFormChain(
                buildNcWithForm(TAG_X400, new byte[] {0x30, 0x00}),
                TAG_X400,
                new byte[] {0x30, 0x00},
                false);
    }

    @Test
    @DisplayName("NameConstraints: ediPartyName + leaf с ediPartyName в SAN -> отказ")
    void testNcEdiLeafHasEdi() throws Exception {
        assertNcFormChain(
                buildNcWithForm(TAG_EDI, new byte[] {0x30, 0x00}),
                TAG_EDI,
                new byte[] {(byte) 0xA1, 0x00},
                false);
    }

    @Test
    @DisplayName(
            "NameConstraints: registeredID + leaf с x400Address в SAN -> принят (формы разные)")
    void testNcRegisteredIdLeafHasX400Accepted() throws Exception {
        assertNcFormChain(
                buildNcWithForm(TAG_REGISTERED_ID, new byte[] {0x2B, 0x06, 0x01}),
                TAG_X400,
                new byte[] {0x30, 0x00},
                true);
    }

    @Test
    @DisplayName("NameConstraints: registeredID + leaf с otherName в SAN -> принят (формы разные)")
    void testNcRegisteredIdLeafHasOtherNameAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithForm(TAG_REGISTERED_ID, new byte[] {0x2B, 0x06, 0x01}));
        CertBundle leaf = createLeafWithUpn(ca, "user@domain.ru");

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "ограничение registeredID не относится к otherName");
    }

    @Test
    @DisplayName("NameConstraints: неподдерживаемая форма + leaf без таких имён -> принят")
    void testNcUnsupportedFormLeafWithoutSuchNamesAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithForm(TAG_REGISTERED_ID, new byte[] {0x2B, 0x06, 0x01}));
        CertBundle leaf = createLeafWithSan(ca, "host.example.com", null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "ограничение неприменимо, если в SAN нет имён этой формы");
    }

    @Test
    @DisplayName("NameConstraints: registeredID в IssuerAltName не влияет на проверку")
    void testNcRegisteredIdInIanIgnored() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithForm(TAG_REGISTERED_ID, new byte[] {0x2B, 0x06, 0x01}));
        byte[] ianValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(TAG_REGISTERED_ID, new byte[] {0x2B, 6, 1}));
        byte[] ianExt = buildNcExtension(new byte[] {0x55, 0x1D, 0x12}, false, ianValue);
        CertBundle leaf = createLeafWithRawExtensions(ca, ianExt);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "NameConstraints применяются к SAN, а не к IAN");
    }

    @Test
    @DisplayName("NameConstraints: многоуровневое накопление rfc822Name (дедушка->внук->leaf)")
    void testNcRfc822MultiLevelAccumulation() throws Exception {
        CertBundle root = createRootCaWithNameConstraints(buildNcPermittedRfc822("example.com"));
        CertBundle subCa = createIntermediateCa(root, null);
        CertBundle leaf = createLeafWithRfc822(subCa, "user@example.com");

        List<GostCertificate> chain = List.of(leaf.cert, subCa.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chainMatch, anchors));
        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chainExact, anchors));
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
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chainMatch, anchors));
        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chainSub, anchors));
    }

    @Test
    @DisplayName("NameConstraints: завершающая точка в URI-хосте не обходит excluded")
    void testNcUriTrailingDotDoesNotEscapeExcluded() throws Exception {
        CertBundle root = createRootCa();
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        for (String constraint : new String[] {".evil.com", "evil.com"}) {
            CertBundle ca =
                    createIntermediateCaWithNameConstraints(root, buildNcExcludedUri(constraint));
            String host = constraint.startsWith(".") ? "a.evil.com." : "evil.com.";
            CertBundle leaf = createLeafWithUri(ca, "https://" + host + "/path");
            List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
            assertThrows(
                    PkixException.class,
                    () -> ChainValidator.validateChain(chain, anchors),
                    "Хост с завершающей точкой должен попадать под запрет " + constraint);
        }
    }

    @Test
    @DisplayName("NameConstraints: завершающая точка в URI-хосте не мешает permitted")
    void testNcUriTrailingDotStillPermitted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri(".example.com"));
        CertBundle leaf = createLeafWithUri(ca, "https://a.example.com./path");
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);

        assertDoesNotThrow(
                () -> ChainValidator.validateChain(chain, TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: регистр хоста и ограничения в URI не имеет значения")
    void testNcUriCaseInsensitive() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri(".Evil.COM"));
        CertBundle leaf = createLeafWithUri(ca, "https://A.EVIL.com/path");
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChain(chain, TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NameConstraints: URI-хост с пустой меткой отвергается, а не сравнивается")
    void testNcUriEmptyLabelHostRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri(".other.org"));
        CertBundle leaf = createLeafWithUri(ca, "https://evil.com../path");
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChain(chain, TrustAnchors.ofCertificate(root.cert)),
                "Две точки подряд - это пустая метка, имя не нормализуется");
    }

    @Test
    @DisplayName("NameConstraints: SAN 10.0.0.1 попадает под excluded ::ffff:10.0.0.0/120")
    void testNcExcludedMappedConstraintCatchesIpv4San() throws Exception {
        CertBundle root = createRootCa();
        byte[] mappedConstraint = new byte[32];
        mappedConstraint[10] = (byte) 0xFF;
        mappedConstraint[11] = (byte) 0xFF;
        mappedConstraint[12] = 10;
        // маска /120: первые 15 байт 0xFF, последний 0x00
        java.util.Arrays.fill(mappedConstraint, 16, 31, (byte) 0xFF);
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedIp(mappedConstraint));
        CertBundle leaf = createLeafWithSan(ca, null, "10.0.0.1");
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChain(chain, TrustAnchors.ofCertificate(root.cert)),
                "IPv4-адрес в mapped-ограничении не должен обходить запрет");
    }

    @Test
    @DisplayName("isIpInExcludedSubtrees: обе формы адреса против ограничений обоих семейств")
    void testExcludedIpBothFormsAgainstBothFamilies() {
        byte[] ipv4 = {10, 0, 0, 1};
        byte[] mapped = new byte[16];
        mapped[10] = (byte) 0xFF;
        mapped[11] = (byte) 0xFF;
        System.arraycopy(ipv4, 0, mapped, 12, 4);
        byte[] outsideMapped = mapped.clone();
        outsideMapped[12] = 11;

        byte[] v4Constraint = {10, 0, 0, 0, (byte) 0xFF, 0, 0, 0};
        byte[] mappedConstraint = new byte[32];
        mappedConstraint[10] = (byte) 0xFF;
        mappedConstraint[11] = (byte) 0xFF;
        mappedConstraint[12] = 10;
        java.util.Arrays.fill(mappedConstraint, 16, 31, (byte) 0xFF);
        // ::/80: покрывает адреса, у которых первые 80 бит нулевые, в том числе mapped
        byte[] wideConstraint = new byte[32];
        java.util.Arrays.fill(wideConstraint, 16, 26, (byte) 0xFF);

        assertTrue(
                ChainValidator.isIpInExcludedSubtrees(mapped, new byte[][] {v4Constraint}),
                "mapped SAN под IPv4-запретом 10.0.0.0/8");
        assertTrue(
                ChainValidator.isIpInExcludedSubtrees(ipv4, new byte[][] {mappedConstraint}),
                "IPv4 SAN под mapped-запретом");
        assertTrue(
                ChainValidator.isIpInExcludedSubtrees(ipv4, new byte[][] {wideConstraint}),
                "IPv4 SAN под запретом ::/80 (маска не доходит до границы IPv4)");
        assertFalse(
                ChainValidator.isIpInExcludedSubtrees(outsideMapped, new byte[][] {v4Constraint}),
                "mapped SAN вне запрета не должен попадать");
        assertFalse(
                ChainValidator.isIpInExcludedSubtrees(new byte[16], new byte[][] {v4Constraint}),
                "не mapped IPv6 не пересчитывается в IPv4");
    }

    @Test
    @DisplayName("isIpInSubtrees (permitted): адрес другой формы не принимается, fail-closed")
    void testPermittedIpDoesNotMixFamilies() {
        byte[] mapped = new byte[16];
        mapped[10] = (byte) 0xFF;
        mapped[11] = (byte) 0xFF;
        mapped[12] = 10;
        byte[] v4Constraint = {10, 0, 0, 0, (byte) 0xFF, 0, 0, 0};

        assertFalse(
                ChainValidator.isIpInSubtrees(mapped, new byte[][] {v4Constraint}),
                "под permitted mapped SAN не принимается IPv4-ограничением");
    }

    @Test
    @DisplayName("NameConstraints: URI с IP-хостом под активным ограничением -> REJECT")
    void testNcUriIpHostReject() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri("example.com"));
        CertBundle leaf = createLeafWithUri(ca, "https://1.2.3.4/path");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName(
            "NameConstraints: IPv4 с ведущими нулями в URI-хосте отвергается как IP-хост, а не"
                    + " проходит как DNS-имя")
    void testNcUriLeadingZeroIpv4RejectedAsIpHost() throws Exception {
        CertBundle root = createRootCa();
        // Под excluded-ограничением неподходящее DNS-имя прошло бы; IP-хост обязан отвергаться
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri("example.com"));
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        // Строгий IPv4-детектор не считает такие хосты адресом (ведущий ноль), но java.net.URI
        // разбирает их как IPv4: отказ обязан сохраниться через предикат числовых форм.
        for (String host : new String[] {"1.2.3.4", "0177.0.0.1", "09.0.0.1", "00.0.0.0"}) {
            CertBundle leaf = createLeafWithUri(ca, "https://" + host + "/path");
            List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () -> ChainValidator.validateChain(chain, anchors),
                            "IPv4-хост " + host + " обязан отвергаться");
            assertTrue(
                    ex.getMessage().contains("IP address as host"),
                    "отказ именно как IP-хост, а не по другой причине: " + ex.getMessage());
        }
    }

    @Test
    @DisplayName("NameConstraints: числовые формы IPv4, которые URI не считает хостом, отвергаются")
    void testNcUriNumericIpv4FormsReject() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri("example.com"));
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        for (String host : new String[] {"2130706433", "127.1", "0x7f000001"}) {
            CertBundle leaf = createLeafWithUri(ca, "https://" + host + "/path");
            List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
            assertThrows(
                    PkixException.class,
                    () -> ChainValidator.validateChain(chain, anchors),
                    "числовая форма IPv4 " + host + " обязана отвергаться");
        }
    }

    @Test
    @DisplayName("NameConstraints: permitted URI — любой URI вне permitted -> REJECT")
    void testNcPermittedUriRejectsAnyNameOutside() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedUri("example.com"));
        CertBundle leaf = createLeafWithUri(ca, "https://example.com/ok", "https://bank.ru/bad");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("NameConstraints: URI wildcard-SAN под URI-NC — fail-closed")
    void testNcUriWildcardSanFailClosed() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri("example.com"));
        CertBundle leaf = createLeafWithUri(ca, "https://*.example.com/path");

        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertThrows(PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName(
            "NameConstraints: excluded URI с ведущей точкой — поддомен запрещён, apex разрешён")
    void testNcExcludedUriLeadingDot() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcExcludedUri(".example.com"));
        CertBundle sub = createLeafWithUri(ca, "https://pay.example.com/");
        CertBundle apex = createLeafWithUri(ca, "https://example.com/");
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(sub.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(apex.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    // ========================================================================
    // Якорь доверия и обход basicConstraints
    // ========================================================================

    @Test
    @DisplayName("basicConstraints: не-CA верхний сертификат, подписанный якорем, -> NOT_CA")
    void testNonCaTopCertificateSignedByAnchorRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle attackerEe = createLeaf(root);
        CertBundle forgedLeaf = createLeafWithSan(attackerEe, "bank.example.com", null);

        List<GostCertificate> chain = List.of(forgedLeaf.cert, attackerEe.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
        assertEquals(PkixException.Reason.NOT_CA, ex.reason());
    }

    @Test
    @DisplayName("basicConstraints: верхний CA без keyCertSign -> MISSING_KEY_CERT_SIGN")
    void testTopCaWithoutKeyCertSignRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle caWithoutKeyCertSign = createCaWithoutKeyCertSign(root);
        CertBundle leaf = createLeaf(caWithoutKeyCertSign);

        List<GostCertificate> chain = List.of(leaf.cert, caWithoutKeyCertSign.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
        assertEquals(PkixException.Reason.MISSING_KEY_CERT_SIGN, ex.reason());
    }

    @Test
    @DisplayName("Якорь: одиночный leaf, выпущенный якорем, -> успех")
    void testSingleLeafIssuedByAnchorAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle leaf = createLeaf(root);

        List<GostCertificate> chain = List.of(leaf.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("Якорь: self-signed якорь как единственный сертификат -> успех")
    void testSingleSelfSignedAnchorAccepted() throws Exception {
        CertBundle root = createRootCa();

        List<GostCertificate> chain = List.of(root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName(
            "Якорь: поддельный якорь с ключом доверенного CA и чужой подписью -> ROOT_NOT_SIGNED")
    void testFakeAnchorWithTrustedKeyAndForeignSignatureRejected() throws Exception {
        CertBundle root = createRootCa();
        var attackerKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] attackerDn = GostDnParser.encodeDn("CN=Attacker");
        GostCertificate fakeAnchor =
                createFakeAnchorWithTrustedKey(root.pub, attackerKp.getPrivate(), attackerDn);

        List<GostCertificate> chain = List.of(fakeAnchor);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class, () -> ChainValidator.validateChain(chain, anchors));
        assertEquals(PkixException.Reason.ROOT_NOT_SIGNED, ex.reason());
    }

    @Test
    @DisplayName("Якорь: закреплённый промежуточный CA, подписанный внешним корнем, -> успех")
    void testPinnedIntermediateAnchorAccepted() throws Exception {
        CertBundle externalRoot = createRootCa();
        CertBundle pinnedIntermediate = createIntermediateCa(externalRoot, null);
        CertBundle leaf = createLeaf(pinnedIntermediate);

        List<GostCertificate> chain = List.of(leaf.cert, pinnedIntermediate.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(pinnedIntermediate.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("Якорь: сертификаты выше закреплённого якоря игнорируются -> успех")
    void testChainAbovePinnedAnchorIgnored() throws Exception {
        CertBundle root = createRootCa();
        CertBundle pinnedIntermediate = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(pinnedIntermediate);

        List<GostCertificate> chain = List.of(leaf.cert, pinnedIntermediate.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(pinnedIntermediate.cert);

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, anchors));
    }

    @Test
    @DisplayName("Cert-якорь: NameConstraints корня проверяются при опущенном корне")
    void testCertAnchorRootNameConstraintsEnforcedWithOmittedRoot() throws Exception {
        CertBundle root = createRootCaWithNameConstraints(buildNcPermittedDns("example.com"));
        CertBundle intermediate = createIntermediateCa(root, null);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        CertBundle evilLeaf = createLeafWithSan(intermediate, "evil.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(evilLeaf.cert, intermediate.cert), anchors));

        CertBundle goodLeaf = createLeafWithSan(intermediate, "host.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(goodLeaf.cert, intermediate.cert), anchors));
    }

    @Test
    @DisplayName("Cert-якорь: pathLen корня проверяется при опущенном корне")
    void testCertAnchorRootPathLenEnforcedWithOmittedRoot() throws Exception {
        CertBundle root0 = createRootCa(0);
        CertBundle intermediate0 = createIntermediateCa(root0, null);
        CertBundle leaf0 = createLeaf(intermediate0);
        TrustAnchors anchors0 = TrustAnchors.ofCertificates(List.of(root0.cert));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        List.of(leaf0.cert, intermediate0.cert), anchors0));
        assertEquals(PkixException.Reason.PATH_LEN_EXCEEDED, ex.reason());

        CertBundle root1 = createRootCa(1);
        CertBundle intermediate1 = createIntermediateCa(root1, null);
        CertBundle leaf1 = createLeaf(intermediate1);
        TrustAnchors anchors1 = TrustAnchors.ofCertificates(List.of(root1.cert));
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf1.cert, intermediate1.cert), anchors1));
    }

    @Test
    @DisplayName(
            "Cert-якорь: перевыпущенный корень с тем же ключом принимается через локальный якорь")
    void testCertAnchorAcceptsReissuedRootWithSameKey() throws Exception {
        CertBundle oldRoot = createRootCaWithNameConstraints(buildNcPermittedDns("example.com"));
        CertBundle intermediate = createIntermediateCa(oldRoot, null);
        CertBundle newRoot =
                createReissuedRoot(
                        oldRoot, BigInteger.valueOf(2), "20250101120000Z", "21150101120000Z");
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(oldRoot.cert));

        CertBundle goodLeaf = createLeafWithSan(intermediate, "host.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(goodLeaf.cert, intermediate.cert, newRoot.cert), anchors));

        CertBundle evilLeaf = createLeafWithSan(intermediate, "evil.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(evilLeaf.cert, intermediate.cert, newRoot.cert), anchors));
    }

    @Test
    @DisplayName("Cert-якорь: поддельный корень выше якоря игнорируется")
    void testCertAnchorIgnoresFakeRootAboveAnchorIssuedIntermediate() throws Exception {
        var attackerKp = KeyGenerator.generateKeyPair(PARAMS);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(intermediate);
        GostCertificate fakeRoot =
                createFakeAnchorWithTrustedKey(
                        root.pub, attackerKp.getPrivate(), GostDnParser.encodeDn("CN=Attacker"));
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, fakeRoot), anchors));

        CertBundle ncRoot = createRootCaWithNameConstraints(buildNcPermittedDns("example.com"));
        CertBundle ncIntermediate = createIntermediateCa(ncRoot, null);
        CertBundle evilLeaf = createLeafWithSan(ncIntermediate, "evil.com", null);
        GostCertificate ncFakeRoot =
                createFakeAnchorWithTrustedKey(
                        ncRoot.pub, attackerKp.getPrivate(), GostDnParser.encodeDn("CN=Attacker"));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(evilLeaf.cert, ncIntermediate.cert, ncFakeRoot),
                                TrustAnchors.ofCertificates(List.of(ncRoot.cert))));
    }

    @Test
    @DisplayName("Cert-якорь: чужая цепочка с тем же DN корня -> ROOT_NOT_SIGNED")
    void testCertAnchorRejectsUnrelatedChain() throws Exception {
        CertBundle rootA = createRootCa();
        CertBundle rootB = createRootCa();
        CertBundle intermediateB = createIntermediateCa(rootB, null);
        CertBundle leafB = createLeaf(intermediateB);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(rootA.cert));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        List.of(leafB.cert, intermediateB.cert), anchors));
        assertEquals(PkixException.Reason.ROOT_NOT_SIGNED, ex.reason());
    }

    @Test
    @DisplayName("Cert-якорь: поддельный leaf с ключом якоря и чужой подписью -> ROOT_NOT_SIGNED")
    void testCertAnchorRejectsFakeLeafWithTrustedKey() throws Exception {
        var attackerKp = KeyGenerator.generateKeyPair(PARAMS);
        CertBundle root = createRootCa();
        GostCertificate fakeLeaf =
                createFakeAnchorWithTrustedKey(root.pub, attackerKp.getPrivate(), root.dn);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChain(List.of(fakeLeaf), anchors));
        assertEquals(PkixException.Reason.ROOT_NOT_SIGNED, ex.reason());
    }

    @Test
    @DisplayName("Cert-якорь: закреплённый промежуточный CA обрезает цепочку выше")
    void testCertAnchorPinnedIntermediateTruncatesChainAbove() throws Exception {
        CertBundle root = createRootCa();
        CertBundle pinnedIntermediate = createIntermediateCa(root, null);
        CertBundle leaf = createLeaf(pinnedIntermediate);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(pinnedIntermediate.cert));

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, pinnedIntermediate.cert, root.cert), anchors));

        CertBundle ncRoot = createRootCa();
        CertBundle ncIntermediate =
                createIntermediateCaWithNameConstraints(ncRoot, buildNcPermittedDns("example.com"));
        TrustAnchors ncAnchors = TrustAnchors.ofCertificates(List.of(ncIntermediate.cert));
        CertBundle goodLeaf = createLeafWithSan(ncIntermediate, "host.example.com", null);
        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(goodLeaf.cert, ncIntermediate.cert, ncRoot.cert),
                                ncAnchors));
        CertBundle evilLeaf = createLeafWithSan(ncIntermediate, "evil.com", null);
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(evilLeaf.cert, ncIntermediate.cert, ncRoot.cert),
                                ncAnchors));
    }

    @Test
    @DisplayName("Cert-якорь: истёкший корень при n > 1 принимается с WARNING")
    void testCertAnchorExpiredRootWithIntermediateAccepted() throws Exception {
        CertBundle expiredRoot = createRootCaWithValidity("20200101120000Z", "20210101120000Z");
        CertBundle intermediate = createIntermediateCa(expiredRoot, null);
        CertBundle leaf = createLeaf(intermediate);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(expiredRoot.cert));

        assertDoesNotThrow(
                () -> ChainValidator.validateChain(List.of(leaf.cert, intermediate.cert), anchors));
    }

    @Test
    @DisplayName("Cert-якорь: явный WARN принимает истёкший корень при n > 1, как DEFAULT")
    void testCertAnchorExpiredRootExplicitWarnAccepted() throws Exception {
        CertBundle expiredRoot = createRootCaWithValidity("20200101120000Z", "20210101120000Z");
        CertBundle intermediate = createIntermediateCa(expiredRoot, null);
        CertBundle leaf = createLeaf(intermediate);
        TrustAnchors anchors =
                TrustAnchors.ofCertificates(List.of(expiredRoot.cert))
                        .withExpiryPolicy(AnchorExpiryPolicy.WARN);

        assertDoesNotThrow(
                () -> ChainValidator.validateChain(List.of(leaf.cert, intermediate.cert), anchors),
                "WARN должен пропускать истёкший корень при n > 1");
    }

    @Test
    @DisplayName("Cert-якорь: явный REJECT отклоняет истёкший корень при n > 1")
    void testCertAnchorExpiredRootRejectPolicyRejected() throws Exception {
        CertBundle expiredRoot = createRootCaWithValidity("20200101120000Z", "20210101120000Z");
        CertBundle intermediate = createIntermediateCa(expiredRoot, null);
        CertBundle leaf = createLeaf(intermediate);
        TrustAnchors anchors =
                TrustAnchors.ofCertificates(List.of(expiredRoot.cert))
                        .withExpiryPolicy(AnchorExpiryPolicy.REJECT);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        List.of(leaf.cert, intermediate.cert), anchors));
        assertEquals(
                PkixException.Reason.EXPIRED, ex.reason(), "REJECT должен давать причину EXPIRED");
    }

    @Test
    @DisplayName("Cert-якорь: REJECT отклоняет и истёкший закреплённый промежуточный CA")
    void testCertAnchorExpiredPinnedIntermediateRejectPolicyRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle expiredIntermediate =
                createIntermediateCaWithDn(
                        root, "CN=Expired Intermediate", "20200101120000Z", "20210101120000Z");
        CertBundle leaf = createLeaf(expiredIntermediate);
        TrustAnchors anchors =
                TrustAnchors.ofCertificates(List.of(expiredIntermediate.cert))
                        .withExpiryPolicy(AnchorExpiryPolicy.REJECT);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        List.of(leaf.cert, expiredIntermediate.cert), anchors));
        assertEquals(PkixException.Reason.EXPIRED, ex.reason());
    }

    @Test
    @DisplayName("Cert-якорь: закреплённый leaf при n == 1 отклоняется при любой политике")
    void testCertAnchorExpiredPinnedLeafRejectedForEveryPolicy() throws Exception {
        CertBundle expiredRoot = createRootCaWithValidity("20200101120000Z", "20210101120000Z");
        for (AnchorExpiryPolicy policy : AnchorExpiryPolicy.values()) {
            TrustAnchors anchors =
                    TrustAnchors.ofCertificates(List.of(expiredRoot.cert)).withExpiryPolicy(policy);
            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () -> ChainValidator.validateChain(List.of(expiredRoot.cert), anchors),
                            "Закреплённый leaf должен отклоняться при политике " + policy);
            assertEquals(PkixException.Reason.EXPIRED, ex.reason());
        }
    }

    @Test
    @DisplayName("Cert-якорь: истёкший закреплённый leaf при n == 1 отклоняется")
    void testCertAnchorExpiredPinnedLeafRejected() throws Exception {
        CertBundle expiredRoot = createRootCaWithValidity("20200101120000Z", "20210101120000Z");
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(expiredRoot.cert));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> ChainValidator.validateChain(List.of(expiredRoot.cert), anchors));
        assertEquals(PkixException.Reason.EXPIRED, ex.reason());
    }

    @Test
    @DisplayName("Cert-якорь: истёкший закреплённый промежуточный CA принимается")
    void testCertAnchorExpiredPinnedIntermediateAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle expiredIntermediate =
                createIntermediateCaWithDn(
                        root, "CN=Expired Intermediate", "20200101120000Z", "20210101120000Z");
        CertBundle leaf = createLeaf(expiredIntermediate);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(expiredIntermediate.cert));

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, expiredIntermediate.cert), anchors));
    }

    @Test
    @DisplayName("Cert-якорь: лимит длины цепочки считает только сертификаты пира")
    void testCertAnchorPeerChainLimitExcludesAppendedAnchor() throws Exception {
        CertBundle root = createRootCa();
        CertBundle current = root;
        List<CertBundle> intermediates = new ArrayList<>();
        for (int i = 1; i <= 9; i++) {
            current =
                    createIntermediateCaWithDn(
                            current, "CN=Chain CA " + i, "20240501120000Z", "21060101120000Z");
            intermediates.add(current);
        }
        CertBundle leaf = createLeaf(current);

        List<GostCertificate> peerChain = new ArrayList<>();
        peerChain.add(leaf.cert);
        for (int i = intermediates.size() - 1; i >= 0; i--) {
            peerChain.add(intermediates.get(i).cert);
        }
        assertEquals(10, peerChain.size());
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));
        assertDoesNotThrow(() -> ChainValidator.validateChain(peerChain, anchors));

        List<GostCertificate> tooLong = new ArrayList<>(peerChain);
        tooLong.add(root.cert);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> ChainValidator.validateChain(tooLong, anchors));
        assertEquals(PkixException.Reason.CHAIN_TOO_LONG, ex.reason());
    }

    @Test
    @DisplayName(
            "validateChain: 10 peer + локальный якорь допустимы, возвращается эффективная цепочка")
    void testValidateChainReturnsEffectiveChainWithAnchor() throws Exception {
        CertBundle root = createRootCa();
        List<GostCertificate> peerChain = createPeerChain(root, 9);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        List<GostCertificate> effective = ChainValidator.validateChain(peerChain, anchors);

        assertEquals(11, effective.size(), "10 peer-сертификатов плюс локальный якорь");
        assertEquals(
                root.cert,
                effective.get(effective.size() - 1),
                "Последним должен быть сохранённый сертификат якоря");
        assertEquals(
                effective,
                ChainValidator.resolveChain(peerChain, anchors),
                "validateChain должен возвращать ту же цепочку, что и resolveChain");
    }

    @Test
    @DisplayName("Внешний IMPLICIT NameConstraints применяется end-to-end")
    void testExternalImplicitNameConstraintsEnforcedEndToEnd() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExtension(NC_OID_BYTES, true, EXTERNAL_IMPLICIT_NC));
        CertBundle good = createLeafWithSan(intermediate, "host.example.com", null);
        CertBundle bad = createLeafWithSan(intermediate, "evil.com", null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(good.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(bad.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("Legacy EXPLICIT NameConstraints продолжает применяться end-to-end")
    void testLegacyExplicitNameConstraintsEnforcedEndToEnd() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNcExtension(NC_OID_BYTES, true, LEGACY_EXPLICIT_NC));
        CertBundle good = createLeafWithSan(intermediate, "host.example.com", null);
        CertBundle bad = createLeafWithSan(intermediate, "evil.com", null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(good.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(bad.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("Malformed NameConstraints отклоняются fail-closed")
    void testMalformedNameConstraintsFailClosed() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNameConstraintsExtension(null, null, true));
        CertBundle leaf = createLeaf(intermediate);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChain(
                                        List.of(leaf.cert, intermediate.cert, root.cert),
                                        TrustAnchors.ofCertificate(root.cert)));
        assertTrue(
                ex.getMessage().contains("malformed NameConstraints"),
                "ожидался отказ из-за malformed NameConstraints, было: " + ex.getMessage());
    }

    @Test
    @DisplayName("directoryName: excluded subject -> отказ")
    void testDirectoryNameExcludedSubjectRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, GostDnParser.encodeDn("O=Evil,CN=x"), null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: excluded, лишний AVA в RDN subject не обходит запрет -> отказ")
    void testDirectoryNameExcludedMultiValuedRdnRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, dnMultiValuedOWithOu("Evil", "x"), null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: excluded, многозначный RDN с другим O не срабатывает -> успех")
    void testDirectoryNameExcludedMultiValuedRdnOtherValueAccepted() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, dnMultiValuedOWithOu("Good", "x"), null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: permitted, многозначный RDN шире поддерева -> отказ")
    void testDirectoryNamePermittedMultiValuedRdnRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Evil"), null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, dnMultiValuedOWithOu("Evil", "x"), null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: permitted subject вне поддерева -> отказ")
    void testDirectoryNamePermittedSubjectRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Good"), null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, GostDnParser.encodeDn("O=Other,CN=x"), null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: permitted без SAN, пустой subject -> vacuous")
    void testDirectoryNamePermittedEmptySubjectVacuous() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Good"), null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf = createLeafWithSubjectAndDirSan(intermediate, null, null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: permitted SAN внутри поддерева -> успех")
    void testDirectoryNamePermittedSanAccepted() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Good"), null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, null, GostDnParser.encodeDn("O=Good,CN=x"));

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: subject в permitted, SAN вне -> отказ")
    void testDirectoryNameSubjectAndSanOneOutside() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Good"), null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate,
                        GostDnParser.encodeDn("O=Good,CN=a"),
                        GostDnParser.encodeDn("O=Evil,CN=b"));

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: excluded SAN -> отказ")
    void testDirectoryNameExcludedSanRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, null, GostDnParser.encodeDn("O=Evil,CN=x"));

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: пустое ограничение -> fail-closed")
    void testDirectoryNameEmptyConstraintRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(new byte[] {0x30, 0x00}, null);
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf = createLeafWithSubjectAndDirSan(intermediate, null, null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: excluded PrintableString против UTF8String -> отказ")
    void testDirectoryNameExcludedPrintableVsUtf8() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, dnPrintableO("Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, GostDnParser.encodeDn("O=Evil,CN=x"), null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("directoryName: NC корня с cert-якорем при опущенном корне -> отказ")
    void testDirectoryNameRootNcCertAnchorOmittedRoot() throws Exception {
        byte[] nc = buildDirectoryNameNc(GostDnParser.encodeDn("O=Good"), null);
        CertBundle root = createRootCaWithNameConstraints(nc);
        CertBundle intermediate = createIntermediateCa(root, null);
        CertBundle leaf =
                createLeafWithSubjectAndDirSan(
                        intermediate, GostDnParser.encodeDn("O=Evil,CN=x"), null);
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root.cert));

        assertThrows(
                PkixException.class,
                () -> ChainValidator.validateChain(List.of(leaf.cert, intermediate.cert), anchors));
    }

    @Test
    @DisplayName("directoryName: self-issued leaf с SAN в excluded -> отказ")
    void testDirectoryNameSelfIssuedLeafSanRejected() throws Exception {
        byte[] nc = buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil"));
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, GostDnParser.encodeDn("O=Good,CN=SubCA"), nc);
        CertBundle leaf =
                createSelfIssuedLeafWithDirSan(intermediate, GostDnParser.encodeDn("O=Evil,CN=x"));

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("NC только dNSName: legacy subject DN не разбирается и не мешает")
    void testDnsOnlyNcDoesNotParseLegacySubject() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(root, buildNcPermittedDns("example.com"));
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        ca, legacyCyrillicPrintableDn(), "host.example.com", null, null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "subject DN не участвует в DNS-ограничении и не должен разбираться");
    }

    @Test
    @DisplayName("NC directoryName: legacy subject DN разбирается строго")
    void testDirectoryNameNcParsesLegacySubjectStrictly() throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca =
                createIntermediateCaWithNameConstraints(
                        root, buildDirectoryNameNc(null, GostDnParser.encodeDn("O=Evil")));
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        ca, legacyCyrillicPrintableDn(), "host.example.com", null, null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, ca.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "при активном directoryName некорректная строка DN должна отклоняться");
    }

    @Test
    @DisplayName("rfc822Name: emailAddress в subject вне permitted -> отказ")
    void testRfc822SubjectEmailPermittedRejected() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        null,
                        null,
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("rfc822Name: emailAddress в subject в permitted -> успех")
    void testRfc822SubjectEmailPermittedAccepted() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@example.com"),
                        null,
                        null,
                        null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("rfc822Name: SAN только с dNSName не отключает emailAddress-проверку")
    void testRfc822SubjectEmailWithDnsSanRejected() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        "host.example.com",
                        null,
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("rfc822Name: SAN в permitted, но emailAddress в subject вне permitted -> отказ")
    void testRfc822SanAndSubjectEmailBothChecked() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        null,
                        "user@example.com",
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "emailAddress в subject вне permitted не должен прятаться за разрешённым SAN");
    }

    @Test
    @DisplayName("rfc822Name: SAN допустим, emailAddress в subject в excluded -> отказ")
    void testRfc822SanAllowedSubjectEmailExcludedRejected() throws Exception {
        byte[] nc = buildNcExcludedRfc822("evil.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        null,
                        "user@example.com",
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "emailAddress в excluded должен отклоняться и при наличии SAN rfc822");
    }

    @Test
    @DisplayName("rfc822Name: SAN и emailAddress в permitted -> принят")
    void testRfc822SanAndSubjectEmailBothPermittedAccepted() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=admin@example.com"),
                        null,
                        "user@example.com",
                        null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "оба адреса в permitted — цепочка должна приниматься");
    }

    @Test
    @DisplayName("rfc822Name: NC только с mailbox-формой + leaf только с emailAddress -> отказ")
    void testRfc822MailboxFormOnlySubjectEmailRejected() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithMailboxExcluded("root@example.com"));
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        "host.example.com",
                        null,
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "mailbox-форма не сопоставляется, поэтому subject emailAddress должен давать отказ");
    }

    @Test
    @DisplayName("rfc822Name: NC только с mailbox-формой + leaf без email -> принят")
    void testRfc822MailboxFormOnlyNoEmailAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNcWithMailboxExcluded("root@example.com"));
        CertBundle leaf = createLeafWithSan(intermediate, "host.example.com", null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "ограничение неприменимо, если у листа нет rfc822-имён");
    }

    @Test
    @DisplayName("rfc822Name: NC с host-формой + leaf без email -> принят")
    void testRfc822HostFormNoEmailAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, buildNcPermittedRfc822("example.com"));
        CertBundle leaf = createLeafWithSan(intermediate, "host.example.com", null);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "leaf без rfc822-имён и emailAddress ограничением не затрагивается");
    }

    @Test
    @DisplayName("rfc822Name: excluded emailAddress в subject -> отказ")
    void testRfc822SubjectEmailExcludedRejected() throws Exception {
        byte[] nc = buildNcExcludedRfc822("evil.com");
        CertBundle root = createRootCa();
        CertBundle intermediate = createIntermediateCaWithNameConstraints(root, nc);
        CertBundle leaf =
                createLeafWithSubjectAndSans(
                        intermediate,
                        GostDnParser.encodeDn("CN=Leaf,EMAILADDRESS=user@evil.com"),
                        null,
                        null,
                        null);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("rfc822Name: self-issued leaf с emailAddress вне permitted -> отказ")
    void testRfc822SelfIssuedLeafSubjectEmailRejected() throws Exception {
        byte[] nc = buildNcPermittedRfc822("example.com");
        CertBundle root = createRootCa();
        CertBundle intermediate =
                createIntermediateCaWithNameConstraints(
                        root, GostDnParser.encodeDn("CN=SubCA,EMAILADDRESS=user@evil.com"), nc);
        CertBundle leaf = createSelfIssuedLeafWithoutSan(intermediate);

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)));
    }

    @Test
    @DisplayName("validateChainWithRevocation: PoC-цепочка отклоняется до проверки отзыва")
    void testRevocationVariantRejectsNonCaTop() throws Exception {
        CertBundle root = createRootCa();
        CertBundle attackerEe = createLeaf(root);
        CertBundle forgedLeaf = createLeafWithSan(attackerEe, "bank.example.com", null);

        List<GostCertificate> chain = List.of(forgedLeaf.cert, attackerEe.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChainWithRevocation(
                                        chain,
                                        anchors,
                                        Collections.<CertRevocationData>nCopies(
                                                chain.size(), null)));
        assertEquals(PkixException.Reason.NOT_CA, ex.reason());
    }

    @Test
    @DisplayName("Якорь: cross-signed якорь с доверенным издателем -> успех")
    void testCrossSignedAnchorAccepted() throws Exception {
        CertBundle root = createRootCa();
        CertBundle crossSignedAnchor = createIntermediateCa(root, null);

        List<GostCertificate> chain = List.of(crossSignedAnchor.cert);
        TrustAnchors trustAnchors =
                TrustAnchors.ofCertificates(List.of(crossSignedAnchor.cert, root.cert));

        assertDoesNotThrow(() -> ChainValidator.validateChain(chain, trustAnchors));
    }

    // ========================================================================
    // Name Constraints helpers
    // ========================================================================

    private static final byte[] NC_OID_BYTES = {0x55, 0x1D, 0x1E};

    // extnValue NameConstraints без OCTET STRING. IMPLICIT-вектор получен OpenSSL:
    // nameConstraints=critical,permitted;DNS:example.com
    private static final byte[] EXTERNAL_IMPLICIT_NC = {
        0x30,
        0x11,
        (byte) 0xA0,
        0x0F,
        0x30,
        0x0D,
        (byte) 0x82,
        0x0B,
        0x65,
        0x78,
        0x61,
        0x6D,
        0x70,
        0x6C,
        0x65,
        0x2E,
        0x63,
        0x6F,
        0x6D
    };

    // Legacy EXPLICIT-форма старого builder'а библиотеки.
    private static final byte[] LEGACY_EXPLICIT_NC = {
        0x30,
        0x13,
        (byte) 0xA0,
        0x11,
        0x30,
        0x0F,
        0x30,
        0x0D,
        (byte) 0x82,
        0x0B,
        0x65,
        0x78,
        0x61,
        0x6D,
        0x70,
        0x6C,
        0x65,
        0x2E,
        0x63,
        0x6F,
        0x6D
    };

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

    /** Сборка NameConstraints: только excluded iPAddress. */
    private static byte[] buildNcExcludedIp(byte[] ipConstraint) {
        byte[] ip = DerCodec.encodeTlv(0x87, ipConstraint);
        byte[] st = generalSubtreeNc(ip, null, null);
        byte[] gs = generalSubtreesNc(st);
        byte[] es = DerCodec.encodeContextConstructed(1, gs);
        return buildNameConstraintsExtension(null, es, true);
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

    /** Создаёт peer-цепочку [leaf, intermediate..., firstIntermediate]. */
    private static List<GostCertificate> createPeerChain(CertBundle root, int intermediateCount)
            throws Exception {
        CertBundle current = root;
        List<CertBundle> intermediates = new ArrayList<>();
        for (int i = 1; i <= intermediateCount; i++) {
            current =
                    createIntermediateCaWithDn(
                            current,
                            "CN=Resolved Chain CA " + i,
                            "20240501120000Z",
                            "21060101120000Z");
            intermediates.add(current);
        }
        CertBundle leaf = createLeaf(current);
        List<GostCertificate> chain = new ArrayList<>();
        chain.add(leaf.cert);
        for (int i = intermediates.size() - 1; i >= 0; i--) {
            chain.add(intermediates.get(i).cert);
        }
        return chain;
    }

    /** Сборка NameConstraints: только excluded rfc822Name. */
    private static byte[] buildNcExcludedRfc822(String... names) {
        byte[][] subs = new byte[names.length][];
        for (int i = 0; i < names.length; i++) {
            byte[] base = DerCodec.encodeTlv(0x81, names[i].getBytes(StandardCharsets.US_ASCII));
            subs[i] = generalSubtreeNc(base, null, null);
        }
        byte[] gs = generalSubtreesNc(subs);
        byte[] es = DerCodec.encodeContextConstructed(1, gs);
        return buildNameConstraintsExtension(null, es, true);
    }

    /** Сборка NameConstraints: только excluded URI. */
    private static byte[] buildNcExcludedUri(String... uris) {
        byte[][] subs = new byte[uris.length][];
        for (int i = 0; i < uris.length; i++) {
            byte[] base = DerCodec.encodeTlv(0x86, uris[i].getBytes(StandardCharsets.US_ASCII));
            subs[i] = generalSubtreeNc(base, null, null);
        }
        byte[] gs = generalSubtreesNc(subs);
        byte[] es = DerCodec.encodeContextConstructed(1, gs);
        return buildNameConstraintsExtension(null, es, true);
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

    private static final int TAG_X400 = 0xA3;
    private static final int TAG_EDI = 0xA5;
    private static final int TAG_REGISTERED_ID = 0x88;
    private static final byte[] SAN_OID_BYTES_TEST = {0x55, 0x1D, 0x11};

    /** Сборка NameConstraints: permitted с одним GeneralName заданной формы. */
    private static byte[] buildNcWithForm(int tag, byte[] content) {
        byte[] base = DerCodec.encodeTlv(tag, content);
        byte[] sub = generalSubtreeNc(base, null, null);
        byte[] ps = DerCodec.encodeContextConstructed(0, generalSubtreesNc(sub));
        return buildNameConstraintsExtension(ps, null, true);
    }

    /** Проверяет цепочку: NC ограничивает одну форму, лист несёт имя другой/той же формы. */
    private void assertNcFormChain(byte[] nc, int leafTag, byte[] leafContent, boolean accepted)
            throws Exception {
        CertBundle root = createRootCa();
        CertBundle ca = createIntermediateCaWithNameConstraints(root, nc);
        byte[] sanValue = DerCodec.encodeSequence(DerCodec.encodeTlv(leafTag, leafContent));
        byte[] sanExt = buildNcExtension(SAN_OID_BYTES_TEST, false, sanValue);
        CertBundle leaf = createLeafWithRawExtensions(ca, sanExt);
        List<GostCertificate> chain = List.of(leaf.cert, ca.cert, root.cert);
        TrustAnchors anchors = TrustAnchors.ofCertificate(root.cert);
        if (accepted) {
            assertDoesNotThrow(
                    () -> ChainValidator.validateChain(chain, anchors),
                    "разные формы имён не конфликтуют, цепочка должна приниматься");
        } else {
            assertThrows(
                    PkixException.class,
                    () -> ChainValidator.validateChain(chain, anchors),
                    "ограничение неподдерживаемой формы + имя той же формы -> отказ");
        }
    }

    /** Создаёт leaf с готовыми DER-расширениями (SAN/IAN и т.п.) поверх KU/SKI/AKI. */
    private static CertBundle createLeafWithRawExtensions(CertBundle issuer, byte[] extraExt)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf Raw");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki, extraExt);
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

    /** Содержимое GeneralSubtrees для IMPLICIT-тега [0]/[1] (RFC 5280). */
    private static byte[] generalSubtreesNc(byte[]... subtrees) {
        return concatExtensions(subtrees);
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

    @Test
    @DisplayName("legacy CA: issuer DN из DER проходит, строковая перекодировка — нет")
    void testLegacyDnEncodingMigration() throws Exception {
        CertBundle root = createLegacyRootCa();
        CertBundle leafFromDer = createLeafWithIssuerDn(root, root.dn);

        assertDoesNotThrow(
                () ->
                        ChainValidator.validateChain(
                                List.of(leafFromDer.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "issuer DN, взятый из DER старого CA, должен проходить");

        CertBundle leafFromString =
                createLeafWithIssuerDn(root, GostDnParser.encodeDn("CN=Legacy Root,C=RU"));
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChain(
                                List.of(leafFromString.cert, root.cert),
                                TrustAnchors.ofCertificate(root.cert)),
                "строковая перекодировка DN старого CA не должна совпадать");
    }

    private static CertBundle createLegacyRootCa() throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = legacyDnWithUtf8Country("Legacy Root");
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240101000000Z")
                        .notAfter("20450101000000Z")
                        .issuerDn(dn)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .basicConstraints(true, null)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())),
                dn);
    }

    private static CertBundle createLeafWithIssuerDn(CertBundle issuer, byte[] issuerDn)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Legacy Leaf");
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240101000000Z")
                        .notAfter("20450101000000Z")
                        .issuerDn(issuerDn)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .serial(BigInteger.TWO)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /** DN старого формата: countryName ещё UTF8String, как до RFC 5280-фикса. */
    private static byte[] legacyDnWithUtf8Country(String cn) {
        return DerCodec.encodeSequence(
                DerCodec.encodeSetOf(
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.ATTR_CN),
                                DerCodec.encodeUTF8String(cn))),
                DerCodec.encodeSetOf(
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.ATTR_C),
                                DerCodec.encodeUTF8String("RU"))));
    }

    private static CertBundle createRootCa() throws Exception {
        return createRootCa(null);
    }

    /**
     * Создаёт intermediate CA с расширением NameConstraints.
     */
    private static CertBundle createIntermediateCaWithNameConstraints(
            CertBundle issuer, byte[] ncExtension) throws Exception {
        return createIntermediateCaWithNameConstraints(
                issuer, GostDnParser.encodeDn("CN=NC Intermediate CA"), ncExtension);
    }

    private static CertBundle createIntermediateCaWithNameConstraints(
            CertBundle issuer, byte[] subjectDn, byte[] ncExtension) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
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
        return createRootCaWithNameConstraints(ncExtension, "20240501120000Z", "21060101120000Z");
    }

    private static CertBundle createRootCaWithNameConstraints(
            byte[] ncExtension, String notBefore, String notAfter) throws Exception {
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
                        .notBefore(notBefore)
                        .notAfter(notAfter)
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

    private static CertBundle createRootCaWithValidity(String notBefore, String notAfter)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Root CA validity");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] additional = concatExtensions(bc, ku, ski);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore(notBefore)
                        .notAfter(notAfter)
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

    private static CertBundle createIntermediateCaWithDn(
            CertBundle issuer, String subjectCn, String notBefore, String notAfter)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn(subjectCn);
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(bc, ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore(notBefore)
                        .notAfter(notAfter)
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

    private static CertBundle createReissuedRoot(
            CertBundle oldRoot, BigInteger serial, String notBefore, String notAfter)
            throws Exception {
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(oldRoot.pub);
        byte[] additional = concatExtensions(bc, ku, ski);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, oldRoot.dn)
                        .publicKey(oldRoot.pub)
                        .notBefore(notBefore)
                        .notAfter(notAfter)
                        .additionalExtensions(additional)
                        .issuerDn(oldRoot.dn)
                        .serial(serial)
                        .buildTbs();
        return new CertBundle(
                oldRoot.priv,
                oldRoot.pub,
                GostCertificateBuilder.sign(tbs, GostSigner.of(oldRoot.priv)),
                oldRoot.dn);
    }

    /**
     * Создаёт leaf-сертификат с произвольным набором SAN разных типов.
     * Нужен для проверки, что permitted проверяет каждое имя, а не любое.
     */
    private static CertBundle createLeafWithSans(
            CertBundle issuer,
            String[] dnsNames,
            String[] ipAddresses,
            String[] rfc822Names,
            String[] uris)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Leaf NC multi");
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
        if (dnsNames != null) {
            builder.sanDns(dnsNames);
        }
        if (ipAddresses != null) {
            builder.sanIp(ipAddresses);
        }
        if (rfc822Names != null) {
            builder.sanRfc822Name(rfc822Names);
        }
        if (uris != null) {
            builder.sanUri(uris);
        }
        byte[] tbs = builder.buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                subjectDn);
    }

    /**
     * Создаёт leaf-сертификат с указанным SAN dNSName и/или iPAddress.
     */
    private static byte[] buildDirectoryNameNc(byte[] permitted, byte[] excluded) {
        byte[] permittedDer = null;
        byte[] excludedDer = null;
        if (permitted != null) {
            permittedDer =
                    permittedSubtrees(
                            generalSubtreesNc(
                                    generalSubtreeNc(
                                            GeneralNameCodec.encodeDirectoryName(permitted),
                                            null,
                                            null)));
        }
        if (excluded != null) {
            excludedDer =
                    DerCodec.encodeContextConstructed(
                            1,
                            generalSubtreesNc(
                                    generalSubtreeNc(
                                            GeneralNameCodec.encodeDirectoryName(excluded),
                                            null,
                                            null)));
        }
        return buildNameConstraintsExtension(permittedDer, excludedDer, true);
    }

    /** Subject DN из двух RDN: {@code O=<o>+OU=<ou>} (один многозначный RDN) и {@code CN=x}. */
    private static byte[] dnMultiValuedOWithOu(String o, String ou) {
        byte[] oAva =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_O),
                        DerCodec.encodeTlv(
                                0x0C, o.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        byte[] ouAva =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_OU),
                        DerCodec.encodeTlv(
                                0x0C, ou.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        byte[] cnAva =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_CN),
                        DerCodec.encodeTlv(
                                0x0C, "x".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return DerCodec.encodeSequence(
                DerCodec.encodeSetOf(oAva, ouAva), DerCodec.encodeSetOf(cnAva));
    }

    private static byte[] dnPrintableO(String value) {
        byte[] ava =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_O),
                        DerCodec.encodeTlv(
                                0x13, value.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        return DerCodec.encodeSequence(DerCodec.encodeSetOf(ava));
    }

    /** Legacy subject DN: кириллица Windows-1251 в PrintableString (невалидно по X.680). */
    private static byte[] legacyCyrillicPrintableDn() {
        byte[] ava =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.ATTR_CN),
                        DerCodec.encodeTlv(
                                0x13,
                                new byte[] {
                                    (byte) 0xCF, (byte) 0xF0, (byte) 0xE8, (byte) 0xE2, (byte) 0xF2
                                }));
        return DerCodec.encodeSequence(DerCodec.encodeSetOf(ava));
    }

    private static CertBundle createLeafWithSubjectAndSans(
            CertBundle issuer, byte[] subjectDn, String dns, String rfc822, byte[] directoryNameSan)
            throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
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
        if (dns != null) {
            builder.sanDns(dns);
        }
        if (rfc822 != null) {
            builder.sanRfc822Name(rfc822);
        }
        if (directoryNameSan != null) {
            builder.sanDirectoryName(directoryNameSan);
        }
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(issuer.priv)),
                subjectDn);
    }

    private static CertBundle createSelfIssuedLeafWithoutSan(CertBundle issuer) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
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

    private static CertBundle createLeafWithSubjectAndDirSan(
            CertBundle issuer, byte[] subjectDn, byte[] directoryNameSan) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
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
        if (directoryNameSan != null) {
            builder.sanDirectoryName(directoryNameSan);
        }
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(issuer.priv)),
                subjectDn != null ? subjectDn : new byte[] {0x30, 0x00});
    }

    private static CertBundle createSelfIssuedLeafWithDirSan(
            CertBundle issuer, byte[] directoryNameSan) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, issuer.dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .sanDirectoryName(directoryNameSan)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return new CertBundle(
                kp.getPrivate(),
                kp.getPublic(),
                GostCertificateBuilder.sign(tbs, GostSigner.of(issuer.priv)),
                issuer.dn);
    }

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
     * Создаёт CA с basicConstraints CA=true, но KeyUsage без keyCertSign.
     * Нужен для проверки, что наличие KeyUsage без нужного бита отклоняется;
     * при полном отсутствии KeyUsage парсер считает keyCertSign допустимым.
     */
    private static CertBundle createCaWithoutKeyCertSign(CertBundle issuer) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CA without keyCertSign");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
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
     * Создаёт сертификат, у которого subject public key принадлежит доверенному
     * якорю, но подпись сделана чужим ключом. Такой сертификат не должен
     * приниматься как якорь: ключ доверенный, а содержимое не заверено.
     */
    private static GostCertificate createFakeAnchorWithTrustedKey(
            PublicKeyParameters subjectKey, PrivateKeyParameters signingKey, byte[] issuerDn)
            throws Exception {
        byte[] subjectDn = GostDnParser.encodeDn("CN=bank.example");
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(subjectKey)
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .sanDns("bank.example")
                        .additionalExtensions(ku)
                        .issuerDn(issuerDn)
                        .serial(BigInteger.ONE)
                        .buildTbs();
        return GostCertificateBuilder.sign(tbs, GostSigner.of(signingKey));
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

    private static CertBundle createSelfIssuedLeaf(CertBundle issuer, String dns) throws Exception {
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(kp.getPublic());
        byte[] aki = GostCertificateBuilder.buildAkiExtension(issuer.pub);
        byte[] additional = concatExtensions(ku, ski, aki);
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, issuer.dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .additionalExtensions(additional)
                        .issuerDn(issuer.dn)
                        .sanDns(dns)
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
