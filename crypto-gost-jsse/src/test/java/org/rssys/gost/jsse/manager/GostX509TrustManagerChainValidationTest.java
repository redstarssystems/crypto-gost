package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostX509TrustManager: проверка верхнего сертификата цепочки")
class GostX509TrustManagerChainValidationTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String NOT_BEFORE = "20240501120000Z";
    private static final String NOT_AFTER = "21060101120000Z";

    @Test
    @DisplayName("Не-CA верхний сертификат, подписанный доверенным CA, -> CertificateException")
    void testNonCaTopCertificateRejected() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle nonCaEe = createNonCaCert(root);
        PkixCertTestHelper.CertBundle leafUnderNonCa =
                createServerLeaf(nonCaEe, "bank.example.com");

        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(root.cert));

        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () ->
                                trustManager.validateChainWithOcsp(
                                        List.of(leafUnderNonCa.cert, nonCaEe.cert),
                                        "bank.example.com",
                                        false),
                        "сервер под не-CA верхним сертификатом должна отклоняться");
        assertTrue(
                ex.getMessage() != null && ex.getMessage().contains("is not a CA"),
                "ожидалась причина NOT_CA, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Валидная цепочка [leaf, rootCA] -> успех")
    void testValidChainAccepted() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(root, "gost.example.com");

        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(root.cert));

        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(leaf.cert, root.cert), "gost.example.com", false));
    }

    @Test
    @DisplayName("Закреплённый промежуточный якорь -> успех")
    void testPinnedIntermediateAnchorAccepted() throws Exception {
        PkixCertTestHelper.CertBundle externalRoot = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle pinnedIntermediate =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        externalRoot.priv,
                        externalRoot.cert.getPublicKey(),
                        externalRoot.subjectDn,
                        NOT_BEFORE,
                        NOT_AFTER,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        0);
        PkixCertTestHelper.CertBundle leaf =
                createServerLeaf(pinnedIntermediate, "gost.example.com");

        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(pinnedIntermediate.cert));

        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(leaf.cert, pinnedIntermediate.cert),
                                "gost.example.com",
                                false));
    }

    @Test
    @DisplayName("Битая цепочка: OCSP fetch не выполняется до структурной проверки")
    void testNoOcspFetchBeforeStructureValidation() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        byte[] aiaExt = PkixCertTestHelper.buildAiaOcspExtension("http://ocsp.example.com/");
        PkixCertTestHelper.CertBundle expiredLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20200101000000Z",
                        "20210101000000Z",
                        new String[] {"gost.example.com"},
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null,
                        aiaExt);

        AtomicInteger fetchCount = new AtomicInteger();
        OcspFetcher countingFetcher =
                (certDer, issuerDer, uri) -> {
                    fetchCount.incrementAndGet();
                    return null;
                };
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        countingFetcher);

        assertThrows(
                CertificateException.class,
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(expiredLeaf.cert, root.cert), "gost.example.com", false),
                "истёкший leaf должен отклоняться");
        assertTrue(
                fetchCount.get() == 0,
                "OCSP-запрос не должен выполняться до структурной проверки, было: "
                        + fetchCount.get());
    }

    @Test
    @DisplayName("Cert-якорь: NameConstraints корня действуют при опущенном корне")
    void testCertAnchorRootNameConstraintsEnforced() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, new String[] {"example.com"}, null);
        PkixCertTestHelper.CertBundle goodLeaf = createServerLeaf(root, "host.example.com");
        PkixCertTestHelper.CertBundle untrustedLeaf = createServerLeaf(root, "bank.ru");
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(root.cert)));

        assertThrows(
                CertificateException.class,
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(untrustedLeaf.cert), "bank.ru", false),
                "SAN вне permitted корня должен отклоняться даже без корня в цепочке");
        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(goodLeaf.cert), "host.example.com", false),
                "SAN в permitted корня должен приниматься");
    }

    @Test
    @DisplayName("Cert-якорь: перевыпущенный корень с тем же ключом принимается")
    void testCertAnchorReissuedRootAccepted() throws Exception {
        PkixCertTestHelper.CertBundle oldRoot =
                PkixCertTestHelper.createRootCAWithNameConstraints(
                        PARAMS, new String[] {"example.com"}, null);
        PkixCertTestHelper.CertBundle newRoot =
                PkixCertTestHelper.createReissuedRoot(
                        PARAMS, oldRoot, "20250101000000Z", "21150101000000Z");
        PkixCertTestHelper.CertBundle goodLeaf = createServerLeaf(oldRoot, "host.example.com");
        PkixCertTestHelper.CertBundle untrustedLeaf = createServerLeaf(oldRoot, "bank.ru");
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(oldRoot.cert)));

        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(goodLeaf.cert, newRoot.cert), "host.example.com", false),
                "локальный якорь должен принимать перевыпущенный корень по ключу");
        assertThrows(
                CertificateException.class,
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(untrustedLeaf.cert, newRoot.cert), "bank.ru", false),
                "ограничения локального якоря должны применяться, новый корень игнорируется");
    }

    @Test
    @DisplayName("Cert-якорь: закреплённый промежуточный CA обрезает цепочку выше")
    void testCertAnchorPinnedIntermediateTruncatesChainAbove() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        NOT_BEFORE,
                        NOT_AFTER,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        0);
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(intermediate, "gost.example.com");
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(intermediate.cert)));

        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(leaf.cert, intermediate.cert, root.cert),
                                "gost.example.com",
                                false),
                "цепочка выше закреплённого промежуточного якоря должна игнорироваться");
    }

    @Test
    @DisplayName("Cert-якорь: закреплённый leaf всё равно проверяется по сроку")
    void testCertAnchorExpiredPinnedLeafRejected() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle expiredLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20200101000000Z",
                        "20210101000000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(expiredLeaf.cert)));

        assertThrows(
                CertificateException.class,
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(expiredLeaf.cert), "gost.example.com", false),
                "срок закреплённого leaf должен проверяться несмотря на статус якоря");
    }

    private static PkixCertTestHelper.CertBundle createNonCaCert(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                null,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    @Test
    @DisplayName("insecureTrustAll + STAPLING_OR_FETCH: OCSP не обязателен, сетевых вызовов нет")
    void testInsecureTrustAllDoesNotRequireOcsp() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(root, "gost.example.com");
        AtomicInteger fetchCount = new AtomicInteger();
        OcspFetcher countingFetcher =
                (certDer, issuerDer, uri) -> {
                    fetchCount.incrementAndGet();
                    return null;
                };
        GostX509TrustManager trustManager =
                GostX509TrustManager.insecureTrustAll(
                        OcspPolicy.STAPLING_OR_FETCH, countingFetcher);

        assertDoesNotThrow(
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(leaf.cert), "gost.example.com", false),
                "без обязательного OCSP сертификат без staple должен приниматься");
        assertEquals(0, fetchCount.get(), "insecure-режим не должен делать сетевых запросов");
        assertThrows(
                CertificateException.class,
                () ->
                        trustManager.validateChainWithOcsp(
                                List.of(leaf.cert), "gost.example.com", true),
                "при requireOcsp=true отсутствие staple должно отклоняться");
        assertEquals(0, fetchCount.get(), "insecure-режим не должен делать сетевых запросов");
    }

    private static PkixCertTestHelper.CertBundle createServerLeaf(
            PkixCertTestHelper.CertBundle issuer, String dnsName) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                new String[] {dnsName},
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_SERVER_AUTH},
                false,
                null);
    }

    @Test
    @DisplayName("Cert-якорь: 10 peer + локальный якорь допустимы, 11 peer отклоняются")
    void testPeerLimitExcludesAppendedAnchor() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        GostX509TrustManager trustManager =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificates(List.of(root.cert)));

        List<GostCertificate> tenPeer = createPeerChain(root, 9);
        assertDoesNotThrow(
                () -> trustManager.validateChainWithOcsp(tenPeer, "host.example.com", false));

        List<GostCertificate> elevenPeer = createPeerChain(root, 10);
        assertThrows(
                CertificateException.class,
                () -> trustManager.validateChainWithOcsp(elevenPeer, "host.example.com", false));
    }

    private static List<GostCertificate> createPeerChain(
            PkixCertTestHelper.CertBundle root, int intermediateCount) throws Exception {
        PkixCertTestHelper.CertBundle current = root;
        List<PkixCertTestHelper.CertBundle> intermediates = new ArrayList<>();
        for (int i = 0; i < intermediateCount; i++) {
            current =
                    PkixCertTestHelper.createCertSignedBy(
                            PARAMS,
                            current.priv,
                            current.cert.getPublicKey(),
                            current.subjectDn,
                            NOT_BEFORE,
                            NOT_AFTER,
                            null,
                            new byte[] {(byte) 0x04},
                            null,
                            true,
                            null);
            intermediates.add(current);
        }
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(current, "host.example.com");
        List<GostCertificate> chain = new ArrayList<>();
        chain.add(leaf.cert);
        for (int i = intermediates.size() - 1; i >= 0; i--) {
            chain.add(intermediates.get(i).cert);
        }
        return chain;
    }
}
