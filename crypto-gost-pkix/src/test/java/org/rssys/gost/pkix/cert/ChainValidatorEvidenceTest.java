package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;

@DisplayName("ChainValidator.validateRevocationEvidence: все доказательства")
class ChainValidatorEvidenceTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair leafKp;
    private static GostCertificate leaf;

    @BeforeAll
    static void setup() {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        root =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Root CA"))
                        .publicKey(rootKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .sign(rootKp.getPrivate());

        leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leaf =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Leaf"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());
    }

    @Test
    @DisplayName("fresh good + stale revoked: revoked отклоняет")
    void staleRevokedRejects() throws Exception {
        byte[] good = ocsp(Instant.now(), "good");
        byte[] staleRevoked = ocsp(Instant.now().minusSeconds(3600), "revoked");
        RevocationEvidenceWindow window = window();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateRevocationEvidence(
                                        List.of(leaf, root),
                                        List.of(
                                                new CertRevocationEvidence(
                                                        List.of(), List.of(good, staleRevoked)),
                                                empty()),
                                        window,
                                        RevocationFreshnessPolicy.STRICT));
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName("fresh good + stale good: успех")
    void staleGoodDoesNotReject() throws Exception {
        byte[] fresh = ocsp(Instant.now(), "good");
        byte[] stale = ocsp(Instant.now().minusSeconds(3600), "good");
        ChainValidator.validateRevocationEvidence(
                List.of(leaf, root),
                List.of(new CertRevocationEvidence(List.of(), List.of(fresh, stale)), empty()),
                window(),
                RevocationFreshnessPolicy.STRICT);
    }

    @Test
    @DisplayName("нет good в окне: REVOCATION_EVIDENCE_OUT_OF_WINDOW")
    void noGoodInWindow() throws Exception {
        byte[] stale = ocsp(Instant.now().minusSeconds(3600), "good");
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateRevocationEvidence(
                                        List.of(leaf, root),
                                        List.of(
                                                new CertRevocationEvidence(
                                                        List.of(), List.of(stale)),
                                                empty()),
                                        window(),
                                        RevocationFreshnessPolicy.STRICT));
        assertEquals(PkixException.Reason.REVOCATION_EVIDENCE_OUT_OF_WINDOW, ex.reason());
    }

    @Test
    @DisplayName("Более 8 уникальных доказательств на сертификат отвергаются")
    void evidenceLimitRejects() throws Exception {
        java.util.List<byte[]> many = new java.util.ArrayList<>();
        for (int i = 0; i < 9; i++) {
            many.add(ocsp(Instant.now().minusSeconds(i), "good"));
        }
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateRevocationEvidence(
                                List.of(leaf, root),
                                List.of(new CertRevocationEvidence(List.of(), many), empty()),
                                window(),
                                RevocationFreshnessPolicy.STRICT));
    }

    @Test
    @DisplayName("Дубликаты доказательств дедуплицируются до применения лимита")
    void evidenceDuplicatesDeduplicated() throws Exception {
        byte[] good = ocsp(Instant.now(), "good");
        java.util.List<byte[]> duplicates = new java.util.ArrayList<>();
        for (int i = 0; i < 9; i++) {
            duplicates.add(good);
        }
        ChainValidator.validateRevocationEvidence(
                List.of(leaf, root),
                List.of(new CertRevocationEvidence(List.of(), duplicates), empty()),
                window(),
                RevocationFreshnessPolicy.STRICT);
    }

    @Test
    @DisplayName("Ответчик OCSP только среди кандидатов: подпись принимается")
    void responderCandidateAllowsOcspVerification() throws Exception {
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = responderCert(responderKp);
        byte[] ocsp = ocspSignedByResponder(responderKp);
        List<CertRevocationEvidence> evidence =
                List.of(new CertRevocationEvidence(List.of(), List.of(ocsp)), empty());
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root));

        ChainValidator.validateChainWithRevocationEvidence(
                List.of(leaf, root),
                anchors,
                evidence,
                window(),
                RevocationFreshnessPolicy.STRICT,
                List.of(responder));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                ChainValidator.validateChainWithRevocationEvidence(
                                        List.of(leaf, root),
                                        anchors,
                                        evidence,
                                        window(),
                                        RevocationFreshnessPolicy.STRICT,
                                        List.of()));
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, ex.reason());
    }

    @Test
    @DisplayName("Возвращается только проверенное evidence ниже якоря, без дублей и без якоря")
    void returnsOnlyVerifiedEvidenceBelowAnchor() throws Exception {
        byte[] good = ocsp(Instant.now(), "good");
        // Данные якоря не проверяются (у якоря нет издателя), поэтому в результат не попадают,
        // даже если это мусор: потребитель не должен принять их за проверенные.
        byte[] anchorGarbage = new byte[] {0x30, 0x03, 0x02, 0x01, 0x00};
        List<CertRevocationEvidence> evidence =
                List.of(
                        new CertRevocationEvidence(List.of(), List.of(good, good)),
                        new CertRevocationEvidence(List.of(), List.of(anchorGarbage)));

        List<CertRevocationEvidence> verified =
                ChainValidator.validateChainWithRevocationEvidence(
                        List.of(leaf, root),
                        TrustAnchors.ofCertificates(List.of(root)),
                        evidence,
                        window(),
                        RevocationFreshnessPolicy.STRICT,
                        List.of());

        assertEquals(1, verified.size(), "только сертификаты ниже якоря: индекс 0");
        assertEquals(1, verified.get(0).ocspResponseDers().size(), "дубликаты удалены");
        org.junit.jupiter.api.Assertions.assertArrayEquals(
                good, verified.get(0).ocspResponseDers().get(0), "значение прошло проверку");
    }

    @Test
    @DisplayName("Кандидат-ответчик валиден, но якорь чужой: цепочка не становится доверенной")
    void responderCandidateDoesNotMakeChainTrusted() throws Exception {
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = responderCert(responderKp);
        byte[] ocsp = ocspSignedByResponder(responderKp);
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreignRoot =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Foreign Root"))
                        .publicKey(foreignKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .sign(foreignKp.getPrivate());
        // Кандидаты нужны только для подписи OCSP: доверие даёт исключительно якорь.
        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateChainWithRevocationEvidence(
                                List.of(leaf, root),
                                TrustAnchors.ofCertificates(List.of(foreignRoot)),
                                List.of(
                                        new CertRevocationEvidence(List.of(), List.of(ocsp)),
                                        empty()),
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                List.of(responder, root)));
    }

    @Test
    @DisplayName("null-элемент в списке кандидатов ответчиков: IllegalArgumentException")
    void nullResponderCandidateElementRejected() {
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root));
        List<GostCertificate> withNull = new java.util.ArrayList<>();
        withNull.add(null);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ChainValidator.validateChainWithRevocationEvidence(
                                List.of(leaf, root),
                                anchors,
                                List.of(empty(), empty()),
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                withNull));
    }

    @Test
    @DisplayName("null вместо списка кандидатов ответчиков: IllegalArgumentException")
    void nullResponderCandidatesRejected() {
        TrustAnchors anchors = TrustAnchors.ofCertificates(List.of(root));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ChainValidator.validateChainWithRevocationEvidence(
                                List.of(leaf, root),
                                anchors,
                                List.of(empty(), empty()),
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                null));
    }

    private static GostCertificate responderCert(KeyPair responderKp) throws Exception {
        return GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Responder"))
                .issuerDn(root.getSubjectDnBytes())
                .publicKey(responderKp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForDays(30)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(true, GostOids.EXT_OCSP_SIGNING)
                .sign(rootKp.getPrivate());
    }

    private static byte[] ocspSignedByResponder(KeyPair responderKp) {
        return GostOcspResponseBuilder.create(leaf.getSerialNumber())
                .caPublicKey(root.getPublicKey())
                .issuerDn(root.getSubjectDnBytes())
                .thisUpdate(Instant.now())
                .nextUpdate(Instant.now().plusSeconds(3600))
                .good()
                .sign(responderKp.getPrivate());
    }

    private static CertRevocationEvidence empty() {
        return new CertRevocationEvidence(List.of(), List.of());
    }

    private static RevocationEvidenceWindow window() {
        return new RevocationEvidenceWindow(
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));
    }

    private static byte[] ocsp(Instant thisUpdate, String status) throws Exception {
        GostOcspResponseBuilder builder =
                GostOcspResponseBuilder.create(leaf.getSerialNumber())
                        .issuerDn(root.getSubjectDnBytes())
                        .thisUpdate(thisUpdate)
                        .nextUpdate(Instant.now().plusSeconds(3600));
        if ("revoked".equals(status)) {
            builder.revoked(GostSignatureHelper.formatGeneralizedTime(Instant.now()));
        } else {
            builder.good();
        }
        return builder.sign(rootKp.getPrivate());
    }
}
