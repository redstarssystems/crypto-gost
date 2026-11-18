package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;

/**
 * Делегированный OCSP-ответчик, найденный среди недоверенных кандидатов
 * (certificate-values CAdES-X Long), а не в самом ответе.
 */
@DisplayName("OcspVerifier.verifyEvidence: кандидаты в делегированные ответчики")
class OcspVerifierResponderCandidatesTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final RevocationFreshnessPolicy POLICY = RevocationFreshnessPolicy.ETSI_DEFAULT;

    private static PkixCertTestHelper.CertBundle ca;
    private static PkixCertTestHelper.CertBundle foreignCa;
    private static PkixCertTestHelper.CertBundle leaf;
    private static PkixCertTestHelper.CertBundle responder;
    private static RevocationEvidenceWindow window;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ca = PkixCertTestHelper.createRootCA(PARAMS);
        foreignCa = PkixCertTestHelper.createRootCA(PARAMS);
        leaf = issued(ca, new String[] {GostOids.EXT_SERVER_AUTH}, "21060101120000Z");
        responder = issued(ca, new String[] {GostOids.EXT_OCSP_SIGNING}, "21060101120000Z");
        Instant now = Instant.now();
        window = new RevocationEvidenceWindow(now.minusSeconds(120), now);
    }

    private static PkixCertTestHelper.CertBundle issued(
            PkixCertTestHelper.CertBundle issuer, String[] eku, String notAfter) throws Exception {
        byte[] ku =
                GostCertificateBuilder.keyUsageFlags(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                notAfter,
                null,
                null,
                ku,
                eku,
                false,
                null);
    }

    /** OCSP-ответ на leaf, подписанный responder; самого ответчика в ответе нет. */
    private static byte[] ocspSignedBy(PkixCertTestHelper.CertBundle signer) throws Exception {
        Instant now = Instant.now();
        return GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                .caPublicKey(ca.cert.getPublicKey())
                .issuerDn(ca.subjectDn)
                .thisUpdate(now.minusSeconds(60))
                .nextUpdate(now.plusSeconds(86400))
                .producedAt(now.minusSeconds(60))
                .good()
                .sign(signer.priv);
    }

    private static EvidenceFreshness verify(byte[] ocsp, List<GostCertificate> candidates)
            throws PkixException {
        return OcspVerifier.verifyEvidence(
                ocsp, leaf.cert.getSerialNumber(), ca.cert, window, POLICY, candidates);
    }

    @Test
    @DisplayName("Ответчик только среди кандидатов: подпись принимается")
    void responderFromCandidatesAccepted() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);

        assertEquals(EvidenceFreshness.IN_WINDOW, verify(ocsp, List.of(responder.cert)));
    }

    @Test
    @DisplayName("Без кандидата и без встроенного ответчика: OCSP signature verification failed")
    void withoutCandidateRejected() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);

        PkixException ex = assertThrows(PkixException.class, () -> verify(ocsp, List.of()));
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, ex.reason());
    }

    @Test
    @DisplayName("Старая перегрузка без кандидатов ведёт себя как раньше")
    void legacyOverloadRejectsMissingResponder() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);

        assertThrows(
                PkixException.class,
                () ->
                        OcspVerifier.verifyEvidence(
                                ocsp, leaf.cert.getSerialNumber(), ca.cert, window, POLICY));
    }

    @Test
    @DisplayName("Кандидат без id-kp-OCSPSigning отвергается")
    void candidateWithoutOcspSigningRejected() throws Exception {
        PkixCertTestHelper.CertBundle plain =
                issued(ca, new String[] {GostOids.EXT_SERVER_AUTH}, "21060101120000Z");
        byte[] ocsp = ocspSignedBy(plain);

        assertThrows(PkixException.class, () -> verify(ocsp, List.of(plain.cert)));
    }

    @Test
    @DisplayName("Кандидат другого издателя отвергается: подпись издателем обязательна")
    void candidateOfForeignIssuerRejected() throws Exception {
        PkixCertTestHelper.CertBundle foreign =
                issued(foreignCa, new String[] {GostOids.EXT_OCSP_SIGNING}, "21060101120000Z");
        byte[] ocsp = ocspSignedBy(foreign);

        assertThrows(PkixException.class, () -> verify(ocsp, List.of(foreign.cert)));
    }

    @Test
    @DisplayName("Просроченный кандидат отвергается")
    void expiredCandidateRejected() throws Exception {
        PkixCertTestHelper.CertBundle expired =
                issued(ca, new String[] {GostOids.EXT_OCSP_SIGNING}, "20240601120000Z");
        byte[] ocsp = ocspSignedBy(expired);

        assertThrows(PkixException.class, () -> verify(ocsp, List.of(expired.cert)));
    }

    @Test
    @DisplayName("null вместо списка кандидатов: IllegalArgumentException, как в ChainValidator")
    void nullCandidateListRejected() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);

        assertThrows(IllegalArgumentException.class, () -> verify(ocsp, null));
    }

    @Test
    @DisplayName("null-элемент в списке кандидатов: IllegalArgumentException, а не NPE")
    void nullCandidateRejected() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);
        List<GostCertificate> withNull = new ArrayList<>();
        withNull.add(responder.cert);
        withNull.add(null);

        assertThrows(IllegalArgumentException.class, () -> verify(ocsp, withNull));
    }

    @Test
    @DisplayName("Девять различных кандидатов (больше лимита): отказ")
    void nineDistinctCandidatesRejected() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);
        List<GostCertificate> distinct = new ArrayList<>();
        for (int i = 0; i <= GostOids.MAX_OCSP_RESPONDER_CANDIDATES; i++) {
            distinct.add(
                    issued(ca, new String[] {GostOids.EXT_OCSP_SIGNING}, "21060101120000Z").cert);
        }

        PkixException ex = assertThrows(PkixException.class, () -> verify(ocsp, distinct));
        assertEquals(PkixException.Reason.OTHER, ex.reason());
    }

    @Test
    @DisplayName("Сырой список с дубликатами в пределах сырого лимита: схлопывается, успех")
    void duplicatesWithinRawLimitCollapse() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);
        List<GostCertificate> raw = new ArrayList<>();
        for (int i = 0; i < GostOids.MAX_RAW_OCSP_RESPONDER_CANDIDATES; i++) {
            raw.add(responder.cert);
        }

        assertEquals(EvidenceFreshness.IN_WINDOW, verify(ocsp, raw));
    }

    @Test
    @DisplayName("Сырой список длиннее сырого лимита: отказ до дедупликации")
    void rawLimitExceededRejected() throws Exception {
        byte[] ocsp = ocspSignedBy(responder);
        List<GostCertificate> raw = new ArrayList<>();
        for (int i = 0; i <= GostOids.MAX_RAW_OCSP_RESPONDER_CANDIDATES; i++) {
            raw.add(responder.cert);
        }

        assertThrows(PkixException.class, () -> verify(ocsp, raw));
    }
}
