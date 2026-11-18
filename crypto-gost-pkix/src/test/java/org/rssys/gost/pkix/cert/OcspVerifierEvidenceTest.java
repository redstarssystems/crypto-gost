package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;

@DisplayName("OcspVerifier.evaluateFreshness: границы окна")
class OcspVerifierEvidenceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final long SKEW = GostOids.CLOCK_SKEW_MS;
    private static final RevocationEvidenceWindow WINDOW =
            new RevocationEvidenceWindow(T0, T0.plusSeconds(3600));

    @Test
    @DisplayName("STRICT: thisUpdate на нижней границе skew — в окне")
    void strictLowerBoundary() {
        SingleOcspResponse target =
                sr(T0.minusMillis(SKEW), WINDOW.collectionTime().plusMillis(SKEW));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                OcspVerifier.evaluateFreshness(
                        target,
                        WINDOW,
                        RevocationFreshnessPolicy.STRICT,
                        GostOids.MAX_OCSP_AGE_MS));
    }

    @Test
    @DisplayName("STRICT: thisUpdate на 1 мс раньше границы — вне окна; ETSI_DEFAULT — в окне")
    void strictLowerBoundaryMinusOne() {
        SingleOcspResponse target =
                sr(T0.minusMillis(SKEW + 1), WINDOW.collectionTime().plusMillis(SKEW));
        assertEquals(
                EvidenceFreshness.OUT_OF_WINDOW,
                OcspVerifier.evaluateFreshness(
                        target,
                        WINDOW,
                        RevocationFreshnessPolicy.STRICT,
                        GostOids.MAX_OCSP_AGE_MS));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                OcspVerifier.evaluateFreshness(
                        target,
                        WINDOW,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        GostOids.MAX_OCSP_AGE_MS));
    }

    @Test
    @DisplayName("Верхняя граница thisUpdate и nextUpdate проверяется с skew")
    void upperBoundaries() {
        SingleOcspResponse thisUpdateFuture =
                sr(
                        WINDOW.collectionTime().plusMillis(SKEW + 1),
                        WINDOW.collectionTime().plusSeconds(3600));
        assertEquals(
                EvidenceFreshness.OUT_OF_WINDOW,
                OcspVerifier.evaluateFreshness(
                        thisUpdateFuture,
                        WINDOW,
                        RevocationFreshnessPolicy.STRICT,
                        GostOids.MAX_OCSP_AGE_MS));

        SingleOcspResponse nextUpdatePast =
                sr(T0.minusSeconds(1), WINDOW.collectionTime().minusMillis(SKEW + 1));
        assertEquals(
                EvidenceFreshness.OUT_OF_WINDOW,
                OcspVerifier.evaluateFreshness(
                        nextUpdatePast,
                        WINDOW,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        GostOids.MAX_OCSP_AGE_MS));
    }

    @Test
    @DisplayName("OCSP без nextUpdate использует MAX_OCSP_AGE относительно collection")
    void noNextUpdateUsesMaxAge() {
        Instant thisUpdate = WINDOW.collectionTime().minusMillis(GostOids.MAX_OCSP_AGE_MS);
        SingleOcspResponse inWindow = sr(thisUpdate, null);
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                OcspVerifier.evaluateFreshness(
                        inWindow,
                        WINDOW,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        GostOids.MAX_OCSP_AGE_MS));

        SingleOcspResponse outOfWindow = sr(thisUpdate.minusMillis(SKEW + 1), null);
        assertEquals(
                EvidenceFreshness.OUT_OF_WINDOW,
                OcspVerifier.evaluateFreshness(
                        outOfWindow,
                        WINDOW,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        GostOids.MAX_OCSP_AGE_MS));
    }

    @Test
    @DisplayName("revoked и unknown отклоняются независимо от окна")
    void statusRejectedBeforeWindow() {
        SingleOcspResponse revoked =
                new SingleOcspResponse(
                        new byte[] {0x01},
                        0xA1,
                        T0.minusSeconds(3600),
                        null,
                        new byte[32],
                        new byte[32]);
        SingleOcspResponse unknown =
                new SingleOcspResponse(
                        new byte[] {0x01},
                        0xA2,
                        T0.minusSeconds(3600),
                        null,
                        new byte[32],
                        new byte[32]);

        PkixException revokedEx =
                assertThrows(PkixException.class, () -> OcspVerifier.verifyStatus(revoked));
        assertEquals(PkixException.Reason.REVOKED, revokedEx.reason());
        assertThrows(PkixException.class, () -> OcspVerifier.verifyStatus(unknown));
    }

    private static SingleOcspResponse sr(Instant thisUpdate, Instant nextUpdate) {
        return new SingleOcspResponse(
                new byte[] {0x01}, 0xA0, thisUpdate, nextUpdate, new byte[32], new byte[32]);
    }
}
