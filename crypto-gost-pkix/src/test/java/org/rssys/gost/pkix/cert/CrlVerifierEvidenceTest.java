package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CrlVerifier.verifyEvidence: partial scope и окно")
class CrlVerifierEvidenceTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CDP = "http://crl.example.com/leaf.crl";

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair leafKp;
    private static GostCertificate leaf;
    private static KeyPair intKp;
    private static GostCertificate intCa;

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
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());

        leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leaf =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Leaf"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .crlDistributionPoints(CDP)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());

        intKp = KeyGenerator.generateKeyPair(PARAMS);
        intCa =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Int CA"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(intKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
    }

    @Test
    @DisplayName("onlyContainsUserCerts: leaf допустим, CA отвергается")
    void onlyContainsUserCertsScope() throws Exception {
        byte[] crl = crlWithIdp(idp(fl(true), null));
        RevocationEvidenceWindow window = window();

        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                CrlVerifier.verifyEvidence(
                        crl,
                        leaf,
                        root,
                        window,
                        RevocationFreshnessPolicy.STRICT,
                        CrlLimits.DEFAULT));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                crl,
                                intCa,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("onlyContainsCACerts: CA допустим, leaf отвергается")
    void onlyContainsCaCertsScope() throws Exception {
        byte[] crl = crlWithIdp(idp(fl(false), null));
        RevocationEvidenceWindow window = window();

        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                CrlVerifier.verifyEvidence(
                        crl,
                        intCa,
                        root,
                        window,
                        RevocationFreshnessPolicy.STRICT,
                        CrlLimits.DEFAULT));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                crl,
                                leaf,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("onlySomeReasons и onlyContainsAttributeCerts отвергаются")
    void unsupportedPartialFlagsRejected() throws Exception {
        RevocationEvidenceWindow window = window();
        byte[] onlyReasons = crlWithIdp(idp(null, tlv(0x83, new byte[] {(byte) 0xFF})));
        byte[] attributeCerts = crlWithIdp(idp(null, tlv(0x85, new byte[] {(byte) 0xFF})));

        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                onlyReasons,
                                leaf,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                attributeCerts,
                                leaf,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("distributionPoint должен совпадать с CDP сертификата")
    void distributionPointMustMatchCdp() throws Exception {
        RevocationEvidenceWindow window = window();
        byte[] matching = crlWithIdp(idp(null, fullName(CDP)));
        byte[] foreign = crlWithIdp(idp(null, fullName("http://crl.example.com/other.crl")));

        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                CrlVerifier.verifyEvidence(
                        matching,
                        leaf,
                        root,
                        window,
                        RevocationFreshnessPolicy.STRICT,
                        CrlLimits.DEFAULT));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                foreign,
                                leaf,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                matching,
                                intCa,
                                root,
                                window,
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("Легаси CrlVerifier: EXPIRED раньше SIGNATURE_INVALID")
    void legacyErrorPrecedenceUnchanged() throws Exception {
        String old = GostSignatureHelper.formatGeneralizedTime(Instant.now().minusSeconds(86400));
        byte[] expiredBadSignature =
                GostCrlBuilder.create(root.getSubjectDnBytes())
                        .thisUpdate(old)
                        .nextUpdate(old)
                        .withCrlNumber(1)
                        .sign(leafKp.getPrivate());

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> CrlVerifier.verify(expiredBadSignature, leaf, root));
        assertEquals(PkixException.Reason.EXPIRED, ex.reason());
    }

    @Test
    @DisplayName("STRICT: thisUpdate на границе skew и на 1 мс раньше")
    void strictSkewBoundaries() throws Exception {
        Instant signing =
                Instant.now().minusSeconds(60).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        RevocationEvidenceWindow window =
                new RevocationEvidenceWindow(signing, signing.plusSeconds(120));
        String onBoundary =
                GostSignatureHelper.formatGeneralizedTime(
                        signing.minusMillis(GostOids.CLOCK_SKEW_MS));
        String beforeBoundary =
                GostSignatureHelper.formatGeneralizedTime(
                        signing.minusMillis(GostOids.CLOCK_SKEW_MS + 1));

        byte[] on = crlWithIdp(idp(null, null), onBoundary, "20990601120000Z");
        byte[] before = crlWithIdp(idp(null, null), beforeBoundary, "20990601120000Z");

        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                CrlVerifier.verifyEvidence(
                        on,
                        leaf,
                        root,
                        window,
                        RevocationFreshnessPolicy.STRICT,
                        CrlLimits.DEFAULT));
        assertEquals(
                EvidenceFreshness.OUT_OF_WINDOW,
                CrlVerifier.verifyEvidence(
                        before,
                        leaf,
                        root,
                        window,
                        RevocationFreshnessPolicy.STRICT,
                        CrlLimits.DEFAULT));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                CrlVerifier.verifyEvidence(
                        before,
                        leaf,
                        root,
                        window,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("CRL без nextUpdate отвергается")
    void crlWithoutNextUpdateRejected() throws Exception {
        byte[] crl = crlWithIdp(idp(null, null), GostSignatureHelper.nowGeneralizedTime(), null);
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verifyEvidence(
                                        crl,
                                        leaf,
                                        root,
                                        window(),
                                        RevocationFreshnessPolicy.STRICT,
                                        CrlLimits.DEFAULT),
                        "CRL без nextUpdate должен быть отвергнут");
        assertEquals(
                PkixException.Reason.NEXT_UPDATE_MISSING,
                e.reason(),
                "причина отказа та же, что на прямом пути приёмки");
    }

    @Test
    @DisplayName("delta CRL в X-Long отвергается")
    void deltaCrlRejected() throws Exception {
        byte[] delta =
                GostCrlBuilder.create(root.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(1)
                        .sign(rootKp.getPrivate());
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                delta,
                                leaf,
                                root,
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    @Test
    @DisplayName("indirect CRL отвергается")
    void indirectCrlRejected() throws Exception {
        byte[] crl = crlWithIdp(idp(tlv(0x84, new byte[] {(byte) 0xFF}), null));
        assertThrows(
                PkixException.class,
                () ->
                        CrlVerifier.verifyEvidence(
                                crl,
                                leaf,
                                root,
                                window(),
                                RevocationFreshnessPolicy.STRICT,
                                CrlLimits.DEFAULT));
    }

    private static RevocationEvidenceWindow window() {
        return new RevocationEvidenceWindow(
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));
    }

    private static byte[] idp(byte[] flags, byte[] distributionPoint) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (distributionPoint != null) {
            out.writeBytes(distributionPoint);
        }
        if (flags != null) {
            out.writeBytes(flags);
        }
        return DerCodec.encodeSequence(out.toByteArray());
    }

    private static byte[] fl(boolean userCerts) {
        return tlv(userCerts ? 0x81 : 0x82, new byte[] {(byte) 0xFF});
    }

    private static byte[] fullName(String uri) {
        byte[] gn = tlv(0x86, uri.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] fullName = DerCodec.encodeTlv(0xA0, gn);
        return DerCodec.encodeTlv(0xA0, fullName);
    }

    private static byte[] tlv(int tag, byte[] value) {
        return DerCodec.encodeTlv(tag, value);
    }

    private static byte[] crlWithIdp(byte[] idpSeq) {
        return crlWithIdp(idpSeq, GostSignatureHelper.nowGeneralizedTime(), "20990601120000Z");
    }

    private static byte[] crlWithIdp(byte[] idpSeq, String thisUpdate, String nextUpdate) {
        byte[] idpExt =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.28"), DerCodec.encodeTlv(0x04, idpSeq));
        ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
        tbsOut.writeBytes(DerCodec.encodeTlv(0x02, new byte[] {0x01}));
        tbsOut.writeBytes(GostSignatureHelper.buildAlgId(PARAMS));
        tbsOut.writeBytes(root.getSubjectDnBytes());
        tbsOut.writeBytes(DerCodec.encodeTime(thisUpdate));
        if (nextUpdate != null) {
            tbsOut.writeBytes(DerCodec.encodeTime(nextUpdate));
        }
        tbsOut.writeBytes(DerCodec.encodeTlv(0xA0, DerCodec.encodeSequence(idpExt)));
        byte[] tbs = DerCodec.encodeSequence(tbsOut.toByteArray());
        byte[] hash = GostSignatureHelper.doHash(tbs, PARAMS.hlen);
        byte[] sig = Signature.signHash(hash, rootKp.getPrivate());
        return DerCodec.encodeSequence(
                tbs, GostSignatureHelper.buildAlgId(PARAMS), DerCodec.encodeBitString(sig));
    }
}
