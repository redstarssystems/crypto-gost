package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Пределы CRL при проверке CMS SignedData: встроенные и внешние CRL, обязательный и
 * необязательный отзыв. Превышение - отказ, а не пропуск CRL.
 */
@DisplayName("CMS: пределы CRL при проверке подписи")
class CmsCrlLimitsTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int ENTRIES = 11;
    private static final int ENTRIES_LIMIT = 10;

    private static KeyPair caKp;
    private static GostCertificate caCert;
    private static KeyPair leafKp;
    private static GostCertificate leafCert;
    private static GostCrl crl;
    private static byte[] signedWithEmbeddedCrl;
    private static byte[] signedWithoutCrl;

    @BeforeAll
    static void setUp() throws Exception {
        caKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn = CmsTestUtils.buildDn("CN=Limits CA");
        caCert =
                GostCertificateBuilder.create(PARAMS, caDn)
                        .issuerDn(caDn)
                        .publicKey(caKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(caKp.getPrivate());
        leafKp = KeyGenerator.generateKeyPair(PARAMS);
        leafCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Limits Leaf"))
                        .issuerDn(caCert.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(caKp.getPrivate());
        crl = crlWithEntries(ENTRIES);
        signedWithEmbeddedCrl =
                CmsSignedDataBuilder.create()
                        .data("limits".getBytes())
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .addCertificate(caCert)
                        .addCrl(crl)
                        .build();
        signedWithoutCrl =
                CmsSignedDataBuilder.create()
                        .data("limits".getBytes())
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .addCertificate(caCert)
                        .build();
    }

    /** CRL УЦ с заданным числом записей; сертификат подписанта среди них не значится. */
    private static GostCrl crlWithEntries(int count) throws Exception {
        List<RevokedEntry> entries = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            entries.add(new RevokedEntry(BigInteger.valueOf(i).toByteArray(), "20250601120000Z"));
        }
        return new GostCrl(
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(7)
                        .addRevoked(entries)
                        .sign(caKp.getPrivate()));
    }

    private static VerifyOptions options(Revocation revocation) {
        return VerifyOptions.trusting(
                TrustAnchors.ofCertificates(caCert), SignerSelection.ALL, revocation);
    }

    private enum Mode {
        REQUIRED,
        IF_AVAILABLE
    }

    private static Revocation revocation(Mode mode, List<GostCrl> external) {
        return mode == Mode.REQUIRED
                ? Revocation.required(external)
                : Revocation.ifAvailable(external);
    }

    // ------------------------------------------------------------------------
    // Встроенный CRL
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @EnumSource(Mode.class)
    @DisplayName("Встроенный CRL: превышение числа записей - CRL_LIMIT_EXCEEDED при любой политике")
    void embeddedEntriesLimitExceeded(Mode mode) {
        VerifyOptions options =
                options(revocation(mode, List.of()))
                        .crlLimits(CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES_LIMIT));

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CmsSignedDataVerifier.verify(signedWithEmbeddedCrl, options),
                        "превышение предела не должно превращаться в пропуск CRL");

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(
                e.getMessage().contains("revoked entries exceed maximum"),
                "сообщение называет предел записей: " + e.getMessage());
    }

    @Test
    @DisplayName("Встроенный CRL: превышение размера - CRL_LIMIT_EXCEEDED, а не «Corrupted CRL»")
    void embeddedSizeLimitExceeded() {
        VerifyOptions options =
                options(Revocation.none())
                        .crlLimits(CrlLimits.DEFAULT.withMaxSize(crl.getEncoded().length - 1));

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CmsSignedDataVerifier.verify(signedWithEmbeddedCrl, options));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(e.getMessage().contains("size"), "сообщение называет размер: " + e.getMessage());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Mode.class)
    @DisplayName("Встроенный CRL: ровно на пределе принимается")
    void embeddedExactlyAtLimitsAccepted(Mode mode) {
        VerifyOptions options =
                options(revocation(mode, List.of()))
                        .crlLimits(new CrlLimits(crl.getEncoded().length, ENTRIES));

        assertDoesNotThrow(() -> CmsSignedDataVerifier.verify(signedWithEmbeddedCrl, options));
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Mode.class)
    @DisplayName("Значения по умолчанию пропускают тот же CRL")
    void defaultLimitsAcceptCrl(Mode mode) {
        VerifyOptions options = options(revocation(mode, List.of()));

        assertDoesNotThrow(() -> CmsSignedDataVerifier.verify(signedWithEmbeddedCrl, options));
        assertEquals(
                new CrlLimits(67_108_864, 1_000_000),
                CrlLimits.DEFAULT,
                "значения по умолчанию не должны меняться");
    }

    // ------------------------------------------------------------------------
    // Внешний CRL
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @EnumSource(Mode.class)
    @DisplayName("Внешний CRL: превышение числа записей - CRL_LIMIT_EXCEEDED")
    void externalEntriesLimitExceeded(Mode mode) {
        VerifyOptions options =
                options(revocation(mode, List.of(crl)))
                        .crlLimits(CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES_LIMIT));

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CmsSignedDataVerifier.verify(signedWithoutCrl, options));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Mode.class)
    @DisplayName("Внешний CRL: поднятый предел пропускает CRL")
    void externalRaisedLimitAccepted(Mode mode) {
        VerifyOptions options =
                options(revocation(mode, List.of(crl)))
                        .crlLimits(CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES));

        assertDoesNotThrow(() -> CmsSignedDataVerifier.verify(signedWithoutCrl, options));
    }

    // ------------------------------------------------------------------------
    // Параметры
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "VerifyOptions.crlLimits: null отвергается, пределы переживают detached и кандидатов")
    void optionsKeepLimitsAndRejectNull() {
        assertThrows(
                IllegalArgumentException.class, () -> options(Revocation.none()).crlLimits(null));

        byte[] detached =
                CmsSignedDataBuilder.create()
                        .data("limits".getBytes())
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .addCertificate(caCert)
                        .addCrl(crl)
                        .detached(true)
                        .build();
        VerifyOptions options =
                options(Revocation.required(List.of()))
                        .crlLimits(CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES_LIMIT))
                        .detached("limits".getBytes())
                        .untrustedCandidates(List.of());

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CmsSignedDataVerifier.verify(detached, options),
                        "пределы не должны теряться при detached() и untrustedCandidates()");
        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
    }
}
