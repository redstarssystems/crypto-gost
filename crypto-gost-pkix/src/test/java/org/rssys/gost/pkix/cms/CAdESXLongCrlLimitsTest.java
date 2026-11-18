package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.RevokedEntry;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;

/**
 * Пределы CRL в CAdES-X Long: проверка подписи, декодер revocation-values и построение. Превышение
 * - {@code CRL_LIMIT_EXCEEDED}, проверка отзыва не пропускается.
 */
@DisplayName("CAdES-X Long: пределы CRL")
class CAdESXLongCrlLimitsTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String TSA_POLICY = "1.2.3.4.5";
    private static final int ENTRIES = 11;
    private static final int ENTRIES_LIMIT = 10;
    private static final byte[] CONTENT = "xlong crl limits".getBytes();

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static TspTransport transport;
    private static GostCrl crlForSigner;
    private static GostCrl crlForAnchor;
    private static byte[] cadesTAttached;
    private static byte[] cadesTDetached;
    private static byte[] xlongAttached;
    private static byte[] xlongDetached;
    private static GostCrl embeddedCrl;
    private static byte[] xlongWithEmbeddedCrl;

    @BeforeAll
    static void setUp() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("Limits XLong Root");
        root =
                GostCertificateBuilder.create(PARAMS, rootDn)
                        .issuerDn(rootDn)
                        .publicKey(rootKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Limits XLong TSA"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(tsaKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                        .sign(rootKp.getPrivate());
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Limits XLong Signer"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());

        long[] serial = {1};
        transport =
                (req, url) -> {
                    try {
                        // escTimeStamp обязан быть позже signature-time-stamp
                        Thread.sleep(1100);
                        return TspResponseBuilder.create(req)
                                .signer(tsaKp.getPrivate(), tsaCert)
                                .policyOid(TSA_POLICY)
                                .serialNumber(BigInteger.valueOf(serial[0]++))
                                .accuracy(1)
                                .withCAdES()
                                .buildGranted();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        // Крупный CRL в поле crls SignedData: больше CRL-доказательств, чтобы предел размера,
        // меньший него, не задевал доказательства и срабатывал именно на встроенном CRL
        embeddedCrl = crlWithEntries(3, 3 * ENTRIES);
        cadesTAttached = cadesT(false, null);
        cadesTDetached = cadesT(true, null);
        byte[] cadesTEmbedded = cadesT(false, embeddedCrl);
        // CRL выпускаются после штампа подписи: доказательство обязано быть свежее штампа
        Thread.sleep(1100);
        crlForSigner = crlWithEntries(1, ENTRIES);
        crlForAnchor = crlWithEntries(2, 0);
        xlongAttached = embed(cadesTAttached, CrlLimits.DEFAULT);
        xlongDetached = embed(cadesTDetached, CrlLimits.DEFAULT);
        xlongWithEmbeddedCrl = embed(cadesTEmbedded, CrlLimits.DEFAULT);
    }

    private static byte[] cadesT(boolean detached, GostCrl embedded) throws Exception {
        CmsSignedDataBuilder builder =
                CmsSignedDataBuilder.create()
                        .data(CONTENT)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .detached(detached)
                        .withCAdES();
        if (embedded != null) {
            builder.addCrl(embedded);
        }
        byte[] bes = builder.build();
        return CAdESExtender.addTimestamp(bes, "local://tsa", transport, root);
    }

    private static byte[] embed(byte[] cadesT, CrlLimits limits) throws Exception {
        return CAdESExtender.embedXLongType1(
                cadesT,
                List.of(signerCert, root),
                Arrays.asList(crlForSigner, crlForAnchor),
                Arrays.asList((GostOcspResponse) null, null),
                "local://tsa",
                transport,
                RevocationFreshnessPolicy.STRICT,
                limits,
                root);
    }

    private static GostCrl crlWithEntries(int number, int count) throws Exception {
        List<RevokedEntry> entries = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            entries.add(new RevokedEntry(BigInteger.valueOf(i).toByteArray(), "20250601120000Z"));
        }
        return new GostCrl(
                GostCrlBuilder.create(root.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(number)
                        .addRevoked(entries)
                        .sign(rootKp.getPrivate()));
    }

    private static TrustAnchors anchors() {
        return TrustAnchors.ofCertificates(root);
    }

    private static CrlLimits entriesLimit() {
        return CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES_LIMIT);
    }

    private static CrlLimits sizeLimit() {
        return CrlLimits.DEFAULT.withMaxSize(crlForSigner.getEncoded().length - 1);
    }

    // ------------------------------------------------------------------------
    // Проверка подписи
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("verifyXLong: значения по умолчанию принимают подпись")
    void defaultsAccept() {
        assertDoesNotThrow(() -> CAdESVerifier.verifyXLong(xlongAttached, anchors()));
        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                xlongDetached,
                                CONTENT,
                                RevocationFreshnessPolicy.STRICT,
                                anchors()));
    }

    @Test
    @DisplayName("verifyXLong: превышение числа записей - CRL_LIMIT_EXCEEDED")
    void verifyEntriesLimitExceeded() {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        xlongAttached,
                                        RevocationFreshnessPolicy.STRICT,
                                        anchors(),
                                        entriesLimit()));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(
                e.getMessage().contains("revoked entries exceed maximum"),
                "сообщение называет предел записей: " + e.getMessage());
    }

    @Test
    @DisplayName("verifyXLong: превышение размера - CRL_LIMIT_EXCEEDED, а не «malformed DER»")
    void verifySizeLimitExceeded() {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        xlongAttached,
                                        RevocationFreshnessPolicy.STRICT,
                                        anchors(),
                                        sizeLimit()));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertTrue(e.getMessage().contains("size"), "сообщение называет размер: " + e.getMessage());
    }

    @Test
    @DisplayName("verifyXLong: ровно на пределе и поднятый предел принимают подпись")
    void verifyAtAndAboveLimitsAccepted() {
        int size = Math.max(crlForSigner.getEncoded().length, crlForAnchor.getEncoded().length);
        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                xlongAttached,
                                RevocationFreshnessPolicy.STRICT,
                                anchors(),
                                new CrlLimits(size, ENTRIES)));
        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                xlongAttached,
                                RevocationFreshnessPolicy.STRICT,
                                anchors(),
                                CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES + 1)));
    }

    @Test
    @DisplayName("verifyXLongDetached: пределы действуют и на detached-подпись")
    void detachedLimitsApply() {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLongDetached(
                                        xlongDetached,
                                        CONTENT,
                                        RevocationFreshnessPolicy.STRICT,
                                        anchors(),
                                        entriesLimit()));
        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                xlongDetached,
                                CONTENT,
                                RevocationFreshnessPolicy.STRICT,
                                anchors(),
                                CrlLimits.DEFAULT.withMaxRevokedEntries(ENTRIES)));
    }

    @Test
    @DisplayName("Полные перегрузки отвергают null вместо пределов")
    void nullLimitsRejected() {
        assertThrows(
                NullPointerException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                xlongAttached, RevocationFreshnessPolicy.STRICT, anchors(), null));
        assertThrows(
                NullPointerException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                xlongDetached,
                                CONTENT,
                                RevocationFreshnessPolicy.STRICT,
                                anchors(),
                                null));
        assertThrows(
                NullPointerException.class,
                () -> CAdESXLongData.decodeRevocationValues(new byte[] {0x30, 0x00}, null));
    }

    @Test
    @DisplayName("verifyXLong: предел размера доходит до CRL, встроенного в поле crls SignedData")
    void embeddedCrlInSignedDataObeysSizeLimit() {
        CrlLimits tight = CrlLimits.DEFAULT.withMaxSize(embeddedCrl.getEncoded().length - 1);
        assertTrue(
                tight.maxSize() >= crlForSigner.getEncoded().length,
                "предел не должен задевать CRL-доказательства");

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        xlongWithEmbeddedCrl,
                                        RevocationFreshnessPolicy.STRICT,
                                        anchors(),
                                        tight));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertDoesNotThrow(
                () -> CAdESVerifier.verifyXLong(xlongWithEmbeddedCrl, anchors()),
                "с умолчаниями подпись со встроенным CRL принимается");
    }

    // ------------------------------------------------------------------------
    // Декодер revocation-values
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("decodeRevocationValues: размер сверх предела - CRL_LIMIT_EXCEEDED")
    void decoderSizeLimitExceeded() throws Exception {
        byte[] der = CAdESXLongData.encodeRevocationValues(List.of(crlForSigner), List.of());

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> CAdESXLongData.decodeRevocationValues(der, sizeLimit()));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
        assertEquals(
                1,
                CAdESXLongData.decodeRevocationValues(der).crls().size(),
                "с умолчаниями CRL декодируется");
    }

    // ------------------------------------------------------------------------
    // Построение
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "embedXLongType1: превышение пределов при проверке доказательств перед встраиванием")
    void embedChecksLimits() {
        PkixException e =
                assertThrows(PkixException.class, () -> embed(cadesTAttached, entriesLimit()));

        assertEquals(PkixException.Reason.CRL_LIMIT_EXCEEDED, e.reason());
    }
}
