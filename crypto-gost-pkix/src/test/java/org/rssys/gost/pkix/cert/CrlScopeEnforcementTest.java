package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_AKI;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_CRL_NUMBER;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_DELTA_CRL_INDICATOR;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_IDP;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_REASON_CODE;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.concat;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crl;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crlExtensions;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.extension;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.extensionList;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.integerValue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.reasonCodeValue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedEntry;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedList;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CrlVerifier: область CRL (IssuingDistributionPoint) на всех путях приёмки")
class CrlScopeEnforcementTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String CDP_A = "http://crl.example.test/a.crl";
    private static final String CDP_B = "http://crl.example.test/b.crl";
    private static final String CDP_OTHER = "http://crl.example.test/other.crl";
    private static final BigInteger LEAF_SERIAL = BigInteger.valueOf(5000);
    private static final int REMOVE_FROM_CRL = 8;

    private static KeyPair caKp;
    private static byte[] caDn;
    private static GostCertificate leaf;
    private static GostCertificate leafWithTwoCdps;
    private static GostCertificate subCa;

    @BeforeAll
    static void setUp() {
        caKp = KeyGenerator.generateKeyPair(PARAMS);
        caDn = GostDnParser.encodeDn("CN=Scope CA,O=Test,C=RU");
        KeyPair subjectKp = KeyGenerator.generateKeyPair(PARAMS);
        leaf = issue("CN=Leaf,O=Test,C=RU", subjectKp, LEAF_SERIAL, false, CDP_A);
        leafWithTwoCdps =
                issue(
                        "CN=Leaf2,O=Test,C=RU",
                        subjectKp,
                        BigInteger.valueOf(5001),
                        false,
                        CDP_A,
                        CDP_B);
        subCa = issue("CN=Sub CA,O=Test,C=RU", subjectKp, BigInteger.valueOf(5002), true, CDP_A);
    }

    private static GostCertificate issue(
            String subject, KeyPair subjectKp, BigInteger serial, boolean ca, String... cdps) {
        GostCertificateBuilder builder =
                GostCertificateBuilder.create(PARAMS, subject)
                        .publicKey(subjectKp.getPublic())
                        .issuerDn(caDn)
                        .notBefore("250101000000Z")
                        .notAfter("350101000000Z")
                        .serial(serial)
                        .crlDistributionPoints(cdps);
        if (ca) {
            builder.basicConstraints(true, null);
        }
        return GostCertificateBuilder.sign(builder.buildTbs(), GostSigner.of(caKp.getPrivate()));
    }

    // ------------------------------------------------------------------------
    // Сборка CRL
    // ------------------------------------------------------------------------

    private static byte[] tlv(int tag, byte... value) {
        return DerCodec.encodeTlv(tag, value);
    }

    private static byte[] idp(byte[]... fields) {
        return extension(OID_IDP, true, DerCodec.encodeSequence(concat(fields)));
    }

    private static byte[] distributionPoint(String uri) {
        byte[] generalName = tlv(0x86, uri.getBytes(StandardCharsets.US_ASCII));
        return tlv(0xA0, tlv(0xA0, generalName));
    }

    private static byte[] onlyUserCerts() {
        return tlv(0x81, (byte) 0xFF);
    }

    private static byte[] onlyCaCerts() {
        return tlv(0x82, (byte) 0xFF);
    }

    private static byte[] number(int crlNumber) {
        return extension(OID_CRL_NUMBER, false, integerValue(BigInteger.valueOf(crlNumber)));
    }

    private static byte[] deltaIndicator(int baseNumber) {
        return extension(
                OID_DELTA_CRL_INDICATOR, true, integerValue(BigInteger.valueOf(baseNumber)));
    }

    private static byte[] aki(byte... keyIdentifier) {
        return extension(OID_AKI, false, DerCodec.encodeSequence(tlv(0x80, keyIdentifier)));
    }

    private static byte[] entry(BigInteger serial) {
        return revokedEntry(serial, null);
    }

    private static byte[] removeEntry(BigInteger serial) {
        return revokedEntry(
                serial,
                extensionList(extension(OID_REASON_CODE, false, reasonCodeValue(REMOVE_FROM_CRL))));
    }

    /** CRL, подписанный УЦ: необязательный список записей и необязательный набор расширений. */
    private static byte[] signedCrl(byte[] revokedListOrNull, byte[]... extensions) {
        byte[] tail =
                revokedListOrNull == null
                        ? crlExtensions(extensions)
                        : concat(revokedListOrNull, crlExtensions(extensions));
        return crl(caKp.getPrivate(), PARAMS, caDn, tail);
    }

    private static PkixException.Reason verifyReason(byte[] crlDer, GostCertificate cert) {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        crlDer, cert, CrlTestCerts.issuerOf(caKp.getPublic())),
                        "CRL должен отклоняться как PkixException");
        return e.reason();
    }

    // ------------------------------------------------------------------------
    // Прямой путь
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("onlyContainsCACerts не покрывает конечный сертификат -> IDP_NOT_SUPPORTED")
    void onlyCaCertsDoesNotCoverLeaf() {
        byte[] crl = signedCrl(null, idp(onlyCaCerts()));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(crl, leaf));
    }

    @Test
    @DisplayName("onlyContainsUserCerts не покрывает CA -> IDP_NOT_SUPPORTED")
    void onlyUserCertsDoesNotCoverCa() {
        byte[] crl = signedCrl(null, idp(onlyUserCerts()));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(crl, subCa));
    }

    @Test
    @DisplayName(
            "onlyContainsUserCerts покрывает конечный сертификат: не отозван проходит, отозван ловится")
    void onlyUserCertsCoversLeaf() {
        byte[] clean = signedCrl(null, idp(onlyUserCerts()));
        assertDoesNotThrow(
                () -> CrlVerifier.verify(clean, leaf, CrlTestCerts.issuerOf(caKp.getPublic())));

        byte[] revoked = signedCrl(revokedList(entry(LEAF_SERIAL)), idp(onlyUserCerts()));
        assertEquals(PkixException.Reason.REVOKED, verifyReason(revoked, leaf));
    }

    @Test
    @DisplayName("onlyContainsCACerts покрывает CA")
    void onlyCaCertsCoversCa() {
        byte[] crl = signedCrl(null, idp(onlyCaCerts()));
        assertDoesNotThrow(
                () -> CrlVerifier.verify(crl, subCa, CrlTestCerts.issuerOf(caKp.getPublic())));
    }

    @Test
    @DisplayName("distributionPoint чужого сегмента без флагов не покрывает сертификат")
    void foreignDistributionPointRejected() {
        byte[] foreign = signedCrl(null, idp(distributionPoint(CDP_OTHER)));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(foreign, leaf));

        byte[] matching = signedCrl(null, idp(distributionPoint(CDP_A)));
        assertDoesNotThrow(
                () -> CrlVerifier.verify(matching, leaf, CrlTestCerts.issuerOf(caKp.getPublic())));
    }

    @Test
    @DisplayName("onlySomeReasons, onlyContainsAttributeCerts, nameRelativeToCRLIssuer отклоняются")
    void unsupportedIdpFlagsRejected() {
        byte[] someReasons = signedCrl(null, idp(tlv(0x83, (byte) 0x06, (byte) 0x40)));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(someReasons, leaf));

        byte[] attributeCerts = signedCrl(null, idp(tlv(0x85, (byte) 0xFF)));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(attributeCerts, leaf));

        byte[] nameRelative = signedCrl(null, idp(tlv(0xA0, tlv(0xA1, (byte) 0x00))));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, verifyReason(nameRelative, leaf));
    }

    @Test
    @DisplayName("Запись об отзыве в CRL чужого сегмента даёт REVOKED, а не IDP_NOT_SUPPORTED")
    void revokedEntryWinsOverScope() {
        // Подлинный CRL другого сегмента с номером сертификата: отзыв не должен потеряться
        byte[] foreign = signedCrl(revokedList(entry(LEAF_SERIAL)), idp(onlyCaCerts()));
        assertEquals(PkixException.Reason.REVOKED, verifyReason(foreign, leaf));

        byte[] foreignDp =
                signedCrl(revokedList(entry(LEAF_SERIAL)), idp(distributionPoint(CDP_OTHER)));
        assertEquals(PkixException.Reason.REVOKED, verifyReason(foreignDp, leaf));
    }

    @Test
    @DisplayName("Пустой IDP принимается как полный CRL")
    void emptyIdpIsFullCrl() {
        byte[] crl = signedCrl(null, idp());
        assertDoesNotThrow(
                () -> CrlVerifier.verify(crl, leaf, CrlTestCerts.issuerOf(caKp.getPublic())));
        assertDoesNotThrow(
                () -> CrlVerifier.verify(crl, subCa, CrlTestCerts.issuerOf(caKp.getPublic())));
    }

    // ------------------------------------------------------------------------
    // Делегированный путь
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("verifyDelegated применяет область: покрытие и порядок «отзыв, затем область»")
    void delegatedAppliesScope() {
        byte[] notCovering = signedCrl(null, idp(onlyCaCerts()));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verifyDelegated(
                                        notCovering,
                                        leaf,
                                        CrlTestCerts.issuerOf(caKp.getPublic()),
                                        List.of()));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, e.reason());

        byte[] foreignRevoked = signedCrl(revokedList(entry(LEAF_SERIAL)), idp(onlyCaCerts()));
        PkixException revoked =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verifyDelegated(
                                        foreignRevoked,
                                        leaf,
                                        CrlTestCerts.issuerOf(caKp.getPublic()),
                                        List.of()));
        assertEquals(PkixException.Reason.REVOKED, revoked.reason());

        byte[] covering = signedCrl(null, idp(onlyUserCerts()));
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verifyDelegated(
                                covering,
                                leaf,
                                CrlTestCerts.issuerOf(caKp.getPublic()),
                                List.of()));
    }

    // ------------------------------------------------------------------------
    // Пара base + delta
    // ------------------------------------------------------------------------

    private static byte[] base(byte[] revokedListOrNull, byte[]... extra) {
        byte[][] extensions = new byte[extra.length + 1][];
        extensions[0] = number(1);
        System.arraycopy(extra, 0, extensions, 1, extra.length);
        return signedCrl(revokedListOrNull, extensions);
    }

    private static byte[] delta(byte[] revokedListOrNull, byte[]... extra) {
        byte[][] extensions = new byte[extra.length + 2][];
        extensions[0] = number(2);
        extensions[1] = deltaIndicator(1);
        System.arraycopy(extra, 0, extensions, 2, extra.length);
        return signedCrl(revokedListOrNull, extensions);
    }

    private static PkixException.Reason pairReason(
            byte[] base, byte[] delta, GostCertificate cert) {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        base, delta, cert, CrlTestCerts.issuerOf(caKp.getPublic())),
                        "Пара base+delta должна отклоняться");
        return e.reason();
    }

    @Test
    @DisplayName("base+delta: согласованная область принимается, REMOVE_FROM_CRL снимает отзыв")
    void pairCoveredRemoveFromCrlApplies() {
        byte[] baseCrl = base(revokedList(entry(LEAF_SERIAL)), idp(onlyUserCerts()));
        byte[] deltaCrl = delta(revokedList(removeEntry(LEAF_SERIAL)), idp(onlyUserCerts()));
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                baseCrl, deltaCrl, leaf, CrlTestCerts.issuerOf(caKp.getPublic())));
    }

    @Test
    @DisplayName("base+delta: чужой delta с REMOVE_FROM_CRL не снимает отзыв из base")
    void foreignDeltaDoesNotRemoveRevocation() {
        byte[] baseCrl = base(revokedList(entry(LEAF_SERIAL)), idp(distributionPoint(CDP_A)));
        byte[] foreignDelta =
                delta(revokedList(removeEntry(LEAF_SERIAL)), idp(distributionPoint(CDP_OTHER)));
        assertEquals(PkixException.Reason.REVOKED, pairReason(baseCrl, foreignDelta, leaf));
    }

    @Test
    @DisplayName("base+delta: чужая base с номером даёт REVOKED, а не пропуск")
    void foreignBaseWithSerialIsRevoked() {
        byte[] foreignBase = base(revokedList(entry(LEAF_SERIAL)), idp(onlyCaCerts()));
        byte[] deltaCrl = delta(null, idp(onlyCaCerts()));
        assertEquals(PkixException.Reason.REVOKED, pairReason(foreignBase, deltaCrl, leaf));
    }

    @Test
    @DisplayName("base+delta: чужая пара без записи -> IDP_NOT_SUPPORTED")
    void foreignPairWithoutEntryRejected() {
        byte[] foreignBase = base(null, idp(onlyCaCerts()));
        byte[] foreignDelta = delta(null, idp(onlyCaCerts()));
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                pairReason(foreignBase, foreignDelta, leaf));
    }

    @Test
    @DisplayName("base+delta: оба покрывают сертификат по отдельности, но IDP различаются")
    void differentIdpOfBasAndDeltaRejected() {
        // Сертификат содержит оба CDP: каждая часть по отдельности покрывает его
        byte[] baseCrl = base(null, idp(distributionPoint(CDP_A)));
        byte[] deltaCrl = delta(null, idp(distributionPoint(CDP_B)));
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                pairReason(baseCrl, deltaCrl, leafWithTwoCdps));

        // Разные флаги, оба покрывают конечный сертификат (пустой IDP и onlyContainsUserCerts)
        byte[] fullBase = base(null, idp());
        byte[] userDelta = delta(null, idp(onlyUserCerts()));
        assertEquals(PkixException.Reason.IDP_NOT_SUPPORTED, pairReason(fullBase, userDelta, leaf));
    }

    @Test
    @DisplayName("base+delta: AKI с разными keyIdentifier -> отказ, у одного нет AKI -> принято")
    void akiConflictAndOneSidedAki() {
        byte[] baseCrl = base(null, aki((byte) 1, (byte) 2));
        byte[] deltaOtherKey = delta(null, aki((byte) 9, (byte) 9));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CrlVerifier.verify(
                                        baseCrl,
                                        deltaOtherKey,
                                        leaf,
                                        CrlTestCerts.issuerOf(caKp.getPublic())));
        assertTrue(
                e.getMessage().contains("AKI"), "Причина должна называть AKI: " + e.getMessage());

        byte[] deltaWithoutAki = delta(null);
        assertDoesNotThrow(
                () ->
                        CrlVerifier.verify(
                                baseCrl,
                                deltaWithoutAki,
                                leaf,
                                CrlTestCerts.issuerOf(caKp.getPublic())));
    }
}
