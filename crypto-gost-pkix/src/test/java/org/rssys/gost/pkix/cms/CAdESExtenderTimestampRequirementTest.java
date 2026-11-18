package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESExtender: обязательная signature-time-stamp для C/X Long")
class CAdESExtenderTimestampRequirementTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static GostCrl signerCrl;
    private static GostOcspResponse signerOcsp;
    private static KeyPair signer2Kp;
    private static GostCertificate signer2Cert;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static KeyPair countersignerKp;
    private static GostCertificate countersignerCert;

    @BeforeAll
    static void setUp() throws Exception {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKp.getPrivate(),
                        signerKp.getPublic(),
                        BigInteger.valueOf(1),
                        "Signer");
        signer2Kp = KeyGenerator.generateKeyPair(PARAMS);
        signer2Cert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signer2Kp.getPrivate(),
                        signer2Kp.getPublic(),
                        BigInteger.valueOf(2),
                        "Signer2");

        byte[] crlDer =
                GostCrlBuilder.create(signerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(signerKp.getPrivate());
        signerCrl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(signerCert.getSerialNumber())
                        .issuerDn(signerCert.getSubjectDnBytes())
                        .sign(signerKp.getPrivate());
        signerOcsp = new GostOcspResponse(ocspDer);

        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = CmsTestUtils.createTsaCert(tsaKp.getPrivate(), tsaKp.getPublic());

        countersignerKp = KeyGenerator.generateKeyPair(PARAMS);
        countersignerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        countersignerKp.getPrivate(),
                        countersignerKp.getPublic(),
                        BigInteger.valueOf(3),
                        "Countersigner");
    }

    // ========================================================================
    // Отсутствие метки
    // ========================================================================

    @Test
    @DisplayName("CAdES-C: BES с добавленными C-атрибутами без метки отвергается")
    void cadesCRejectsMissingTimestamp() throws Exception {
        byte[] cadesC = buildCadesC(buildBes(false));
        byte[] withoutT = modifyUnsignedAttrs(cadesC, GostOids.SIGNATURE_TIME_STAMP, null, -1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyC(
                                        withoutT,
                                        TrustAnchors.ofCertificates(signerCert, tsaCert)));
        assertTrue(
                ex.getMessage().contains("no signature-time-stamp"),
                "ожидалось сообщение об отсутствии метки, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("CAdES-X Long: подпись без метки отвергается")
    void cadesXLongRejectsMissingTimestamp() throws Exception {
        byte[] cadesXLong = buildCadesXLong(buildBes(false));
        byte[] withoutT = modifyUnsignedAttrs(cadesXLong, GostOids.SIGNATURE_TIME_STAMP, null, -1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        withoutT,
                                        TrustAnchors.ofCertificates(signerCert, tsaCert)));
        assertTrue(
                ex.getMessage().contains("no signature-time-stamp"),
                "ожидалось сообщение об отсутствии метки, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("detached CAdES-C: подпись без метки отвергается")
    void detachedCadesCRejectsMissingTimestamp() throws Exception {
        byte[] data = "detached cades-c".getBytes();
        byte[] cadesC = buildCadesC(buildBes(data, true));
        byte[] withoutT = modifyUnsignedAttrs(cadesC, GostOids.SIGNATURE_TIME_STAMP, null, -1);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyCDetached(
                                withoutT, data, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("detached CAdES-X Long: подпись без метки отвергается")
    void detachedCadesXLongRejectsMissingTimestamp() throws Exception {
        byte[] data = "detached cades-xlong".getBytes();
        byte[] cadesXLong = buildCadesXLong(buildBes(data, true));
        byte[] withoutT = modifyUnsignedAttrs(cadesXLong, GostOids.SIGNATURE_TIME_STAMP, null, -1);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                withoutT, data, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("CAdES-C: метка у одного из двух подписантов обязательна")
    void multiSignerMissingTimestampRejected() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("multi-signer".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();
        byte[] cadesC = buildCadesC(cadesBes);
        byte[] withoutSecondT = modifyUnsignedAttrs(cadesC, GostOids.SIGNATURE_TIME_STAMP, null, 1);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyC(
                                withoutSecondT,
                                TrustAnchors.ofCertificates(signerCert, signer2Cert, tsaCert)));
    }

    @Test
    @DisplayName("CAdES-X Long: метка у одного из двух подписантов обязательна")
    void cadesXLongMultiSignerMissingTimestampRejected() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("multi-signer-xlong".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();
        byte[] cadesXLong = buildCadesXLong(cadesBes);
        byte[] withoutSecondT =
                modifyUnsignedAttrs(cadesXLong, GostOids.SIGNATURE_TIME_STAMP, null, 1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        withoutSecondT,
                                        TrustAnchors.ofCertificates(
                                                signerCert, signer2Cert, tsaCert)));
        assertTrue(
                ex.getMessage().contains("no signature-time-stamp"),
                "ожидалось сообщение об отсутствии метки, получено: " + ex.getMessage());
    }

    // ========================================================================
    // Присутствующая, но невалидная метка
    // ========================================================================

    @Test
    @DisplayName("CAdES-C: метка с чужим messageImprint отвергается")
    void invalidTimestampRejected() throws Exception {
        byte[] tampered = withInvalidTimestamp(buildCadesC(buildBes(false)));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyC(
                                tampered, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("CAdES-X Long: метка с чужим messageImprint отвергается")
    void cadesXLongInvalidTimestampRejected() throws Exception {
        byte[] tampered = withInvalidTimestamp(buildCadesXLong(buildBes(false)));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                tampered, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("detached CAdES-C: метка с чужим messageImprint отвергается")
    void detachedCadesCInvalidTimestampRejected() throws Exception {
        byte[] data = "detached invalid cades-c".getBytes();
        byte[] tampered = withInvalidTimestamp(buildCadesC(buildBes(data, true)));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyCDetached(
                                tampered, data, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("detached CAdES-X Long: метка с чужим messageImprint отвергается")
    void detachedCadesXLongInvalidTimestampRejected() throws Exception {
        byte[] data = "detached invalid cades-xlong".getBytes();
        byte[] tampered = withInvalidTimestamp(buildCadesXLong(buildBes(data, true)));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                tampered, data, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("Пустой SET signature-time-stamp отвергается на T/C/X Long")
    void emptyTimestampSetRejected() throws Exception {
        byte[] cadesT = addLocalTimestamp(buildBes(false));
        byte[] cadesC = buildCadesC(buildBes(false));
        byte[] cadesXLong = buildCadesXLong(buildBes(false));
        byte[] emptyAttr = CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP);

        byte[] tWithEmpty =
                modifyUnsignedAttrs(cadesT, GostOids.SIGNATURE_TIME_STAMP, emptyAttr, -1);
        byte[] cWithEmpty =
                modifyUnsignedAttrs(cadesC, GostOids.SIGNATURE_TIME_STAMP, emptyAttr, -1);
        byte[] xWithEmpty =
                modifyUnsignedAttrs(cadesXLong, GostOids.SIGNATURE_TIME_STAMP, emptyAttr, -1);

        assertTrue(
                assertThrows(
                                PkixException.class,
                                () ->
                                        CAdESVerifier.verifyT(
                                                tWithEmpty,
                                                TrustAnchors.ofCertificates(signerCert, tsaCert)))
                        .getMessage()
                        .contains("empty SET"));
        assertTrue(
                assertThrows(
                                PkixException.class,
                                () ->
                                        CAdESVerifier.verifyC(
                                                cWithEmpty,
                                                TrustAnchors.ofCertificates(signerCert, tsaCert)))
                        .getMessage()
                        .contains("empty SET"));
        assertTrue(
                assertThrows(
                                PkixException.class,
                                () ->
                                        CAdESVerifier.verifyXLong(
                                                xWithEmpty,
                                                TrustAnchors.ofCertificates(signerCert, tsaCert)))
                        .getMessage()
                        .contains("empty SET"));
    }

    @Test
    @DisplayName("Несколько значений в одном экземпляре метки отвергаются")
    void multipleValuesInOneTimestampAttrRejected() throws Exception {
        byte[] cadesC = buildCadesC(buildBes(false));
        byte[] token = buildTimeStampToken(Digest.digest256("any".getBytes()), BigInteger.ONE);
        byte[] twoValues = CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP, token, token);
        byte[] tampered = modifyUnsignedAttrs(cadesC, GostOids.SIGNATURE_TIME_STAMP, twoValues, -1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyC(
                                        tampered,
                                        TrustAnchors.ofCertificates(signerCert, tsaCert)));
        assertTrue(
                ex.getMessage().contains("exactly one value"),
                "ожидалось сообщение о ровно одном значении, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Несколько отдельных экземпляров метки от разных TSA допускаются")
    void multipleTimestampInstancesAccepted() throws Exception {
        byte[] twoTimestamps = addLocalTimestamp(addLocalTimestamp(buildBes(false)));
        byte[] cadesC = buildCadesC(twoTimestamps);

        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyC(
                                cadesC, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("Смешанные экземпляры метки: пустой и валидный отвергаются")
    void mixedEmptyAndValidTimestampInstancesRejected() throws Exception {
        byte[] emptyAttr = CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP);
        byte[] besWithEmpty =
                modifyUnsignedAttrs(buildBes(false), GostOids.SIGNATURE_TIME_STAMP, emptyAttr, -1);
        byte[] mixedBes = addLocalTimestamp(besWithEmpty);

        PkixException embedEx =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESExtender.embedCompleteRefs(
                                        mixedBes,
                                        List.of(signerCert),
                                        List.of(signerCrl),
                                        List.of(signerOcsp)));
        assertTrue(
                embedEx.getMessage().contains("CAdES-T input required"),
                "ожидалось сообщение о требовании CAdES-T, получено: " + embedEx.getMessage());

        byte[] cadesC = buildCadesC(buildBes(false));
        byte[] mixedC = appendUnsignedAttr(cadesC, emptyAttr, -1);
        PkixException verifyEx =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyC(
                                        mixedC, TrustAnchors.ofCertificates(signerCert, tsaCert)));
        assertTrue(
                verifyEx.getMessage().contains("empty SET"),
                "ожидалось сообщение о пустом SET, получено: " + verifyEx.getMessage());
    }

    // ========================================================================
    // Embed-сторона
    // ========================================================================

    @Test
    @DisplayName("embedCompleteRefs отвергает BES без метки")
    void embedCompleteRefsRequiresTimestamp() throws Exception {
        byte[] cadesBes = buildBes(false);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESExtender.embedCompleteRefs(
                                        cadesBes,
                                        List.of(signerCert),
                                        List.of(signerCrl),
                                        List.of(signerOcsp)));
        assertTrue(
                ex.getMessage().contains("CAdES-T input required"),
                "ожидалось сообщение о требовании CAdES-T, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("embedXLongType1 без TSP отвергается: escTimeStamp требует TSA")
    void embedXLongWithoutTspRejected() throws Exception {
        byte[] cadesBes = buildBes(false);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESExtender.embedXLongType1(
                                        cadesBes,
                                        List.of(signerCert),
                                        List.of(signerCrl),
                                        List.of(signerOcsp),
                                        null,
                                        null));
        assertTrue(
                ex.getMessage().contains("requires TSP URL/transport"),
                "ожидалось сообщение о необходимости TSP, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("embedXLongType1 с TSP принимает CAdES-T и встраивает escTimeStamp")
    void embedXLongWithTspAcceptsCadesT() throws Exception {
        byte[] cadesT = addLocalTimestamp(buildBes(false));

        byte[] cadesXLong = embedXLong(cadesT);

        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("Пустой SET counterSignature отвергается")
    void emptyCounterSignatureSetRejected() throws Exception {
        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        buildBes(false), countersignerKp.getPrivate(), countersignerCert);
        byte[] emptyAttr = CmsAttribute.encode(GostOids.ATTR_COUNTERSIGNATURE);
        byte[] tampered =
                modifyUnsignedAttrs(countersigned, GostOids.ATTR_COUNTERSIGNATURE, emptyAttr, -1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyCountersignature(
                                        tampered,
                                        TrustAnchors.ofCertificates(
                                                signerCert, countersignerCert)));
        assertTrue(
                ex.getMessage().contains("empty SET"),
                "ожидалось сообщение о пустом SET, получено: " + ex.getMessage());
    }

    // ========================================================================
    // Фикстуры
    // ========================================================================

    private byte[] buildBes(boolean detached) throws Exception {
        return CmsSignedDataBuilder.create()
                .data("timestamp requirement".getBytes())
                .addSigner(signerKp.getPrivate(), signerCert)
                .withCAdES()
                .detached(detached)
                .build();
    }

    private byte[] buildBes(byte[] data, boolean detached) throws Exception {
        return CmsSignedDataBuilder.create()
                .data(data)
                .addSigner(signerKp.getPrivate(), signerCert)
                .withCAdES()
                .detached(detached)
                .build();
    }

    private byte[] buildCadesC(byte[] cadesBes) throws Exception {
        return CAdESExtender.embedCompleteRefs(
                addLocalTimestamp(cadesBes),
                List.of(signerCert),
                List.of(signerCrl),
                List.of(signerOcsp));
    }

    private byte[] buildCadesXLong(byte[] cadesBes) throws Exception {
        return embedXLong(addLocalTimestamp(cadesBes));
    }

    private byte[] withInvalidTimestamp(byte[] cades) throws Exception {
        byte[] wrongToken =
                buildTimeStampToken(Digest.digest256("wrong".getBytes()), BigInteger.ONE);
        return modifyUnsignedAttrs(
                cades,
                GostOids.SIGNATURE_TIME_STAMP,
                CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP, wrongToken),
                -1);
    }

    private byte[] addLocalTimestamp(byte[] cadesDer) throws Exception {
        return CAdESExtender.addTimestamp(
                cadesDer, "http://local.tsa", dynamicTsTransport(), tsaCert);
    }

    private TspTransport dynamicTsTransport() {
        return (req, url) -> {
            try {
                byte[] hash = extractMessageImprintFromRequest(req);
                BigInteger nonce = parseNonceFromRequest(req);
                byte[] token = buildTimeStampToken(hash, nonce);
                byte[] pkiStatus =
                        DerCodec.encodeSequence(
                                DerCodec.encodeInteger(
                                        BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
                return DerCodec.encodeSequence(pkiStatus, token);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private byte[] embedXLong(byte[] cadesDer) throws Exception {
        return CAdESExtender.embedXLongType1(
                cadesDer,
                List.of(signerCert),
                List.of(signerCrl),
                List.of(signerOcsp),
                "http://local.tsa",
                dynamicTsTransport(),
                tsaCert);
    }

    private byte[] buildTimeStampToken(byte[] sigHash, BigInteger nonce) throws Exception {
        byte[] tstInfo = buildTstInfo(sigHash, nonce);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKp.getPrivate(), tsaCert)
                .build();
    }

    private byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg =
                CmsAlgorithmIdentifier.encode(
                        hash.length == 32 ? GostOids.DIGEST_256 : GostOids.DIGEST_512);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(nonce);
        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    private static BigInteger parseNonceFromRequest(byte[] tspReqDer) {
        try {
            byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
            if (parts.length < 3) return BigInteger.ZERO;
            for (int i = 2; i < parts.length; i++) {
                if (parts[i].length > 0 && (parts[i][0] & 0xFF) == DerCodec.TAG_INTEGER) {
                    return DerCodec.parseInteger(parts[i], 0);
                }
            }
            return BigInteger.ZERO;
        } catch (Exception e) {
            return BigInteger.ZERO;
        }
    }

    private static byte[] extractMessageImprintFromRequest(byte[] tspReqDer) throws Exception {
        byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
        byte[][] miParts = DerCodec.parseSequenceContents(parts[1], 0);
        return DerCodec.parseOctetString(miParts[1], 0);
    }

    /**
     * Удаляет или заменяет unsigned-атрибут с заданным OID.
     *
     * @param onlySigner индекс SignerInfo для применения (-1 - все подписанты)
     */
    private static byte[] modifyUnsignedAttrs(
            byte[] signedDataDer, String oid, byte[] replacementOrNull, int onlySigner)
            throws Exception {
        return rewriteUnsignedAttrs(
                signedDataDer,
                onlySigner,
                attrs -> {
                    attrs.removeIf(attr -> oid.equals(CmsAttribute.decode(attr).attrType()));
                    if (replacementOrNull != null) {
                        attrs.add(replacementOrNull);
                    }
                });
    }

    private static byte[] appendUnsignedAttr(byte[] signedDataDer, byte[] attrDer, int onlySigner)
            throws Exception {
        return rewriteUnsignedAttrs(signedDataDer, onlySigner, attrs -> attrs.add(attrDer));
    }

    private static byte[] rewriteUnsignedAttrs(
            byte[] signedDataDer, int onlySigner, Consumer<List<byte[]>> mutator) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        int siIdx = sdParts.length - 1;
        byte[][] signerInfos = DerCodec.parseSetContents(sdParts[siIdx], 0);

        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        for (int s = 0; s < signerInfos.length; s++) {
            if (onlySigner >= 0 && s != onlySigner) {
                modifiedSignerInfos.add(signerInfos[s]);
                continue;
            }
            List<byte[]> parts =
                    new ArrayList<>(
                            Arrays.asList(DerCodec.parseSequenceContents(signerInfos[s], 0)));

            int unsignedIdx = -1;
            for (int i = 0; i < parts.size(); i++) {
                byte[] p = parts.get(i);
                if (p.length > 0 && (p[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                    unsignedIdx = i;
                    break;
                }
            }

            List<byte[]> attrs = new ArrayList<>();
            if (unsignedIdx >= 0) {
                byte[] field = parts.get(unsignedIdx);
                int[] lenInfo = DerCodec.decodeLength(field, 1);
                int contentOff = 1 + lenInfo[1];
                byte[] content = Arrays.copyOfRange(field, contentOff, field.length);
                int pos = 0;
                while (pos < content.length) {
                    int[] attrLen = DerCodec.decodeLength(content, pos + 1);
                    int attrTotal = 1 + attrLen[1] + attrLen[0];
                    attrs.add(Arrays.copyOfRange(content, pos, pos + attrTotal));
                    pos += attrTotal;
                }
            }
            mutator.accept(attrs);
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);

            if (unsignedIdx >= 0) {
                if (sorted.length == 0) {
                    parts.remove(unsignedIdx);
                } else {
                    parts.set(
                            unsignedIdx,
                            DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted)));
                }
            } else if (sorted.length > 0) {
                parts.add(DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted)));
            }
            modifiedSignerInfos.add(DerCodec.encodeSequence(parts.toArray(new byte[0][])));
        }

        List<byte[]> sd = new ArrayList<>(Arrays.asList(sdParts));
        sd.set(siIdx, DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][])));
        return CmsContentInfo.encode(
                GostOids.CMS_SIGNED_DATA, DerCodec.encodeSequence(sd.toArray(new byte[0][])));
    }
}
