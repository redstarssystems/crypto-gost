package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESExtenderXLong: embedXLongType1 -> verifyCAdESXLong полный цикл")
class CAdESExtenderXLongTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static KeyPair signer2Kp;
    private static GostCertificate signer2Cert;
    private static GostCrl signerCrl;
    private static GostOcspResponse signerOcsp;
    private static KeyPair otherKp;
    private static GostCertificate otherCert;
    private static KeyPair rootKp;
    private static GostCertificate rootCert;
    private static KeyPair caSignerKp;
    private static GostCertificate caSignerCert;
    private static KeyPair caSigner2Kp;
    private static GostCertificate caSigner2Cert;
    private static KeyPair intCAKp;
    private static GostCertificate intCACert;
    private static KeyPair leafUnderIntCAKp;
    private static GostCertificate leafUnderIntCACert;

    @BeforeAll
    static void setUp() throws Exception {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKp.getPrivate(),
                        signerKp.getPublic(),
                        BigInteger.valueOf(100),
                        "Signer");

        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = CmsTestUtils.createTsaCert(tsaKp.getPrivate(), tsaKp.getPublic());

        signer2Kp = KeyGenerator.generateKeyPair(PARAMS);
        signer2Cert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signer2Kp.getPrivate(),
                        signer2Kp.getPublic(),
                        BigInteger.valueOf(200),
                        "Signer2");

        otherKp = KeyGenerator.generateKeyPair(PARAMS);
        otherCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        otherKp.getPrivate(), otherKp.getPublic(), BigInteger.valueOf(99), "Other");

        // УЦ для multi-signer сценария
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        rootCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        rootKp.getPrivate(),
                        rootKp.getPublic(),
                        BigInteger.valueOf(700),
                        "MultiRoot");

        byte[] cs1DnDer = CmsTestUtils.buildDn("MultiSigner1");
        caSignerKp = KeyGenerator.generateKeyPair(PARAMS);
        caSignerCert =
                GostCertificateBuilder.create(PARAMS, cs1DnDer)
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .publicKey(caSignerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(rootKp.getPrivate());

        byte[] cs2DnDer = CmsTestUtils.buildDn("MultiSigner2");
        caSigner2Kp = KeyGenerator.generateKeyPair(PARAMS);
        caSigner2Cert =
                GostCertificateBuilder.create(PARAMS, cs2DnDer)
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .publicKey(caSigner2Kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(rootKp.getPrivate());

        // Промежуточный CA и leaf под ним для теста с 3-уровневой цепочкой (certRefs непуст)
        byte[] intDn = CmsTestUtils.buildDn("IntCA");
        intCAKp = KeyGenerator.generateKeyPair(PARAMS);
        intCACert =
                GostCertificateBuilder.create(PARAMS, intDn)
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .publicKey(intCAKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .basicConstraints(true, 0)
                        .sign(rootKp.getPrivate());
        byte[] leafUnderIntDn = CmsTestUtils.buildDn("LeafUnderIntCA");
        leafUnderIntCAKp = KeyGenerator.generateKeyPair(PARAMS);
        leafUnderIntCACert =
                GostCertificateBuilder.create(PARAMS, leafUnderIntDn)
                        .issuerDn(intCACert.getSubjectDnBytes())
                        .publicKey(leafUnderIntCAKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(intCAKp.getPrivate());

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
    }

    private byte[] addLocalTimestamp(byte[] cadesBesDer) throws Exception {
        byte[] sigHash = extractAndHashSignature(cadesBesDer);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        return CAdESExtender.addTimestamp(cadesBesDer, "http://local.tsa", mockTransport, tsaCert);
    }

    @Test
    @DisplayName("Полный roundtrip: CAdES-BES -> embedXLongType1 -> verifyCAdESXLong")
    void fullXLongRoundtrip() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("xlong test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        ocspList,
                        "http://local.tsa",
                        mockTransport,
                        tsaCert);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, signerCert, tsaCert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertNotNull(result.signers().get(0).completeCertRefs());
        assertNotNull(result.signers().get(0).certificateValues());
        assertNotNull(result.signers().get(0).revocationValues());
    }

    @Test
    @DisplayName("embedXLongType1 с предварительно построенным CAdES-T (tspUrl == null)")
    void embedXLongWithExistingCAdEST() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("xlong from T".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(cadesT, chain, crls, ocspList, null, null);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, signerCert, tsaCert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertTrue(
                result.signers().get(0).timestamps().size() >= 1,
                "Должна быть хотя бы одна метка времени (из CAdES-T)");
    }

    @Test
    @DisplayName("embedXLongType1 с CAdES-C на входе")
    void embedXLongWithCAdESC() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("xlong from C".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(cadesC, chain, crls, ocspList, null, null);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, signerCert, tsaCert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertNotNull(result.signers().get(0).certificateValues());
    }

    @Test
    @DisplayName("verifyCAdESXLong падает если атрибут certificate-values отсутствует")
    void verifyFailsWithoutCertValues() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("no cert-vals".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] cadesXLongNoCertVals = buildXLongWithOnlyRevocValues(cadesC, crls, ocspList);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESXLong(cadesXLongNoCertVals, signerCert, tsaCert),
                "Отсутствие certificate-values должно вызывать PkixException");
    }

    @Test
    @DisplayName("verifyCAdESXLong падает если атрибут revocation-values отсутствует")
    void verifyFailsWithoutRevocValues() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("no revoc-vals".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] cadesXLongNoRevocVals = buildXLongWithOnlyCertValues(cadesC, chain);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESXLong(cadesXLongNoRevocVals, signerCert, tsaCert),
                "Отсутствие revocation-values должно вызывать PkixException");
    }

    @Test
    @DisplayName(
            "verifyCAdESXLong падает если certHash из C-refs не совпадает с сертификатом в cert-values")
    void verifyFailsOnCertHashMismatch() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("hash mismatch".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] wrongCertValues = CAdESXLongData.encodeCertificateValues(List.of(otherCert));
        byte[] wrongCertValuesAttr =
                CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, wrongCertValues);

        byte[] revocValuesDer = CAdESXLongData.encodeRevocationValues(crls, ocspList);
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesC).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDerTest(signerInfos[0], wrongCertValuesAttr);
        modifiedSi = injectUnsignedAttrDerTest(modifiedSi, revocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        byte[] cadesXLongWrong = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESXLong(cadesXLongWrong, signerCert, tsaCert),
                "Несовпадение certHash в certificate-values должно вызывать PkixException");
    }

    @Test
    @DisplayName(
            "verifyCAdESXLong падает если crlHash из C-refs не совпадает с CRL в revocation-values")
    void verifyFailsOnCrlHashMismatch() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("crl hash mismatch".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] otherCrlDer =
                GostCrlBuilder.create(signerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(2)
                        .sign(signerKp.getPrivate());
        GostCrl otherCrl = new GostCrl(otherCrlDer);

        byte[] certValuesDer = CAdESXLongData.encodeCertificateValues(chain);
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, certValuesDer);

        byte[] wrongRevocValues =
                CAdESXLongData.encodeRevocationValues(List.of(otherCrl), ocspList);
        byte[] wrongRevocValuesAttr =
                CmsAttribute.encode(GostOids.REVOCATION_VALUES, wrongRevocValues);

        byte[] signedDataBody = CmsContentInfo.decode(cadesC).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDerTest(signerInfos[0], certValuesAttr);
        modifiedSi = injectUnsignedAttrDerTest(modifiedSi, wrongRevocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        byte[] cadesXLongWrong = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESXLong(cadesXLongWrong, signerCert, tsaCert),
                "Несовпадение crlHash в revocation-values должно вызывать PkixException");
    }

    @Test
    @DisplayName("verifyCAdESXLong падает если сертификат отозван по CRL")
    void verifyFailsWhenCertRevoked() throws Exception {
        KeyPair issuerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate issuerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        issuerKp.getPrivate(),
                        issuerKp.getPublic(),
                        BigInteger.valueOf(500),
                        "RevokedCA");

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDnDer = CmsTestUtils.buildDn("RevokedLeaf");
        GostCertificate leafCert =
                GostCertificateBuilder.create(PARAMS, leafDnDer)
                        .issuerDn(issuerCert.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(issuerKp.getPrivate());

        // CRL выпущенная УЦ, отзывающая leafCert
        byte[] revokingCrlDer =
                GostCrlBuilder.create(issuerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(10)
                        .addRevoked(
                                leafCert.getSerialNumber(),
                                GostSignatureHelper.nowGeneralizedTime())
                        .sign(issuerKp.getPrivate());
        GostCrl revokingCrl = new GostCrl(revokingCrlDer);

        // OCSP-ответ: отозван
        byte[] ocspDer =
                GostOcspResponseBuilder.create(leafCert.getSerialNumber())
                        .issuerDn(issuerCert.getSubjectDnBytes())
                        .revoked(GostSignatureHelper.nowGeneralizedTime())
                        .sign(issuerKp.getPrivate());
        GostOcspResponse ocspResp = new GostOcspResponse(ocspDer);

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("revoked signer".getBytes())
                        .addSigner(leafKp.getPrivate(), leafCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        List<GostCertificate> chain = List.of(leafCert, issuerCert);
        List<GostCrl> crls = Arrays.asList(revokingCrl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(ocspResp, null);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        ocspList,
                        "http://local.tsa",
                        mockTransport,
                        tsaCert);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESXLong(cadesXLong, issuerCert, tsaCert),
                "Отозванный сертификат должен вызывать PkixException при верификации");
    }

    @Test
    @DisplayName("content-time-stamp (ES-C): проверяется при верификации X-Long")
    void contentTimestampIsExtractedAndVerified() throws Exception {
        byte[] data = new byte[] {1, 2, 3};
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .contentTimestamp(
                                "http://local.tsa",
                                (req, url) -> {
                                    try {
                                        BigInteger reqNonce = parseNonceFromRequest(req);
                                        byte[] token =
                                                buildTimeStampToken(
                                                        org.rssys.gost.api.Digest.digest256(data),
                                                        reqNonce);
                                        return buildTspResponse(
                                                org.rssys.gost.api.Digest.digest256(data),
                                                token,
                                                reqNonce);
                                    } catch (Exception e) {
                                        throw new RuntimeException(e);
                                    }
                                },
                                tsaCert)
                        .build();

        List<GostCertificate> chain = List.of(signerCert);
        byte[] crlDer =
                GostCrlBuilder.create(signerCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(signerKp.getPrivate());
        GostCrl crl = new GostCrl(crlDer);
        List<GostCrl> crls = List.of(crl);
        List<GostOcspResponse> ocsp = Arrays.asList((GostOcspResponse) null);

        byte[] cadesXLong = CAdESExtender.embedXLongType1(cadesBes, chain, crls, ocsp, null, null);

        VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, signerCert, tsaCert);
        assertNotNull(
                result.signers().get(0).contentTimestamp(),
                "content-timestamp должен быть извлечён и проверен verifyCAdESXLong");
    }

    @Test
    @DisplayName("Multi-signer: два подписанта с общим УЦ — embed и структурная проверка")
    void multiSignerXLongRoundtrip() throws Exception {
        byte[] crlDer =
                GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(rootKp.getPrivate());
        GostCrl rootCrl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(caSignerCert.getSerialNumber())
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .sign(rootKp.getPrivate());
        GostOcspResponse rootOcsp = new GostOcspResponse(ocspDer);

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("multi xlong".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .addSigner(caSigner2Kp.getPrivate(), caSigner2Cert)
                        .addCertificate(rootCert)
                        .withCAdES()
                        .build();

        List<byte[]> sigHashes = extractAllSigHashes(cadesBes);
        assertEquals(2, sigHashes.size());

        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] reqHash = extractMessageImprintFromRequest(req);
                        byte[] token = buildTimeStampToken(reqHash, reqNonce);
                        return buildTspResponse(reqHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        List<GostCertificate> chain = List.of(caSignerCert, rootCert);
        List<GostCrl> crls = Arrays.asList(rootCrl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(rootOcsp, null);

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        ocspList,
                        "http://local.tsa",
                        mockTransport,
                        tsaCert);
        assertNotNull(cadesXLong);

        // Multi-signer: проверяем что оба подписанта присутствуют и подписи валидны
        VerifiedCAdESData result = CAdESExtender.verifyCAdEST(cadesXLong, rootCert, tsaCert);
        assertNotNull(result);
        assertEquals(2, result.signers().size());
        for (CAdESSignerResult sr : result.signers()) {
            assertNotNull(sr.signerCertificate());
            assertTrue(sr.timestamps().size() >= 1);
        }
    }

    @Test
    @DisplayName(
            "3-уровневая цепочка: RootCA->IntCA->Leaf — verifyCAdESXLong проходит (regression: certRefs непуст)")
    void xLongWithIntermediateCA() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("3-level xlong".getBytes())
                        .addSigner(leafUnderIntCAKp.getPrivate(), leafUnderIntCACert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = Arrays.asList(leafUnderIntCACert, intCACert, rootCert);

        byte[] crlDer =
                GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(rootKp.getPrivate());
        GostCrl crl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(leafUnderIntCACert.getSerialNumber())
                        .issuerDn(intCACert.getSubjectDnBytes())
                        .good()
                        .sign(intCAKp.getPrivate());
        GostOcspResponse ocsp = new GostOcspResponse(ocspDer);

        List<GostCrl> crls = Arrays.asList(null, crl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(ocsp, null, null);

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesXLong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        ocspList,
                        "http://local.tsa",
                        mockTransport,
                        tsaCert);
        assertNotNull(cadesXLong);

        // Проверяем что verifyCAdESXLong проходит (непадает с certHash/IssuerSerial mismatch)
        VerifiedCAdESData result = CAdESExtender.verifyCAdESXLong(cadesXLong, rootCert, tsaCert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertEquals(
                3,
                result.signers().get(0).certificateValues().size(),
                "certificate-values должна содержать 3 сертификата (leaf, intCA, root)");
        assertEquals(
                1,
                result.signers().get(0).revocationValues().crls().size(),
                "должен быть 1 CRL (от rootCA для intCA)");
        assertEquals(
                1,
                result.signers().get(0).revocationValues().ocspResponses().size(),
                "должен быть 1 OCSP (от intCA для leaf)");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static byte[] buildXLongWithOnlyRevocValues(
            byte[] cadesCDer, List<GostCrl> crls, List<GostOcspResponse> ocspList)
            throws Exception {
        int revocEnd = Math.max(1, 1);
        byte[] revocValuesDer =
                CAdESXLongData.encodeRevocationValues(
                        crls.subList(0, revocEnd), ocspList.subList(0, revocEnd));
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesCDer).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDerTest(signerInfos[0], revocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private static byte[] buildXLongWithOnlyCertValues(
            byte[] cadesCDer, List<GostCertificate> chain) throws Exception {
        byte[] certValuesDer = CAdESXLongData.encodeCertificateValues(chain);
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, certValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesCDer).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDerTest(signerInfos[0], certValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private static byte[] injectUnsignedAttrDerTest(byte[] signerInfoDer, byte[] attrDer)
            throws Exception {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "SignerInfo is empty");
        }

        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }

        byte[] newUnsignedAttrs;
        if (unsignedIdx >= 0) {
            byte[] existingField = siParts[unsignedIdx];
            int[] lenInfo = DerCodec.decodeLength(existingField, 1);
            int contentOff = 1 + lenInfo[1];
            byte[] existingContent =
                    Arrays.copyOfRange(existingField, contentOff, existingField.length);

            List<byte[]> attrs = new ArrayList<>();
            int pos = 0;
            while (pos < existingContent.length) {
                int[] attrLen = DerCodec.decodeLength(existingContent, pos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                attrs.add(Arrays.copyOfRange(existingContent, pos, pos + attrTotal));
                pos += attrTotal;
            }
            attrs.add(attrDer);
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);
            byte[] expandedContent = DerCodec.concat(sorted);
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, expandedContent);
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, attrDer);
            byte[][] newParts = Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newUnsignedAttrs;
            siParts = newParts;
        }

        return DerCodec.encodeSequence(siParts);
    }

    // ========================================================================
    // TSP helpers
    // ========================================================================

    private byte[] extractAndHashSignature(byte[] signedDataDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[] sigOctet = null;
        for (int i = siParts.length - 1; i >= 0; i--) {
            if ((siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                sigOctet = siParts[i];
                break;
            }
        }
        byte[] sig = DerCodec.parseOctetString(sigOctet, 0);
        int hlen = (sig.length == 64) ? 32 : 64;
        return hlen == 32
                ? org.rssys.gost.api.Digest.digest256(sig)
                : org.rssys.gost.api.Digest.digest512(sig);
    }

    private byte[] buildTimeStampToken(byte[] sigHash) throws Exception {
        return buildTimeStampToken(sigHash, BigInteger.valueOf(42));
    }

    private byte[] buildTimeStampToken(byte[] sigHash, BigInteger nonce) throws Exception {
        byte[] tstInfo = buildTstInfo(sigHash, nonce);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKp.getPrivate(), tsaCert)
                .build();
    }

    private byte[] buildTspResponse(byte[] sigHash, byte[] timeStampToken) {
        return buildTspResponse(sigHash, timeStampToken, BigInteger.valueOf(42));
    }

    private byte[] buildTspResponse(byte[] sigHash, byte[] timeStampToken, BigInteger nonce) {
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        return DerCodec.encodeSequence(pkiStatus, timeStampToken);
    }

    private byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg = CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256);
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

    private static byte[] extractMessageImprintFromRequest(byte[] tspReqDer) {
        byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
        if (parts.length < 2) return null;
        byte[][] miParts = DerCodec.parseSequenceContents(parts[1], 0);
        if (miParts.length < 2) return null;
        return DerCodec.parseOctetString(miParts[1], 0);
    }

    private List<byte[]> extractAllSigHashes(byte[] signedDataDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        List<byte[]> hashes = new ArrayList<>();
        for (byte[] si : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);
            byte[] sigOctet = null;
            for (int i = siParts.length - 1; i >= 0; i--) {
                if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                    sigOctet = siParts[i];
                    break;
                }
            }
            if (sigOctet == null) continue;
            byte[] sig = DerCodec.parseOctetString(sigOctet, 0);
            int hlen = (sig.length == 64) ? 32 : 64;
            byte[] hash =
                    hlen == 32
                            ? org.rssys.gost.api.Digest.digest256(sig)
                            : org.rssys.gost.api.Digest.digest512(sig);
            hashes.add(hash);
        }
        return hashes;
    }
}
