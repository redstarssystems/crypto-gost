package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.CertRevocationEvidence;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationEvidenceWindow;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspRequest;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESExtenderXLong: embedXLongType1 -> verifyXLong полный цикл")
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
        return CAdESExtender.addTimestamp(
                cadesBesDer, "http://local.tsa", dynamicTsTransport(), tsaCert);
    }

    private TspTransport dynamicTsTransport() {
        return (req, url) -> {
            try {
                TspRequest request = TspRequest.fromDer(req);
                byte[] hash = request.messageImprintHash();
                BigInteger nonce = parseNonceFromRequest(req);
                byte[] token = buildTimeStampToken(hash, nonce);
                return buildTspResponse(hash, token, nonce);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private byte[] embedXLong(
            byte[] cadesDer,
            List<GostCertificate> chain,
            List<GostCrl> crls,
            List<GostOcspResponse> ocsp)
            throws Exception {
        return CAdESExtender.embedXLongType1(
                cadesDer, chain, crls, ocsp, "http://local.tsa", dynamicTsTransport(), tsaCert);
    }

    @Test
    @DisplayName("Полный roundtrip: CAdES-BES -> embedXLongType1 -> verifyXLong")
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

        byte[] cadesXLong = embedXLong(cadesBes, chain, crls, ocspList);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertNotNull(result.signers().get(0).completeCertRefs());
        assertNotNull(result.signers().get(0).certificateValues());
        assertNotNull(result.signers().get(0).revocationValues());
    }

    @Test
    @DisplayName("Detached CAdES-C: verifyCDetached привязывает подпись к документу")
    void detachedCadesCRoundtrip() throws Exception {
        byte[] data = "detached cades-c".getBytes();
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .detached(true)
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        byte[] cadesC =
                CAdESExtender.embedCompleteRefs(
                        cadesT, chain, List.of(signerCrl), List.of(signerOcsp));

        VerifiedCAdESData result =
                CAdESVerifier.verifyCDetached(
                        cadesC, data, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertArrayEquals(data, result.data(), "detached-метод должен вернуть документ");
        assertNotNull(result.signers().get(0).completeCertRefs());
        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyCDetached(
                                cadesC,
                                "tampered".getBytes(),
                                TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "подменённый документ должен отклоняться");
    }

    @Test
    @DisplayName("Detached CAdES-X Long: verifyXLongDetached привязывает подпись к документу")
    void detachedCadesXLongRoundtrip() throws Exception {
        byte[] data = "detached cades-xlong".getBytes();
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .detached(true)
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        byte[] cadesXLong = embedXLong(cadesT, chain, List.of(signerCrl), List.of(signerOcsp));

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLongDetached(
                        cadesXLong, data, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertArrayEquals(data, result.data(), "detached-метод должен вернуть документ");
        assertNotNull(result.signers().get(0).certificateValues());
        assertNotNull(result.signers().get(0).revocationValues());
        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                cadesXLong,
                                "tampered".getBytes(),
                                TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "подменённый документ должен отклоняться");
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

        byte[] cadesXLong = embedXLong(cadesT, chain, crls, ocspList);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertTrue(
                result.signers().get(0).timestamps().size() >= 1,
                "Должна быть хотя бы одна метка времени (из CAdES-T)");
    }

    @Test
    @DisplayName(
            "OCSP-ответ со статусом не 0 (tryLater) в CAdES-C и X Long -> PkixException, не NPE")
    void nonSuccessfulOcspIsRejectedNotNullPointer() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("non-successful ocsp".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);
        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        // 30 03 0A 01 03: OCSPResponse со статусом tryLater без responseBytes
        List<GostOcspResponse> tryLater =
                List.of(new GostOcspResponse(new byte[] {0x30, 0x03, 0x0A, 0x01, 0x03}));

        PkixException refs =
                assertThrows(
                        PkixException.class,
                        () -> CAdESExtender.embedCompleteRefs(cadesT, chain, crls, tryLater),
                        "CAdES-C: ответ без responseBytes должен давать PkixException");
        assertTrue(
                refs.getMessage().contains("non-successful status 3"),
                "Ожидался отказ по статусу ответа, получено: " + refs.getMessage());

        PkixException xlong =
                assertThrows(
                        PkixException.class,
                        () -> embedXLong(cadesT, chain, crls, tryLater),
                        "X Long: ответ без responseBytes должен давать PkixException");
        assertTrue(
                xlong.getMessage().contains("non-successful status 3"),
                "Ожидался отказ по статусу ответа, получено: " + xlong.getMessage());
    }

    @Test
    @DisplayName("Построители CAdES-C и RevocationValues отвергают ответ со статусом не 0 напрямую")
    void builders_rejectNonSuccessfulOcspDirectly() throws Exception {
        List<GostOcspResponse> tryLater =
                List.of(new GostOcspResponse(new byte[] {0x30, 0x03, 0x0A, 0x01, 0x03}));

        PkixException refs =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESCompleteData.buildCompleteRefsResult(
                                        List.of(signerCert),
                                        List.of(signerCrl),
                                        tryLater,
                                        List.of()),
                        "buildCompleteRefsResult: ответ без responseBytes -> PkixException");
        assertTrue(
                refs.getMessage().contains("non-successful status 3"),
                "Ожидался отказ по статусу ответа, получено: " + refs.getMessage());

        PkixException values =
                assertThrows(
                        PkixException.class,
                        () -> CAdESXLongData.encodeRevocationValues(List.of(signerCrl), tryLater),
                        "encodeRevocationValues: ответ без responseBytes -> PkixException");
        assertTrue(
                values.getMessage().contains("non-successful status 3"),
                "Ожидался отказ по статусу ответа, получено: " + values.getMessage());
    }

    @Test
    @DisplayName("RevocationValues из контейнера: OCSP-ответ со статусом не 0 не декодируется")
    void decodeRevocationValues_rejectsNonSuccessfulOcsp() {
        // Через ocspVals нельзя получить ответ со статусом не 0: элемент с первым байтом 0A
        // разбирается как OCSPResponse и не является SEQUENCE, остальные идут как
        // BasicOCSPResponse, где структура 30 03 0A 01 03 недопустима
        byte[][] elements = {
            new byte[] {0x30, 0x03, 0x0A, 0x01, 0x03}, new byte[] {0x0A, 0x01, 0x03}
        };
        for (byte[] element : elements) {
            byte[] revocationValues =
                    DerCodec.encodeSequence(
                            DerCodec.encodeContextConstructed(1, DerCodec.encodeSequence(element)));

            assertThrows(
                    PkixException.class,
                    () -> CAdESXLongData.decodeRevocationValues(revocationValues),
                    "Ответ со статусом не 0 из контейнера должен давать PkixException");
        }
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

        byte[] cadesXLong = embedXLong(cadesC, chain, crls, ocspList);
        assertNotNull(cadesXLong);

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertNotNull(result.signers().get(0).certificateValues());
    }

    @Test
    @DisplayName("verifyBES принимает CAdES-C и X Long и не оценивает атрибуты старших уровней")
    void verifyBesAcceptsCompleteAndXLongWithoutEvaluatingHigherLevels() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("bes on higher levels".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);
        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);
        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);
        byte[] cadesXLong = embedXLong(cadesC, chain, crls, ocspList);
        // Только подписант: якоря TSA не нужны, потому что метки на уровне BES не проверяются
        TrustAnchors signerOnly = TrustAnchors.ofCertificates(signerCert);

        for (byte[] higherLevel : List.of(cadesC, cadesXLong)) {
            CAdESSignerResult signer =
                    CAdESVerifier.verifyBES(higherLevel, signerOnly).signers().get(0);
            assertTrue(
                    signer.timestamps().isEmpty(),
                    "verifyBES не проверяет метки старших уровней, список меток должен быть пуст");
            assertTrue(
                    signer.completeCertRefs().isEmpty() && signer.certificateValues().isEmpty(),
                    "verifyBES не возвращает C-референсы и значения X Long");
        }
    }

    @Test
    @DisplayName("verifyXLong падает если атрибут certificate-values отсутствует")
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
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLongNoCertVals,
                                TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Отсутствие certificate-values должно вызывать PkixException");
    }

    @Test
    @DisplayName("verifyXLong падает если атрибут revocation-values отсутствует")
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
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLongNoRevocVals,
                                TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Отсутствие revocation-values должно вызывать PkixException");
    }

    @Test
    @DisplayName(
            "verifyXLong падает если certHash из C-refs не совпадает с сертификатом в cert-values")
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
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLongWrong, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Несовпадение certHash в certificate-values должно вызывать PkixException");
    }

    @Test
    @DisplayName("certificate-values: дубликат подписанта с тем же ключом и другим DER отклоняется")
    void verifyFailsOnSameKeyDifferentDerWithoutCertRef() throws Exception {
        // CN должен совпадать с подписантом: иначе ChainValidator отклонит
        // цепочку по DN_MISMATCH, и тест не проверит CAdES-проверку.
        GostCertificate duplicateSigner =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKp.getPrivate(),
                        signerKp.getPublic(),
                        BigInteger.valueOf(101),
                        "Signer");
        assertTrue(
                Arrays.equals(signerCert.getSubjectDnBytes(), duplicateSigner.getSubjectDnBytes()),
                "дубликат должен иметь тот же subject DN");
        assertTrue(
                !signerCert.getSerialNumberBigInt().equals(duplicateSigner.getSerialNumberBigInt()),
                "дубликат должен иметь другой serial");
        assertTrue(
                !Arrays.equals(signerCert.getEncoded(), duplicateSigner.getEncoded()),
                "дубликат должен иметь другой DER");
        assertEquals(
                signerCert.getPublicKey(),
                duplicateSigner.getPublicKey(),
                "дубликат должен иметь тот же открытый ключ");

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("same key different der".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        List<GostCertificate> chain = List.of(signerCert);
        List<GostCrl> crls = List.of(signerCrl);
        List<GostOcspResponse> ocspList = List.of(signerOcsp);
        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesT, chain, crls, ocspList);

        byte[] certValuesDer =
                CAdESXLongData.encodeCertificateValues(List.of(signerCert, duplicateSigner));
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, certValuesDer);
        byte[] revocValuesDer = CAdESXLongData.encodeRevocationValues(crls, ocspList);
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        byte[] signedDataBody = CmsContentInfo.decode(cadesC).content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = injectUnsignedAttrDerTest(signerInfos[0], certValuesAttr);
        modifiedSi = injectUnsignedAttrDerTest(modifiedSi, revocValuesAttr);
        byte[] newSignerInfos = DerCodec.encodeSetOf(new byte[][] {modifiedSi});
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        byte[] cadesXLong = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        cadesXLong,
                                        TrustAnchors.ofCertificates(signerCert, tsaCert)),
                        "Неучтённый дубликат подписанта с тем же ключом и другим DER"
                                + " должен отклоняться");
        assertTrue(
                ex.getMessage() != null
                        && (ex.getMessage().contains("outside the primary verified chain")
                                || ex.getMessage().contains("escTimeStamp")),
                "ожидалось отклонение подменённых C-ссылок через escTimeStamp, получено: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName("verifyXLong падает если crlHash из C-refs не совпадает с CRL в revocation-values")
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
                () ->
                        CAdESVerifier.verifyXLong(
                                cadesXLongWrong, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "Несовпадение crlHash в revocation-values должно вызывать PkixException");
    }

    @Test
    @DisplayName("verifyXLong падает если сертификат отозван по CRL")
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

        List<GostCertificate> chain = List.of(leafCert, issuerCert);
        List<GostCrl> crls = Arrays.asList(revokingCrl, null);
        List<GostOcspResponse> ocspList = Arrays.asList(ocspResp, null);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> embedXLong(cadesBes, chain, crls, ocspList),
                        "Отозванный сертификат должен отклоняться при встраивании");
        assertTrue(
                ex.getMessage().contains("revoked"),
                "ожидалось сообщение об отзыве, получено: " + ex.getMessage());
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

        byte[] cadesXLong = embedXLong(addLocalTimestamp(cadesBes), chain, crls, ocsp);

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        cadesXLong, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertNotNull(
                result.signers().get(0).contentTimestamp(),
                "content-timestamp должен быть извлечён и проверен verifyXLong");
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
        VerifiedCAdESData result =
                CAdESVerifier.verifyT(cadesXLong, TrustAnchors.ofCertificates(rootCert, tsaCert));
        assertNotNull(result);
        assertEquals(2, result.signers().size());
        for (CAdESSignerResult sr : result.signers()) {
            assertNotNull(sr.signerCertificate());
            assertTrue(sr.timestamps().size() >= 1);
        }
    }

    @Test
    @DisplayName(
            "3-уровневая цепочка: RootCA->IntCA->Leaf — verifyXLong проходит (regression: certRefs непуст)")
    void xLongWithIntermediateCA() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("3-level xlong".getBytes())
                        .addSigner(leafUnderIntCAKp.getPrivate(), leafUnderIntCACert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = Arrays.asList(leafUnderIntCACert, intCACert, rootCert);

        // CRL строится до штампа, который embedXLong получает сам: thisUpdateNow() (на 5 минут
        // назад) оставляет нулевой запас до нижней границы окна STRICT и при смене секунды
        // между CRL и штампом выпадает из окна. Берём текущий момент.
        byte[] crlDer =
                GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                        .thisUpdate(Instant.now())
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

        byte[] cadesXLong = embedXLong(cadesBes, chain, crls, ocspList);
        assertNotNull(cadesXLong);

        // Проверяем что verifyXLong проходит (непадает с certHash/IssuerSerial mismatch)
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        cadesXLong, TrustAnchors.ofCertificates(rootCert, tsaCert));
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

    @Test
    @DisplayName(
            "X Long: цепочка certificate-values следует политике срока якоря (DEFAULT отклоняет, WARN допускает)")
    void xLongCertificateValuesChainFollowsExpiryPolicy() throws Exception {
        KeyPair expiredRootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] expiredRootDn = CmsTestUtils.buildDn("ExpiredXLongRoot");
        GostCertificate expiredRoot =
                GostCertificateBuilder.create(PARAMS, expiredRootDn)
                        .publicKey(expiredRootKp.getPublic())
                        .notBefore("200101000000Z")
                        .notAfter("210101000000Z")
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .basicConstraints(true, null)
                        .ski()
                        .randomSerial()
                        .sign(expiredRootKp.getPrivate());
        KeyPair intKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate intCa =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("ExpiredXLongInt"))
                        .issuerDn(expiredRootDn)
                        .publicKey(intKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .basicConstraints(true, 0)
                        .sign(expiredRootKp.getPrivate());
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate leaf =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("ExpiredXLongLeaf"))
                        .issuerDn(intCa.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(intKp.getPrivate());
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("expired xlong root".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .withCAdES()
                        .build();
        // thisUpdateNow() даёт «сейчас - CLOCK_SKEW_MS», то есть ровно нижнюю границу окна STRICT
        // (thisUpdate >= время подписи - CLOCK_SKEW_MS). Штамп времени получает отметку позже CRL,
        // и при переходе на следующую секунду между ними CRL выпадал из окна. Берём текущий момент:
        // он внутри окна с запасом.
        GostCrl crl =
                new GostCrl(
                        GostCrlBuilder.create(expiredRoot.getSubjectDnBytes())
                                .thisUpdate(Instant.now())
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(expiredRootKp.getPrivate()));
        GostOcspResponse ocsp =
                new GostOcspResponse(
                        GostOcspResponseBuilder.create(leaf.getSerialNumber())
                                .issuerDn(intCa.getSubjectDnBytes())
                                .good()
                                .sign(intKp.getPrivate()));
        byte[] cadesXLong =
                embedXLong(
                        cadesBes,
                        Arrays.asList(leaf, intCa, expiredRoot),
                        Arrays.asList(null, crl, null),
                        Arrays.asList(ocsp, null, null));

        TrustAnchors byDefault = TrustAnchors.ofCertificates(expiredRoot, tsaCert);
        PkixException rejected =
                assertThrows(
                        PkixException.class,
                        () -> CAdESVerifier.verifyXLong(cadesXLong, byDefault),
                        "DEFAULT в CAdES трактуется как REJECT и для цепочки certificate-values");
        assertEquals(PkixException.Reason.EXPIRED, rejected.reason());

        VerifiedCAdESData warned =
                CAdESVerifier.verifyXLong(
                        cadesXLong, byDefault.withExpiryPolicy(AnchorExpiryPolicy.WARN));
        assertEquals(
                3,
                warned.signers().get(0).certificateValues().size(),
                "Явный WARN должен допускать истёкший якорь в цепочке certificate-values");
    }

    @Test
    @DisplayName("X Long: certificate-values в произвольном порядке канонизируются")
    void xLongCanonicalizesCertificateValuesOrder() throws Exception {
        NcChain c = createNcChain();
        byte[] xlong = buildXLong(c, List.of(c.signer, c.intCert, c.root));
        byte[] modified = replaceCertValues(xlong, List.of(c.signer, c.root, c.intCert));

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(modified, TrustAnchors.ofCertificates(c.root, tsaCert));
        List<GostCertificate> values = result.signers().get(0).certificateValues();
        assertEquals(3, values.size());
        assertTrue(Arrays.equals(values.get(0).getEncoded(), c.signer.getEncoded()));
        assertTrue(Arrays.equals(values.get(1).getEncoded(), c.intCert.getEncoded()));
        assertTrue(Arrays.equals(values.get(2).getEncoded(), c.root.getEncoded()));
    }

    @Test
    @DisplayName("X Long: корень можно опустить в certificate-values")
    void xLongAcceptsMissingRoot() throws Exception {
        NcChain c = createNcChain();
        byte[] xlong =
                replaceCertValues(
                        buildXLong(c, List.of(c.signer, c.intCert, c.root)),
                        List.of(c.signer, c.intCert));

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(c.root, tsaCert));
        List<GostCertificate> values = result.signers().get(0).certificateValues();
        assertEquals(3, values.size(), "результат содержит канонизированную цепочку с якорем");
        assertTrue(Arrays.equals(values.get(2).getEncoded(), c.root.getEncoded()));
    }

    @Test
    @DisplayName("X Long: отсутствующий промежуточный сертификат отклоняется")
    void xLongRejectsMissingIntermediate() throws Exception {
        NcChain c = createNcChain();
        byte[] xlong = buildXLong(c, List.of(c.signer, c.intCert, c.root));
        byte[] modified = replaceCertValues(xlong, List.of(c.signer, c.root));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                modified, TrustAnchors.ofCertificates(c.root, tsaCert)));
    }

    @Test
    @DisplayName("X Long: посторонний сертификат в certificate-values отклоняется")
    void xLongRejectsForeignCertificate() throws Exception {
        NcChain c = createNcChain();
        byte[] xlong = buildXLong(c, List.of(c.signer, c.intCert, c.root));
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreign =
                CmsTestUtils.createSelfSignedCertWithDn(
                        foreignKp.getPrivate(),
                        foreignKp.getPublic(),
                        BigInteger.valueOf(901),
                        "Foreign");
        byte[] modified = replaceCertValues(xlong, List.of(c.signer, c.intCert, c.root, foreign));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        modified, TrustAnchors.ofCertificates(c.root, tsaCert)));
        assertTrue(
                ex.getMessage() != null
                        && ex.getMessage().contains("outside the primary verified chain"),
                "ожидалось отклонение сертификата вне первичной цепочки, получено: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName("X Long: поддельный корень с тем же ключом и DN отклоняется")
    void xLongRejectsFakeRootWithTrustedKey() throws Exception {
        NcChain c = createNcChain();
        byte[] xlong = buildXLong(c, List.of(c.signer, c.intCert, c.root));
        KeyPair attackerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate fakeRoot =
                GostCertificateBuilder.create(PARAMS, c.root.getSubjectDnBytes())
                        .issuerDn(c.root.getSubjectDnBytes())
                        .publicKey(c.root.getPublicKey())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .sign(attackerKp.getPrivate());
        byte[] modified = replaceCertValues(xlong, List.of(c.signer, c.intCert, c.root, fakeRoot));

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        modified, TrustAnchors.ofCertificates(c.root, tsaCert)));
        assertTrue(
                ex.getMessage() != null
                        && ex.getMessage().contains("outside the primary verified chain"),
                "ожидалось отклонение поддельного корня, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("X Long: отозванный промежуточный CA из первичной цепочки отклоняется")
    void xLongRejectsRevokedIntermediate() throws Exception {
        NcChain c = createNcChain();
        byte[] crlDer =
                GostCrlBuilder.create(c.root.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(10)
                        .addRevoked(
                                c.intCert.getSerialNumber(),
                                GostSignatureHelper.nowGeneralizedTime())
                        .sign(c.rootKp.getPrivate());
        GostCrl crl = new GostCrl(crlDer);
        List<GostOcspResponse> ocsp = goodOcsp(c, List.of(c.signer, c.intCert, c.root));
        ocsp.set(1, null);
        assertThrows(
                PkixException.class,
                () ->
                        buildXLong(
                                c,
                                List.of(c.signer, c.intCert, c.root),
                                Arrays.asList(null, crl, null),
                                ocsp),
                "Отозванный промежуточный CA должен отклоняться при встраивании");
    }

    @Test
    @DisplayName("X Long: несоответствие цепочки и доказательств отклоняется при встраивании")
    void xLongRejectsInconsistentChainEvidence() throws Exception {
        NcChain c = createNcChain();
        byte[] signerOcspDer =
                GostOcspResponseBuilder.create(c.signer.getSerialNumber())
                        .issuerDn(c.intCert.getSubjectDnBytes())
                        .good()
                        .sign(c.intKp.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        buildXLong(
                                c,
                                List.of(c.signer, c.root),
                                Arrays.asList(null, null),
                                Arrays.asList(new GostOcspResponse(signerOcspDer), null)),
                "OCSP должен отклоняться, если цепочка не содержит его издателя");
    }

    @Test
    @DisplayName("X Long: отсутствие данных отзыва подписанта отклоняется")
    void xLongRejectsMissingSignerRevocationData() throws Exception {
        byte[] ocspDer =
                GostOcspResponseBuilder.create(caSignerCert.getSerialNumber())
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .good()
                        .sign(rootKp.getPrivate());
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("signer no revoc".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);
        byte[] xlong =
                embedXLong(
                        cadesT,
                        List.of(caSignerCert, rootCert),
                        Arrays.asList(null, null),
                        Arrays.asList(new GostOcspResponse(ocspDer), null));

        CAdESCompleteData.OcspIdentifier ocspId =
                new CAdESCompleteData.OcspIdentifier(
                        DerCodec.encodeContextConstructed(1, rootCert.getSubjectDnBytes()),
                        GostSignatureHelper.nowGeneralizedTime());
        byte[] emptyHashRef =
                CAdESCompleteData.encodeCrlOcspRef(
                        List.of(), List.of(CAdESCompleteData.encodeOcspResponsesID(ocspId, null)));
        byte[] revocRefsDer = CAdESCompleteData.encodeCompleteRevocationRefs(List.of(emptyHashRef));
        byte[] emptyValuesDer = CAdESXLongData.encodeRevocationValues(List.of(), List.of());
        xlong =
                replaceUnsignedAttr(
                        xlong,
                        GostOids.COMPLETE_REVOCATION_REFS,
                        CmsAttribute.encode(GostOids.COMPLETE_REVOCATION_REFS, revocRefsDer));
        xlong =
                replaceUnsignedAttr(
                        xlong,
                        GostOids.REVOCATION_VALUES,
                        CmsAttribute.encode(GostOids.REVOCATION_VALUES, emptyValuesDer));

        final byte[] modified = xlong;
        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                modified, TrustAnchors.ofCertificates(rootCert, tsaCert)));
    }

    @Test
    @DisplayName("X Long: OCSP-ответ для чужого сертификата отклоняется")
    void xLongRejectsOcspForForeignCertificate() throws Exception {
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreign =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Foreign Ocsp"))
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .publicKey(foreignKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());
        byte[] foreignOcspDer =
                GostOcspResponseBuilder.create(foreign.getSerialNumber())
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .good()
                        .sign(rootKp.getPrivate());
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("foreign ocsp".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        assertThrows(
                PkixException.class,
                () ->
                        embedXLong(
                                cadesT,
                                List.of(caSignerCert, rootCert),
                                Arrays.asList(null, null),
                                Arrays.asList(new GostOcspResponse(foreignOcspDer), null)),
                "OCSP для чужого сертификата должен отклоняться уже при встраивании");
    }

    @Test
    @DisplayName("STRICT отвергает CRL, выпущенный до подписи; ETSI_DEFAULT принимает")
    void strictRejectsCrlIssuedBeforeSignature() throws Exception {
        String oldThisUpdate =
                GostSignatureHelper.formatGeneralizedTime(Instant.now().minusSeconds(3600));
        GostCrl oldCrl =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdate(oldThisUpdate)
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        List<GostCertificate> chain = List.of(caSignerCert, rootCert);
        List<GostCrl> crls = Arrays.asList(oldCrl, null);
        List<GostOcspResponse> noOcsp = Arrays.asList(null, null);

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("strict crl".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();

        assertThrows(
                PkixException.class,
                () -> embedXLong(cadesBes, chain, crls, noOcsp),
                "STRICT должен отвергать CRL, выпущенный до подписи");

        byte[] xlong =
                CAdESExtender.embedXLongType1(
                        cadesBes,
                        chain,
                        crls,
                        noOcsp,
                        "http://local.tsa",
                        dynamicTsTransport(),
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        tsaCert);
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(
                        xlong,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        TrustAnchors.ofCertificates(rootCert, tsaCert));
        assertEquals(RevocationFreshnessPolicy.ETSI_DEFAULT, result.revocationPolicy());
    }

    @Test
    @DisplayName(
            "STRICT: CRL от thisUpdateNow(), построенный до штампа, вне окна; Instant.now() внутри")
    void thisUpdateNowCrlBuiltBeforeStampIsOutsideStrictWindow() throws Exception {
        GostCrl shiftedCrl =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdateNow()
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        GostCrl currentCrl =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdate(Instant.now())
                                .nextUpdateDays(30)
                                .withCrlNumber(2)
                                .sign(rootKp.getPrivate()));
        List<GostCertificate> chain = List.of(caSignerCert, rootCert);
        List<GostOcspResponse> noOcsp = Arrays.asList(null, null);
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("shifted crl".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();

        // штамп получает embedXLong; пауза гарантирует смену секунды между CRL и штампом,
        // поэтому результат детерминирован, а не зависит от момента запуска
        Thread.sleep(1100);

        PkixException rejected =
                assertThrows(
                        PkixException.class,
                        () -> embedXLong(cadesBes, chain, Arrays.asList(shiftedCrl, null), noOcsp),
                        "thisUpdateNow() даёт нулевой запас: CRL до штампа выпадает из окна STRICT");
        // именно окно свежести, а не другая ошибка встраивания
        assertEquals(
                PkixException.Reason.REVOCATION_EVIDENCE_OUT_OF_WINDOW,
                rejected.reason(),
                "ожидалось нарушение окна STRICT, получено: " + rejected.getMessage());
        assertTrue(
                rejected.getMessage().contains("evidence issued before signature time"),
                "ожидалась подсказка о доказательстве, выпущенном до подписи: "
                        + rejected.getMessage());
        assertNotNull(
                embedXLong(cadesBes, chain, Arrays.asList(currentCrl, null), noOcsp),
                "CRL с thisUpdate = текущий момент должен укладываться в окно STRICT");
    }

    @Test
    @DisplayName("CRL без nextUpdate отвергается в обеих политиках")
    void crlWithoutNextUpdateRejected() throws Exception {
        GostCrl noNextUpdate =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .withoutNextUpdate()
                                .thisUpdateNow()
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("no nextUpdate".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();
        List<GostCertificate> chain = List.of(caSignerCert, rootCert);
        List<GostCrl> crls = Arrays.asList(noNextUpdate, null);
        List<GostOcspResponse> noOcsp = Arrays.asList(null, null);

        for (RevocationFreshnessPolicy policy : RevocationFreshnessPolicy.values()) {
            PkixException ex =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    CAdESExtender.embedXLongType1(
                                            cadesBes,
                                            chain,
                                            crls,
                                            noOcsp,
                                            "http://local.tsa",
                                            dynamicTsTransport(),
                                            policy,
                                            tsaCert));
            assertTrue(
                    ex.getMessage().contains("nextUpdate"),
                    "ожидалось требование nextUpdate, получено: " + ex.getMessage());
        }
    }

    @Test
    @DisplayName("Несколько CRL/OCSP: revoked в любом доказательстве отклоняет")
    void multipleEvidenceAnyRevokedRejects() throws Exception {
        byte[] goodOcspDer =
                GostOcspResponseBuilder.create(caSignerCert.getSerialNumber())
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .good()
                        .sign(rootKp.getPrivate());
        byte[] revokedOcspDer =
                GostOcspResponseBuilder.create(caSignerCert.getSerialNumber())
                        .issuerDn(rootCert.getSubjectDnBytes())
                        .revoked(GostSignatureHelper.nowGeneralizedTime())
                        .sign(rootKp.getPrivate());
        RevocationEvidenceWindow window =
                new RevocationEvidenceWindow(
                        Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));
        CertRevocationEvidence evidence =
                new CertRevocationEvidence(
                        List.of(),
                        List.of(new GostOcspResponse(goodOcspDer).getEncoded(), revokedOcspDer));

        assertThrows(
                PkixException.class,
                () ->
                        ChainValidator.validateRevocationEvidence(
                                List.of(caSignerCert, rootCert),
                                List.of(evidence, new CertRevocationEvidence(List.of(), List.of())),
                                window,
                                RevocationFreshnessPolicy.STRICT),
                "revoked в любом доказательстве должен отклонять");
    }

    @Test
    @DisplayName("Подмена escTimeStamp ломает верификацию")
    void tamperedEscTimestampRejected() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("tamper esc".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] xlong =
                embedXLong(cadesBes, List.of(signerCert), List.of(signerCrl), List.of(signerOcsp));

        byte[] wrongToken =
                buildTimeStampToken(
                        org.rssys.gost.api.Digest.digest256("wrong".getBytes()), BigInteger.ONE);
        byte[] tampered =
                replaceUnsignedAttr(
                        xlong,
                        GostOids.ESC_TIME_STAMP,
                        CmsAttribute.encode(GostOids.ESC_TIME_STAMP, wrongToken));

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                tampered, TrustAnchors.ofCertificates(signerCert, tsaCert)),
                "escTimeStamp с чужим messageImprint должен отклоняться");
    }

    @Test
    @DisplayName("embedXLongType1 заменяет существующие C-ссылки данными из аргументов")
    void embedReplacesExistingCompleteRefs() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("replace refs".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        // CRL строятся сразу после штампа; thisUpdateNow() прошёл бы окно STRICT только за счёт
        // нулевого запаса (округление до секунды), поэтому берём текущий момент
        GostCrl oldCrl =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdate(Instant.now())
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        GostCrl newCrl =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdate(Instant.now())
                                .nextUpdateDays(30)
                                .withCrlNumber(2)
                                .sign(rootKp.getPrivate()));

        List<GostCertificate> chain = List.of(caSignerCert, rootCert);
        byte[] cadesC =
                CAdESExtender.embedCompleteRefs(
                        cadesT, chain, Arrays.asList(oldCrl, null), Arrays.asList(null, null));

        byte[] xlong =
                embedXLong(cadesC, chain, Arrays.asList(newCrl, null), Arrays.asList(null, null));

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(rootCert, tsaCert));
        assertEquals(1, result.signers().size());
        assertArrayEquals(
                newCrl.getEncoded(),
                result.signers().get(0).revocationValues().crls().get(0).getEncoded(),
                "должна использоваться новая CRL из аргументов, а не старая C-ссылка");
    }

    @Test
    @DisplayName("embedXLongType1 не добавляет вторую signature-time-stamp")
    void embedDoesNotDuplicateSignatureTimestamp() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("one timestamp".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);

        byte[] xlong =
                embedXLong(cadesT, List.of(signerCert), List.of(signerCrl), List.of(signerOcsp));

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(signerCert, tsaCert));
        assertEquals(
                1,
                result.signers().get(0).timestamps().size(),
                "повторный TSP-запрос не должен добавлять вторую signature-time-stamp");
    }

    @Test
    @DisplayName("embedXLongType1 отвергает смешанное наличие signature-time-stamp")
    void embedRejectsMixedSignatureTimestamps() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("mixed timestamp".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);
        byte[] mixed = removeSignatureTimestamp(cadesT, 1);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                embedXLong(
                                        mixed,
                                        List.of(signerCert),
                                        List.of(signerCrl),
                                        List.of(signerOcsp)));
        assertTrue(
                ex.getMessage().contains("some signers only"),
                "ожидалось сообщение о смешанном состоянии, получено: " + ex.getMessage());
    }

    private static byte[] removeSignatureTimestamp(byte[] cades, int signerIndex) throws Exception {
        byte[] body = CmsContentInfo.decode(cades).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[signerIndex], 0);
        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }
        if (unsignedIdx < 0) {
            throw new IllegalStateException("unsignedAttrs not found");
        }
        byte[] field = siParts[unsignedIdx];
        int[] lenInfo = DerCodec.decodeLength(field, 1);
        int contentOff = 1 + lenInfo[1];
        byte[] content = Arrays.copyOfRange(field, contentOff, field.length);
        List<byte[]> kept = new ArrayList<>();
        int pos = 0;
        while (pos < content.length) {
            int[] attrLen = DerCodec.decodeLength(content, pos + 1);
            int total = 1 + attrLen[1] + attrLen[0];
            byte[] attr = Arrays.copyOfRange(content, pos, pos + total);
            if (!GostOids.SIGNATURE_TIME_STAMP.equals(CmsAttribute.decode(attr).attrType())) {
                kept.add(attr);
            }
            pos += total;
        }
        byte[][] sorted = kept.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        siParts[unsignedIdx] = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
        signerInfos[signerIndex] = DerCodec.encodeSequence(siParts);
        byte[] newSignedData = sd.rebuild(sd.certs(), DerCodec.encodeSetOf(signerInfos));
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    @Test
    @DisplayName("Две escTimeStamp: проверяются обе, обе валидные проходят")
    void multipleEscTimestampsAllVerified() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("two esc".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        byte[] xlong =
                embedXLong(cadesBes, List.of(signerCert), List.of(signerCrl), List.of(signerOcsp));
        byte[] token = firstUnsignedAttrValue(xlong, GostOids.ESC_TIME_STAMP);
        byte[] doubled =
                injectUnsignedAttrDerTest(
                        signerInfoDer(xlong, 0),
                        CmsAttribute.encode(GostOids.ESC_TIME_STAMP, token));
        byte[] withTwoEsc = replaceFirstSignerInfo(xlong, doubled);

        assertDoesNotThrow(
                () ->
                        CAdESVerifier.verifyXLong(
                                withTwoEsc, TrustAnchors.ofCertificates(signerCert, tsaCert)));
    }

    @Test
    @DisplayName("embedXLongType1 отвергает CRL с истёкшим nextUpdate")
    void embedRejectsExpiredNextUpdate() throws Exception {
        String thisUpdate =
                GostSignatureHelper.formatGeneralizedTime(Instant.now().minusSeconds(2 * 86400));
        String nextUpdate =
                GostSignatureHelper.formatGeneralizedTime(Instant.now().minusSeconds(86400));
        GostCrl expired =
                new GostCrl(
                        GostCrlBuilder.create(rootCert.getSubjectDnBytes())
                                .thisUpdate(thisUpdate)
                                .nextUpdate(nextUpdate)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("expired nextUpdate".getBytes())
                        .addSigner(caSignerKp.getPrivate(), caSignerCert)
                        .withCAdES()
                        .build();

        assertThrows(
                PkixException.class,
                () ->
                        embedXLong(
                                cadesBes,
                                List.of(caSignerCert, rootCert),
                                Arrays.asList(expired, null),
                                Arrays.asList(null, null)),
                "CRL с истёкшим nextUpdate не должен встраиваться");
    }

    private static byte[] signerInfoDer(byte[] cadesDer, int index) throws Exception {
        byte[] body = CmsContentInfo.decode(cadesDer).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        return signerInfos[index];
    }

    private static byte[] firstUnsignedAttrValue(byte[] cadesDer, String oid) throws Exception {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer(cadesDer, 0), 0);
        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }
        if (unsignedIdx < 0) {
            throw new AssertionError("unsignedAttrs not found");
        }
        int[] len = DerCodec.decodeLength(siParts[unsignedIdx], 1);
        int off = 1 + len[1];
        byte[] content = Arrays.copyOfRange(siParts[unsignedIdx], off, siParts[unsignedIdx].length);
        int pos = 0;
        while (pos < content.length) {
            int[] attrLen = DerCodec.decodeLength(content, pos + 1);
            int total = 1 + attrLen[1] + attrLen[0];
            byte[] attrDer = Arrays.copyOfRange(content, pos, pos + total);
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            if (oid.equals(attr.attrType())) {
                return attr.attrValues()[0];
            }
            pos += total;
        }
        throw new AssertionError("attribute not found: " + oid);
    }

    private static byte[] replaceFirstSignerInfo(byte[] cadesDer, byte[] newSignerInfo)
            throws Exception {
        byte[] body = CmsContentInfo.decode(cadesDer).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        signerInfos[0] = newSignerInfo;
        byte[] newSignerInfos = DerCodec.encodeSetOf(signerInfos);
        return CmsContentInfo.encode(
                GostOids.CMS_SIGNED_DATA, sd.rebuild(sd.certs(), newSignerInfos));
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    // ========================================================================
    // Делегированный OCSP-ответчик в ссылках и certificate-values
    // ========================================================================

    private static GostCertificate createOcspResponder(
            NcChain c, KeyPair responderKp, boolean withNoCheck, boolean withOcspEku)
            throws Exception {
        GostCertificateBuilder b =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("NC OCSP Responder"))
                        .issuerDn(c.intCert.getSubjectDnBytes())
                        .publicKey(responderKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        if (withOcspEku) {
            b = b.extendedKeyUsage(true, org.rssys.gost.pkix.GostOids.EXT_OCSP_SIGNING);
        }
        if (withNoCheck) {
            b = b.ocspNoCheck();
        }
        return b.sign(c.intKp.getPrivate());
    }

    private static GostOcspResponse delegatedOcsp(
            NcChain c, GostCertificate responder, KeyPair responderKp) throws Exception {
        return new GostOcspResponse(
                GostOcspResponseBuilder.create(c.signer.getSerialNumber())
                        .issuerDn(c.intCert.getSubjectDnBytes())
                        .caPublicKey(c.intCert.getPublicKey())
                        .good()
                        .withDelegatedCerts(responder.getEncoded())
                        .sign(responderKp.getPrivate()));
    }

    private byte[] buildXLongWithDelegatedResponder(
            NcChain c, GostCertificate responder, KeyPair responderKp) throws Exception {
        List<GostCertificate> chain = List.of(c.signer, c.intCert, c.root);
        List<GostOcspResponse> ocsp = new ArrayList<>(goodOcsp(c, chain));
        ocsp.set(0, delegatedOcsp(c, responder, responderKp));
        return buildXLong(c, chain, Arrays.asList(new GostCrl[chain.size()]), ocsp);
    }

    @Test
    @DisplayName("X Long: сертификат делегированного OCSP-ответчика входит в ссылки и значения")
    void xLongReferencesDelegatedOcspResponder() throws Exception {
        NcChain c = createNcChain();
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = createOcspResponder(c, responderKp, true, true);

        byte[] xlong = buildXLongWithDelegatedResponder(c, responder, responderKp);

        List<CAdESCompleteData.OtherCertID> certRefs =
                CAdESCompleteData.decodeCompleteCertificateRefs(
                        firstUnsignedAttrValue(xlong, GostOids.COMPLETE_CERTIFICATE_REFS));
        assertEquals(3, certRefs.size(), "ссылки: промежуточный УЦ, корень, ответчик");
        assertEquals(
                responder.getSerialNumberBigInt(),
                certRefs.get(2).issuerSerial().serial(),
                "ответчик идёт после цепочки");
        List<CAdESCompleteData.CrlOcspRef> revocRefs =
                CAdESCompleteData.decodeCompleteRevocationRefs(
                        firstUnsignedAttrValue(xlong, GostOids.COMPLETE_REVOCATION_REFS));
        assertEquals(4, revocRefs.size(), "подписант, промежуточный, корень, ответчик");
        assertTrue(revocRefs.get(3).ocspList().isEmpty() && revocRefs.get(3).crlList().isEmpty());

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(c.root, tsaCert));
        assertEquals(1, result.signers().size(), "наш верификатор принимает такую подпись");
    }

    @Test
    @DisplayName("X Long: мусор в certs OCSP-ответа пропускается, ссылки строятся без него")
    void xLongSkipsGarbageInOcspCerts() throws Exception {
        NcChain c = createNcChain();
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = createOcspResponder(c, responderKp, true, true);
        // Корректный по TLV элемент, но не сертификат: разбор бросает IllegalArgumentException.
        // Стоит после ответчика: при byName построитель сам разбирает первый элемент certs
        byte[] garbage = DerCodec.encodeSequence(new byte[0]);
        List<GostCertificate> chain = List.of(c.signer, c.intCert, c.root);
        List<GostOcspResponse> ocsp = new ArrayList<>(goodOcsp(c, chain));
        ocsp.set(
                0,
                new GostOcspResponse(
                        GostOcspResponseBuilder.create(c.signer.getSerialNumber())
                                .issuerDn(c.intCert.getSubjectDnBytes())
                                .caPublicKey(c.intCert.getPublicKey())
                                .good()
                                .withDelegatedCerts(responder.getEncoded(), garbage)
                                .sign(responderKp.getPrivate())));

        byte[] xlong = buildXLong(c, chain, Arrays.asList(new GostCrl[chain.size()]), ocsp);

        List<CAdESCompleteData.OtherCertID> certRefs =
                CAdESCompleteData.decodeCompleteCertificateRefs(
                        firstUnsignedAttrValue(xlong, GostOids.COMPLETE_CERTIFICATE_REFS));
        assertEquals(3, certRefs.size(), "ссылки: промежуточный УЦ, корень и только ответчик");
    }

    @Test
    @DisplayName("X Long: сертификат ответчика из ссылок не становится доверенным якорем")
    void xLongResponderCertificateIsNotTrustAnchor() throws Exception {
        NcChain c = createNcChain();
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = createOcspResponder(c, responderKp, true, true);
        byte[] xlong = buildXLongWithDelegatedResponder(c, responder, responderKp);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                xlong, TrustAnchors.ofCertificates(responder, tsaCert)),
                "ответчик не должен заменять доверенный корень цепочки подписанта");
    }

    @Test
    @DisplayName("X Long: делегированный ответчик без EKU OCSPSigning отклоняется при встраивании")
    void xLongRejectsResponderWithoutOcspSigningEku() throws Exception {
        NcChain c = createNcChain();
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = createOcspResponder(c, responderKp, false, false);

        assertThrows(
                PkixException.class,
                () -> buildXLongWithDelegatedResponder(c, responder, responderKp));
    }

    @Test
    @DisplayName("X Long: ответ, подписанный не ключом сертификата ответчика, отклоняется")
    void xLongRejectsResponseSignedByForeignKey() throws Exception {
        NcChain c = createNcChain();
        KeyPair responderKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate responder = createOcspResponder(c, responderKp, true, true);
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);

        assertThrows(
                PkixException.class,
                () -> buildXLongWithDelegatedResponder(c, responder, foreignKp));
    }

    private static final class NcChain {
        final KeyPair rootKp;
        final KeyPair intKp;
        final KeyPair signerKp;
        final GostCertificate root;
        final GostCertificate intCert;
        final GostCertificate signer;

        NcChain(
                KeyPair rootKp,
                KeyPair intKp,
                KeyPair signerKp,
                GostCertificate root,
                GostCertificate intCert,
                GostCertificate signer) {
            this.rootKp = rootKp;
            this.intKp = intKp;
            this.signerKp = signerKp;
            this.root = root;
            this.intCert = intCert;
            this.signer = signer;
        }
    }

    private static NcChain createNcChain() throws Exception {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("NC Root");
        GostCertificate root =
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
                        .nameConstraints(new String[] {"example.com"}, null, null, null)
                        .sign(rootKp.getPrivate());

        KeyPair intKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] intDn = CmsTestUtils.buildDn("NC Intermediate");
        GostCertificate intCert =
                GostCertificateBuilder.create(PARAMS, intDn)
                        .issuerDn(rootDn)
                        .publicKey(intKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .sign(rootKp.getPrivate());

        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signer =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("NC Signer"))
                        .issuerDn(intCert.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sanDns("host.example.com")
                        .sign(intKp.getPrivate());
        return new NcChain(rootKp, intKp, signerKp, root, intCert, signer);
    }

    private byte[] buildXLong(NcChain c, List<GostCertificate> chain) throws Exception {
        return buildXLong(c, chain, Arrays.asList(new GostCrl[chain.size()]), goodOcsp(c, chain));
    }

    private static List<GostOcspResponse> goodOcsp(NcChain c, List<GostCertificate> chain)
            throws Exception {
        List<GostOcspResponse> result = new ArrayList<>(chain.size());
        for (int i = 0; i < chain.size(); i++) {
            GostCertificate cert = chain.get(i);
            if (Arrays.equals(cert.getEncoded(), c.root.getEncoded())) {
                result.add(null);
                continue;
            }
            GostCertificate issuer = i + 1 < chain.size() ? chain.get(i + 1) : c.root;
            KeyPair issuerKp = issuer == c.intCert ? c.intKp : c.rootKp;
            byte[] ocspDer =
                    GostOcspResponseBuilder.create(cert.getSerialNumber())
                            .issuerDn(issuer.getSubjectDnBytes())
                            .good()
                            .sign(issuerKp.getPrivate());
            result.add(new GostOcspResponse(ocspDer));
        }
        return result;
    }

    private byte[] buildXLong(
            NcChain c, List<GostCertificate> chain, List<GostCrl> crls, List<GostOcspResponse> ocsp)
            throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("nc xlong".getBytes())
                        .addSigner(c.signerKp.getPrivate(), c.signer)
                        .withCAdES()
                        .build();
        byte[] cadesT = addLocalTimestamp(cadesBes);
        return embedXLong(cadesT, chain, crls, ocsp);
    }

    private static byte[] replaceCertValues(byte[] cadesXLong, List<GostCertificate> certValues)
            throws Exception {
        byte[] attr =
                CmsAttribute.encode(
                        GostOids.CERTIFICATE_VALUES,
                        CAdESXLongData.encodeCertificateValues(certValues));
        byte[] body = CmsContentInfo.decode(cadesXLong).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi =
                replaceUnsignedAttrDerTest(signerInfos[0], GostOids.CERTIFICATE_VALUES, attr);
        byte[] newSignedData = sd.rebuild(sd.certs(), DerCodec.encodeSetOf(modifiedSi));
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private static byte[] replaceUnsignedAttrDerTest(
            byte[] signerInfoDer, String oid, byte[] newAttr) throws Exception {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }
        List<byte[]> attrs = new ArrayList<>();
        if (unsignedIdx >= 0) {
            byte[] existingField = siParts[unsignedIdx];
            int[] lenInfo = DerCodec.decodeLength(existingField, 1);
            int contentOff = 1 + lenInfo[1];
            byte[] existingContent =
                    Arrays.copyOfRange(existingField, contentOff, existingField.length);
            int pos = 0;
            while (pos < existingContent.length) {
                int[] attrLen = DerCodec.decodeLength(existingContent, pos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                byte[] attr = Arrays.copyOfRange(existingContent, pos, pos + attrTotal);
                if (!oid.equals(CmsAttribute.decode(attr).attrType())) {
                    attrs.add(attr);
                }
                pos += attrTotal;
            }
        }
        attrs.add(newAttr);
        byte[][] sorted = attrs.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        byte[] newField = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
        if (unsignedIdx >= 0) {
            siParts[unsignedIdx] = newField;
        } else {
            byte[][] newParts = Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newField;
            siParts = newParts;
        }
        return DerCodec.encodeSequence(siParts);
    }

    private static byte[] replaceCerts(byte[] cadesXLong, List<GostCertificate> certs)
            throws Exception {
        byte[][] encoded = new byte[certs.size()][];
        for (int i = 0; i < certs.size(); i++) {
            encoded[i] = certs.get(i).getEncoded();
        }
        DerCodec.sortDer(encoded);
        byte[] certsField = DerCodec.encodeContextConstructed(0, DerCodec.concat(encoded));
        byte[] body = CmsContentInfo.decode(cadesXLong).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[] newSignedData = sd.rebuild(certsField, sd.signerInfosField());
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private static byte[] replaceUnsignedAttr(byte[] cadesXLong, String oid, byte[] attr)
            throws Exception {
        byte[] body = CmsContentInfo.decode(cadesXLong).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] modifiedSi = replaceUnsignedAttrDerTest(signerInfos[0], oid, attr);
        byte[] newSignedData = sd.rebuild(sd.certs(), DerCodec.encodeSetOf(modifiedSi));
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

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
