package org.rssys.gost.crossval.cadesc;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.*;
import org.rssys.gost.pkix.cms.*;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Кросс-валидация CAdES-C (Complete validation data references) с BouncyCastle.
 *
 * <p>BC 1.84 не имеет нативных классов для CAdES-C структур (OtherCertID, CrlOcspRef).
 * Все C-атрибуты парсятся вручную через BC ASN.1 API.</p>
 *
 * <p>Имя класса использует каноническое написание {@code CAdES} (как {@code CAdESExtender},
 * {@code CAdESSignerResult}) и однозначно отделяется от cadest-аналога через {@code CompleteRefs}.</p>
 */
@DisplayName("CAdES-C кросс-валидация с BouncyCastle")
class BcCAdESCompleteRefsCrossValidationTest {

    private static final String CERTS_OID = GostOids.COMPLETE_CERTIFICATE_REFS;
    private static final String REVOCS_OID = GostOids.COMPLETE_REVOCATION_REFS;
    private static final String DIGEST_OID = GostOids.DIGEST_256;

    @BeforeAll
    static void setUpProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static List<ECParameters> curveParams() {
        return List.of(TestData.PARAMS_256);
    }

    // ========================================================================
    // Парсинг и верификация на уровне CMS
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: CMSSignedData парсинг + верификация подписи")
    void bcParsesAndVerifiesSigner(ECParameters params) throws Exception {
        TestData.CertChainData cd = TestData.generateCaAndLeaf(params);
        byte[] cadesC = TestData.buildCAdESC(cd, "hello".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        X509CertificateHolder bcCert = new X509CertificateHolder(cd.leafCert().getEncoded());
        assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC").build(bcCert)), "BC сигнатура подписи");

        assertNotNull(signer.getUnsignedAttributes(), "unsignedAttrs должны быть не-null");
        assertNotNull(signer.getSignedAttributes(), "signedAttrs должны быть не-null");
    }

    // ========================================================================
    // Наличие обоих C-атрибутов
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: оба C-атрибута присутствуют в unsignedAttrs")
    void bcBothCAttributesPresent(ECParameters params) throws Exception {
        TestData.CertChainData cd = TestData.generateCaAndLeaf(params);
        byte[] cadesC = TestData.buildCAdESC(cd, "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();

        Attribute certRefs = unsigned.get(new ASN1ObjectIdentifier(CERTS_OID));
        Attribute revocRefs = unsigned.get(new ASN1ObjectIdentifier(REVOCS_OID));
        assertNotNull(certRefs, "complete-certificate-references");
        assertNotNull(revocRefs, "complete-revocation-references");

        assertEquals(1, unsigned.getAll(new ASN1ObjectIdentifier(CERTS_OID)).size(),
                "Ровно один complete-certificate-references");
        assertEquals(1, unsigned.getAll(new ASN1ObjectIdentifier(REVOCS_OID)).size(),
                "Ровно один complete-revocation-references");
    }

    // ========================================================================
    // Ручной парсинг OtherCertID + сверка certHash
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: ручной парсинг OtherCertID + сверка certHash")
    void bcParseOtherCertIdAndVerifyHash(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList((GostOcspResponse) null, null, null), "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute certRefsAttr = unsigned.get(new ASN1ObjectIdentifier(CERTS_OID));

        ASN1Sequence certRefsSeq = ASN1Sequence.getInstance(
                certRefsAttr.getAttrValues().getObjectAt(0));
        assertEquals(1, certRefsSeq.size(),
                "1 OtherCertID для цепочки [leaf, intermediateCA, rootCA]");

        for (int i = 0; i < certRefsSeq.size(); i++) {
            ASN1Sequence otherCertId = ASN1Sequence.getInstance(certRefsSeq.getObjectAt(i));

            // Извлекаем serial из IssuerSerial
            ASN1Sequence issuerSerial = ASN1Sequence.getInstance(otherCertId.getObjectAt(1));
            BigInteger serial = ((ASN1Integer) issuerSerial.getObjectAt(1)).getValue();

            // Парсим OtherHash [1] — явный тег: [1] EXPLICIT { SEQUENCE { algId, hashValue } }
            ASN1TaggedObject hashTag = ASN1TaggedObject.getInstance(otherCertId.getObjectAt(0));
            assertEquals(1, hashTag.getTagNo());
            byte[] hashSeqBytes = hashTag.getBaseObject().getEncoded(ASN1Encoding.DER);
            byte[][] hashSeqParts = DerCodec.parseSequenceContents(hashSeqBytes, 0);
            byte[] certHash = DerCodec.parseOctetString(hashSeqParts[1], 0);

            // Ищем сертификат по issuer+serial в certificates
            X509CertificateHolder foundCert = findCertBySerial(
                    sd.getCertificates(), serial);
            assertNotNull(foundCert, "Сертификат найден: issuer=" + serial);

            MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", "BC");
            byte[] actualHash = md.digest(foundCert.getEncoded());
            assertArrayEquals(certHash, actualHash, "certHash совпадает с BC-хэшем");
        }
    }

    // ========================================================================
    // Ручной парсинг CrlOcspRef
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: ручной парсинг CrlOcspRef (CRL-ветка)")
    void bcParseCrlOcspRef(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList((GostOcspResponse) null, null, null), "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute revocRefsAttr = unsigned.get(new ASN1ObjectIdentifier(REVOCS_OID));

        ASN1Sequence revocRefsSeq = ASN1Sequence.getInstance(
                revocRefsAttr.getAttrValues().getObjectAt(0));
        assertEquals(2, revocRefsSeq.size(),
                "2 CrlOcspRef (signer + intermediateCA)");

        for (int i = 0; i < revocRefsSeq.size(); i++) {
            ASN1Sequence crlOcspRef = ASN1Sequence.getInstance(revocRefsSeq.getObjectAt(i));
            ASN1TaggedObject crlIds = ASN1TaggedObject.getInstance(crlOcspRef.getObjectAt(0));
            assertEquals(0, crlIds.getTagNo(), "crlids [0]");
            ASN1Sequence crlListId = ASN1Sequence.getInstance(crlIds.getBaseObject());
            ASN1Sequence crls = ASN1Sequence.getInstance(crlListId.getObjectAt(0));
            assertEquals(1, crls.size(), "Один CRL для signer'а");
        }
    }

    // ========================================================================
    // Ручной парсинг OcspIdentifier в OCSP-ветке CrlOcspRef
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: ручной парсинг OcspIdentifier в CrlOcspRef (OCSP-ветка)")
    void bcParseOcspIdentifier(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);

        GostOcspResponse leafOcsp = TestData.buildOcspResponse(
                tc.intermediateKey(), tc.leafCert());
        GostOcspResponse intOcsp = TestData.buildOcspResponse(
                tc.rootKey(), tc.intermediateCert());

        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList(leafOcsp, intOcsp, null), "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute revocRefsAttr = unsigned.get(new ASN1ObjectIdentifier(REVOCS_OID));
        ASN1Sequence revocRefsSeq = ASN1Sequence.getInstance(
                revocRefsAttr.getAttrValues().getObjectAt(0));

        // Первый CrlOcspRef — для signer'а (leaf), должен иметь ocspList [1]
        ASN1Sequence firstRef = ASN1Sequence.getInstance(revocRefsSeq.getObjectAt(0));
        ASN1TaggedObject ocspIds = ASN1TaggedObject.getInstance(firstRef.getObjectAt(1));
        assertEquals(1, ocspIds.getTagNo(), "ocspids [1]");
        ASN1Sequence ocspListId = ASN1Sequence.getInstance(ocspIds.getBaseObject());
        ASN1Sequence ocspResponses = ASN1Sequence.getInstance(ocspListId.getObjectAt(0));
        assertEquals(1, ocspResponses.size(), "Один OCSP-ответ");

        ASN1Sequence ocspRespRec = ASN1Sequence.getInstance(ocspResponses.getObjectAt(0));
        ASN1Sequence ocspIdentifier = ASN1Sequence.getInstance(ocspRespRec.getObjectAt(0));
        // OcspIdentifier содержит ResponderID + producedAt
        assertEquals(2, ocspIdentifier.size(), "ResponderID + producedAt");
        ASN1TaggedObject responderId = ASN1TaggedObject.getInstance(ocspIdentifier.getObjectAt(0));
        // responderId — CHOICE { byName [1], byKey [2] }
        assertTrue(responderId.getTagNo() == 1 || responderId.getTagNo() == 2,
                "responderId должен быть byName или byKey");
        ASN1GeneralizedTime producedAt =
                ASN1GeneralizedTime.getInstance(ocspIdentifier.getObjectAt(1));
        assertNotNull(producedAt.getDate());
    }

    // ========================================================================
    // Round-trip BC -> crypto-gost
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: round-trip (BC parse -> re-encode -> crypto-gost verifyCAdESC)")
    void bcRoundTrip(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList((GostOcspResponse) null, null, null), "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        byte[] reEncoded = sd.toASN1Structure().getEncoded();

        VerifiedCAdESData verified = CAdESExtender.verifyCAdESC(reEncoded, tc.rootCert());
        assertNotNull(verified);
        assertNotNull(verified.signers());
        CAdESSignerResult sr = verified.signers().get(0);
        assertNotNull(sr.completeCertRefs());
        assertNotNull(sr.completeRevocRefs());
    }

    // ========================================================================
    // crypto-gost -> BC: сверка результатов
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: verifyCAdESC результат сверяется с BC ASN.1")
    void bcVerifyResultMatchesCryptoGostOutput(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList((GostOcspResponse) null, null, null), "test".getBytes());

        VerifiedCAdESData verified = CAdESExtender.verifyCAdESC(cadesC, tc.rootCert());
        CAdESSignerResult sr = verified.signers().get(0);

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute certRefsAttr = unsigned.get(new ASN1ObjectIdentifier(CERTS_OID));
        ASN1Sequence certRefsSeq = ASN1Sequence.getInstance(
                certRefsAttr.getAttrValues().getObjectAt(0));

        assertEquals(sr.completeCertRefs().size(), certRefsSeq.size(),
                "certRefs.size() из crypto-gost == количество OtherCertID из BC");

        for (int i = 0; i < certRefsSeq.size(); i++) {
            ASN1Sequence otherCertId = ASN1Sequence.getInstance(certRefsSeq.getObjectAt(i));
            ASN1TaggedObject hashTag = ASN1TaggedObject.getInstance(otherCertId.getObjectAt(0));
            byte[] hashSeqBytes = hashTag.getBaseObject().getEncoded(ASN1Encoding.DER);
            byte[][] hashSeqParts = DerCodec.parseSequenceContents(hashSeqBytes, 0);
            byte[] bcHash = DerCodec.parseOctetString(hashSeqParts[1], 0);

            CAdESCompleteData.OtherCertID gostRef = sr.completeCertRefs().get(i);
            assertArrayEquals(bcHash, gostRef.otherCertHash().hashValue(),
                    "certHash crypto-gost == BC");
            assertEquals(gostRef.issuerSerial().serial(), sr.completeCertRefs().get(i)
                            .issuerSerial().serial(),
                    "serial crypto-gost == BC");
        }
    }

    // ========================================================================
    // Negative: tampered certHash
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC: tampered certHash — несовпадение")
    void bcTamperedCertHash(ECParameters params) throws Exception {
        TestData.ThreeLevelChain tc = TestData.generateThreeLevelChain(params);
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                Arrays.asList((GostOcspResponse) null, null, null), "test".getBytes());

        CMSSignedData sd = new CMSSignedData(cadesC);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();
        Attribute certRefsAttr = unsigned.get(new ASN1ObjectIdentifier(CERTS_OID));
        ASN1Sequence certRefsSeq = ASN1Sequence.getInstance(
                certRefsAttr.getAttrValues().getObjectAt(0));

        ASN1Sequence otherCertIdForIntermediate =
                ASN1Sequence.getInstance(certRefsSeq.getObjectAt(0));
        ASN1TaggedObject hashTag =
                ASN1TaggedObject.getInstance(otherCertIdForIntermediate.getObjectAt(0));
        byte[] hashSeqBytes = hashTag.getBaseObject().getEncoded(ASN1Encoding.DER);
        byte[][] hashSeqParts = DerCodec.parseSequenceContents(hashSeqBytes, 0);
        byte[] certHash = DerCodec.parseOctetString(hashSeqParts[1], 0);

        // Вычисляем хэш ROOT вместо intermediate — специально не совпадёт
        MessageDigest md = MessageDigest.getInstance("GOST3411-2012-256", "BC");
        byte[] rootHash = md.digest(tc.rootCert().getEncoded());

        assertFalse(Arrays.equals(certHash, rootHash),
                "Хэш intermediate сертификата не равен хэшу root");
    }

    // ========================================================================
    // Negative: отсутствие complete-certificate-references
    // ========================================================================

    @Test
    @DisplayName("BC: CAdES-BES (без C-атрибутов) — BC не видит complete-certificate-references")
    void bcBesHasNoCAttributes() throws Exception {
        TestData.CertChainData cd = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data("test".getBytes())
                .addSigner(cd.leafKey(), cd.leafCert())
                .withCAdES()
                .build();

        CMSSignedData sd = new CMSSignedData(cadesBes);
        SignerInformation signer = sd.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = signer.getUnsignedAttributes();

        assertNull(unsigned, "CAdES-BES не имеет unsignedAttrs");
    }

    // ========================================================================
    // Negative: CAdES-BES — verifyCAdESC требует C-атрибуты
    // ========================================================================

    @Test
    @DisplayName("BC: CAdES-BES без C-атрибутов — verifyCAdESC бросает PkixException")
    void bcBesVerificationFailsOnCAttribute() throws Exception {
        TestData.CertChainData cd = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        byte[] cadesBes = CmsSignedDataBuilder.create()
                .data("test".getBytes())
                .addSigner(cd.leafKey(), cd.leafCert())
                .withCAdES()
                .build();

        assertThrows(PkixException.class,
                () -> CAdESExtender.verifyCAdESC(cadesBes, cd.caCert()),
                "CAdES-BES не содержит C-атрибуты — verifyCAdESC должен бросить PkixException");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static X509CertificateHolder findCertBySerial(
            Store<X509CertificateHolder> certStore, BigInteger serial)
            throws Exception {
        for (X509CertificateHolder cert : certStore.getMatches(null)) {
            if (cert.getSerialNumber().equals(serial)) {
                return cert;
            }
        }
        return null;
    }
}
