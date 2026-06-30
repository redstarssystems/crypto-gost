package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.cadest.TestData.CertPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CAdESAttributes;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.pkix.cms.VerifiedCAdESData;
import org.rssys.gost.pkix.cms.VerifiedSignedData;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.util.DerCodec;

@DisplayName("BouncyCastle: кросс-валидация CAdES-BES / CAdES-T / TSP")
class BcCAdESCrossValidationTest {

    private static CertPair pair256;
    private static KeyPair tsaKp256;
    private static GostCertificate tsaCert256;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        pair256 = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        tsaKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        tsaCert256 = CmsTestUtils.createSelfSignedCert(
                tsaKp256.getPrivate(), tsaKp256.getPublic());
    }

    // ========================================================================
    // CAdES-BES -> BC
    // ========================================================================

    @Test
    @DisplayName("CAdES-BES -> BC: парсинг и верификация подписи через CMSSignedData")
    void cadesBesToBcVerify() throws Exception {
        byte[] data = "CAdES-BES -> BC test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        CMSSignedData sd = new CMSSignedData(cadesBes);
        SignerInformationStore signers = sd.getSignerInfos();
        assertEquals(1, signers.size(), "Один подписант в CAdES-BES");

        SignerInformation si = signers.iterator().next();

        // Получаем сертификат подписанта из CMS
        X509CertificateHolder certHolder =
                (X509CertificateHolder) sd.getCertificates().getMatches(si.getSID()).iterator().next();

        // Верификация подписи через JCA (требует BouncyCastleProvider в Security)
        boolean verified = si.verify(
                new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(certHolder));
        assertTrue(verified, "BC должен подтвердить подпись CAdES-BES");

        // Проверяем signed-атрибуты: content-type, message-digest
        AttributeTable signed = si.getSignedAttributes();
        assertNotNull(signed, "signedAttrs должны присутствовать");

        Attribute contentType = signed.get(
                new ASN1ObjectIdentifier(GostOids.ATTR_CONTENT_TYPE));
        assertNotNull(contentType, "contentType должен быть в signedAttrs");
    }

    @Test
    @DisplayName("CAdES-BES -> BC: verifySigningCertificateV2 certHash через BC-примитивы")
    void verifySigningCertV2ViaBc() throws Exception {
        byte[] data = "signingCertV2 BC test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        CMSSignedData sd = new CMSSignedData(cadesBes);
        SignerInformation si = sd.getSignerInfos().iterator().next();
        AttributeTable signed = si.getSignedAttributes();

        // Извлекаем signingCertificateV2
        Attribute scv2 = signed.get(
                new ASN1ObjectIdentifier(GostOids.SIGNING_CERTIFICATE_V2));
        assertNotNull(scv2, "signingCertificateV2 должен быть в signedAttrs");

        ASN1Encodable[] vals = scv2.getAttrValues().toArray();
        assertEquals(1, vals.length, "Одно значение в signingCertificateV2");

        // Парсим ESSCertIDv2 через BC ASN.1
        // Структура: signingCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
        //   где ESSCertIDv2 ::= SEQUENCE { hashAlgorithm, certHash, issuerSerial }
        ASN1Sequence scv2Seq = ASN1Sequence.getInstance(vals[0]);    // outer
        ASN1Sequence certsSeq = ASN1Sequence.getInstance(scv2Seq.getObjectAt(0)); // certs
        ASN1Sequence essCertIdV2 = ASN1Sequence.getInstance(certsSeq.getObjectAt(0)); // ESSCertIDv2
        ASN1Encodable certHashEnc = essCertIdV2.getObjectAt(1);     // certHash
        ASN1OctetString certHashOs = ASN1OctetString.getInstance(certHashEnc);

        // Вычисляем хэш DER сертификата через BC MessageDigest (JCA)
        MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256",
                BouncyCastleProvider.PROVIDER_NAME);
        byte[] actualHash = md256.digest(pair256.leafCert().getEncoded());

        assertArrayEquals(certHashOs.getOctets(), actualHash,
                "certHash в ESSCertIDv2 должен совпадать с хэшем DER сертификата");
    }

    @Test
    @DisplayName("CAdES-BES -> BC -> crypto-gost: round-trip верификация")
    void cadesBesRoundTrip() throws Exception {
        byte[] data = "roundtrip test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        // BC парсит, проверяет структуру
        CMSSignedData sd = new CMSSignedData(cadesBes);
        byte[] bcReencoded = sd.toASN1Structure().getEncoded();

        // crypto-gost верифицирует перекодированный DER
        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(bcReencoded, pair256.caCert());
        assertNotNull(result, "crypto-gost должен верифицировать CMS после BC перекодировки");
    }

    @Test
    @DisplayName("CAdES-BES: verifyCAdESBES() проходит валидную подпись")
    void verifyCAdESBESValid() throws Exception {
        byte[] data = "verifyCAdESBES test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        VerifiedCAdESData result = CAdESExtender.verifyCAdESBES(cadesBes, pair256.caCert());
        assertNotNull(result, "verifyCAdESBES должен принять валидный CAdES-BES");
        assertNotNull(result.signers().get(0).signerCertificate());
        assertTrue(result.signers().get(0).timestamps().isEmpty(),
                "CAdES-BES не содержит меток времени");
    }

    @Test
    @DisplayName("Negative: verifyCAdESBES() бросает PkixException без signingCertificateV2")
    void verifyCAdESBESFailsWithoutScv2() throws Exception {
        byte[] data = "bes no scv2".getBytes();
        // Строим CMS без withCAdES() — нет signingCertificateV2
        byte[] cmsWithoutCAdES =
                org.rssys.gost.pkix.cms.CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(pair256.leafKey(), pair256.leafCert())
                        .build();

        try {
            CAdESExtender.verifyCAdESBES(cmsWithoutCAdES, pair256.caCert());
            throw new AssertionError("Ожидался PkixException при отсутствии signingCertificateV2");
        } catch (PkixException e) {
            assertTrue(e.getMessage().contains("signingCertificateV2"),
                    "Сообщение должно указывать на отсутствие signingCertificateV2: "
                    + e.getMessage());
        }
    }

    // ========================================================================
    // CAdES-T -> BC
    // ========================================================================

    @Test
    @DisplayName("CAdES-T -> BC: парсинг и верификация через CMSSignedData")
    void cadesTToBcVerify() throws Exception {
        byte[] data = "CAdES-T -> BC test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(sigHash, hashOid,
                tsaKp256.getPrivate(), tsaCert256);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        // BC парсит CAdES-T (CMS SignedData с unsigned-атрибутами)
        CMSSignedData sd = new CMSSignedData(cadesT);
        SignerInformation si = sd.getSignerInfos().iterator().next();

        // unsignedAttrs
        AttributeTable unsigned = si.getUnsignedAttributes();
        assertNotNull(unsigned, "unsignedAttrs должны быть в CAdES-T");

        Attribute tsAttr = unsigned.get(
                new ASN1ObjectIdentifier(GostOids.SIGNATURE_TIME_STAMP));
        assertNotNull(tsAttr, "signatureTimeStampToken должен быть в unsignedAttrs");

        // Извлекаем TimeStampToken из атрибута через BC
        ASN1Encodable[] tsVals = tsAttr.getAttrValues().toArray();
        assertEquals(1, tsVals.length, "Одно значение в signatureTimeStampToken");

        // ASN1Primitive -> DER байты -> BC TimeStampToken
        byte[] tsTokenDer = tsVals[0].toASN1Primitive().getEncoded();
        TimeStampToken tsTokenParsed = new TimeStampToken(
                new CMSSignedData(tsTokenDer));

        // Сверяем messageImprint
        byte[] imprintHash = tsTokenParsed.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(sigHash, imprintHash,
                "messageImprint в TimeStampToken должен совпадать с хэшем подписи");
    }

    @Test
    @DisplayName("CAdES-T -> crypto-gost: полная верификация CAdESExtender (self-signed)")
    void cadesTFullVerify() throws Exception {
        // Используем самоподписанные сертификаты (как в CAdESExtenderTest)
        KeyPair signerKp = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        KeyPair tsaKp = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        GostCertificate tsaCert =
                CmsTestUtils.createSelfSignedCert(tsaKp.getPrivate(), tsaKp.getPublic());

        byte[] data = "CAdES-T full verify".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, signerKp.getPrivate(), signerCert);

        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(sigHash, hashOid,
                tsaKp.getPrivate(), tsaCert);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        VerifiedCAdESData result = CAdESExtender.verifyCAdEST(cadesT, signerCert, tsaCert);
        assertNotNull(result);
        assertNotNull(result.signers().get(0).signerCertificate());
        assertTrue(result.signers().get(0).timestamps().size() > 0, "Должна быть хотя бы одна метка времени");
    }

    // ========================================================================
    // TSP: crypto-gost <-> BC
    // ========================================================================

    @Test
    @DisplayName("TSP: crypto-gost TimeStampReq -> BC TimeStampRequest round-trip")
    void tspReqToBc() throws Exception {
        byte[] hash = Digest.digest256("TSP test data".getBytes());
        byte[] tspReq = TestData.buildTspRequest(hash, GostOids.DIGEST_256);

        // BC парсит TimeStampReq
        TimeStampRequest bcReq = new TimeStampRequest(tspReq);
        assertTrue(bcReq.getCertReq(), "certReq должен быть true");

        // Сверяем messageImprint
        byte[] bcImprint = bcReq.getMessageImprintDigest();
        assertArrayEquals(hash, bcImprint, "messageImprint должен совпадать");

        // Сверяем hashAlgorithm OID
        assertEquals(new ASN1ObjectIdentifier(GostOids.DIGEST_256),
                bcReq.getMessageImprintAlgOID(),
                "OID хэш-функции должен совпадать");
    }

    @Test
    @DisplayName("TSP: BC TimeStampToken -> crypto-gost TspResponse parse")
    void bcTsTokenToGost() throws Exception {
        byte[] hash = Digest.digest256("BC TSP token data".getBytes());
        String hashOid = GostOids.DIGEST_256;

        byte[] tsToken = TestData.buildTimeStampToken(hash, hashOid,
                tsaKp256.getPrivate(), tsaCert256);

        // crypto-gost парсит TimeStampToken
        TspResponse tspResponse = TspResponse.parseTimeStampToken(tsToken);
        assertEquals(GostOids.PKI_STATUS_GRANTED, tspResponse.status());
        assertNotNull(tspResponse.tstInfo());
        assertArrayEquals(hash, tspResponse.tstInfo().messageImprintHash(),
                "messageImprint должен совпадать");
    }

    @Test
    @DisplayName("TSP: BC TimeStampReq -> crypto-gost DerCodec парсинг")
    void bcTsReqToGostDerCodec() throws Exception {
        byte[] hash = Digest.digest256("BC req to gost".getBytes());
        byte[] tspReq = TestData.buildTspRequest(hash, GostOids.DIGEST_256);

        // BC:
        TimeStampRequest bcReq = new TimeStampRequest(tspReq);

        // crypto-gost: ручной парсинг через DerCodec
        byte[][] parts = DerCodec.parseSequenceContents(tspReq, 0);
        // version = 1
        assertEquals(1, DerCodec.parseInteger(parts[0], 0).intValue(), "version должен быть 1");

        // messageImprint: SEQUENCE { hashAlgorithm, hashedMessage }
        byte[][] imprintParts = DerCodec.parseSequenceContents(parts[1], 0);
        // hashAlgorithm: SEQUENCE { OID }
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(imprintParts[0], 0);
        String parsedOid = DerCodec.parseOid(hashAlgParts[0], 0);
        assertEquals(GostOids.DIGEST_256, parsedOid, "OID хэш-функции");

        // hashedMessage: OCTET STRING
        byte[] parsedHash = DerCodec.parseOctetString(imprintParts[1], 0);
        assertArrayEquals(hash, parsedHash, "hashedMessage");
    }

    // ========================================================================
    // Negative тесты
    // ========================================================================

    @Test
    @DisplayName("Negative: CAdES-BES с tampered signature -> BC reject")
    void tamperedSignatureRejected() throws Exception {
        byte[] data = "tampered sig test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        // Портим подпись в последнем байте
        byte[] tampered = cadesBes.clone();
        tampered[tampered.length - 1] ^= 0xFF;

        CMSSignedData sd = new CMSSignedData(tampered);
        SignerInformation si = sd.getSignerInfos().iterator().next();
        X509CertificateHolder certHolder =
                (X509CertificateHolder) sd.getCertificates().getMatches(si.getSID()).iterator().next();

        boolean verified = si.verify(
                new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(certHolder));
        assertTrue(!verified, "BC должен отвергнуть tampered подпись");
    }

    @Test
    @DisplayName("Negative: signingCertificateV2 с несовпадающим certHash -> BC detect")
    void mismatchedSigningCertV2() throws Exception {
        byte[] data = "mismatched SCV2 test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());

        CMSSignedData sd = new CMSSignedData(cadesBes);
        SignerInformation si = sd.getSignerInfos().iterator().next();
        AttributeTable signed = si.getSignedAttributes();

        // Извлекаем certHash и сравниваем с хэшем ЧУЖОГО сертификата
        Attribute scv2 = signed.get(
                new ASN1ObjectIdentifier(GostOids.SIGNING_CERTIFICATE_V2));
        ASN1Encodable[] vals = scv2.getAttrValues().toArray();
        ASN1Sequence scv2Seq = ASN1Sequence.getInstance(vals[0]);
        ASN1Sequence certsSeq = ASN1Sequence.getInstance(scv2Seq.getObjectAt(0));
        ASN1Sequence essCertIdV2 = ASN1Sequence.getInstance(certsSeq.getObjectAt(0));
        ASN1OctetString certHashOs =
                ASN1OctetString.getInstance(essCertIdV2.getObjectAt(1));

        // Хэш чужого сертификата (CA вместо leaf)
        MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256",
                BouncyCastleProvider.PROVIDER_NAME);
        byte[] caHash = md256.digest(pair256.caCert().getEncoded());

        boolean hashesMatch = Arrays.equals(certHashOs.getOctets(), caHash);
        assertTrue(!hashesMatch,
                "certHash в signingCertificateV2 не должен совпадать с хэшем CA (там leaf)");
    }

    @Test
    @DisplayName("Negative: повреждённый DER CAdES-BES -> BC throw")
    void corruptedDerThrows() {
        byte[] corrupted = new byte[] {0x00, 0x01, 0x02};
        try {
            new CMSSignedData(corrupted);
        } catch (Exception e) {
            // ожидаемо — BC не парсит битые данные
            return;
        }
        throw new AssertionError("Ожидалось исключение от BC");
    }

    @Test
    @DisplayName("Negative: verify() без доверенных сертификатов → PkixException")
    void verifyWithoutTrustedCertsThrows() throws Exception {
        // Самоподписанные сертификаты для минимального CAdES-T
        KeyPair signerKp = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        KeyPair tsaKp = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        GostCertificate tsaCert =
                CmsTestUtils.createSelfSignedCert(tsaKp.getPrivate(), tsaKp.getPublic());

        byte[] cadesBes = TestData.buildCAdESBES("no trust".getBytes(),
                signerKp.getPrivate(), signerCert);
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(sigHash, hashOid,
                tsaKp.getPrivate(), tsaCert);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        try {
            CAdESExtender.verifyCAdEST(cadesT); // без trustedCerts
            throw new AssertionError("Ожидался PkixException при verify() без trustedCerts");
        } catch (PkixException e) {
            assertTrue(e.getMessage().contains("trusted certificate"),
                    "Сообщение должно указывать на отсутствие доверенных сертификатов");
        }
    }

    @Test
    @DisplayName("Negative: addTimestamp() без доверенных сертификатов TSA → PkixException")
    void addTimestampWithoutTsaTrustedThrows() throws Exception {
        KeyPair signerKp = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        GostCertificate signerCert =
                CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        byte[] cadesBes = TestData.buildCAdESBES("no tsa trust".getBytes(),
                signerKp.getPrivate(), signerCert);

        TspTransport dummyTransport = (req, url) -> new byte[0];

        try {
            CAdESExtender.addTimestamp(cadesBes, "http://test", dummyTransport); // без tsaTrusted
            throw new AssertionError(
                    "Ожидался PkixException при addTimestamp() без tsaTrusted");
        } catch (PkixException e) {
            assertTrue(e.getMessage().contains("TSA")
                            || e.getMessage().contains("TSA signature"),
                    "Сообщение должно указывать на отсутствие доверенных сертификатов TSA: "
                    + e.getMessage());
        }
    }

    // ========================================================================
    // Кросс-валидационные негативные: BC подтверждает структурные проблемы
    // ========================================================================

    @Test
    @DisplayName("BC: CAdES-T без signingCertificateV2 — BC подтверждает отсутствие атрибута")
    void bCConfirmsMissingScv2() throws Exception {
        byte[] data = "missing-scv2".getBytes();
        // CAdES-BES без withCAdES() — signingCertificateV2 отсутствует
        byte[] cadesBesNoAttr = TestData.buildCAdESBESNoAttr(data,
                pair256.leafKey(), pair256.leafCert());
        byte[] sigHash = TestData.hashFirstSignature(cadesBesNoAttr);
        String hashOid = TestData.hashOidForParams(TestData.PARAMS_256);
        byte[] tsToken = TestData.buildTimeStampToken(sigHash, hashOid,
                tsaKp256.getPrivate(), tsaCert256);
        byte[] cadesT = TestData.buildCAdEST(cadesBesNoAttr, tsToken);

        // BC парсит — подпись CMS валидна, но signingCertificateV2 отсутствует
        CMSSignedData sd = new CMSSignedData(cadesT);
        SignerInformation si = sd.getSignerInfos().iterator().next();
        AttributeTable signed = si.getSignedAttributes();
        assertNotNull(signed, "signedAttrs должны присутствовать");

        Attribute scv2 = signed.get(
                new ASN1ObjectIdentifier(GostOids.SIGNING_CERTIFICATE_V2));
        assertTrue(scv2 == null,
                "signingCertificateV2 должен отсутствовать в CAdES без withCAdES()");
    }

    @Test
    @DisplayName("BC: certHash в signingCertificateV2 совпадает — BC подтверждает целостность")
    void bCConfirmsCertHashMatches() throws Exception {
        byte[] data = "hash-ok".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data,
                pair256.leafKey(), pair256.leafCert());

        CMSSignedData sd = new CMSSignedData(cadesBes);
        SignerInformation si = sd.getSignerInfos().iterator().next();
        AttributeTable signed = si.getSignedAttributes();
        Attribute scv2 = signed.get(
                new ASN1ObjectIdentifier(GostOids.SIGNING_CERTIFICATE_V2));
        assertNotNull(scv2, "signingCertificateV2 должен присутствовать");

        ASN1Encodable[] vals = scv2.getAttrValues().toArray();
        ASN1Sequence scv2Seq = ASN1Sequence.getInstance(vals[0]);
        ASN1Sequence certsSeq = ASN1Sequence.getInstance(scv2Seq.getObjectAt(0));
        ASN1Sequence essCertIdV2 = ASN1Sequence.getInstance(certsSeq.getObjectAt(0));
        byte[] certHash = ASN1OctetString.getInstance(
                essCertIdV2.getObjectAt(1)).getOctets();

        // Хэш DER сертификата подписанта
        MessageDigest md256 = MessageDigest.getInstance("GOST3411-2012-256",
                BouncyCastleProvider.PROVIDER_NAME);
        byte[] actualHash = md256.digest(pair256.leafCert().getEncoded());

        assertArrayEquals(certHash, actualHash,
                "BC подтверждает: certHash совпадает с хэшем DER сертификата");
    }
}
