package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.junit.jupiter.api.*;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Кросс-валидация TSP (RFC 3161) между библиотекой и BouncyCastle.
 */
@DisplayName("Кросс-валидация TSP: библиотека <-> BouncyCastle")
class BcTspCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final String DUMMY_POLICY_OID = "1.3.6.1.4.1.4146.1.2.1";
    private static final ASN1ObjectIdentifier STB256_OID =
            new ASN1ObjectIdentifier(GostOids.DIGEST_256);

    private static final ASN1ObjectIdentifier TSA_POLICY_OID =
            new ASN1ObjectIdentifier(DUMMY_POLICY_OID);

    private static org.rssys.gost.api.KeyPair tsaGostKp256;
    private static GostCertificate tsaGostCert256;
    private static KeyPair tsaBcKp256;
    private static X509Certificate tsaBcCert256;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        tsaGostKp256 = KeyGenerator.generateKeyPair(PARAMS_256);
        tsaGostCert256 = buildGostTsaCert(tsaGostKp256);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        kpg.initialize(new ECNamedCurveGenParameterSpec(
                "Tc26-Gost-3410-12-256-paramSetA"), new SecureRandom());
        tsaBcKp256 = kpg.generateKeyPair();
        tsaBcCert256 = buildBcSelfSignedCert(tsaBcKp256, "CN=BC TSA256");
    }

    // ========================================================================
    // BC -> GOST: запрос
    // ========================================================================

    @Test
    @DisplayName("BC TimeStampReq -> ГОСТ ручной парсинг через DerCodec")
    void bcTsReqToGostManual() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());

        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        BigInteger nonce = BigInteger.valueOf(12345);
        TimeStampRequest bcReq = gen.generate(STB256_OID, hash, nonce);

        byte[] reqDer = bcReq.getEncoded();

        byte[][] parts = DerCodec.parseSequenceContents(reqDer, 0);
        assertEquals(1, DerCodec.parseInteger(parts[0], 0).intValue(), "version = 1");

        byte[][] imprintParts = DerCodec.parseSequenceContents(parts[1], 0);
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(imprintParts[0], 0);
        assertEquals(GostOids.DIGEST_256, DerCodec.parseOid(hashAlgParts[0], 0));
        assertArrayEquals(hash, DerCodec.parseOctetString(imprintParts[1], 0));

        BigInteger parsedNonce = null;
        for (int i = 2; i < parts.length; i++) {
            if ((parts[i][0] & 0xFF) == DerCodec.TAG_INTEGER) {
                parsedNonce = DerCodec.parseInteger(parts[i], 0);
                break;
            }
        }
        assertEquals(nonce, parsedNonce, "nonce должен совпадать");
        assertTrue(bcReq.getCertReq(), "certReq должен быть true");
    }

    // ========================================================================
    // BC -> GOST: TimeStampToken
    // ========================================================================

    @Test
    @DisplayName("BC TimeStampToken -> ГОСТ TspResponse.parseTimeStampToken()")
    void bcTsTokenToGost() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest bcReq = reqGen.generate(STB256_OID, hash);

        TimeStampToken tsToken = buildBcTimeStampToken(bcReq, tsaBcKp256,
                BigInteger.ONE);

        TspResponse tspResp = TspResponse.parseTimeStampToken(tsToken.getEncoded());
        assertNotNull(tspResp.tstInfo());
        assertArrayEquals(hash, tspResp.tstInfo().messageImprintHash());
        assertEquals(GostOids.DIGEST_256, tspResp.tstInfo().messageImprintAlgOid());
        assertNotNull(tspResp.tstInfo().genTime());
        assertEquals(BigInteger.ONE, tspResp.tstInfo().serialNumber());
    }

    // ========================================================================
    // BC -> GOST: TimeStampResp
    // ========================================================================

    @Test
    @DisplayName("BC TimeStampResp -> ГОСТ TspResponse.fromDer()")
    void bcTsRespToGost() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest bcReq = reqGen.generate(STB256_OID, hash);

        TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(
                createTokenGenerator(tsaBcKp256, tsaBcCert256),
                Set.of(GostOids.DIGEST_256));
        TimeStampResponse bcResp = respGen.generate(bcReq, BigInteger.ONE, new Date());

        TspResponse tspResp = TspResponse.fromDer(bcResp.getEncoded());
        assertEquals(GostOids.PKI_STATUS_GRANTED, tspResp.status());
        assertNotNull(tspResp.tstInfo());
    }

    // ========================================================================
    // BC -> GOST: nonce round-trip
    // ========================================================================

    @Test
    @DisplayName("BC -> ГОСТ nonce round-trip")
    void bcNonceRoundTrip() throws Exception {
        byte[] hash = Digest.digest256("nonce test".getBytes());
        BigInteger nonce = BigInteger.valueOf(0xDEADBEEFL);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest bcReq = reqGen.generate(STB256_OID, hash, nonce);

        TimeStampToken tsToken = buildBcTimeStampToken(bcReq, tsaBcKp256,
                BigInteger.TWO);

        TspResponse tspResp = TspResponse.parseTimeStampToken(tsToken.getEncoded());
        assertNotNull(tspResp.tstInfo().nonce());
        assertEquals(nonce, tspResp.tstInfo().nonce(), "nonce должен совпадать");
    }

    // ========================================================================
    // BC -> GOST: верификация подписи
    // ========================================================================

    @Test
    @DisplayName("ГОСТ TimeStampToken -> verify() с критическим EKU timeStamping")
    void gostTsTokenVerifyWithEku() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());

        // ГОСТ строит TimeStampToken с сертификатом, имеющим критический EKU timeStamping
        byte[] tstInfoDer = TestData.buildTstInfoDer(hash, GostOids.DIGEST_256);
        byte[] tokenDer = org.rssys.gost.pkix.cms.CmsSignedDataBuilder.create()
                .data(tstInfoDer)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaGostKp256.getPrivate(), tsaGostCert256)
                .withCAdES()
                .build();

        TspResponse tspResp = TspResponse.parseTimeStampToken(tokenDer);
        assertNotNull(tspResp.tstInfo());

        tspResp.verify(hash, GostOids.DIGEST_256, null, tsaGostCert256);
        assertTrue(tspResp.isSignatureVerified());
    }

    // ========================================================================
    // GOST -> BC: TimeStampResp
    // ========================================================================

    @Test
    @DisplayName("ГОСТ TimeStampResp -> BC TimeStampResponse парсинг")
    void gostTsRespToBc() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());
        byte[] tsTokenDer = TestData.buildTimeStampToken(hash, GostOids.DIGEST_256,
                tsaGostKp256.getPrivate(), tsaGostCert256);
        byte[] tspRespDer = TestData.buildTspResponse(tsTokenDer);

        TimeStampResponse bcResp = new TimeStampResponse(tspRespDer);
        assertEquals(0, bcResp.getStatus(), "Статус должен быть GRANTED");
        assertNotNull(bcResp.getTimeStampToken(), "TimeStampToken должен присутствовать");
    }

    // ========================================================================
    // GOST -> BC: TimeStampToken
    // ========================================================================

    @Test
    @DisplayName("ГОСТ TimeStampToken -> BC TimeStampToken.validate()")
    void gostTsTokenToBcValidate() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());
        byte[] tsTokenDer = TestData.buildTimeStampToken(hash, GostOids.DIGEST_256,
                tsaGostKp256.getPrivate(), tsaGostCert256);

        TimeStampToken bcToken = new TimeStampToken(new CMSSignedData(tsTokenDer));
        byte[] imprintHash = bcToken.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(hash, imprintHash);

        // Валидация тем же сертификатом, что подписал токен (GOST)
        X509Certificate gostTsaX509 = (X509Certificate) java.security.cert.CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(
                        tsaGostCert256.getEncoded()));
        bcToken.validate(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC").build(new JcaX509CertificateHolder(gostTsaX509)));
    }

    // ========================================================================
    // Negative
    // ========================================================================

    @Test
    @DisplayName("Tampered messageImprint -> mismatch")
    void tamperedImprintDetected() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());
        byte[] tsTokenDer = TestData.buildTimeStampToken(hash, GostOids.DIGEST_256,
                tsaGostKp256.getPrivate(), tsaGostCert256);

        TimeStampToken bcToken = new TimeStampToken(new CMSSignedData(tsTokenDer));
        byte[] wrongHash = Digest.digest256("wrong".getBytes());
        assertFalse(MessageDigest.isEqual(
                wrongHash, bcToken.getTimeStampInfo().getMessageImprintDigest()));
    }

    @Test
    @DisplayName("Tampered подпись -> BC reject")
    void tamperedSignatureRejected() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());
        byte[] tsTokenDer = TestData.buildTimeStampToken(hash, GostOids.DIGEST_256,
                tsaGostKp256.getPrivate(), tsaGostCert256);

        // Конвертируем GOST-сертификат в X509Certificate для BC-верификации
        X509Certificate gostTsaX509 = (X509Certificate) java.security.cert.CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(
                        tsaGostCert256.getEncoded()));

        byte[] tampered = tsTokenDer.clone();
        tampered[tampered.length - 1] ^= 0xFF;

        try {
            TimeStampToken broken = new TimeStampToken(new CMSSignedData(tampered));
            assertThrows(Exception.class, () -> broken.validate(
                    new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC").build(
                                    new JcaX509CertificateHolder(gostTsaX509))));
        } catch (Exception e) {
            // BC не может распарсить битые данные — допустимо
        }
    }

    @Test
    @DisplayName("Rejected TSP status -> ГОСТ PkixException")
    void rejectedStatusThrows() throws Exception {
        // Строим rejected ответ вручную: статус 2 без токена
        byte[] status = DerCodec.encodeSequence(
                DerCodec.encodeInteger(BigInteger.valueOf(
                        GostOids.PKI_STATUS_REJECTED)));
        byte[] badDer = DerCodec.encodeSequence(status);

        assertThrows(PkixException.class, () -> TspResponse.fromDer(badDer));
    }

    @Test
    @DisplayName("Granted без TimeStampToken -> ГОСТ PkixException")
    void grantedWithoutTokenThrows() throws Exception {
        byte[] status = DerCodec.encodeSequence(
                DerCodec.encodeInteger(BigInteger.valueOf(
                        GostOids.PKI_STATUS_GRANTED)));
        byte[] badDer = DerCodec.encodeSequence(status);

        assertThrows(PkixException.class, () -> TspResponse.fromDer(badDer));
    }

    // ========================================================================
    // TspResponseBuilder -> BC: новый TSP-серверный билдер
    // ========================================================================

    @Test
    @DisplayName("TspResponseBuilder -> BC TimeStampResponse парсинг и validate")
    void tspResponseBuilderToBc() throws Exception {
        byte[] hash = Digest.digest256("builder-test".getBytes());
        byte[] reqDer = TspRequestBuilder.create()
                .messageImprint(hash, GostOids.DIGEST_256)
                .build();
        byte[] respDer = TspResponseBuilder.create(reqDer)
                .signer(tsaGostKp256.getPrivate(), tsaGostCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .withCAdES()
                .buildGranted();

        TimeStampResponse bcResp = new TimeStampResponse(respDer);
        assertEquals(0, bcResp.getStatus(), "PKIStatus должен быть GRANTED");
        assertNotNull(bcResp.getTimeStampToken(), "TimeStampToken должен быть");

        X509Certificate gostTsaX509 = gostCertToX509(tsaGostCert256);
        bcResp.getTimeStampToken().validate(
                new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider("BC").build(new JcaX509CertificateHolder(gostTsaX509)));
    }

    @Test
    @DisplayName("TspResponseBuilder -> BC: nonce echo проверяется")
    void tspResponseBuilderToBcNonce() throws Exception {
        byte[] hash = Digest.digest256("nonce-test".getBytes());
        BigInteger nonce = BigInteger.valueOf(98765);
        byte[] reqDer = TspRequestBuilder.create()
                .messageImprint(hash, GostOids.DIGEST_256)
                .nonce(nonce)
                .build();
        byte[] respDer = TspResponseBuilder.create(reqDer)
                .signer(tsaGostKp256.getPrivate(), tsaGostCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .withCAdES()
                .buildGranted();

        TimeStampResponse bcResp = new TimeStampResponse(respDer);
        assertEquals(nonce, bcResp.getTimeStampToken().getTimeStampInfo().getNonce(),
                "nonce должен совпадать");
    }

    @Test
    @DisplayName("TspResponseBuilder -> BC: rejected — PKIFreeText round-trip")
    void tspResponseBuilderRejectedToBc() throws Exception {
        byte[] rejectionDer = TspResponseBuilder.buildRejected("Go away");

        TimeStampResponse bcResp = new TimeStampResponse(rejectionDer);
        assertEquals(2, bcResp.getStatus(), "PKIStatus должен быть REJECTED");
        assertEquals("Go away", bcResp.getStatusString(),
                "statusString должен быть распарсен BC");
    }

    @Test
    @DisplayName("TspResponseBuilder -> BC: неверный imprint детектится")
    void tspResponseBuilderWrongImprintToBc() throws Exception {
        byte[] hash = Digest.digest256("imprint-test".getBytes());
        byte[] reqDer = TspRequestBuilder.create()
                .messageImprint(hash, GostOids.DIGEST_256)
                .build();
        byte[] respDer = TspResponseBuilder.create(reqDer)
                .signer(tsaGostKp256.getPrivate(), tsaGostCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .withCAdES()
                .buildGranted();

        TimeStampResponse bcResp = new TimeStampResponse(respDer);
        byte[] wrongHash = Digest.digest256("wrong-imprint".getBytes());
        assertFalse(MessageDigest.isEqual(
                wrongHash, bcResp.getTimeStampToken().getTimeStampInfo()
                        .getMessageImprintDigest()),
                "Imprint не должен совпадать с чужим хэшем");
    }

    @Test
    @DisplayName("TspResponseBuilder -> BC: failInfo BAD_ALG round-trip")
    void tspResponseBuilderFailInfoToBc() throws Exception {
        byte[] rejectionDer = TspResponseBuilder.buildRejected(GostOids.PKI_FAIL_BAD_ALG);

        TimeStampResponse bcResp = new TimeStampResponse(rejectionDer);
        assertEquals(2, bcResp.getStatus(), "PKIStatus должен быть REJECTED");
        // BC PKIFailureInfo.badAlg.intValue() — бит 0 = 128
        assertEquals(128, bcResp.getFailInfo().intValue(),
                "failInfo должен быть badAlg (бит 0, intValue=128)");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    private static X509Certificate gostCertToX509(GostCertificate gostCert) throws Exception {
        return (X509Certificate) java.security.cert.CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(
                        gostCert.getEncoded()));
    }

    private TimeStampToken buildBcTimeStampToken(TimeStampRequest req, KeyPair tsaKp,
                                                  BigInteger serial) throws Exception {
        TimeStampTokenGenerator tokenGen = createTokenGenerator(tsaKp, tsaBcCert256);
        return tokenGen.generate(req, serial, new Date());
    }

    private static TimeStampTokenGenerator createTokenGenerator(KeyPair kp,
                                                                 X509Certificate cert)
            throws Exception {
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(
                "GOST3411-2012-256WITHECGOST3410-2012-256")
                .setProvider("BC");
        ContentSigner signer = csBuilder.build(kp.getPrivate());

        JcaDigestCalculatorProviderBuilder digestProviderBuilder =
                new JcaDigestCalculatorProviderBuilder().setProvider("BC");
        JcaSignerInfoGeneratorBuilder sigInfoBuilder =
                new JcaSignerInfoGeneratorBuilder(digestProviderBuilder.build());
        SignerInfoGenerator sigInfoGen = sigInfoBuilder.build(signer, certHolder);

        DigestCalculator stbCalc = digestProviderBuilder.build().get(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        new ASN1ObjectIdentifier(GostOids.DIGEST_256)));
        return new TimeStampTokenGenerator(sigInfoGen, stbCalc,
                new ASN1ObjectIdentifier(DUMMY_POLICY_OID));
    }

    private static GostCertificate buildGostTsaCert(org.rssys.gost.api.KeyPair kp) {
        return org.rssys.gost.pkix.cert.GostCertificateBuilder
                .create(PARAMS_256, "CN=TSA")
                .publicKey(kp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("20351231235959Z")
                .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                .assembleCert(kp.getPrivate());
    }

    private static X509Certificate buildBcSelfSignedCert(KeyPair kp, String dnStr)
            throws Exception {
        var issuer = new org.bouncycastle.asn1.x500.X500Name(dnStr);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86400000L);
        var certBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, kp.getPublic());
        // EKU id-kp-timeStamping — критический (RFC 5280 §4.2.1.12 требует CRITICAL для EKU)
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping));
        var signer = new JcaContentSignerBuilder(
                "GOST3411-2012-256WITHECGOST3410-2012-256")
                .setProvider("BC").build(kp.getPrivate());
        var holder = certBuilder.build(signer);
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(holder);
    }
}
