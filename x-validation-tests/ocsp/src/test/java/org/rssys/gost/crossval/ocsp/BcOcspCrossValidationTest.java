package org.rssys.gost.crossval.ocsp;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.*;
import org.junit.jupiter.api.*;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.*;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Кросс-валидация OCSP (RFC 6960, RFC 8954, RFC 9215) между библиотекой и BouncyCastle.
 */
@DisplayName("Кросс-валидация OCSP: библиотека <-> BouncyCastle")
class BcOcspCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    private static org.rssys.gost.api.KeyPair caKp256;
    private static GostCertificate caCert256;
    private static org.rssys.gost.api.KeyPair leafKp256;
    private static GostCertificate leafCert256;

    private static org.rssys.gost.api.KeyPair caKp512;
    private static GostCertificate caCert512;

    // BC-ключи для направления BC -> GOST
    private static KeyPair bcCaKp256;
    private static X509Certificate bcCaCert256;
    private static GostCertificate bcCaCert256AsGost;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // GOST-ключи (для GOST -> BC)
        caKp256 = KeyGenerator.generateKeyPair(PARAMS_256);
        caCert256 = buildCa(PARAMS_256, caKp256, "CN=CA256");
        leafKp256 = KeyGenerator.generateKeyPair(PARAMS_256);
        leafCert256 = buildLeaf(PARAMS_256, leafKp256, caKp256, caCert256, "CN=Leaf256");

        caKp512 = KeyGenerator.generateKeyPair(PARAMS_512);
        caCert512 = buildCa(PARAMS_512, caKp512, "CN=CA512");

        // BC-ключи (для BC -> GOST)
        bcCaKp256 = BcOcspHelper.generateBcKeyPair(PARAMS_256);
        bcCaCert256 = BcOcspHelper.buildBcSelfSignedCert(
                bcCaKp256, "CN=BC CA256", PARAMS_256);
        bcCaCert256AsGost = new GostCertificate(bcCaCert256.getEncoded());
    }

    // ========================================================================
    // GOST -> BC: Response
    // ========================================================================

    @Test
    @DisplayName("GOST-ответ good -> BC BasicOCSPResp парсинг")
    void gostRespGoodToBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .good()
                .sign(caKp256.getPrivate());

        OCSPResp ocspResp = new OCSPResp(ocspDer);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, ocspResp.getStatus());

        BasicOCSPResp basic = (BasicOCSPResp) ocspResp.getResponseObject();
        assertNotNull(basic);
        assertEquals(1, basic.getResponses().length);

        CertificateStatus status = basic.getResponses()[0].getCertStatus();
        assertNull(status, "good статус = null в BC");
    }

    @Test
    @DisplayName("GOST-ответ revoked -> BC RevokedStatus")
    void gostRespRevokedToBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .revoked("20260515120000Z")
                .sign(caKp256.getPrivate());

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        assertTrue(basic.getResponses()[0].getCertStatus() instanceof RevokedStatus);
    }

    @Test
    @DisplayName("GOST-ответ unknown -> BC UnknownStatus")
    void gostRespUnknownToBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .unknown()
                .sign(caKp256.getPrivate());

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        assertTrue(basic.getResponses()[0].getCertStatus() instanceof UnknownStatus);
    }

    @Test
    @DisplayName("GOST-ответ с nonce -> BC nonce расширение")
    void gostRespNonceToBc() throws Exception {
        byte[] nonceVal = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .nonce(nonceVal)
                .good()
                .sign(caKp256.getPrivate());

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        Extension nonceExt = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        assertNotNull(nonceExt);
        // extnValue содержит DER типа Nonce (OCTET STRING): BC разбирает его как вложенный слой
        assertArrayEquals(nonceVal,
                org.bouncycastle.asn1.ASN1OctetString.getInstance(nonceExt.getParsedValue())
                        .getOctets(),
                "BC должен прочитать nonce из внутреннего OCTET STRING");
    }

    @Test
    @DisplayName("GOST-ответ с делегированными сертификатами -> BC getCerts()")
    void gostRespDelegatedCertsToBc() throws Exception {
        var responderKp = KeyGenerator.generateKeyPair(PARAMS_256);
        GostCertificate responderCert = buildLeaf(PARAMS_256, responderKp,
                caKp256, caCert256, "CN=Responder");

        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .withDelegatedCerts(responderCert.getEncoded())
                .good()
                .sign(responderKp.getPrivate());

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        assertNotNull(basic.getCerts());
        assertTrue(basic.getCerts().length > 0, "Список делегированных сертификатов непустой");
    }

    @Test
    @DisplayName("GOST-ответ -> BC isSignatureValid")
    void gostRespSignatureVerifyByBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .good()
                .sign(caKp256.getPrivate());

        X509Certificate bcCa = BcOcspHelper.gostCertToBcX509Cert(caCert256);
        JcaContentVerifierProviderBuilder verifierBuilder =
                new JcaContentVerifierProviderBuilder().setProvider("BC");

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        assertTrue(basic.isSignatureValid(verifierBuilder.build(bcCa.getPublicKey())),
                "BC должен подтвердить подпись");
    }

    @Test
    @DisplayName("GOST-ответ 512-битная кривая -> BC парсинг")
    void gostResp512ToBc() throws Exception {
        var leaf512Kp = KeyGenerator.generateKeyPair(PARAMS_512);
        GostCertificate leaf512 = buildLeaf(PARAMS_512, leaf512Kp, caKp512, caCert512, "CN=Leaf512");

        byte[] ocspDer = GostOcspResponseBuilder.create(leaf512.getSerialNumber())
                .issuerDn(caCert512.getSubjectDnBytes())
                .caPublicKey(caKp512.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .good()
                .sign(caKp512.getPrivate());

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        assertEquals(1, basic.getResponses().length);
        assertEquals(GostOids.STREEBOG_512_HASH_LEN,
                basic.getResponses()[0].getCertID().getIssuerNameHash().length);
    }

    // ========================================================================
    // GOST -> BC: Request
    // ========================================================================

    @Test
    @DisplayName("GOST-запрос -> BC OCSPReq парсинг")
    void gostReqToBc() throws Exception {
        byte[] reqDer = GostOcspRequestBuilder.create()
                .targetCert(leafCert256.getEncoded())
                .issuerCert(caCert256.getEncoded())
                .hashLen(32)
                .build();

        OCSPReq req = new OCSPReq(reqDer);
        assertEquals(1, req.getRequestList().length);
        CertificateID certId = req.getRequestList()[0].getCertID();
        assertEquals(0, certId.getSerialNumber().compareTo(
                new BigInteger(1, leafCert256.getSerialNumber())));
    }

    @Test
    @DisplayName("ГОСТ-подписанный запрос -> BC isSigned + GOST verifySignature")
    void gostSignedReqToBc() throws Exception {
        byte[] reqDer = GostOcspRequestBuilder.create()
                .targetCert(leafCert256.getEncoded())
                .issuerCert(caCert256.getEncoded())
                .signKey(leafKp256.getPrivate())
                .params(PARAMS_256)
                .build();

        OCSPReq req = new OCSPReq(reqDer);
        assertTrue(req.isSigned());

        GostOcspRequest parsed = GostOcspRequest.fromDer(reqDer);
        assertTrue(parsed.isSigned());
        parsed.verifySignature(leafKp256.getPublic());
        assertTrue(parsed.isSignatureVerified());
    }

    @Test
    @DisplayName("ГОСТ multi-cert запрос -> BC два Req")
    void gostMultiCertReqToBc() throws Exception {
        byte[] reqDer = GostOcspRequestBuilder.create()
                .targetCert(leafCert256.getEncoded())
                .issuerCert(caCert256.getEncoded())
                .addRequest(leafCert256.getEncoded(), caCert256.getEncoded())
                .hashLen(32)
                .build();

        OCSPReq req = new OCSPReq(reqDer);
        assertEquals(2, req.getRequestList().length);
    }

    // ========================================================================
    // BC -> GOST: Response
    // ========================================================================

    @Test
    @DisplayName("BC-ответ good -> GOST GostOcspResponse парсинг")
    void bcRespGoodToGost() throws Exception {
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponse(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, "good");

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertEquals(1, resp.getResponses().size());
        assertTrue(resp.getResponses().get(0).isGood());
        assertNotNull(resp.getProducedAt());
    }

    @Test
    @DisplayName("BC-ответ revoked -> GOST isRevoked")
    void bcRespRevokedToGost() throws Exception {
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponse(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, "revoked");

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertTrue(resp.getResponses().get(0).isRevoked());
    }

    @Test
    @DisplayName("BC-ответ unknown -> GOST isUnknown()")
    void bcRespUnknownToGost() throws Exception {
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponse(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, "unknown");

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertTrue(resp.getResponses().get(0).isUnknown(),
                "Статус должен быть unknown (BC кодирует тэг 0x82 primitive)");
    }

    @Test
    @DisplayName("BC-ответ -> GOST GostOcspResponse.verify")
    void bcRespSignatureVerifyByGost() throws Exception {
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponse(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, "good");

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());

        PublicKeyParameters bcCaPub = BcOcspHelper.extractGostPubKey(bcCaCert256);
        resp.verify(bcCaPub);
        assertTrue(resp.isSignatureVerified());
    }

    @Test
    @DisplayName("BC-ответ с nonce -> GOST структурная целостность")
    void bcRespNonceToGost() throws Exception {
        byte[] nonceVal = new byte[]{10, 20, 30, 40, 50, 60, 70, 80,
                9, 8, 7, 6, 5, 4, 3, 2};
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponse(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, "good", nonceVal);

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertTrue(resp.getResponses().get(0).isGood());
        assertArrayEquals(nonceVal, resp.getNonce(),
                "Nonce, корректно закодированный BC, должен разбираться без искажений");
    }

    @Test
    @DisplayName("BC-ответ с делегированными сертификатами -> GOST getDelegatedCertificates")
    void bcRespDelegatedCertsToGost() throws Exception {
        KeyPair responderBcKp = BcOcspHelper.generateBcKeyPair(PARAMS_256);
        X509Certificate responderBcCert = BcOcspHelper.buildBcSelfSignedCert(
                responderBcKp, "CN=BC Responder", PARAMS_256);

        byte[] ocspDer = BcOcspHelper.buildBcOcspResponseDelegated(
                leafCert256.getEncoded(), caCert256.getEncoded(),
                bcCaKp256, bcCaCert256, responderBcKp, responderBcCert);

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertFalse(resp.getDelegatedCertificates().isEmpty());
    }

    // ========================================================================
    // BC <-> GOST: byKey ResponderID
    // ========================================================================

    @Test
    @DisplayName("GOST byKey ответ -> BC BasicOCSPResp.readObject")
    void gostByKeyRespToBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .withResponderByKey()
                .good()
                .sign(caKp256.getPrivate());

        OCSPResp ocspResp = new OCSPResp(ocspDer);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, ocspResp.getStatus());

        BasicOCSPResp basic = (BasicOCSPResp) ocspResp.getResponseObject();
        assertNotNull(basic);
        assertEquals(1, basic.getResponses().length);
        assertNull(basic.getResponses()[0].getCertStatus(), "good статус = null в BC");
    }

    @Test
    @DisplayName("BC byKey ответ (Streebog) -> GOST парсинг")
    void bcByKeyRespToGost() throws Exception {
        byte[] streebogKeyHash = CertIdHasher.hashIssuerPublicKey(bcCaCert256AsGost);

        byte[] ocspDer = BcOcspHelper.buildBcOcspResponseByKey(
                bcCaCert256.getEncoded(), bcCaCert256.getEncoded(),
                bcCaKp256, bcCaCert256, streebogKeyHash);

        GostOcspResponse resp = GostOcspResponse.fromDer(ocspDer);
        assertTrue(resp.isSuccessful());
        assertEquals(1, resp.getResponses().size());
        assertTrue(resp.getResponses().get(0).isGood());
        assertEquals(GostOcspResponse.ResponderIdType.BY_KEY, resp.getResponderIdType());
        assertArrayEquals(streebogKeyHash, resp.getResponderKeyHash(),
                "keyHash из BC-ответа должен совпадать с ожидаемым Streebog-хэшем");
    }

    // ========================================================================
    // BC -> GOST: Response c ГОСТ-совместимым CertID (verify() round-trip)
    // ========================================================================

    @Test
    @DisplayName("BC-ответ с GOST CertID -> OcspVerifier.verify()")
    void bcRespWithGostCertId_verifyByGost() throws Exception {
        byte[] ocspDer = BcOcspHelper.buildBcOcspResponseWithGostCertId(
                bcCaCert256.getEncoded(), bcCaCert256.getEncoded(),
                bcCaKp256, bcCaCert256);

        OcspVerifier.verify(
                ocspDer, bcCaCert256AsGost.getSerialNumber(), bcCaCert256AsGost);
    }

    @Test
    @DisplayName("BC-ответ byKey с GOST CertID -> OcspVerifier.verify()")
    void bcByKeyRespWithGostCertId_verifyByGost() throws Exception {
        byte[] streebogKeyHash = CertIdHasher.hashIssuerPublicKey(bcCaCert256AsGost);

        byte[] ocspDer = BcOcspHelper.buildBcOcspResponseByKeyWithGostCertId(
                bcCaCert256.getEncoded(), bcCaCert256.getEncoded(),
                bcCaKp256, bcCaCert256, streebogKeyHash);

        OcspVerifier.verify(
                ocspDer, bcCaCert256AsGost.getSerialNumber(), bcCaCert256AsGost);
    }

    @Test
    @DisplayName("BC-ответ делегированный с GOST CertID -> OcspVerifier.verify()")
    void bcDelegatedWithGostCertId_verifyByGost() throws Exception {
        KeyPair responderKp = BcOcspHelper.generateBcKeyPair(PARAMS_256);
        X509Certificate responderCert = BcOcspHelper.buildBcResponderCert(
                responderKp, "CN=BC OCSP Responder",
                bcCaKp256, "CN=BC CA256", PARAMS_256);

        byte[] ocspDer = BcOcspHelper.buildBcOcspResponseDelegatedWithGostCertId(
                bcCaCert256.getEncoded(), bcCaCert256.getEncoded(),
                responderKp, responderCert,
                responderKp, responderCert);

        OcspVerifier.verify(
                ocspDer, bcCaCert256AsGost.getSerialNumber(),
                bcCaCert256AsGost, bcCaCert256AsGost, null);
    }

    // ========================================================================
    // BC -> GOST: Request
    // ========================================================================

    @Test
    @DisplayName("BC-запрос -> GOST GostOcspRequest парсинг")
    void bcReqToGost() throws Exception {
        BcOcspHelper.BcOcspRequest bcRequest = BcOcspHelper.buildBcOcspRequestWithNonce(
                leafCert256.getEncoded(), caCert256.getEncoded());

        GostOcspRequest parsed = GostOcspRequest.fromDer(bcRequest.der());
        assertEquals(1, parsed.getCertIds().size());
        CertId certId = parsed.getCertIds().get(0);
        assertArrayEquals(leafCert256.getSerialNumber(), certId.serialNumber());
        assertArrayEquals(bcRequest.nonce(), parsed.getNonce(),
                "Nonce из BC-запроса должен совпасть побайтно");
        assertFalse(parsed.isSigned());
    }

    @Test
    @DisplayName("BC-запрос SHA-256 CertID -> GOST парсинг (parser flexibility)")
    void bcReqSha256ToGost() throws Exception {
        byte[] reqDer = BcOcspHelper.buildBcOcspRequestSha256(
                leafCert256.getEncoded(), caCert256.getEncoded());

        GostOcspRequest parsed = GostOcspRequest.fromDer(reqDer);
        assertEquals(1, parsed.getCertIds().size());
        assertArrayEquals(leafCert256.getSerialNumber(),
                parsed.getCertIds().get(0).serialNumber());
    }

    // ========================================================================
    // CertID cross-check
    // ========================================================================

    @Test
    @DisplayName("CertID round-trip — GOST-ответ -> BC парсинг, сверка issuerNameHash/issuerKeyHash")
    void certIdCrossCheck() throws Exception {
        // Строим OCSP-ответ через GOST
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .good()
                .sign(caKp256.getPrivate());

        // GOST парсит — извлекаем issuerNameHash/issuerKeyHash из SingleResponse
        GostOcspResponse gostResp = GostOcspResponse.fromDer(ocspDer);
        SingleOcspResponse gostSr = gostResp.getResponses().get(0);
        byte[] gostNameHash = gostSr.issuerNameHash();
        byte[] gostKeyHash = gostSr.issuerKeyHash();

        // BC парсит — извлекаем из CertificateID
        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(ocspDer).getResponseObject();
        CertificateID bcCertId = basic.getResponses()[0].getCertID();

        assertArrayEquals(gostNameHash, bcCertId.getIssuerNameHash(),
                "issuerNameHash из GOST и BC должны совпадать");
        assertArrayEquals(gostKeyHash, bcCertId.getIssuerKeyHash(),
                "issuerKeyHash из GOST и BC должны совпадать");
    }

    // ========================================================================
    // Negative
    // ========================================================================

    @Test
    @DisplayName("Tampered подпись OCSP -> BC isSignatureValid = false")
    void tamperedOcspSigRejectedByBc() throws Exception {
        byte[] ocspDer = GostOcspResponseBuilder.create(leafCert256.getSerialNumber())
                .issuerDn(caCert256.getSubjectDnBytes())
                .caPublicKey(caKp256.getPublic())
                .producedAt("20260601000000Z")
                .thisUpdate("20260601000000Z")
                .good()
                .sign(caKp256.getPrivate());

        byte[] tampered = ocspDer.clone();
        tampered[tampered.length - 1] ^= 0xFF;

        X509Certificate bcCa = BcOcspHelper.gostCertToBcX509Cert(caCert256);
        JcaContentVerifierProviderBuilder verifierBuilder =
                new JcaContentVerifierProviderBuilder().setProvider("BC");

        BasicOCSPResp basic = (BasicOCSPResp) new OCSPResp(tampered).getResponseObject();
        assertFalse(basic.isSignatureValid(verifierBuilder.build(bcCa.getPublicKey())),
                "BC должен отвергнуть tampered подпись");
    }

    @Test
    @DisplayName("Non-successful responseStatus -> GOST isSuccessful() = false")
    void nonSuccessfulStatusGost() throws Exception {
        // ENUMERATED 1 = malformedRequest, без responseBytes
        byte[] badDer = org.rssys.gost.util.DerCodec.encodeSequence(
                new byte[]{0x0A, 0x01, 0x01});

        GostOcspResponse resp = GostOcspResponse.fromDer(badDer);
        assertFalse(resp.isSuccessful());
        assertTrue(resp.getResponses().isEmpty());
    }

    @Test
    @DisplayName("Non-successful статус -> BC read")
    void nonSuccessfulStatusBc() throws Exception {
        // ENUMERATED 1 (malformedRequest), без responseBytes
        byte[] badDer = org.rssys.gost.util.DerCodec.encodeSequence(
                new byte[]{0x0A, 0x01, 0x01});

        OCSPResp ocspResp = new OCSPResp(badDer);
        assertEquals(1, ocspResp.getStatus());
    }

    @Test
    @DisplayName("Malformed DER -> GOST бросает исключение")
    void malformedDerThrows() {
        byte[] corrupted = new byte[]{0x00, 0x01, 0x02};
        assertThrows(Exception.class, () -> GostOcspResponse.fromDer(corrupted));

        // BC может бросить или распарсить как не-успешный статус — оба варианта допустимы
        try {
            new OCSPResp(corrupted);
        } catch (Exception ignored) {
            // BC тоже может бросить — это приемлемо
        }
    }

    // ========================================================================
    // id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1): кросс-валидация кодировки
    // ========================================================================

    // Каноническая extnValue: OCTET STRING, оборачивающий DER NULL. Именно байты
    // фиксируем, а не «команда не упала»: исторически часть реализаций кодирует
    // пустой OCTET STRING (04 00), что несовместимо с 04 02 05 00.
    private static final byte[] NOCHECK_EXTN_VALUE = {0x04, 0x02, 0x05, 0x00};

    @Test
    @DisplayName("GOST cert с ocspNoCheck -> BC парсит расширение, extnValue = 04 02 05 00")
    void gostNoCheck_parsedByBc() throws Exception {
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
        GostCertificate cert =
                GostCertificateBuilder.create(PARAMS_256, "CN=GOST Responder")
                        .publicKey(kp.getPublic())
                        .issuerDn(caCert256.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20250103000000Z")
                        .extendedKeyUsage(GostOids.EXT_OCSP_SIGNING)
                        .ocspNoCheck()
                        .serial(BigInteger.valueOf(1))
                        .sign(caKp256.getPrivate());

        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
        Extension ext = holder.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck);
        assertNotNull(ext, "BC обязан увидеть расширение id-pkix-ocsp-nocheck");
        assertFalse(ext.isCritical(), "nocheck обязано быть non-critical");
        assertArrayEquals(
                NOCHECK_EXTN_VALUE,
                ext.getExtnValue().getEncoded(),
                "extnValue должно быть OCTET STRING, оборачивающий DER NULL (04 02 05 00)");
    }

    @Test
    @DisplayName("BC cert с ocsp-nocheck -> GOST hasOcspNoCheck() == true, кодировка совпадает")
    void bcNoCheck_readByGost() throws Exception {
        KeyPair kp = BcOcspHelper.generateBcKeyPair(PARAMS_256);
        X500Name dn = new X500Name("CN=BC Responder NoCheck");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date nb = new Date(System.currentTimeMillis() - 86400000L);
        Date na = new Date(System.currentTimeMillis() + 86400000L);
        JcaX509v3CertificateBuilder cb =
                new JcaX509v3CertificateBuilder(dn, serial, nb, na, dn, kp.getPublic());
        cb.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning));
        cb.addExtension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nocheck,
                false,
                org.bouncycastle.asn1.DERNull.INSTANCE);
        ContentSigner signer =
                new JcaContentSignerBuilder("GOST3411-2012-256WITHECGOST3410-2012-256")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(kp.getPrivate());
        X509CertificateHolder holder = cb.build(signer);
        X509Certificate bcCert =
                new JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate(holder);

        GostCertificate gostCert = new GostCertificate(bcCert.getEncoded());
        assertTrue(
                gostCert.hasOcspNoCheck(),
                "GOST обязан распознать nocheck в BC-построенном сертификате");
        // BC независимо кодирует DERNull.INSTANCE как 04 02 05 00 — подтверждает,
        // что наша каноническая кодировка совпадает с эталонной реализацией.
        assertArrayEquals(
                NOCHECK_EXTN_VALUE,
                holder.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck)
                        .getExtnValue()
                        .getEncoded(),
                "BC-кодировка nocheck должна совпадать с канонической (04 02 05 00)");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================
    private static GostCertificate buildCa(ECParameters params,
                                           org.rssys.gost.api.KeyPair caKp, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(caKp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("20351231235959Z")
                .basicConstraints(true, null)
                .keyUsage(KeyUsage.KEY_CERT_SIGN)
                .serial(BigInteger.valueOf(2))
                .sign(caKp.getPrivate());
    }

    private static GostCertificate buildLeaf(ECParameters params,
                                             org.rssys.gost.api.KeyPair leafKp,
                                             org.rssys.gost.api.KeyPair caKp,
                                             GostCertificate ca, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(leafKp.getPublic())
                .issuerDn(ca.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20261231235959Z")
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .serial(BigInteger.valueOf(3))
                .sign(caKp.getPrivate());
    }
}
