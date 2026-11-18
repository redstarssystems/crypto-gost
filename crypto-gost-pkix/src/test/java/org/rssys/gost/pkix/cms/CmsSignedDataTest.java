package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RawCrlTestSupport;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CMS SignedData: подпись и верификация")
class CmsSignedDataTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static PrivateKeyParameters privateKey;
    private static PublicKeyParameters publicKey;
    private static GostCertificate selfSignedCert;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
        selfSignedCert = CmsTestUtils.createSelfSignedCert(privateKey, publicKey);
    }

    @Test
    @DisplayName("SignedData: подпись и верификация с инкапсулированными данными")
    void signAndVerifyEncapsulated() throws PkixException {
        byte[] data = "Hello, CMS SignedData!".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        assertNotNull(signedData);
        assertTrue(signedData.length > 0);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ANY,
                                Revocation.none()));

        assertNotNull(result.data());
        assertArrayEquals(data, result.data());
        assertNotNull(result.signerCertificate());
    }

    @Test
    @DisplayName("SignedData: detached подпись")
    void signAndVerifyDetached() throws PkixException {
        byte[] data = "Detached signature test".getBytes();

        CmsSignedDataBuilder builder =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true);

        byte[] signedData = builder.build();
        assertNotNull(signedData);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())
                                .detached(data));

        assertArrayEquals(data, result.data(), "detached-метод должен вернуть переданный документ");
        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "attached-режим не должен принимать detached-подпись");
    }

    @Test
    @DisplayName("SignedData: detached-подпись не принимает подменённый документ")
    void verifyDetachedRejectsWrongContent() {
        byte[] data = "Detached signature test".getBytes();
        byte[] tampered = "Tampered content".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true)
                        .build();

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())
                                        .detached(tampered)),
                "подмена документа должна ломать message-digest");
    }

    @Test
    @DisplayName("SignedData: attached-подпись не принимается detached-методом")
    void verifyDetachedRejectsAttached() {
        byte[] data = "Attached content".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())
                                        .detached(data)),
                "detached-метод должен требовать отсутствие eContent");
    }

    @Test
    @DisplayName("SignedData: detached ALL и signature-only варианты")
    void verifyDetachedAllAndSignatureOnly() throws PkixException {
        byte[] data = "Detached all".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true)
                        .build();

        VerifiedSignedData all =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ALL,
                                        Revocation.none())
                                .detached(data));
        assertArrayEquals(data, all.data(), "detached-проверка ALL должна вернуть документ");
        assertEquals(1, all.signers().size());

        VerifiedSignedData anyOnly =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.signatureOnly(SignerSelection.ANY).detached(data));
        assertArrayEquals(data, anyOnly.data());

        VerifiedSignedData allOnly =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.signatureOnly(SignerSelection.ALL).detached(data));
        assertArrayEquals(data, allOnly.data());
    }

    @Test
    @DisplayName(
            "Revocation: список внешних CRL обязателен (null отвергается), закреплённый подписант CRL не требует")
    void verifyDetachedRevocationRequiresExternalCrls() throws PkixException {
        byte[] data = "Detached revocation".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true)
                        .build();

        assertThrows(
                IllegalArgumentException.class,
                () -> Revocation.required(null),
                "null вместо externalCrls должен отклоняться");
        assertThrows(
                IllegalArgumentException.class,
                () -> Revocation.ifAvailable(null),
                "null вместо externalCrls должен отклоняться");

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.required(List.of()))
                                .detached(data));
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("SignedData: неверная подпись — результат false")
    void verifyTamperedData() {
        byte[] data = "Original content".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        signedData[signedData.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Испорченная подпись должна бросить PkixException");
    }

    @Test
    @DisplayName("SignedData: кодирование/декодирование ContentInfo")
    void contentInfoRoundtrip() throws PkixException {
        byte[] content = new byte[] {1, 2, 3, 4, 5};
        byte[] encoded = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, content);
        CmsContentInfo decoded = CmsContentInfo.decode(encoded);

        assertEquals(GostOids.CMS_SIGNED_DATA, decoded.contentType());
        assertArrayEquals(content, decoded.content());
    }

    @Test
    @DisplayName("SignedData: кодирование/декодирование CmsAttribute")
    void attributeRoundtrip() {
        byte[] value = DerCodec.encodeOctetString(new byte[] {0x0A, 0x0B});
        byte[] encoded = CmsAttribute.encode(GostOids.ATTR_CONTENT_TYPE, value);
        CmsAttribute decoded = CmsAttribute.decode(encoded);

        assertEquals(GostOids.ATTR_CONTENT_TYPE, decoded.attrType());
        assertEquals(1, decoded.attrValues().length);
        assertArrayEquals(value, decoded.attrValues()[0]);
    }

    @Test
    @DisplayName("SignedData: CmsAlgorithmIdentifier с NULL-параметрами")
    void algorithmIdentifierNull() {
        byte[] encoded = CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256);
        CmsAlgorithmIdentifier decoded = CmsAlgorithmIdentifier.decode(encoded);

        assertEquals(GostOids.DIGEST_256, decoded.algorithmOid());
        assertNotNull(decoded.parameters());
    }

    @Test
    @DisplayName("Регресс: digestAlgorithm в SignedData и SignerInfo несёт NULL-параметры")
    void digestAlgorithmHasNullParams() throws PkixException {
        // Форма digestAlgorithm (OID+NULL) обязательна по Р 1323565.1.025 §4.1/4.2
        // и совпадает с эталоном openssl gost-engine. Этот ассерт защищает от
        // молчаливого возврата к форме без параметров при будущем рефакторинге —
        // такое расхождение невидимо собственному верификатору, но строгие
        // ГОСТ-верификаторы (напр. КриптоПро) вправе его отвергнуть.
        byte[] data = "digest null param regression".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        // SignedData.digestAlgorithms [1] — SET OF AlgorithmIdentifier
        byte[][] digestAlgs = DerCodec.parseSetContents(sdParts[1], 0);
        for (byte[] algId : digestAlgs) {
            byte[][] algParts = DerCodec.parseSequenceContents(algId, 0);
            assertEquals(
                    2,
                    algParts.length,
                    "digestAlgorithms: AlgorithmIdentifier должен нести OID и NULL");
            assertEquals(
                    DerCodec.TAG_NULL,
                    algParts[1][0] & 0xFF,
                    "digestAlgorithms: параметры должны быть NULL");
        }

        // SignerInfo.digestAlgorithm — SignedData -> signerInfos [last] -> SET ->
        // SignerInfo { version, sid, digestAlgorithm, ... }
        byte[][] signerInfos = DerCodec.parseSetContents(sdParts[sdParts.length - 1], 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[][] siDigestAlg = DerCodec.parseSequenceContents(siParts[2], 0);
        assertEquals(2, siDigestAlg.length, "SignerInfo.digestAlgorithm должен нести OID и NULL");
        assertEquals(
                DerCodec.TAG_NULL,
                siDigestAlg[1][0] & 0xFF,
                "SignerInfo.digestAlgorithm: параметры должны быть NULL");
    }

    @Test
    @DisplayName("SignedData: CmsIssuerAndSerialNumber из сертификата")
    void issuerAndSerialFromCert() {
        byte[] certDer = selfSignedCert.getEncoded();
        CmsIssuerAndSerialNumber ias = CmsIssuerAndSerialNumber.fromCertificate(certDer);

        assertNotNull(ias);
        assertNotNull(ias.issuer());
        assertEquals(selfSignedCert.getSerialNumberBigInt(), ias.serial());

        byte[] encoded = CmsIssuerAndSerialNumber.encode(ias.issuer(), ias.serial());
        CmsIssuerAndSerialNumber decoded = CmsIssuerAndSerialNumber.decode(encoded);
        assertEquals(ias.serial(), decoded.serial());
        assertArrayEquals(ias.issuer(), decoded.issuer());
    }

    @Test
    @DisplayName("SerialCollision: коллизия серийных номеров — выбор сертификата по issuer DN")
    void serialCollisionSelectsByIssuer() throws PkixException {
        var kpA = KeyGenerator.generateKeyPair(PARAMS);
        var kpB = KeyGenerator.generateKeyPair(PARAMS);

        BigInteger sharedSerial = BigInteger.valueOf(99999);
        GostCertificate certA =
                CmsTestUtils.createSelfSignedCertWithDn(
                        kpA.getPrivate(), kpA.getPublic(), sharedSerial, "Signer A");
        GostCertificate certB =
                CmsTestUtils.createSelfSignedCertWithDn(
                        kpB.getPrivate(), kpB.getPublic(), sharedSerial, "Signer B");

        byte[] data = "collision test".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create().data(data).addSigner(kpA.getPrivate(), certA).build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(certA, certB),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertNotNull(
                result,
                "Верификация должна пройти — верификатор выбрал сертификат по issuer DN, а не только по serial");
    }

    @Test
    @DisplayName("SignedData: 512-битная подпись (Streebog-512)")
    void signAndVerify512() throws PkixException {
        ECParameters params512 = ECParameters.tc26a512();
        var kp512 = KeyGenerator.generateKeyPair(params512);
        GostCertificate cert512 =
                CmsTestUtils.createSelfSignedCert(kp512.getPrivate(), kp512.getPublic());

        byte[] data = "512-bit CMS test".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .digestAlgorithm(GostOids.DIGEST_512)
                        .addSigner(kp512.getPrivate(), cert512)
                        .build();

        assertNotNull(signedData);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cert512),
                                SignerSelection.ANY,
                                Revocation.none()));

        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("SignedData с полем crls [1] IMPLICIT: регрессионный тест на индексацию")
    void signedDataWithCrlsField() throws PkixException {
        byte[] data = "CRL field regression test".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addCertificate(selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[] sd = ci.content();
        byte[][] sdParts = DerCodec.parseSequenceContents(sd, 0);

        byte[] emptyCrlField = DerCodec.encodeTlv(0xA1, new byte[0]);

        byte[] sdWithCrls =
                DerCodec.encodeSequence(
                        sdParts[0], sdParts[1], sdParts[2], sdParts[3], emptyCrlField, sdParts[4]);
        byte[] contentInfoWithCrls = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithCrls);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        contentInfoWithCrls,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ANY,
                                Revocation.none()));

        assertArrayEquals(data, result.data());
    }

    // ========================================================================
    // Тесты: addCrl() в CmsSignedDataBuilder
    // ========================================================================

    @Test
    @DisplayName("addCrl не вызывался — поле crls [1] отсутствует в DER")
    void addCrl_noCrlsMeansNoField() throws PkixException {
        byte[] data = "no-crl".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        // После 4-го элемента (certificates [0]) должно идти signerInfos,
        // а не crls [1]. Даже если certificates [0] отсутствует, crls [1] быть не должно.
        boolean foundCrls = false;
        for (byte[] part : sdParts) {
            if (DerCodec.isContextTag(part, 1)) {
                foundCrls = true;
                break;
            }
        }
        assertFalse(foundCrls, "crls [1] должен отсутствовать, если addCrl() не вызывался");
    }

    @Test
    @DisplayName("detached-подпись + CRL: верифицируется, CRL доступен в DER")
    void addCrl_detachedWithCrl() throws PkixException {
        byte[] data = "detached with CRL".getBytes();
        GostCrl crl = createTestCrl(privateKey);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true)
                        .addCrl(crl)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        // Ищем crls [1] среди частей SignedData
        boolean foundCrls = false;
        for (byte[] part : sdParts) {
            if (DerCodec.isContextTag(part, 1)) {
                foundCrls = true;
                break;
            }
        }
        assertTrue(foundCrls, "crls [1] должен присутствовать в DER");

        // Верификация не должна упасть
        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())
                                .detached(data));
        assertArrayEquals(data, result.data(), "detached-метод должен вернуть документ");
        assertEquals(1, result.embeddedCrls().size(), "CRL должен быть доступен в результате");
    }

    @Test
    @DisplayName("certs-only + CRL: crls [1] на месте, GostPkcs7.extractCertificates не падает")
    void addCrl_certsOnlyWithCrl() throws PkixException {
        GostCrl crl = createTestCrl(privateKey);

        byte[] certsOnlyDer =
                CmsSignedDataBuilder.create()
                        .certsOnly()
                        .addCertificate(selfSignedCert)
                        .addCrl(crl)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(certsOnlyDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        boolean foundCrls = false;
        for (byte[] part : sdParts) {
            if (DerCodec.isContextTag(part, 1)) {
                foundCrls = true;
                break;
            }
        }
        assertTrue(foundCrls, "crls [1] должен присутствовать при addCrl() в certs-only режиме");

        // GostPkcs7.extractCertificates() не должен падать при наличии crls [1]
        var certs = GostPkcs7.extractCertificates(certsOnlyDer);
        assertEquals(1, certs.size());
    }

    @Test
    @DisplayName("addCrl round-trip: построить -> verify(ANY) -> получить CRL из результата")
    void addCrl_roundTrip() throws PkixException {
        byte[] data = "round-trip with CRL".getBytes();
        GostCrl crl = createTestCrl(privateKey);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addCrl(crl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertArrayEquals(data, result.data());
        assertNotNull(result.embeddedCrls());
        assertEquals(1, result.embeddedCrls().size());
        GostCrl roundTripped = result.embeddedCrls().get(0);
        assertEquals(crl.getIssuerDn(), roundTripped.getIssuerDn());
        assertEquals(crl.getThisUpdate(), roundTripped.getThisUpdate());
    }

    @Test
    @DisplayName(
            "addCrl(byte[]) round-trip: байты из GostCrlBuilder.sign() -> addCrl -> verify(ANY) -> CRL в embeddedCrls")
    void addCrl_fromBytes() throws PkixException {
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn).nextUpdate("30990601120000Z").sign(privateKey);

        byte[] data = "round-trip from bytes".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addCrl(crlDer)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertArrayEquals(data, result.data());
        assertNotNull(result.embeddedCrls());
        assertEquals(1, result.embeddedCrls().size());

        GostCrl roundTripped = result.embeddedCrls().get(0);
        GostCrl expected = GostCrl.fromDer(crlDer);
        assertEquals(expected.getIssuerDn(), roundTripped.getIssuerDn());
        assertEquals(expected.getThisUpdate(), roundTripped.getThisUpdate());
    }

    @Test
    @DisplayName(
            "addCrl preserved in CAdES: построить с CRL -> CAdESExtender.embedTimestamp не падает")
    void addCrl_preservedInCAdES() throws Exception {
        byte[] data = "CAdES with CRL".getBytes();
        GostCrl crl = createTestCrl(privateKey);

        KeyPair tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate tsaCert = CmsTestUtils.createTsaCert(tsaKp.getPrivate(), tsaKp.getPublic());

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addCrl(crl)
                        .withCAdES()
                        .build();

        // Вычисляем хэш от значения подписи — он будет messageImprint в TSTInfo
        byte[] sigHash = Digest.digest256(data);

        // TSTInfo
        byte[] tstInfo = buildTstInfo(sigHash, new byte[20]);
        byte[] token =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKp.getPrivate(), tsaCert)
                        .build();

        // embedTimestamp должен отработать без исключений — CRL [1] сохраняется opaque
        byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, token);
        assertNotNull(cadesT);
        assertTrue(cadesT.length > 0);
    }

    private static byte[] buildTstInfo(byte[] hash, byte[] nonce) {
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg = CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        Instant now = Instant.now();
        String genTime =
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
                        .withZone(java.time.ZoneOffset.UTC)
                        .format(now);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(new BigInteger(1, nonce));
        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    @Test
    @DisplayName("Верификация SignedData с >MAX_EMBEDDED_CRLS CRL бросает PkixException")
    void verifier_crlsTooMany() throws PkixException {
        byte[] data = "too many CRLs".getBytes();
        GostCrl crl = createTestCrl(privateKey);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        // Строим поле crls [1] c MAX_EMBEDDED_CRLS + 1 CRL
        byte[][] manyCrls = new byte[CmsConstants.MAX_EMBEDDED_CRLS + 1][];
        for (int i = 0; i < manyCrls.length; i++) {
            manyCrls[i] = crl.getEncoded();
        }
        DerCodec.sortDer(manyCrls);
        byte[] oversizedCrlsField = DerCodec.encodeContextConstructed(1, DerCodec.concat(manyCrls));

        // Собираем SignedData с этим полем:
        // version, digestAlgs, encapContentInfo, certs, crls, signerInfos
        List<byte[]> parts = new ArrayList<>();
        parts.add(sdParts[0]); // version
        parts.add(sdParts[1]); // digestAlgorithms
        parts.add(sdParts[2]); // encapContentInfo
        if (sdParts.length > 4) parts.add(sdParts[3]); // certs [0] (может отсутствовать)
        parts.add(oversizedCrlsField);
        parts.add(sdParts[sdParts.length - 1]); // signerInfos

        byte[] sdWithTooManyCrls = DerCodec.encodeSequence(parts.toArray(new byte[0][]));
        byte[] contentInfoWithTooManyCrls =
                CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithTooManyCrls);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        contentInfoWithTooManyCrls,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())));
        assertTrue(e.getMessage().contains("exceed maximum"));
    }

    @Test
    @DisplayName(
            "Верификация SignedData с полем crls [1] >MAX_EMBEDDED_CRLS_TOTAL_SIZE бросает PkixException")
    void verifier_crlsTooLarge() throws PkixException {
        byte[] data = "too large crls".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        // Строим поле crls [1] с размером > MAX_EMBEDDED_CRLS_TOTAL_SIZE
        byte[] hugeContent = new byte[CmsConstants.MAX_EMBEDDED_CRLS_TOTAL_SIZE + 1];
        byte[] oversizedCrlsField = DerCodec.encodeContextConstructed(1, hugeContent);

        List<byte[]> parts = new ArrayList<>();
        parts.add(sdParts[0]); // version
        parts.add(sdParts[1]); // digestAlgorithms
        parts.add(sdParts[2]); // encapContentInfo
        if (sdParts.length > 4) parts.add(sdParts[3]); // certs [0]
        parts.add(oversizedCrlsField);
        parts.add(sdParts[sdParts.length - 1]); // signerInfos

        byte[] sdWithOversizedCrls = DerCodec.encodeSequence(parts.toArray(new byte[0][]));
        byte[] contentInfoWithOversizedCrls =
                CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithOversizedCrls);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        contentInfoWithOversizedCrls,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())));
        assertTrue(e.getMessage().contains("exceeds maximum size"));
    }

    @Test
    @DisplayName("CRL с bogus TLV-длиной (> буфера) бросает PkixException, а не OOM")
    void verifier_craftedCrlBogusLength() throws PkixException {
        byte[] data = "bogus length CRL".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);

        // Crafted TLV: SEQUENCE (0x30) + long-form length 0x84
        // заявляющая 0x40000000 (1 GB) при реальных 4 байтах содержимого
        byte[] bogusContent = new byte[] {0x01, 0x02, 0x03, 0x04};
        byte[] bogusTlv = new byte[1 + 5 + 4];
        bogusTlv[0] = 0x30; // SEQUENCE
        bogusTlv[1] = (byte) 0x84;
        bogusTlv[2] = 0x40;
        bogusTlv[3] = 0x00;
        bogusTlv[4] = 0x00;
        bogusTlv[5] = 0x00;
        System.arraycopy(bogusContent, 0, bogusTlv, 6, 4);

        byte[] crlsField = DerCodec.encodeContextConstructed(1, bogusTlv);

        List<byte[]> parts = new ArrayList<>();
        parts.add(sdParts[0]); // version
        parts.add(sdParts[1]); // digestAlgorithms
        parts.add(sdParts[2]); // encapContentInfo
        if (sdParts.length > 4) parts.add(sdParts[3]); // certs [0]
        parts.add(crlsField);
        parts.add(sdParts[sdParts.length - 1]); // signerInfos

        byte[] sdWithBogusCrl = DerCodec.encodeSequence(parts.toArray(new byte[0][]));
        byte[] contentInfoWithBogusCrl =
                CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithBogusCrl);

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        contentInfoWithBogusCrl,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())));
        assertTrue(
                e.getMessage().contains("exceeds remaining buffer"),
                "Должно быть сообщение о превышении буфера, а не OOM: " + e.getMessage());
    }

    // ========================================================================
    // Вспомогательный метод: создание тестового CRL
    // ========================================================================

    private static GostCrl createTestCrl(PrivateKeyParameters caKey) {
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer = GostCrlBuilder.create(issuerDn).nextUpdate("30990601120000Z").sign(caKey);
        return GostCrl.fromDer(crlDer);
    }

    // ========================================================================
    // Архитектурные тесты: семантика SignerSelection.ANY / ALL
    // ========================================================================

    @Test
    @DisplayName("ANY возвращает первого валидного из нескольких подписантов")
    void signerSelectionAnyReturnsFirstValid() throws Exception {
        byte[] data = "multi-any".getBytes();
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        // Подписываем двумя ключами, только второй сертификат в доверенных
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addSigner(kp2.getPrivate(), cert2)
                        .build();

        // ANY с доверием ко второму подписанту — должен найти второго
        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(cert2),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertNotNull(result);
        assertArrayEquals(data, result.data());
        assertEquals(
                cert2.getSerialNumberBigInt(), result.signerCertificate().getSerialNumberBigInt());
    }

    @Test
    @DisplayName("ANY бросает когда все подписанты невалидны")
    void signerSelectionAnyThrowsWhenAllInvalid() throws Exception {
        byte[] data = "none-valid".getBytes();
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                CmsTestUtils.createSelfSignedCert(wrongKp.getPrivate(), wrongKp.getPublic());

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signed,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(wrongCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Ни один подписант не валиден — должен быть отклонён");
    }

    @Test
    @DisplayName("ALL возвращает всех когда все валидны")
    void signerSelectionAllReturnsAllWhenAllValid() throws Exception {
        byte[] data = "all-valid".getBytes();
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addSigner(kp2.getPrivate(), cert2)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert, cert2),
                                SignerSelection.ALL,
                                Revocation.none()));
        assertNotNull(result);
        assertEquals(2, result.signers().size());
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("ALL бросает когда один подписант невалиден")
    void signerSelectionAllThrowsWhenOneInvalid() throws Exception {
        byte[] data = "one-bad".getBytes();
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addSigner(kp2.getPrivate(), cert2)
                        .build();

        // Доверяем только первому — второй провалит цепочку
        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signed,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ALL,
                                        Revocation.none())),
                "Один подписант невалиден — AND-семантика должна отклонить");
    }

    @Test
    @DisplayName("SignerResult содержит signedAttributes после проверки ALL")
    void signerResultContainsSignedAttributes() throws Exception {
        byte[] data = "signed-attrs".getBytes();
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .withCAdES()
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ALL,
                                Revocation.none()));
        SignerResult sr = result.signers().get(0);
        assertNotNull(sr.signedAttributes());
        assertFalse(
                sr.signedAttributes().isEmpty(),
                "signedAttributes должен содержать contentType и messageDigest");
    }

    @Test
    @DisplayName("SignerResult содержит unsignedAttributes с меткой после addTimestamp")
    void signerResultContainsUnsignedAttributes() throws Exception {
        byte[] data = "unsigned-attrs".getBytes();
        // Ручная сборка: добавляем unsigned-атрибут в билдер
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addUnsignedAttribute(
                                GostOids.SIGNATURE_TIME_STAMP,
                                DerCodec.encodeOctetString(new byte[] {1, 2, 3}))
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signed,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ALL,
                                Revocation.none()));
        SignerResult sr = result.signers().get(0);
        assertNotNull(sr.unsignedAttributes());
        assertTrue(
                sr.unsignedAttributes().size() > 0,
                "unsignedAttributes должен содержать SIGNATURE_TIME_STAMP");
        boolean found = false;
        for (CmsAttribute attr : sr.unsignedAttributes()) {
            if (GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                found = true;
                break;
            }
        }
        assertTrue(found, "SIGNATURE_TIME_STAMP должен быть в unsignedAttributes");
    }

    // ========================================================================
    // vacuous truth при 0 подписантах
    // ========================================================================

    @Test
    @DisplayName("ALL бросает PkixException при пустом SET OF SignerInfo")
    void signerSelectionAllThrowsOnEmptySignerInfos() {
        byte[] emptySignedData = buildSignedDataWithNoSigners();

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                emptySignedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ALL,
                                        Revocation.none())),
                "Пустые signerInfos должны вызывать исключение при SignerSelection.ALL");
    }

    @Test
    @DisplayName("ANY бросает PkixException при пустом SET OF SignerInfo")
    void signerSelectionAnyThrowsOnEmptySignerInfos() {
        byte[] emptySignedData = buildSignedDataWithNoSigners();

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                emptySignedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Пустые signerInfos должны вызывать исключение при SignerSelection.ANY");
    }

    /** SignedData с версией, дайджестами, encapContentInfo, но без подписантов. */
    private static byte[] buildSignedDataWithNoSigners() {
        byte[] data = "test".getBytes();

        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgs =
                DerCodec.encodeSetOf(
                        new byte[][] {
                            DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256))
                        });

        byte[] encapContent =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data)));

        byte[] emptySignerInfos = DerCodec.encodeSetOf(new byte[0][]);

        byte[] signedData =
                DerCodec.encodeSequence(
                        version,
                        digestAlgs,
                        encapContent,
                        DerCodec.encodeContextConstructed(0, new byte[0]),
                        emptySignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
    }

    // ========================================================================
    // signedAttrs без обязательных атрибутов RFC 5652 §5.4
    // ========================================================================

    @Test
    @DisplayName("signedAttrs без messageDigest → PkixException")
    void signedAttrsWithoutMessageDigest() {
        byte[] signedData = buildSignedDataMissingAttr("message-digest");
        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Отсутствие messageDigest в signedAttrs должно вызывать PkixException");
    }

    @Test
    @DisplayName("signedAttrs без contentType → PkixException")
    void signedAttrsWithoutContentType() {
        byte[] signedData = buildSignedDataMissingAttr("content-type");
        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(selfSignedCert),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Отсутствие contentType в signedAttrs должно вызывать PkixException");
    }

    /**
     * Строит валидно подписанный CMS SignedData, где signedAttrs содержит
     * только один из двух обязательных атрибутов (второй опущен намеренно).
     *
     * @param missingAttr "message-digest" или "content-type" — какой атрибут опустить
     */
    private static byte[] buildSignedDataMissingAttr(String missingAttr) {
        byte[] data = "test content".getBytes();

        // encapContentInfo
        byte[] eContentTypeOidDer = DerCodec.encodeOid(GostOids.PKCS7_DATA);
        byte[] encapContent =
                DerCodec.encodeSequence(
                        eContentTypeOidDer,
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data)));

        byte[] dataDigest = Digest.digest256(data);
        byte[] digestOctet = DerCodec.encodeOctetString(dataDigest);

        // signedAttrs SET OF — зависит от missingAttr
        java.util.List<byte[]> attrList = new java.util.ArrayList<>();
        if (!"content-type".equals(missingAttr)) {
            attrList.add(CmsAttribute.encode(GostOids.ATTR_CONTENT_TYPE, eContentTypeOidDer));
        }
        if (!"message-digest".equals(missingAttr)) {
            attrList.add(CmsAttribute.encode(GostOids.ATTR_MESSAGE_DIGEST, digestOctet));
        }
        byte[][] sortedAttrs = attrList.toArray(new byte[0][]);
        DerCodec.sortDer(sortedAttrs);

        byte[] signedAttrsForHash = DerCodec.encodeSet(sortedAttrs);
        byte[] signedAttrsHash = Digest.digest256(signedAttrsForHash);
        byte[] signatureValue = Signature.signHash(signedAttrsHash, privateKey);

        // [0] IMPLICIT signedAttrs — внутри SignerInfo
        byte[] signedAttrsWrapped =
                DerCodec.encodeContextConstructed(0, DerCodec.concat(sortedAttrs));

        // sid: CmsIssuerAndSerialNumber
        byte[] sid =
                CmsIssuerAndSerialNumber.encode(
                        selfSignedCert.getIssuerDnBytes(), selfSignedCert.getSerialNumberBigInt());

        // Алгоритмы
        byte[] digestAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] signAlgId =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_WITH_DIGEST_256));

        byte[] sigOctet = DerCodec.encodeOctetString(signatureValue);

        // SignerInfo SEQUENCE
        byte[] signerInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(CmsConstants.SIGNER_INFO_V1),
                        sid,
                        digestAlgId,
                        signedAttrsWrapped,
                        signAlgId,
                        sigOctet);

        // Сертификат подписанта
        byte[] certDer = selfSignedCert.getEncoded();

        // SignedData
        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgs = DerCodec.encodeSetOf(new byte[][] {digestAlgId});
        byte[] certsField = DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(certDer));
        byte[] signerInfos = DerCodec.encodeSetOf(new byte[][] {signerInfo});

        byte[] signedDataContent =
                DerCodec.encodeSequence(version, digestAlgs, encapContent, certsField, signerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedDataContent);
    }

    // ========================================================================
    // DoS-лимиты: встроенные сертификаты и signerInfos
    // ========================================================================

    @Test
    @DisplayName("SignedData: встроенных сертификатов больше лимита → PkixException")
    void embeddedCertsLimitExceeded() {
        byte[] signedData = buildSignedDataWithCertCount(CmsConstants.MAX_EMBEDDED_CERTS + 1);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "Число встроенных сертификатов больше лимита должно отклоняться");
        assertTrue(
                ex.getMessage().contains("embedded certificates exceed maximum"),
                "должно сработать именно ограничение по количеству: " + ex.getMessage());
    }

    @Test
    @DisplayName("SignedData: signerInfos больше лимита → PkixException")
    void signerInfosLimitExceeded() {
        byte[] signedData = buildSignedDataWithSignerCount(CmsConstants.MAX_SIGNER_INFOS + 1);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "Число signerInfos больше лимита должно отклоняться");
        assertTrue(
                ex.getMessage().contains("signerInfos exceed maximum"),
                "должно сработать именно ограничение по количеству: " + ex.getMessage());
    }

    /**
     * SignedData с {@code n} встроенными сертификатами (дубликаты) и пустыми
     * signerInfos. Count-барьер на сертификаты срабатывает при парсинге до verify.
     */
    private static byte[] buildSignedDataWithCertCount(int n) {
        byte[] data = "test".getBytes();
        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] digestAlgs = DerCodec.encodeSetOf(new byte[][] {digestAlgId});
        byte[] encapContent =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data)));

        byte[] certDer = selfSignedCert.getEncoded();
        byte[][] certs = new byte[n][];
        for (int i = 0; i < n; i++) {
            certs[i] = certDer;
        }
        byte[] certsField = DerCodec.encodeContextConstructed(0, DerCodec.concat(certs));
        byte[] emptySignerInfos = DerCodec.encodeSetOf(new byte[0][]);

        byte[] signedDataContent =
                DerCodec.encodeSequence(
                        version, digestAlgs, encapContent, certsField, emptySignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedDataContent);
    }

    /**
     * SignedData с одним сертификатом и {@code n} фиктивными signerInfos. Count-барьер
     * на signerInfos срабатывает сразу после разбора SET OF, до цикла верификации.
     */
    private static byte[] buildSignedDataWithSignerCount(int n) {
        byte[] data = "test".getBytes();
        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] digestAlgs = DerCodec.encodeSetOf(new byte[][] {digestAlgId});
        byte[] encapContent =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data)));

        byte[] certDer = selfSignedCert.getEncoded();
        byte[] certsField = DerCodec.encodeContextConstructed(0, certDer);

        // Фиктивные, но различимые по DER элементы SET OF — важно лишь их количество.
        byte[][] signers = new byte[n][];
        for (int i = 0; i < n; i++) {
            signers[i] = DerCodec.encodeSequence(DerCodec.encodeInteger(i));
        }
        byte[] signerInfos = DerCodec.encodeSetOf(signers);

        byte[] signedDataContent =
                DerCodec.encodeSequence(version, digestAlgs, encapContent, certsField, signerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedDataContent);
    }

    // ========================================================================
    // Тесты: проверка отзыва (Revocation.required для SignerSelection.ANY / ALL)
    // ========================================================================

    private record CaLeafChain(
            PrivateKeyParameters caPriv,
            PublicKeyParameters caPub,
            GostCertificate caCert,
            byte[] caDn,
            PrivateKeyParameters leafPriv,
            GostCertificate leafCert) {}

    private static CaLeafChain createCaLeafChain() {
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA Revoc");
        byte[] bc = GostCertificateBuilder.buildBasicConstraintsExtension(true, null);
        byte[] ku =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN);
        byte[] ski = GostCertificateBuilder.buildSkiExtension(caKp.getPublic());
        byte[] caTbs =
                GostCertificateBuilder.create(PARAMS, caDn)
                        .publicKey(caKp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn)
                        .additionalExtensions(concatExtensions(bc, ku, ski))
                        .serial(BigInteger.ONE)
                        .buildTbs();
        GostCertificate caCert =
                GostCertificateBuilder.sign(caTbs, GostSigner.of(caKp.getPrivate()));

        var leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        byte[] leafKu =
                GostCertificateBuilder.buildKeyUsageExtension(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE);
        byte[] leafSki = GostCertificateBuilder.buildSkiExtension(leafKp.getPublic());
        byte[] leafAki = GostCertificateBuilder.buildAkiExtension(caKp.getPublic());
        byte[] leafTbs =
                GostCertificateBuilder.create(PARAMS, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn)
                        .additionalExtensions(concatExtensions(leafKu, leafSki, leafAki))
                        .serial(BigInteger.TWO)
                        .buildTbs();
        GostCertificate leafCert =
                GostCertificateBuilder.sign(leafTbs, GostSigner.of(caKp.getPrivate()));

        return new CaLeafChain(
                caKp.getPrivate(), caKp.getPublic(), caCert, caDn, leafKp.getPrivate(), leafCert);
    }

    private static byte[] concatExtensions(byte[]... arrs) {
        if (arrs.length == 0) return new byte[0];
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        for (byte[] a : arrs) {
            try {
                bos.write(a);
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        }
        return bos.toByteArray();
    }

    private static GostCrl createCrlWithRevokedCert(
            PrivateKeyParameters caKey, byte[] issuerDn, byte[] revokedSerial) {
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(1)
                        .nextUpdate("30990601120000Z")
                        .addRevoked(revokedSerial, "20250101000000Z")
                        .sign(caKey);
        return GostCrl.fromDer(crlDer);
    }

    private static GostCrl createCleanCrl(PrivateKeyParameters caKey, byte[] issuerDn) {
        byte[] crlDer =
                GostCrlBuilder.create(issuerDn)
                        .withCrlNumber(1)
                        .nextUpdate("30990601120000Z")
                        .sign(caKey);
        return GostCrl.fromDer(crlDer);
    }

    @Test
    @DisplayName("ANY + Revocation.required: сертификат не в CRL — верификация проходит")
    void withRevocationCheck_validCertNotRevoked() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "valid cert".getBytes();
        GostCrl crl = createCleanCrl(chain.caPriv, chain.caDn);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(crl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain.caCert),
                                SignerSelection.ANY,
                                Revocation.required(List.of())));
        assertNotNull(result);
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("ANY + Revocation.required: сертификат отозван — PkixException REVOKED")
    void withRevocationCheck_certRevoked() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "revoked cert".getBytes();
        GostCrl crl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(crl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Отозванный сертификат должен отклониться");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName("ANY + Revocation.required: внешний CRL с отозванным сертификатом — PkixException")
    void withRevocationCheck_externalCrlUsed() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "external crl".getBytes();
        GostCrl crl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of(crl)))),
                        "Внешний CRL с отозванным сертификатом должен отклонить");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    /** Подписанный УЦ CRL с неизвестным critical-расширением (RFC 5280 §5.2: не использовать). */
    private static GostCrl createCrlWithUnknownCritical(CaLeafChain chain) {
        byte[] extension =
                RawCrlTestSupport.extension(
                        RawCrlTestSupport.OID_UNKNOWN, true, DerCodec.encodeNull());
        byte[] crlDer =
                RawCrlTestSupport.crl(
                        chain.caPriv,
                        PARAMS,
                        chain.caDn,
                        RawCrlTestSupport.crlExtensions(extension));
        return GostCrl.fromDer(crlDer);
    }

    @Test
    @DisplayName(
            "Revocation.required: CRL с неизвестным critical-расширением пропускается —"
                    + " REVOCATION_STATUS_UNKNOWN")
    void withRevocationCheck_unknownCriticalCrlSkipped() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        GostCrl unusable = createCrlWithUnknownCritical(chain);
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("unknown critical".getBytes())
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(unusable)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Единственный CRL непригоден: обязательная проверка не должна проходить");
        assertEquals(PkixException.Reason.REVOCATION_STATUS_UNKNOWN, ex.reason());
    }

    @Test
    @DisplayName(
            "Встроенный CRL с неизвестным critical пропущен, внешний CRL с отзывом всё равно"
                    + " обнаруживает отзыв")
    void withRevocationCheck_unknownCriticalCrlDoesNotHideRevocation() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        GostCrl unusable = createCrlWithUnknownCritical(chain);
        GostCrl revoking =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("unknown critical".getBytes())
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(unusable)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of(revoking)))),
                        "Отзыв во втором CRL не должен быть скрыт непригодным первым");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    /** Подписанный УЦ partial CRL (onlyContainsCACerts), листовой сертификат он не покрывает. */
    private static GostCrl createCaOnlyCrl(CaLeafChain chain, byte[]... entries) {
        byte[] idp =
                RawCrlTestSupport.extension(
                        RawCrlTestSupport.OID_IDP,
                        true,
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(0x82, new byte[] {(byte) 0xFF})));
        byte[] tail = RawCrlTestSupport.crlExtensions(idp);
        if (entries.length > 0) {
            tail = RawCrlTestSupport.concat(RawCrlTestSupport.revokedList(entries), tail);
        }
        return GostCrl.fromDer(RawCrlTestSupport.crl(chain.caPriv, PARAMS, chain.caDn, tail));
    }

    @Test
    @DisplayName(
            "Revocation.required: встроенный partial CRL не покрывает подписанта —"
                    + " REVOCATION_STATUS_UNKNOWN")
    void withRevocationCheck_partialCrlNotCoveringIsSkipped() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("partial crl".getBytes())
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(createCaOnlyCrl(chain))
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Не покрывающий CRL не должен удовлетворять обязательной проверке");
        assertEquals(PkixException.Reason.REVOCATION_STATUS_UNKNOWN, ex.reason());
    }

    @Test
    @DisplayName("Встроенный partial CRL не скрывает отзыв, найденный во внешнем полном CRL")
    void withRevocationCheck_partialCrlDoesNotHideExternalRevocation() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        GostCrl full =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("partial crl".getBytes())
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(createCaOnlyCrl(chain))
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of(full)))),
                        "Отзыв во внешнем полном CRL должен быть обнаружен");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "Встроенный partial CRL другого сегмента с номером подписанта даёт REVOKED, а не пропуск")
    void withRevocationCheck_partialCrlWithSerialIsRevoked() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] entry =
                RawCrlTestSupport.revokedEntry(
                        new java.math.BigInteger(1, chain.leafCert.getSerialNumber()), null);
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("partial crl".getBytes())
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(createCaOnlyCrl(chain, entry))
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Запись об отзыве в подписанном CRL не должна зависеть от его области");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName("Revocation.required: CRL от другого issuer — отказ REVOCATION_STATUS_UNKNOWN")
    void withRevocationCheck_noMatchingCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "no matching crl".getBytes();
        byte[] otherDn = GostDnParser.encodeDn("CN=Other CA");
        GostCrl crl = createCleanCrl(chain.caPriv, otherDn);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(crl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Обязательная проверка без подходящего CRL не должна проходить молча");
        assertEquals(PkixException.Reason.REVOCATION_STATUS_UNKNOWN, ex.reason());

        // Явный режим «если доступно» сохраняет прежнее поведение: предупреждение и приём
        VerifiedSignedData lenient =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain.caCert),
                                SignerSelection.ANY,
                                Revocation.ifAvailable(List.of())));
        assertNotNull(lenient);
        assertArrayEquals(data, lenient.data());
    }

    @Test
    @DisplayName("ANY + Revocation.required: CRL с битой подписью — PkixException")
    void withRevocationCheck_crlSignatureInvalid() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "bad crl sig".getBytes();
        GostCrl validCrl = createCleanCrl(chain.caPriv, chain.caDn);
        byte[] crlDer = validCrl.getEncoded();
        crlDer[crlDer.length - 4] ^= 0x01;
        GostCrl badSigCrl = GostCrl.fromDer(crlDer);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(badSigCrl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "CRL с невалидной подписью должен отклониться");
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, ex.reason());
    }

    @Test
    @DisplayName("ANY + Revocation.required: просроченный CRL — PkixException")
    void withRevocationCheck_expiredCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "expired crl".getBytes();
        byte[] crlDer =
                GostCrlBuilder.create(chain.caDn)
                        .withCrlNumber(1)
                        .nextUpdate("20000101000000Z")
                        .sign(chain.caPriv);
        GostCrl expiredCrl = GostCrl.fromDer(crlDer);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(expiredCrl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Просроченный CRL должен отклониться");
        assertEquals(PkixException.Reason.EXPIRED, ex.reason());
    }

    @Test
    @DisplayName("ANY + Revocation.none(): отозванный сертификат проходит (обратная совместимость)")
    void withRevocationCheck_backwardCompat() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "backward compat".getBytes();
        GostCrl crl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(crl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain.caCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertNotNull(result);
    }

    @Test
    @DisplayName("ANY + Revocation.required: пустой trustedCerts — IllegalArgumentException")
    void withRevocationCheck_emptyTrustedCerts() {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "empty trusted".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .build();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(),
                                        SignerSelection.ANY,
                                        Revocation.required(List.of()))),
                "Пустой trustedCerts должен бросить IllegalArgumentException");
    }

    @Test
    @DisplayName("ALL + Revocation.required: все подписанты валидны, проверка отзыва проходит")
    void withRevocationCheckVerifyAll_allSignersCheck() throws PkixException {
        CaLeafChain chain1 = createCaLeafChain();

        var kp3 = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn2 = GostDnParser.encodeDn("CN=CA2");
        GostCertificate ca2 =
                GostCertificateBuilder.create(PARAMS, caDn2)
                        .publicKey(kp3.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn2)
                        .serial(BigInteger.valueOf(10))
                        .sign(kp3.getPrivate());

        byte[] data = "multi-valid".getBytes();
        GostCrl crl1 = createCleanCrl(chain1.caPriv, chain1.caDn);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain1.leafPriv, chain1.leafCert)
                        .addCertificate(chain1.caCert)
                        .addSigner(kp3.getPrivate(), ca2)
                        .addCrl(crl1)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain1.caCert, ca2),
                                SignerSelection.ALL,
                                Revocation.required(List.of())));
        assertNotNull(result);
        assertEquals(2, result.signers().size());
    }

    @Test
    @DisplayName("ALL + Revocation.required: один подписант отозван — PkixException REVOKED")
    void withRevocationCheckVerifyAll_oneSignerRevoked() throws PkixException {
        CaLeafChain chain1 = createCaLeafChain();

        var kp3 = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn2 = GostDnParser.encodeDn("CN=CA2");
        GostCertificate ca2 =
                GostCertificateBuilder.create(PARAMS, caDn2)
                        .publicKey(kp3.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn2)
                        .serial(BigInteger.valueOf(20))
                        .sign(kp3.getPrivate());

        byte[] data = "one-revoked".getBytes();
        GostCrl crl1 =
                createCrlWithRevokedCert(
                        chain1.caPriv, chain1.caDn, chain1.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain1.leafPriv, chain1.leafCert)
                        .addCertificate(chain1.caCert)
                        .addSigner(kp3.getPrivate(), ca2)
                        .addCrl(crl1)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain1.caCert, ca2),
                                                SignerSelection.ALL,
                                                Revocation.required(List.of()))),
                        "Отозванный подписант при SignerSelection.ALL должен отклониться");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "ANY + Revocation.required: embedded CRL (чистый) + внешний CRL (отозван) → REVOKED")
    void withRevocationCheck_embeddedCleanExternalRevoked() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "downgrade-attack".getBytes();

        // Embedded: старый CRL, где сертификат ещё не отозван
        GostCrl cleanCrl = createCleanCrl(chain.caPriv, chain.caDn);

        // External: свежий CRL, где сертификат отозван
        GostCrl revokedCrl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(cleanCrl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of(revokedCrl)))),
                        "Внешний CRL с отозванным должен перекрыть embedded с чистым");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "ANY + Revocation.required: multi-signer, первый отозван, второй валиден — возвращает второго")
    void withRevocationCheck_orSemanticsFirstRevokedSecondValid() throws PkixException {
        CaLeafChain chain1 = createCaLeafChain();

        // Второй подписант — самоподписанный, не отозван
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                GostCertificateBuilder.create(PARAMS, GostDnParser.encodeDn("CN=Signer2"))
                        .publicKey(kp2.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(GostDnParser.encodeDn("CN=Signer2"))
                        .serial(BigInteger.valueOf(30))
                        .sign(kp2.getPrivate());

        byte[] data = "or-first-revoked".getBytes();

        // CRL: первый подписант отозван
        GostCrl crl =
                createCrlWithRevokedCert(
                        chain1.caPriv, chain1.caDn, chain1.leafCert.getSerialNumber());

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain1.leafPriv, chain1.leafCert)
                        .addCertificate(chain1.caCert)
                        .addSigner(kp2.getPrivate(), cert2)
                        .addCrl(crl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain1.caCert, cert2),
                                SignerSelection.ANY,
                                Revocation.required(List.of())));
        assertNotNull(result, "OR-семантика: должен найти второго, незаблокированного подписанта");
        assertEquals(
                cert2.getSerialNumberBigInt(),
                result.signerCertificate().getSerialNumberBigInt(),
                "Должен вернуться второй подписант (первый отозван)");
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName(
            "ANY + Revocation.required: base + delta CRL — delta пропускается, base используется")
    void withRevocationCheck_basePlusDeltaCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "base+delta".getBytes();

        GostCrl baseCrl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] deltaCrlDer =
                GostCrlBuilder.create(chain.caDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(BigInteger.ONE)
                        .nextUpdate("30990601120000Z")
                        .sign(chain.caPriv);
        GostCrl deltaCrl = GostCrl.fromDer(deltaCrlDer);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(deltaCrl)
                        .addCrl(baseCrl)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert),
                                                SignerSelection.ANY,
                                                Revocation.required(List.of()))),
                        "Отозванный сертификат должен отклониться (delta пропущена, base проверяет)");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "ANY + Revocation.required: delta CRL среди кандидатов пропускается, "
                    + "перебор продолжается по валидному CRL — верификация проходит")
    void withRevocationCheck_deltaCrlSkipped_continuesToValidCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "delta skip".getBytes();

        // delta CRL стоит первым в списке кандидатов: если бы DELTA_CRL_NOT_SUPPORTED
        // не попадал в skip-ветку, перебор бы прервался пробросом до валидного CRL.
        byte[] deltaCrlDer =
                GostCrlBuilder.create(chain.caDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(BigInteger.ONE)
                        .nextUpdate("30990601120000Z")
                        .sign(chain.caPriv);
        GostCrl deltaCrl = GostCrl.fromDer(deltaCrlDer);
        GostCrl cleanCrl = createCleanCrl(chain.caPriv, chain.caDn);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(deltaCrl)
                        .addCrl(cleanCrl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain.caCert),
                                SignerSelection.ANY,
                                Revocation.required(List.of())));
        assertNotNull(result, "delta должна быть пропущена, валидный CRL — обработан");
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName(
            "ANY + Revocation.required: indirect CRL среди кандидатов пропускается, "
                    + "перебор продолжается по валидному CRL — верификация проходит")
    void withRevocationCheck_indirectCrlSkipped_continuesToValidCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "indirect skip".getBytes();

        // indirect CRL строится только тестовым assembleCrl: обычный builder
        // не разрешает генерацию indirectCRL (это осознанно вне scope).
        byte[] indirectCrlDer =
                GostCrlBuilder.assembleCrl(
                        null,
                        chain.caPriv,
                        chain.caDn,
                        "20250101000000Z",
                        "30990601120000Z",
                        false,
                        BigInteger.valueOf(2),
                        null,
                        null,
                        true,
                        false,
                        false,
                        true,
                        null);
        GostCrl indirectCrl = GostCrl.fromDer(indirectCrlDer);
        GostCrl cleanCrl = createCleanCrl(chain.caPriv, chain.caDn);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(chain.leafPriv, chain.leafCert)
                        .addCertificate(chain.caCert)
                        .addCrl(indirectCrl)
                        .addCrl(cleanCrl)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(chain.caCert),
                                SignerSelection.ANY,
                                Revocation.required(List.of())));
        assertNotNull(result, "indirect должна быть пропущена, валидный CRL — обработан");
        assertArrayEquals(data, result.data());
    }

    // ========================================================================
    // Тесты: fail-closed валидация SignerInfo.signatureAlgorithm
    // ========================================================================

    @Test
    @DisplayName("signatureAlgorithm: signWithDigest-OID (.3.2, стиль BouncyCastle) принимается")
    void signatureAlgorithmSignWithDigestAccepted() throws PkixException {
        byte[] data = "sigalg signwithdigest".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        // Подменяем OID открытого ключа (.1.1.1.1) на signWithDigest (.1.1.3.2) — другой
        // легитимный продюсер (BC) кодирует именно так. Битность (256) совпадает с ключом,
        // подпись покрывает только signedAttrs, поэтому контейнер обязан остаться валидным.
        byte[] patched = patchSignerSignatureAlg(signedData, GostOids.SIGN_WITH_DIGEST_256);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        patched,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(selfSignedCert),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertArrayEquals(data, result.data(), "signWithDigest-OID должен приниматься");
    }

    @Test
    @DisplayName("signatureAlgorithm: посторонний OID отклоняется (algorithm-confusion)")
    void signatureAlgorithmUnexpectedOidRejected() throws PkixException {
        byte[] data = "sigalg bogus".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        // sha256WithRSAEncryption — валидный, но чужой алгоритму подписи OID.
        byte[] patched = patchSignerSignatureAlg(signedData, "1.2.840.113549.1.1.11");

        // ALL (strict) пробрасывает конкретную причину; ANY заворачивает её.
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        patched,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ALL,
                                                Revocation.none())),
                        "Посторонний signatureAlgorithm OID должен отклоняться");
        assertTrue(
                ex.getMessage().contains("signatureAlgorithm"),
                "Сообщение должно указывать на signatureAlgorithm, было: " + ex.getMessage());
    }

    @Test
    @DisplayName("signatureAlgorithm: несоответствие битности OID и ключа отклоняется")
    void signatureAlgorithmBitLengthMismatchRejected() throws PkixException {
        byte[] data = "sigalg bitmismatch".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        // Ключ сертификата 256-битный, но заявляем 512-битный OID открытого ключа.
        byte[] patched = patchSignerSignatureAlg(signedData, GostOids.PUBLIC_KEY_512);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        patched,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(selfSignedCert),
                                                SignerSelection.ALL,
                                                Revocation.none())),
                        "Рассогласование битности signatureAlgorithm и ключа должно отклоняться");
        assertTrue(
                ex.getMessage().contains("key size"),
                "Сообщение должно указывать на несоответствие размера ключа, было: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName("ANY без якорей отклоняется, signature-only принимает")
    void verifyWithoutTrustAnchorsRejected() throws PkixException {
        byte[] data = "no trust".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "пустой список якорей должен отклоняться");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(),
                                        SignerSelection.ALL,
                                        Revocation.none())),
                "пустой список якорей должен отклоняться");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(new GostCertificate[] {null}),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "null-элемент якоря должен отклоняться");

        VerifiedSignedData any =
                CmsSignedDataVerifier.verify(
                        signedData, VerifyOptions.signatureOnly(SignerSelection.ANY));
        assertArrayEquals(data, any.data(), "signature-only сохраняет данные");

        VerifiedSignedData all =
                CmsSignedDataVerifier.verify(
                        signedData, VerifyOptions.signatureOnly(SignerSelection.ALL));
        assertEquals(1, all.signers().size(), "signature-only проверяет всех подписантов");
    }

    @Test
    @DisplayName("KeyUsage keyEncipherment у подписанта отклоняется даже с доверенным CA")
    void signerKeyUsageKeyEnciphermentRejected() throws Exception {
        CaLeafChain chain =
                createCaLeafChainWithKeyUsage(GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT);
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("ku test".getBytes())
                        .addSigner(chain.leafPriv(), chain.leafCert())
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert()),
                                                SignerSelection.ALL,
                                                Revocation.none())),
                        "подписант без digitalSignature/nonRepudiation должен отклоняться");
        assertEquals(
                PkixException.Reason.POLICY_VIOLATION, ex.reason(), "причина POLICY_VIOLATION");

        PkixException anyEx =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(chain.caCert()),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "ANY также должен отклонять подписанта");
        assertEquals(
                PkixException.Reason.POLICY_VIOLATION,
                anyEx.reason(),
                "ANY сохраняет причину последней ошибки");
    }

    @Test
    @DisplayName("KeyUsage nonRepudiation у подписанта принимается")
    void signerKeyUsageNonRepudiationAccepted() throws Exception {
        CaLeafChain chain =
                createCaLeafChainWithKeyUsage(GostCertificateBuilder.KeyUsage.NON_REPUDIATION);
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("ku test".getBytes())
                        .addSigner(chain.leafPriv(), chain.leafCert())
                        .build();

        assertDoesNotThrow(
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(chain.caCert()),
                                        SignerSelection.ALL,
                                        Revocation.none())),
                "nonRepudiation допустим для CMS-подписи");
    }

    @Test
    @DisplayName("CMS: истёкший корневой якорь отклоняется, а не пропускается с WARNING")
    void cmsExpiredRootAnchorRejected() throws PkixException {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Expired Root");
        GostCertificate root =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "200101000000Z",
                        "210101000000Z",
                        BigInteger.ONE);

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        leafDn,
                        rootKp,
                        rootDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.TWO);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("expired root".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(root)
                        .build();

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(root),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "Истёкший корневой якорь CMS должен отклоняться");
        assertEquals(PkixException.Reason.EXPIRED, e.reason());
    }

    @Test
    @DisplayName(
            "VerifyOptions: явный WARN в TrustAnchors сохраняется, DEFAULT превращается в REJECT")
    void verifyOptionsExplicitWarnExpiredRootAccepted() throws PkixException {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Expired Root Warn");
        GostCertificate root =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "200101000000Z",
                        "210101000000Z",
                        BigInteger.ONE);
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        GostDnParser.encodeDn("CN=Leaf Warn"),
                        rootKp,
                        rootDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.TWO);
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("warn".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(root)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(root)
                                        .withExpiryPolicy(AnchorExpiryPolicy.WARN),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertNotNull(result, "Явный WARN должен допускать истёкший якорь в CMS");

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(root)
                                                        .withExpiryPolicy(
                                                                AnchorExpiryPolicy.DEFAULT),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "DEFAULT в CMS трактуется как REJECT");
        assertEquals(PkixException.Reason.EXPIRED, e.reason());
    }

    @Test
    @DisplayName(
            "VerifyOptions: фабрики отвергают null и пустые якоря, signatureOnly не принимает кандидатов")
    void verifyOptionsFactoriesRejectInvalidArguments() {
        TrustAnchors anchors = TrustAnchors.ofCertificates(selfSignedCert);
        assertThrows(
                IllegalArgumentException.class,
                () -> VerifyOptions.trusting(null, SignerSelection.ANY, Revocation.none()),
                "null вместо якорей недопустим");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VerifyOptions.trusting(
                                TrustAnchors.empty(), SignerSelection.ANY, Revocation.none()),
                "Пустые якоря не должны означать «только подпись»");
        assertThrows(
                IllegalArgumentException.class,
                () -> VerifyOptions.trusting(anchors, null, Revocation.none()),
                "Выбор подписантов обязателен");
        assertThrows(
                IllegalArgumentException.class,
                () -> VerifyOptions.trusting(anchors, SignerSelection.ANY, null),
                "Политика отзыва обязательна");
        assertThrows(
                IllegalArgumentException.class,
                () -> VerifyOptions.signatureOnly(null),
                "Выбор подписантов обязателен");
        assertThrows(
                IllegalStateException.class,
                () ->
                        VerifyOptions.signatureOnly(SignerSelection.ANY)
                                .untrustedCandidates(List.of(selfSignedCert)),
                "В режиме «только подпись» пул кандидатов не нужен");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        VerifyOptions.trusting(anchors, SignerSelection.ANY, Revocation.none())
                                .detached(null),
                "null вместо документа недопустим");
        assertThrows(
                IllegalArgumentException.class,
                () -> CmsSignedDataVerifier.verify(new byte[0], null),
                "null вместо параметров недопустим");
    }

    @Test
    @DisplayName("VerifyOptions: attached-подпись с detached-документом и наоборот отвергаются")
    void verifyOptionsDetachedModeMustMatchSignedData() throws PkixException {
        byte[] data = "mode mismatch".getBytes();
        byte[] attached =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .build();
        byte[] detached =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .detached(true)
                        .build();
        VerifyOptions trusting =
                VerifyOptions.trusting(
                        TrustAnchors.ofCertificates(selfSignedCert),
                        SignerSelection.ANY,
                        Revocation.none());

        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verify(attached, trusting.detached(data)),
                "SignedData с eContent нельзя проверять как detached");
        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verify(detached, trusting),
                "Detached SignedData требует документ в VerifyOptions.detached");
    }

    @Test
    @DisplayName("VerifiedSignedData.signer() бросает исключение, если подписантов несколько")
    void verifiedSignedDataSignerRequiresExactlyOneSigner() {
        VerifiedSignedData two =
                new VerifiedSignedData(
                        null,
                        List.of(
                                new SignerResult(
                                        selfSignedCert, new byte[] {1}, List.of(), List.of()),
                                new SignerResult(
                                        selfSignedCert, new byte[] {2}, List.of(), List.of())),
                        List.of());

        assertEquals(2, two.signers().size());
        assertThrows(IllegalStateException.class, two::signer, "Выбирать подписанта молча нельзя");
        assertThrows(IllegalStateException.class, two::signerCertificate);
        assertThrows(IllegalStateException.class, two::unsignedAttributes);
    }

    @Test
    @DisplayName("VerifiedSignedData: пустой или null список подписантов отвергается")
    void verifiedSignedDataRejectsEmptySigners() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new VerifiedSignedData(null, List.of(), List.of()),
                "Результат успешной проверки без подписантов невозможен");
        assertThrows(
                IllegalArgumentException.class,
                () -> new VerifiedSignedData(null, null, List.of()),
                "null вместо подписантов должен отвергаться");
    }

    @Test
    @DisplayName("CMS: истёкший закреплённый промежуточный CA отклоняется независимо от n")
    void cmsExpiredPinnedIntermediateRejected() throws PkixException {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Root");
        GostCertificate root =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.ONE);

        KeyPair interKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] interDn = GostDnParser.encodeDn("CN=Expired Intermediate");
        GostCertificate intermediate =
                createTestCert(
                        interKp,
                        interDn,
                        rootKp,
                        rootDn,
                        true,
                        "200101000000Z",
                        "210101000000Z",
                        BigInteger.TWO);

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        leafDn,
                        interKp,
                        interDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.valueOf(3));

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("expired pinned intermediate".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(intermediate)
                        .addCertificate(root)
                        .build();

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedDataVerifier.verify(
                                        signedData,
                                        VerifyOptions.trusting(
                                                TrustAnchors.ofCertificates(intermediate),
                                                SignerSelection.ANY,
                                                Revocation.none())),
                        "Истёкший закреплённый промежуточный CA должен отклоняться");
        assertEquals(PkixException.Reason.EXPIRED, e.reason());
    }

    @Test
    @DisplayName("CMS: перевыпущенный корень с тем же ключом принимается как якорь")
    void cmsReissuedRootSameKeyAccepted() throws PkixException {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Reissued Root");
        GostCertificate oldRoot =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.ONE);
        GostCertificate newRoot =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "370101000000Z",
                        BigInteger.TWO);

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        leafDn,
                        rootKp,
                        rootDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.valueOf(3));

        byte[] data = "reissued root".getBytes();
        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(oldRoot)
                        .build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(newRoot),
                                SignerSelection.ANY,
                                Revocation.none()));
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("CMS: закреплённый промежуточный CA не наследует ограничения корня")
    void cmsPinnedIntermediateIgnoresRootConstraints() throws PkixException {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=NC Root");
        byte[] nc =
                GostCertificateBuilder.buildNameConstraintsExtension(
                        new String[] {"example.com"}, null, null, null);
        GostCertificate root =
                createTestCert(
                        rootKp,
                        rootDn,
                        rootKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.ONE,
                        nc);

        KeyPair interKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] interDn = GostDnParser.encodeDn("CN=Pinned Intermediate");
        GostCertificate intermediate =
                createTestCert(
                        interKp,
                        interDn,
                        rootKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.TWO);

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        byte[] san =
                GostCertificateBuilder.buildSanExtension(
                        new String[] {"evil.com"}, null, null, null, null, null);
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        leafDn,
                        interKp,
                        interDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.valueOf(3),
                        san);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("pinned intermediate".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(intermediate)
                        .addCertificate(root)
                        .build();

        assertDoesNotThrow(
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(intermediate),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Закреплённый промежуточный CA — самостоятельный якорь");

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(root),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "При доверии корню его NameConstraints должны применяться");
    }

    @Test
    @DisplayName("CMS: поддельный корень с тем же DN, но чужим ключом отклоняется")
    void cmsFakeRootRejected() throws PkixException {
        KeyPair trustedKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Shared Root");
        GostCertificate trustedRoot =
                createTestCert(
                        trustedKp,
                        rootDn,
                        trustedKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.ONE);

        KeyPair attackerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate fakeRoot =
                createTestCert(
                        attackerKp,
                        rootDn,
                        attackerKp,
                        rootDn,
                        true,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.TWO);

        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=Leaf");
        GostCertificate leaf =
                createTestCert(
                        leafKp,
                        leafDn,
                        attackerKp,
                        rootDn,
                        false,
                        "260101000000Z",
                        "360101000000Z",
                        BigInteger.valueOf(3));

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data("fake root".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(fakeRoot)
                        .build();

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedDataVerifier.verify(
                                signedData,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(trustedRoot),
                                        SignerSelection.ANY,
                                        Revocation.none())),
                "Поддельный корень с тем же DN не должен приниматься");
    }

    private static GostCertificate createTestCert(
            KeyPair subjectKp,
            byte[] subjectDn,
            KeyPair signerKp,
            byte[] issuerDn,
            boolean ca,
            String notBefore,
            String notAfter,
            BigInteger serial,
            byte[]... extraExtensions) {
        List<byte[]> extensions = new ArrayList<>();
        extensions.add(GostCertificateBuilder.buildBasicConstraintsExtension(ca, null));
        if (ca) {
            extensions.add(
                    GostCertificateBuilder.buildKeyUsageExtension(
                            GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                            GostCertificateBuilder.KeyUsage.CRL_SIGN));
        } else {
            extensions.add(
                    GostCertificateBuilder.buildKeyUsageExtension(
                            GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE));
        }
        extensions.add(GostCertificateBuilder.buildSkiExtension(subjectKp.getPublic()));
        extensions.add(GostCertificateBuilder.buildAkiExtension(signerKp.getPublic()));
        for (byte[] extra : extraExtensions) {
            extensions.add(extra);
        }

        return GostCertificateBuilder.create(PARAMS, subjectDn)
                .publicKey(subjectKp.getPublic())
                .notBefore(notBefore)
                .notAfter(notAfter)
                .issuerDn(issuerDn)
                .additionalExtensions(concatExtensions(extensions.toArray(new byte[0][])))
                .serial(serial)
                .sign(signerKp.getPrivate());
    }

    private static CaLeafChain createCaLeafChainWithKeyUsage(
            GostCertificateBuilder.KeyUsage... leafKeyUsage) {
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA KU");
        GostCertificate caCert =
                GostCertificateBuilder.create(PARAMS, caDn)
                        .publicKey(caKp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .randomSerial()
                        .sign(caKp.getPrivate());

        var leafKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] leafDn = GostDnParser.encodeDn("CN=KU Leaf");
        GostCertificate leafCert =
                GostCertificateBuilder.create(PARAMS, leafDn)
                        .publicKey(leafKp.getPublic())
                        .notBefore("260101000000Z")
                        .notAfter("360101000000Z")
                        .issuerDn(caDn)
                        .basicConstraints(false, null)
                        .keyUsage(leafKeyUsage)
                        .randomSerial()
                        .sign(caKp.getPrivate());

        return new CaLeafChain(
                caKp.getPrivate(), caKp.getPublic(), caCert, caDn, leafKp.getPrivate(), leafCert);
    }

    /**
     * Заменяет OID в {@code SignerInfo.signatureAlgorithm} первого подписанта на заданный,
     * сохраняя остальную структуру SignedData. Используется для проверки fail-closed-логики:
     * поле не покрыто подписью, поэтому крипто-проверка остаётся валидной, а отклонение (если
     * оно есть) вызвано именно валидацией алгоритма.
     */
    private static byte[] patchSignerSignatureAlg(byte[] signedData, String newSignatureOid)
            throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedData);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        int signerInfosIdx = sdParts.length - 1;
        byte[][] signerInfos = DerCodec.parseSetContents(sdParts[signerInfosIdx], 0);
        byte[][] si = DerCodec.parseSequenceContents(signerInfos[0], 0);
        // Порядок SignerInfo: version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, ...
        si[4] = CmsAlgorithmIdentifier.encode(newSignatureOid);
        signerInfos[0] = DerCodec.encodeSequence(si);
        sdParts[signerInfosIdx] = DerCodec.encodeSetOf(signerInfos);
        byte[] newSd = DerCodec.encodeSequence(sdParts);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSd);
    }
}
