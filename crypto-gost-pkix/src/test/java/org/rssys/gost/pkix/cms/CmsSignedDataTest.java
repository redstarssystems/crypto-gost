package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
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

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert);

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

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert);

        assertNull(result.data());
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
                () -> CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert),
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

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, certA, certB);
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

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, cert512);

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

        byte[] emptyCrlField = DerCodec.encodeTlv(0xA1, DerCodec.encodeSequence(new byte[0]));

        byte[] sdWithCrls =
                DerCodec.encodeSequence(
                        sdParts[0], sdParts[1], sdParts[2], sdParts[3], emptyCrlField, sdParts[4]);
        byte[] contentInfoWithCrls = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithCrls);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verifyAny(contentInfoWithCrls, selfSignedCert);

        assertArrayEquals(data, result.data());
    }

    // ========================================================================
    // Архитектурные тесты: verifyAny / verifyAll семантика
    // ========================================================================

    @Test
    @DisplayName("verifyAny возвращает первого валидного из нескольких подписантов")
    void verifyAnyReturnsFirstValid() throws Exception {
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

        // verifyAny с доверием ко второму подписанту — должен найти второго
        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signed, cert2);
        assertNotNull(result);
        assertArrayEquals(data, result.data());
        assertEquals(
                cert2.getSerialNumberBigInt(), result.signerCertificate().getSerialNumberBigInt());
    }

    @Test
    @DisplayName("verifyAny бросает когда все подписанты невалидны")
    void verifyAnyThrowsWhenAllInvalid() throws Exception {
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
                () -> CmsSignedDataVerifier.verifyAny(signed, wrongCert),
                "Ни один подписант не валиден — должен быть отклонён");
    }

    @Test
    @DisplayName("verifyAll возвращает всех когда все валидны")
    void verifyAllReturnsAllWhenAllValid() throws Exception {
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

        MultiSignerVerifiedData result =
                CmsSignedDataVerifier.verifyAll(signed, selfSignedCert, cert2);
        assertNotNull(result);
        assertEquals(2, result.signers().size());
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("verifyAll бросает когда один подписант невалиден")
    void verifyAllThrowsWhenOneInvalid() throws Exception {
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
                () -> CmsSignedDataVerifier.verifyAll(signed, selfSignedCert),
                "Один подписант невалиден — AND-семантика должна отклонить");
    }

    @Test
    @DisplayName("SignerResult содержит signedAttributes после verifyAll")
    void signerResultContainsSignedAttributes() throws Exception {
        byte[] data = "signed-attrs".getBytes();
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .withCAdES()
                        .build();

        MultiSignerVerifiedData result = CmsSignedDataVerifier.verifyAll(signed, selfSignedCert);
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

        MultiSignerVerifiedData result = CmsSignedDataVerifier.verifyAll(signed, selfSignedCert);
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
    @DisplayName("verifyAll бросает PkixException при пустом SET OF SignerInfo")
    void verifyAllThrowsOnEmptySignerInfos() {
        byte[] emptySignedData = buildSignedDataWithNoSigners();

        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verifyAll(emptySignedData, selfSignedCert),
                "Пустые signerInfos должны вызывать исключение в verifyAll");
    }

    @Test
    @DisplayName("verifyAny бросает PkixException при пустом SET OF SignerInfo")
    void verifyAnyThrowsOnEmptySignerInfos() {
        byte[] emptySignedData = buildSignedDataWithNoSigners();

        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verifyAny(emptySignedData, selfSignedCert),
                "Пустые signerInfos должны вызывать исключение в verifyAny");
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
}
