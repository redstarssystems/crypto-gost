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
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
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

        byte[] emptyCrlField = DerCodec.encodeTlv(0xA1, new byte[0]);

        byte[] sdWithCrls =
                DerCodec.encodeSequence(
                        sdParts[0], sdParts[1], sdParts[2], sdParts[3], emptyCrlField, sdParts[4]);
        byte[] contentInfoWithCrls = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, sdWithCrls);

        VerifiedSignedData result =
                CmsSignedDataVerifier.verifyAny(contentInfoWithCrls, selfSignedCert);

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
        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert);
        assertNull(result.data(), "detached подпись должна вернуть data=null");
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
    @DisplayName("addCrl round-trip: построить -> verifyAny -> получить CRL из результата")
    void addCrl_roundTrip() throws PkixException {
        byte[] data = "round-trip with CRL".getBytes();
        GostCrl crl = createTestCrl(privateKey);

        byte[] signedData =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(privateKey, selfSignedCert)
                        .addCrl(crl)
                        .build();

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert);
        assertArrayEquals(data, result.data());
        assertNotNull(result.embeddedCrls());
        assertEquals(1, result.embeddedCrls().size());
        GostCrl roundTripped = result.embeddedCrls().get(0);
        assertEquals(crl.getIssuerDn(), roundTripped.getIssuerDn());
        assertEquals(crl.getThisUpdate(), roundTripped.getThisUpdate());
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
        java.util.Arrays.sort(manyCrls, DerCodec::compareDer);
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
                                CmsSignedDataVerifier.verifyAny(
                                        contentInfoWithTooManyCrls, selfSignedCert));
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
                                CmsSignedDataVerifier.verifyAny(
                                        contentInfoWithOversizedCrls, selfSignedCert));
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
                                CmsSignedDataVerifier.verifyAny(
                                        contentInfoWithBogusCrl, selfSignedCert));
        assertTrue(
                e.getMessage().contains("exceeds remaining buffer"),
                "Должно быть сообщение о превышении буфера, а не OOM: " + e.getMessage());
    }

    // ========================================================================
    // Вспомогательный метод: создание тестового CRL
    // ========================================================================

    private static GostCrl createTestCrl(PrivateKeyParameters caKey) {
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] crlDer =
                GostCrlBuilder.create(caKey, issuerDn).nextUpdate("30990601120000Z").build();
        return GostCrl.fromDer(crlDer);
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

    // ========================================================================
    // signedAttrs без обязательных атрибутов RFC 5652 §5.4
    // ========================================================================

    @Test
    @DisplayName("signedAttrs без messageDigest → PkixException")
    void signedAttrsWithoutMessageDigest() {
        byte[] signedData = buildSignedDataMissingAttr("message-digest");
        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert),
                "Отсутствие messageDigest в signedAttrs должно вызывать PkixException");
    }

    @Test
    @DisplayName("signedAttrs без contentType → PkixException")
    void signedAttrsWithoutContentType() {
        byte[] signedData = buildSignedDataMissingAttr("content-type");
        assertThrows(
                PkixException.class,
                () -> CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert),
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
        byte[] signAlgId = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_ALG_256));

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
                        () -> CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert),
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
                        () -> CmsSignedDataVerifier.verifyAny(signedData, selfSignedCert),
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
    // Тесты: проверка отзыва (verifyAnyWithRevocationCheck / verifyAllWithRevocationCheck)
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
                GostCertificateBuilder.assembleCert(caTbs, caKp.getPrivate(), PARAMS);

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
                GostCertificateBuilder.assembleCert(leafTbs, caKp.getPrivate(), PARAMS);

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
                GostCrlBuilder.create(caKey, issuerDn)
                        .withCrlNumber(1)
                        .nextUpdate("30990601120000Z")
                        .addRevoked(revokedSerial, "20250101000000Z")
                        .build();
        return GostCrl.fromDer(crlDer);
    }

    private static GostCrl createCleanCrl(PrivateKeyParameters caKey, byte[] issuerDn) {
        byte[] crlDer =
                GostCrlBuilder.create(caKey, issuerDn)
                        .withCrlNumber(1)
                        .nextUpdate("30990601120000Z")
                        .build();
        return GostCrl.fromDer(crlDer);
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: сертификат не в CRL — верификация проходит")
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
                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(signedData, chain.caCert);
        assertNotNull(result);
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: сертификат отозван — PkixException REVOKED")
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, chain.caCert),
                        "Отозванный сертификат должен отклониться");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "verifyAnyWithRevocationCheck: внешний CRL с отозванным сертификатом — PkixException")
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, List.of(crl), chain.caCert),
                        "Внешний CRL с отозванным сертификатом должен отклонить");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: CRL от другого issuer — best-effort пропуск")
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

        VerifiedSignedData result =
                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(signedData, chain.caCert);
        assertNotNull(result);
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: CRL с битой подписью — PkixException")
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, chain.caCert),
                        "CRL с невалидной подписью должен отклониться");
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, ex.reason());
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: просроченный CRL — PkixException")
    void withRevocationCheck_expiredCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "expired crl".getBytes();
        byte[] crlDer =
                GostCrlBuilder.create(chain.caPriv, chain.caDn)
                        .withCrlNumber(1)
                        .nextUpdate("20000101000000Z")
                        .build();
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, chain.caCert),
                        "Просроченный CRL должен отклониться");
        assertEquals(PkixException.Reason.EXPIRED, ex.reason());
    }

    @Test
    @DisplayName(
            "verifyAny без проверки отзыва: отозванный сертификат проходит (обратная совместимость)")
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

        VerifiedSignedData result = CmsSignedDataVerifier.verifyAny(signedData, chain.caCert);
        assertNotNull(result);
    }

    @Test
    @DisplayName("verifyAnyWithRevocationCheck: пустой trustedCerts — IllegalArgumentException")
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
                () -> CmsSignedDataVerifier.verifyAnyWithRevocationCheck(signedData),
                "Пустой trustedCerts должен бросить IllegalArgumentException");
    }

    @Test
    @DisplayName("verifyAllWithRevocationCheck: все подписанты валидны, проверка отзыва проходит")
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
                        .assembleCert(kp3.getPrivate());

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

        MultiSignerVerifiedData result =
                CmsSignedDataVerifier.verifyAllWithRevocationCheck(signedData, chain1.caCert, ca2);
        assertNotNull(result);
        assertEquals(2, result.signers().size());
    }

    @Test
    @DisplayName("verifyAllWithRevocationCheck: один подписант отозван — PkixException REVOKED")
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
                        .assembleCert(kp3.getPrivate());

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
                                CmsSignedDataVerifier.verifyAllWithRevocationCheck(
                                        signedData, chain1.caCert, ca2),
                        "Отозванный подписант в verifyAll должен отклониться");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "verifyAnyWithRevocationCheck: embedded CRL (чистый) + внешний CRL (отозван) → REVOKED")
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, List.of(revokedCrl), chain.caCert),
                        "Внешний CRL с отозванным должен перекрыть embedded с чистым");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }

    @Test
    @DisplayName(
            "verifyAnyWithRevocationCheck: multi-signer, первый отозван, второй валиден — возвращает второго")
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
                        .assembleCert(kp2.getPrivate());

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
                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                        signedData, chain1.caCert, cert2);
        assertNotNull(result, "OR-семантика: должен найти второго, незаблокированного подписанта");
        assertEquals(
                cert2.getSerialNumberBigInt(),
                result.signerCertificate().getSerialNumberBigInt(),
                "Должен вернуться второй подписант (первый отозван)");
        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName(
            "verifyAnyWithRevocationCheck: base + delta CRL — delta пропускается, base используется")
    void withRevocationCheck_basePlusDeltaCrl() throws PkixException {
        CaLeafChain chain = createCaLeafChain();
        byte[] data = "base+delta".getBytes();

        GostCrl baseCrl =
                createCrlWithRevokedCert(
                        chain.caPriv, chain.caDn, chain.leafCert.getSerialNumber());

        byte[] deltaCrlDer =
                GostCrlBuilder.create(chain.caPriv, chain.caDn)
                        .withCrlNumber(2)
                        .withDeltaCrlIndicator(BigInteger.ONE)
                        .nextUpdate("30990601120000Z")
                        .build();
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
                                CmsSignedDataVerifier.verifyAnyWithRevocationCheck(
                                        signedData, chain.caCert),
                        "Отозванный сертификат должен отклониться (delta пропущена, base проверяет)");
        assertEquals(PkixException.Reason.REVOKED, ex.reason());
    }
}
