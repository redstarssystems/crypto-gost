package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

@DisplayName("TspResponseBuilder: построение TimeStampResp")
class TspResponseBuilderTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();
    private static final String DUMMY_POLICY_OID = "1.3.6.1.4.1.4146.1.2.1";
    private static KeyPair tsaKey256;
    private static GostCertificate tsaCert256;
    private static KeyPair tsaKey512;
    private static GostCertificate tsaCert512;
    private static byte[] testHash256;
    private static byte[] testHash512;

    @BeforeAll
    static void setUp() throws Exception {
        tsaKey256 = KeyGenerator.generateKeyPair(PARAMS_256);
        tsaCert256 = CmsTestUtils.createSelfSignedCert(
                tsaKey256.getPrivate(), tsaKey256.getPublic());
        tsaKey512 = KeyGenerator.generateKeyPair(PARAMS_512);
        tsaCert512 = CmsTestUtils.createSelfSignedCert(
                tsaKey512.getPrivate(), tsaKey512.getPublic());
        testHash256 = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(testHash256);
        testHash512 = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(testHash512);
    }

    // ========================================================================
    // Полный цикл запрос-ответ
    // ========================================================================

    @Test
    @DisplayName("Round-trip granted с 256-битным ключом")
    void roundTripGranted256() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        assertEquals(GostOids.PKI_STATUS_GRANTED, response.status());
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName("Round-trip granted с 512-битным ключом — авто-DIGEST_512")
    void roundTripGranted512() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash512, GostOids.DIGEST_512)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey512.getPrivate(), tsaCert512)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        assertEquals(GostOids.PKI_STATUS_GRANTED, response.status());
        response.verify(testHash512, GostOids.DIGEST_512, null, tsaCert512);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Эхо nonce
    // ========================================================================

    @Test
    @DisplayName("Nonce echo: nonce из запроса возвращается в ответе")
    void nonceEcho() throws Exception {
        BigInteger nonce = BigInteger.valueOf(12345);
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .nonce(nonce)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        response.verify(testHash256, GostOids.DIGEST_256, nonce, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName("Без nonce: запрос без nonce → ответ без nonce")
    void noNonce() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .nonce(null)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        // null nonce — проверка пропускается
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Отклонение
    // ========================================================================

    @Test
    @DisplayName("Rejection: buildRejected возвращает PKIStatus=2")
    void rejection() {
        byte[] rejectionResp = TspResponseBuilder.buildRejected("Unsupported algorithm");
        assertThrows(PkixException.class, () -> TspResponse.fromDer(rejectionResp));
    }

    @Test
    @DisplayName("Rejection statusString: кодируется как UTF8String, парсер возвращает в тексте PkixException")
    void rejectionStatusString() {
        byte[] rejectionResp = TspResponseBuilder.buildRejected("Unknown policy");
        PkixException ex = assertThrows(
                PkixException.class, () -> TspResponse.fromDer(rejectionResp));
        assertTrue(ex.getMessage().contains("Unknown policy"),
                "Сообщение исключения должно содержать statusString: " + ex.getMessage());
    }

    @Test
    @DisplayName("Rejection без сообщения: buildRejected() без аргументов")
    void rejectionWithoutMessage() {
        byte[] rejectionResp = TspResponseBuilder.buildRejected();
        PkixException ex = assertThrows(
                PkixException.class, () -> TspResponse.fromDer(rejectionResp));
        assertTrue(ex.getMessage().contains("rejection"),
                "Сообщение исключения должно содержать 'rejection': " + ex.getMessage());
    }

    @Test
    @DisplayName("failInfo single bit: buildRejected(PKI_FAIL_BAD_ALG) → BIT STRING с битом 0")
    void failInfoSingleBitDirect() {
        byte[] rejectionResp = TspResponseBuilder.buildRejected(GostOids.PKI_FAIL_BAD_ALG);
        PkixException ex = assertThrows(
                PkixException.class, () -> TspResponse.fromDer(rejectionResp));
        assertEquals(GostOids.PKI_FAIL_BAD_ALG, ex.failInfo(),
                "failInfo должен быть BAD_ALG (1)");
    }

    @Test
    @DisplayName("failInfo combined: BAD_ALG | UNACCEPTED_POLICY")
    void failInfoCombined() {
        int combined = GostOids.PKI_FAIL_BAD_ALG | GostOids.PKI_FAIL_UNACCEPTED_POLICY;
        byte[] rejectionResp = TspResponseBuilder.buildRejected(combined);
        PkixException ex = assertThrows(
                PkixException.class, () -> TspResponse.fromDer(rejectionResp));
        assertEquals(combined, ex.failInfo(),
                "failInfo должен быть BAD_ALG | UNACCEPTED_POLICY");
    }

    @Test
    @DisplayName("failInfo с сообщением: buildRejected(\"msg\", SYSTEM_FAILURE)")
    void failInfoWithMessage() {
        byte[] rejectionResp = TspResponseBuilder.buildRejected(
                "internal error", GostOids.PKI_FAIL_SYSTEM_FAILURE);
        PkixException ex = assertThrows(
                PkixException.class, () -> TspResponse.fromDer(rejectionResp));
        assertTrue(ex.getMessage().contains("internal error"),
                "Сообщение должно содержать statusString: " + ex.getMessage());
        assertEquals(GostOids.PKI_FAIL_SYSTEM_FAILURE, ex.failInfo(),
                "failInfo должен быть SYSTEM_FAILURE (1<<25)");
    }

    // ========================================================================
    // Точность штампа
    // ========================================================================

    @Test
    @DisplayName("Accuracy — только секунды")
    void accuracySecondsOnly() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .accuracy(3)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        TstInfo info = response.tstInfo();
        assertEquals(3, info.accuracySeconds(), "accuracySeconds");
        assertEquals(null, info.accuracyMillis(), "accuracyMillis должен быть null");
    }

    @Test
    @DisplayName("Accuracy — секунды + миллисекунды")
    void accuracySecondsAndMillis() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .accuracy(5, 150)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        TstInfo info = response.tstInfo();
        assertEquals(5, info.accuracySeconds(), "accuracySeconds");
        assertEquals(150, info.accuracyMillis(), "accuracyMillis");
    }

    // ========================================================================
    // Упорядоченность штампов
    // ========================================================================

    @Test
    @DisplayName("Ordering = true сохраняется в TstInfo после round-trip")
    void orderingTrue() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .ordering(true)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        assertTrue(response.tstInfo().ordering(), "ordering должен быть true");
    }

    @Test
    @DisplayName("Ordering по умолчанию false")
    void orderingDefaultFalse() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        assertEquals(false, response.tstInfo().ordering(), "ordering по умолчанию — false");
    }

    // ========================================================================
    // Ответ с модификациями
    // ========================================================================

    @Test
    @DisplayName("grantedWithMods: PKIStatus=1, verify проходит")
    void grantedWithMods() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGrantedWithMods();
        TspResponse response = TspResponse.fromDer(resp);
        assertEquals(GostOids.PKI_STATUS_GRANTED_WITH_MODS, response.status(),
                "PKIStatus=1 (grantedWithMods)");
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Ошибки
    // ========================================================================

    @Test
    @DisplayName("Ошибка: вызов buildGranted без signer")
    void errorNoSigner() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        TspResponseBuilder builder = TspResponseBuilder.create(req)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE);
        IllegalStateException ex = assertThrows(
                IllegalStateException.class, builder::buildGranted);
        assertTrue(ex.getMessage().contains("signer"),
                "Сообщение должно содержать 'signer': " + ex.getMessage());
    }

    @Test
    @DisplayName("Ошибка: вызов buildGranted без policyOid")
    void errorNoPolicyOid() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        TspResponseBuilder builder = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .serialNumber(BigInteger.ONE);
        IllegalStateException ex = assertThrows(
                IllegalStateException.class, builder::buildGranted);
        assertTrue(ex.getMessage().contains("policyOid"),
                "Сообщение должно содержать 'policyOid': " + ex.getMessage());
    }

    @Test
    @DisplayName("Ошибка: вызов buildGranted без serialNumber")
    void errorNoSerialNumber() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        TspResponseBuilder builder = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID);
        IllegalStateException ex = assertThrows(
                IllegalStateException.class, builder::buildGranted);
        assertTrue(ex.getMessage().contains("serialNumber"),
                "Сообщение должно содержать 'serialNumber': " + ex.getMessage());
    }

    @Test
    @DisplayName("Ошибка: create с null байтами")
    void errorCreateNull() {
        assertThrows(NullPointerException.class, () -> TspResponseBuilder.create((byte[]) null));
    }

    @Test
    @DisplayName("Ошибка: создание TspRequest с битыми данными")
    void errorTspRequestParseBadData() {
        assertThrows(RuntimeException.class, () -> TspRequest.fromDer(new byte[] {0x00, 0x01}));
    }

    // ========================================================================
    // Цепочка сертификатов
    // ========================================================================

    @Test
    @DisplayName("addChainCert: дополнительный сертификат включается в SignedData")
    void chainCert() throws Exception {
        KeyPair intermediateKp = KeyGenerator.generateKeyPair(PARAMS_256);
        GostCertificate intermediateCert = CmsTestUtils.createSelfSignedCert(
                intermediateKp.getPrivate(), intermediateKp.getPublic());
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .addChainCert(intermediateCert)
                .buildGranted();
        // Проверяем что ответ парсится и verify проходит
        TspResponse response = TspResponse.fromDer(resp);
        assertDoesNotThrow(
                () -> response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256));
    }

    // ========================================================================
    // Разбор запросов
    // ========================================================================

    @Test
    @DisplayName("TspRequest.fromDer: все поля запроса")
    void tspRequestParseAllFields() throws Exception {
        BigInteger nonce = BigInteger.valueOf(42);
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .reqPolicy(DUMMY_POLICY_OID)
                .nonce(nonce)
                .certReq(true)
                .build();
        TspRequest request = TspRequest.fromDer(req);
        assertEquals(GostOids.DIGEST_256, request.messageImprintAlgOid());
        assertEquals(DUMMY_POLICY_OID, request.reqPolicy());
        assertEquals(nonce, request.nonce());
        assertTrue(request.certReq());
    }

    @Test
    @DisplayName("TspRequest.fromDer: запрос без опциональных полей")
    void tspRequestParseMinimal() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .nonce(null)
                .build();
        TspRequest request = TspRequest.fromDer(req);
        assertEquals(GostOids.DIGEST_256, request.messageImprintAlgOid());
        assertEquals(null, request.reqPolicy());
        assertEquals(null, request.nonce());
        assertEquals(false, request.certReq());
    }

    // ========================================================================
    // CAdES-атрибуты
    // ========================================================================

    @Test
    @DisplayName("без withCAdES() — ответ парсится и verify проходит")
    void withoutCAdES() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName("withCAdES() — ответ парсится и verify проходит")
    void withCAdES() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = TspResponseBuilder.create(req)
                .signer(tsaKey256.getPrivate(), tsaCert256)
                .policyOid(DUMMY_POLICY_OID)
                .serialNumber(BigInteger.ONE)
                .withCAdES()
                .buildGranted();
        TspResponse response = TspResponse.fromDer(resp);
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert256);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Создание из байтов
    // ========================================================================

    @Test
    @DisplayName("create(byte[]) convenience overload работает")
    void createByteArrayOverload() throws Exception {
        byte[] req = TspRequestBuilder.create()
                .messageImprint(testHash256, GostOids.DIGEST_256)
                .build();
        byte[] resp = assertDoesNotThrow(() ->
                TspResponseBuilder.create(req)
                        .signer(tsaKey256.getPrivate(), tsaCert256)
                        .policyOid(DUMMY_POLICY_OID)
                        .serialNumber(BigInteger.ONE)
                        .buildGranted());
        assertNotNull(resp);
    }

    @Test
    @DisplayName("create(TspRequest) — проверка non-null")
    void createTspRequestNonNull() {
        assertThrows(NullPointerException.class,
                () -> TspResponseBuilder.create((TspRequest) null));
    }
}
