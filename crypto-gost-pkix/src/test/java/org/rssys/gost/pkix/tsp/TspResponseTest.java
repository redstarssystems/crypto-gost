package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

@DisplayName("TspResponse: разбор и валидация TimeStampResp")
class TspResponseTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String DUMMY_POLICY_OID = "1.3.6.1.4.1.4146.1.2.1";
    private static KeyPair tsaKey;
    private static GostCertificate tsaCert;
    private static byte[] testHash256;

    @BeforeAll
    static void setUp() throws Exception {
        tsaKey = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = CmsTestUtils.createSelfSignedCert(tsaKey.getPrivate(), tsaKey.getPublic());
        testHash256 = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(testHash256);
    }

    @Test
    @DisplayName("Разбор валидного TimeStampResp с granted")
    void parseGrantedResponse() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        assertEquals(GostOids.PKI_STATUS_GRANTED, response.status());
        assertNotNull(response.tstInfo());
        assertNotNull(response.timeStampTokenDer());
        assertEquals(GostOids.DIGEST_256, response.tstInfo().messageImprintAlgOid());
    }

    @Test
    @DisplayName("Разбор TimeStampResp с rejection вызывает PkixException")
    void parseRejectionResponse() {
        byte[] rejectionResp = buildRejectionResponse();
        assertThrows(PkixException.class, () -> TspResponse.fromDer(rejectionResp));
    }

    @Test
    @DisplayName("verify проходит для валидного ответа")
    void verifyValidResponse() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName("verify падает при несовпадении messageImprint")
    void verifyMismatchedHash() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        byte[] otherHash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(otherHash);
        assertThrows(
                PkixException.class,
                () -> response.verify(otherHash, GostOids.DIGEST_256, null, tsaCert));
    }

    @Test
    @DisplayName("verify падает при несовпадении hashAlgorithm")
    void verifyMismatchedAlg() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        assertThrows(
                PkixException.class,
                () -> response.verify(testHash256, GostOids.DIGEST_512, null, tsaCert));
    }

    @Test
    @DisplayName("nullInput: parse падает на нулевом входе")
    void nullInputThrows() {
        assertThrows(NullPointerException.class, () -> TspResponse.fromDer(null));
    }

    // ========================================================================
    // Nonce-тесты
    // ========================================================================

    @Test
    @DisplayName("nonce: verify проходит при совпадении nonce")
    void verifyCorrectNonce() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        response.verify(testHash256, GostOids.DIGEST_256, BigInteger.valueOf(42), tsaCert);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName("nonce: verify бросает PkixException при несовпадении nonce")
    void verifyNonceMismatch() throws Exception {
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        assertThrows(
                PkixException.class,
                () ->
                        response.verify(
                                testHash256, GostOids.DIGEST_256, BigInteger.valueOf(99), tsaCert),
                "Nonce не совпадает — должен быть отклонён");
    }

    @Test
    @DisplayName("nonce: verify бросает при отсутствии nonce в ответе")
    void verifyMissingNonce() throws Exception {
        byte[] tspResp = buildTspResponseWithoutNonce(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        assertThrows(
                PkixException.class,
                () ->
                        response.verify(
                                testHash256, GostOids.DIGEST_256, BigInteger.valueOf(42), tsaCert),
                "Nonce ожидается, но отсутствует в ответе — должен быть отклонён");
    }

    @Test
    @DisplayName("nonce: verify с null nonce пропускает проверку")
    void verifyNullNonceSkipsCheck() throws Exception {
        byte[] tspResp = buildTspResponseWithoutNonce(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        // null nonce — проверка пропускается
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /**
     * Строит валидный TimeStampResp с granted и TimeStampToken.
     */
    private byte[] buildTspResponse(byte[] messageImprintHash) throws Exception {
        // 1. TSTInfo DER
        byte[] tstInfo = buildTstInfo(messageImprintHash);

        // 2. TimeStampToken = CMS SignedData с TSTInfo
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();

        // 3. PKIStatusInfo: SEQUENCE { INTEGER(granted=0) }
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));

        // 4. TimeStampResp: SEQUENCE { PKIStatusInfo, TimeStampToken }
        return DerCodec.encodeSequence(pkiStatus, timeStampToken);
    }

    /**
     * Строит TimeStampResp с rejection.
     */
    private byte[] buildRejectionResponse() {
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_REJECTED)));
        return DerCodec.encodeSequence(pkiStatus);
    }

    /**
     * Строит TSTInfo DER.
     */
    private byte[] buildTstInfo(byte[] hash) {
        return buildTstInfo(hash, BigInteger.valueOf(42));
    }

    /**
     * Строит TSTInfo DER с заданным nonce.
     */
    private byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());

        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid(DUMMY_POLICY_OID);
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(nonce);

        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    /**
     * Строит TimeStampResp без nonce в TSTInfo.
     */
    private byte[] buildTspResponseWithoutNonce(byte[] messageImprintHash) throws Exception {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());

        // TSTInfo без nonce
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid(DUMMY_POLICY_OID);
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] hashedMsg = DerCodec.encodeOctetString(messageImprintHash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] tstInfo =
                DerCodec.encodeSequence(version, policy, messageImprint, serial, genTimeDer);

        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();

        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        return DerCodec.encodeSequence(pkiStatus, timeStampToken);
    }

    // ========================================================================
    // EKU назначение id-kp-timeStamping
    // ========================================================================

    @Test
    @DisplayName("verify проходит если сертификат TSA без EKU (EMPTY — permissive default)")
    void verifyPassesWhenTsaCertNoEku() throws Exception {
        // tsaCert без EKU — EMPTY ExtensionsResult даёт ekuTimeStamping = true (permissive)
        byte[] tspResp = buildTspResponse(testHash256);
        TspResponse response = TspResponse.fromDer(tspResp);
        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert);
        assertTrue(response.isSignatureVerified());
    }

    @Test
    @DisplayName(
            "verify бросает PkixException если сертификат TSA имеет EKU serverAuth без timeStamping")
    void verifyFailsWhenTsaCertMissingTimeStampingEku() throws Exception {
        // Сертификат с явным EKU serverAuth — ekuPresent=true, ekuTimeStamping=false
        KeyPair noTimeStampKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate noTimeStampCert =
                GostCertificateBuilder.create(PARAMS, "CN=TSA No TimeStamping")
                        .basicConstraints(false, null)
                        .notBefore("250101000000Z")
                        .notAfter("260101000000Z")
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .publicKey(noTimeStampKp.getPublic())
                        .assembleCert(noTimeStampKp.getPrivate());

        byte[] tstInfo = buildTstInfo(testHash256);
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(noTimeStampKp.getPrivate(), noTimeStampCert)
                        .build();
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        byte[] tspResp = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        TspResponse response = TspResponse.fromDer(tspResp);
        assertThrows(
                PkixException.class,
                () -> response.verify(testHash256, GostOids.DIGEST_256, null, noTimeStampCert),
                "TSA без id-kp-timeStamping должен быть отклонён");
    }

    // ========================================================================
    // Статус: успешно с модификациями
    // ========================================================================

    @Test
    @DisplayName("grantedWithMods: parse принимает PKIStatus=1 и verify проходит")
    void parseGrantedWithModsResponse() throws Exception {
        // PKIStatusInfo SEQUENCE { INTEGER(1) }
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(
                                BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED_WITH_MODS)));
        byte[] tstInfo = buildTstInfo(testHash256);
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();
        byte[] tspResp = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        TspResponse response = TspResponse.fromDer(tspResp);
        assertEquals(
                GostOids.PKI_STATUS_GRANTED_WITH_MODS,
                response.status(),
                "PKIStatus=1 (grantedWithMods) должен приниматься");
        assertNotNull(response.tstInfo());

        response.verify(testHash256, GostOids.DIGEST_256, null, tsaCert);
        assertTrue(response.isSignatureVerified());
    }

    // ========================================================================
    // Точность штампа
    // ========================================================================

    @Test
    @DisplayName("accuracy: TSTInfo с accuracySeconds и accuracyMillis парсится корректно")
    void parseTstInfoWithAccuracySecondsAndMillis() throws Exception {
        byte[] tstInfoWithAcc = buildTstInfoWithAccuracy(testHash256, 5, 100);
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfoWithAcc)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        byte[] tspResp = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        TspResponse response = TspResponse.fromDer(tspResp);
        TstInfo info = response.tstInfo();
        assertEquals(5, info.accuracySeconds(), "accuracySeconds");
        assertEquals(100, info.accuracyMillis(), "accuracyMillis");
    }

    @Test
    @DisplayName("accuracy: TSTInfo только с accuracySeconds (без millis)")
    void parseTstInfoWithAccuracySecondsOnly() throws Exception {
        byte[] tstInfoWithAcc = buildTstInfoWithAccuracy(testHash256, 3, null);
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfoWithAcc)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        byte[] tspResp = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        TspResponse response = TspResponse.fromDer(tspResp);
        TstInfo info = response.tstInfo();
        assertEquals(3, info.accuracySeconds(), "accuracySeconds");
        assertEquals(null, info.accuracyMillis(), "accuracyMillis должен быть null");
    }

    // ========================================================================
    // Вспомогательные методы для accuracy
    // ========================================================================

    /**
     * Строит TSTInfo DER с опциональным полем accuracy.
     *
     * @param hash   хэш сообщения
     * @param sec    точность в секундах (null — поле отсутствует)
     * @param millis точность в миллисекундах (null — поле отсутствует)
     */
    private byte[] buildTstInfoWithAccuracy(byte[] hash, Integer sec, Integer millis) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());

        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid(DUMMY_POLICY_OID);
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);

        // accuracy: SEQUENCE { seconds INTEGER OPTIONAL, millis [0] IMPLICIT INTEGER OPTIONAL, ...
        // }
        java.util.List<byte[]> accParts = new java.util.ArrayList<>();
        if (sec != null) {
            accParts.add(DerCodec.encodeInteger(BigInteger.valueOf(sec)));
        }
        if (millis != null) {
            // [0] IMPLICIT INTEGER — кодируем как контекстный примитив с тегом 0
            // Содержимое IMPLICIT INTEGER = bare two's complement integer bytes
            byte[] millisContent = BigInteger.valueOf(millis).toByteArray();
            accParts.add(DerCodec.encodeContextPrimitive(0, millisContent));
        }
        byte[] accuracy = DerCodec.encodeSequence(accParts.toArray(new byte[0][]));

        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, accuracy);
    }
}
