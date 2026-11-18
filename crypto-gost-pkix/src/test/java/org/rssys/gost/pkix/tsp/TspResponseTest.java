package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cms.CmsContentInfo;
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
        tsaCert = CmsTestUtils.createTsaCert(tsaKey.getPrivate(), tsaKey.getPublic());
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
    @DisplayName("verify отклоняет сертификат TSA без EKU (RFC 3161 §2.3 — EKU обязателен)")
    void verifyRejectsWhenTsaCertNoEku() throws Exception {
        // Сертификат без extensions -> EMPTY ExtensionsResult даёт ekuTimeStamping = false,
        // TSA обязан нести id-kp-timeStamping -> fail-closed.
        KeyPair noEkuKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate noEkuCert =
                CmsTestUtils.createSelfSignedCert(noEkuKp.getPrivate(), noEkuKp.getPublic());

        byte[] tstInfo = buildTstInfo(testHash256);
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.TST_INFO)
                        .addSigner(noEkuKp.getPrivate(), noEkuCert)
                        .build();
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        byte[] tspResp = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        TspResponse response = TspResponse.fromDer(tspResp);
        assertThrows(
                PkixException.class,
                () -> response.verify(testHash256, GostOids.DIGEST_256, null, noEkuCert),
                "TSA без EKU должен быть отклонён (fail-closed)");
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
                        .notAfter("21060101000000Z")
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .publicKey(noTimeStampKp.getPublic())
                        .randomSerial()
                        .sign(noTimeStampKp.getPrivate());

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
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            PkixException failure =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    response.verify(
                                            testHash256,
                                            GostOids.DIGEST_256,
                                            null,
                                            noTimeStampCert),
                            "TSA без id-kp-timeStamping должен быть отклонён");
            // Отказ именно по EKU, а не по сроку сертификата или другой причине
            assertTrue(
                    failure.getMessage().contains("id-kp-timeStamping"),
                    "причина отказа: " + failure.getMessage());

            // В исключении серийного номера нет, поэтому одна запись его добавляет; DN
            // службы штампов выдаёт внешний УЦ, в WARNING он не попадает
            List<String> warnings = log.messagesAtOrAbove(Level.WARNING);
            assertEquals(1, warnings.size(), "одна запись WARNING: " + warnings);
            assertTrue(
                    warnings.get(0).contains(noTimeStampCert.getSerialNumberBigInt().toString(16)),
                    "серийный номер сертификата службы штампов: " + warnings.get(0));
            assertFalse(
                    warnings.get(0).contains("TSA No TimeStamping"),
                    "DN не должен быть в WARNING: " + warnings.get(0));
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(m -> m.contains("TSA No TimeStamping")),
                    "усечённый DN доступен на DEBUG");
        }
    }

    @Test
    @DisplayName("Отказы messageImprint, hashAlgorithm и nonce: причина в исключении, WARNING нет")
    void verificationFailuresAreNotDuplicatedInLog() throws Exception {
        TspResponse response = TspResponse.fromDer(buildTspResponse(testHash256));
        byte[] otherHash = new byte[testHash256.length];
        CryptoRandom.INSTANCE.nextBytes(otherHash);
        TspResponse withoutNonce = TspResponse.fromDer(buildTspResponseWithoutNonce(testHash256));

        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            PkixException imprint =
                    assertThrows(
                            PkixException.class,
                            () -> response.verify(otherHash, GostOids.DIGEST_256, null, tsaCert));
            PkixException algorithm =
                    assertThrows(
                            PkixException.class,
                            () -> response.verify(testHash256, GostOids.DIGEST_512, null, tsaCert));
            PkixException nonce =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    response.verify(
                                            testHash256,
                                            GostOids.DIGEST_256,
                                            BigInteger.valueOf(99),
                                            tsaCert));
            PkixException missingNonce =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    withoutNonce.verify(
                                            testHash256,
                                            GostOids.DIGEST_256,
                                            BigInteger.valueOf(42),
                                            tsaCert));

            // Отказ с полным контекстом в исключении журналом не дублируется
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "причина отказа уже в исключении, WARNING не нужен");
            assertTrue(imprint.getMessage().contains("messageImprint"), imprint.getMessage());
            assertTrue(algorithm.getMessage().contains("hashAlgorithm"), algorithm.getMessage());
            assertTrue(nonce.getMessage().contains("nonce"), nonce.getMessage());
            assertTrue(missingNonce.getMessage().contains("nonce"), missingNonce.getMessage());
        }
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

    // ========================================================================
    // eContentType и тип исключения при битом входе
    // ========================================================================

    @Test
    @DisplayName("eContentType не id-ct-TSTInfo: токен отвергается, а не читается как TSTInfo")
    void rejectsTokenWithForeignEContentType() throws Exception {
        byte[] tstInfo = buildTstInfo(testHash256);
        // Содержимое - корректный TSTInfo, но тип в encapContentInfo заявлен как id-data:
        // подпись валидна, и только сверка типа не даёт принять его как метку времени
        byte[] timeStampToken =
                CmsSignedDataBuilder.create()
                        .data(tstInfo)
                        .contentType(GostOids.PKCS7_DATA)
                        .addSigner(tsaKey.getPrivate(), tsaCert)
                        .build();
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        byte[] response = DerCodec.encodeSequence(pkiStatus, timeStampToken);

        PkixException fromResponse =
                assertThrows(PkixException.class, () -> TspResponse.fromDer(response));
        assertEquals(
                PkixException.Reason.OTHER,
                fromResponse.reason(),
                "Чужой eContentType должен давать OTHER");
        assertTrue(
                fromResponse.getMessage().contains("eContentType"),
                "Сообщение должно называть eContentType");
        assertThrows(
                PkixException.class,
                () -> TspResponse.parseTimeStampToken(timeStampToken),
                "parseTimeStampToken должен отвергать чужой eContentType");
    }

    @Test
    @DisplayName("Усечённый TimeStampResp на любой длине даёт только PkixException")
    void truncatedResponseYieldsOnlyPkixException() throws Exception {
        byte[] valid = buildTspResponse(testHash256);
        for (int length = 0; length < valid.length; length++) {
            byte[] truncated = java.util.Arrays.copyOf(valid, length);
            int shown = length;
            assertThrows(
                    PkixException.class,
                    () -> TspResponse.fromDer(truncated),
                    "Усечение до " + shown + " байт должно давать PkixException");
        }
    }

    @Test
    @DisplayName("Усечённый TimeStampToken на любой длине даёт только PkixException")
    void truncatedTokenYieldsOnlyPkixException() throws Exception {
        byte[] response = buildTspResponse(testHash256);
        byte[] token = TspResponse.fromDer(response).timeStampTokenDer();
        for (int length = 0; length < token.length; length++) {
            byte[] truncated = java.util.Arrays.copyOf(token, length);
            int shown = length;
            assertThrows(
                    PkixException.class,
                    () -> TspResponse.parseTimeStampToken(truncated),
                    "Усечение токена до " + shown + " байт должно давать PkixException");
        }
    }

    @Test
    @DisplayName("Мусорные байты вместо TimeStampResp дают PkixException(PARSE_ERROR)")
    void garbageYieldsParseError() {
        byte[] garbage = {0x30, 0x03, 0x02, 0x01};
        PkixException e = assertThrows(PkixException.class, () -> TspResponse.fromDer(garbage));
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), "Ожидался PARSE_ERROR");
    }

    // ========================================================================
    // Границы обёрток eContent: токен пересобирается с испорченным encapContentInfo
    // ========================================================================

    /** Собирает токен, в котором encapContentInfo заменён на SEQUENCE { eContentType, поля }. */
    private byte[] tokenWithEncap(byte[]... encapFieldsAfterType) throws Exception {
        byte[] token = TspResponse.fromDer(buildTspResponse(testHash256)).timeStampTokenDer();
        CmsContentInfo contentInfo = CmsContentInfo.decode(token);
        byte[][] signedData = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        byte[][] encapFields = new byte[1 + encapFieldsAfterType.length][];
        encapFields[0] = DerCodec.encodeOid(GostOids.TST_INFO);
        System.arraycopy(encapFieldsAfterType, 0, encapFields, 1, encapFieldsAfterType.length);
        signedData[2] = DerCodec.encodeSequence(encapFields);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, DerCodec.encodeSequence(signedData));
    }

    private static byte[] concat(byte[]... parts) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private void assertParseError(byte[] token, String message) {
        PkixException e =
                assertThrows(PkixException.class, () -> TspResponse.parseTimeStampToken(token));
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), message);
    }

    @Test
    @DisplayName("Исправный пересобранный токен разбирается (контроль тестовой оснастки)")
    void rebuiltTokenWithValidEncapIsAccepted() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] token = tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, octets));
        assertNotNull(TspResponse.parseTimeStampToken(token), "Исправный токен должен читаться");
    }

    @Test
    @DisplayName("Чужой тег вместо [0] EXPLICIT в eContent отвергается")
    void rejectsWrongExplicitTag() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        assertParseError(
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, octets)),
                "Тег [1] вместо [0] должен давать PARSE_ERROR");
    }

    @Test
    @DisplayName("Хвост после OCTET STRING внутри [0] отвергается")
    void rejectsTrailingBytesAfterOctetString() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] withTail = concat(octets, new byte[] {0x00, 0x00});
        assertParseError(
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, withTail)),
                "Хвост после OCTET STRING должен давать PARSE_ERROR");
    }

    @Test
    @DisplayName("Хвост после constructed OCTET STRING и усечённый constructed отвергаются")
    void rejectsMalformedConstructedOctetString() throws Exception {
        byte[] segment = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] constructed = DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING_CONSTRUCTED, segment);

        byte[] withTail = concat(constructed, new byte[] {0x00, 0x00});
        assertParseError(
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, withTail)),
                "Хвост после constructed OCTET STRING должен давать PARSE_ERROR");

        // Длина заголовка 0x24 больше фактического содержимого: [0] обёрнут корректно, а внутри
        // последний байт отрезан
        byte[] shortened = java.util.Arrays.copyOf(constructed, constructed.length - 1);
        assertParseError(
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, shortened)),
                "Завышенная длина constructed OCTET STRING должна давать PARSE_ERROR");
    }

    @Test
    @DisplayName("Constructed OCTET STRING с одним сегментом принимается")
    void acceptsConstructedOctetStringWithSingleSegment() throws Exception {
        byte[] segment = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] constructed = DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING_CONSTRUCTED, segment);
        byte[] token =
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, constructed));
        assertNotNull(
                TspResponse.parseTimeStampToken(token),
                "Одиночный сегмент в constructed OCTET STRING должен читаться");
    }

    @Test
    @DisplayName("Constructed OCTET STRING из нескольких сегментов: сегменты склеиваются")
    void concatenatesSegmentsOfConstructedOctetString() throws Exception {
        byte[] tstInfo = buildTstInfo(testHash256);
        int half = tstInfo.length / 2;
        byte[] segments =
                concat(
                        DerCodec.encodeOctetString(java.util.Arrays.copyOfRange(tstInfo, 0, half)),
                        DerCodec.encodeOctetString(
                                java.util.Arrays.copyOfRange(tstInfo, half, tstInfo.length)));
        byte[] constructed = DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING_CONSTRUCTED, segments);
        byte[] token =
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, constructed));
        assertNotNull(
                TspResponse.parseTimeStampToken(token),
                "Сегменты читаются как одно значение, как при проверке подписи");
    }

    @Test
    @DisplayName("Пустой eContent [0] отвергается")
    void rejectsEmptyEContent() throws Exception {
        assertParseError(
                tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, new byte[0])),
                "Пустой [0] должен давать PARSE_ERROR");
    }

    @Test
    @DisplayName("BER с неопределённой длиной в [0] (форма КриптоПро) принимается")
    void acceptsIndefiniteLengthExplicitTag() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] indefinite =
                concat(
                        new byte[] {(byte) DerCodec.TAG_CTX_CONSTRUCTED_0, (byte) 0x80},
                        octets,
                        new byte[] {0x00, 0x00});
        assertNotNull(TspResponse.parseTimeStampToken(tokenWithEncap(indefinite)));
    }

    @Test
    @DisplayName("Неопределённая длина [0] без маркера конца отвергается как PARSE_ERROR")
    void rejectsIndefiniteLengthWithoutEoc() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        byte[] unterminated =
                concat(new byte[] {(byte) DerCodec.TAG_CTX_CONSTRUCTED_0, (byte) 0x80}, octets);
        assertParseError(tokenWithEncap(unterminated), "нет 00 00 - PARSE_ERROR");
    }

    @Test
    @DisplayName("Лишний третий элемент encapContentInfo отвергается")
    void rejectsExtraEncapElement() throws Exception {
        byte[] octets = DerCodec.encodeOctetString(buildTstInfo(testHash256));
        assertParseError(
                tokenWithEncap(
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, octets),
                        DerCodec.encodeNull()),
                "Лишний элемент encapContentInfo должен давать PARSE_ERROR");
    }

    // ========================================================================
    // Строгие числа: accuracy и PKIStatus
    // ========================================================================

    /** Токен с TSTInfo, в котором accuracy задан сырой SEQUENCE; остальные поля корректны. */
    private byte[] tokenWithRawAccuracy(byte[] accuracySequence) throws Exception {
        byte[] hashAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256));
        byte[] messageImprint =
                DerCodec.encodeSequence(hashAlg, DerCodec.encodeOctetString(testHash256));
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        byte[] tstInfo =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(1),
                        DerCodec.encodeOid(DUMMY_POLICY_OID),
                        messageImprint,
                        DerCodec.encodeInteger(BigInteger.ONE),
                        DerCodec.encodeGeneralizedTime(fmt.format(Instant.now())),
                        accuracySequence);
        byte[] octets = DerCodec.encodeOctetString(tstInfo);
        return tokenWithEncap(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, octets));
    }

    @Test
    @DisplayName("accuracy: секунды 02 01 FF (минус один) отвергаются")
    void rejectsNegativeAccuracySeconds() throws Exception {
        byte[] accuracy =
                DerCodec.encodeSequence(DerCodec.encodeTlv(0x02, new byte[] {(byte) 0xFF}));
        assertParseError(
                tokenWithRawAccuracy(accuracy), "Отрицательные секунды должны давать PARSE_ERROR");
    }

    @Test
    @DisplayName("accuracy: неминимальные секунды и миллисекунды отвергаются")
    void rejectsNonMinimalAccuracy() throws Exception {
        byte[] seconds = DerCodec.encodeSequence(DerCodec.encodeTlv(0x02, new byte[] {0x00, 0x05}));
        assertParseError(tokenWithRawAccuracy(seconds), "00 05 неминимально");
        byte[] millis =
                DerCodec.encodeSequence(
                        DerCodec.encodeContextPrimitive(0, new byte[] {0x00, 0x05}));
        assertParseError(tokenWithRawAccuracy(millis), "00 05 в миллисекундах неминимально");
    }

    @Test
    @DisplayName("accuracy: значения вне int отвергаются, а не обрезаются")
    void rejectsAccuracyOutsideInt() throws Exception {
        byte[] accuracy =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(0x02, new byte[] {0x01, 0x00, 0x00, 0x00, 0x00}));
        assertParseError(tokenWithRawAccuracy(accuracy), "5 октетов не помещаются в int");
    }

    @Test
    @DisplayName("accuracy: корректные секунды и миллисекунды читаются")
    void acceptsValidRawAccuracy() throws Exception {
        byte[] accuracy =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(0x02, new byte[] {0x03}),
                        DerCodec.encodeContextPrimitive(0, new byte[] {0x01, (byte) 0xF4}));
        TstInfo info = TspResponse.parseTimeStampToken(tokenWithRawAccuracy(accuracy)).tstInfo();
        assertEquals(3, info.accuracySeconds(), "секунды");
        assertEquals(500, info.accuracyMillis(), "миллисекунды");
    }
}
