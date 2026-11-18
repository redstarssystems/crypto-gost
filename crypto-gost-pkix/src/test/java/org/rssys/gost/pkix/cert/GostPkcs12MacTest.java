package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.MacData;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostPkcs12Mac}: изолированный roundtrip compute() -> verify()
 * без зависимости от {@link GostPkcs12Builder} или {@link GostPkcs12Parser#parsePfx}.
 */
@DisplayName("GostPkcs12Mac: изолированный roundtrip MAC")
class GostPkcs12MacTest {

    private static final int ITERATIONS = 100;

    /** 16-байтовая соль из CryptoRandom. */
    private static byte[] randomSalt() {
        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        return salt;
    }

    /** Пароль как UTF-8 байты. */
    private static byte[] pw(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Минимальный authSafe — пустая SEQUENCE (BER). */
    private static byte[] authSafe() {
        return DerCodec.encodeSequence(new byte[0]);
    }

    // ---------------------------------------------------------------
    // Ручной разбор MacData DER
    // ---------------------------------------------------------------

    /**
     * Разбирает MacData DER (результат {@link GostPkcs12Mac#compute}) обратно в {@link MacData}.
     * MacData ::= SEQUENCE { DigestInfo, OCTET STRING salt, INTEGER iterations }
     * DigestInfo ::= SEQUENCE { AlgorithmIdentifier(SEQUENCE{OID}), OCTET STRING digestValue }
     */
    private static MacData parseMacData(byte[] macDataDer) {
        // macSeq[0]=DigestInfo, macSeq[1]=OCTET STRING salt, macSeq[2]=INTEGER iterations
        byte[][] macSeq = DerCodec.parseSequenceContents(macDataDer, 0);
        assertEquals(3, macSeq.length, "MacData SEQUENCE: 3 элемента");

        byte[] digestInfoDer = macSeq[0];
        // diSeq[0]=AlgorithmIdentifier(SEQUENCE{OID}), diSeq[1]=OCTET STRING digest
        byte[][] diSeq = DerCodec.parseSequenceContents(digestInfoDer, 0);

        byte[] algIdSeqDer = diSeq[0];
        // algIdSeq[0]=OID
        byte[][] algIdSeq = DerCodec.parseSequenceContents(algIdSeqDer, 0);

        String digestOid = DerCodec.parseOid(algIdSeq[0], 0);
        byte[] digestValue = DerCodec.parseOctetString(diSeq[1], 0);
        byte[] salt = DerCodec.parseOctetString(macSeq[1], 0);
        int iterations = DerCodec.parseInteger(macSeq[2], 0).intValue();

        // Package-private конструктор доступен в том же пакете
        return new MacData(salt, iterations, digestOid, digestValue);
    }

    // ---------------------------------------------------------------
    // Roundtrip: compute -> verify
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Roundtrip Streebog-512: compute -> ручной разбор MacData -> verify")
    void testRoundtrip512() {
        byte[] authSafe = authSafe();
        byte[] password = pw("correct-password");
        byte[] salt = randomSalt();

        byte[] macDataDer = GostPkcs12Mac.compute(authSafe, password, ITERATIONS, salt);
        MacData macData = parseMacData(macDataDer);

        assertDoesNotThrow(
                () -> GostPkcs12Mac.verify(macData, password, authSafe),
                "Roundtrip Streebog-512: verify должен пройти");
    }

    // ---------------------------------------------------------------
    // Неверный пароль
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Неверный пароль -> verify падает с IllegalArgumentException")
    void testWrongPasswordFails() {
        byte[] authSafe = authSafe();
        byte[] correctPwd = pw("correct");
        byte[] wrongPwd = pw("wrong");
        byte[] salt = randomSalt();

        byte[] macDataDer = GostPkcs12Mac.compute(authSafe, correctPwd, ITERATIONS, salt);
        MacData macData = parseMacData(macDataDer);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Mac.verify(macData, wrongPwd, authSafe),
                "Неверный пароль должен вызывать исключение");
    }

    // ---------------------------------------------------------------
    // Повреждённый authSafe
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Повреждённый authSafe -> verify падает")
    void testCorruptedAuthSafeFails() {
        byte[] authSafe = authSafe();
        byte[] password = pw("test-password");
        byte[] salt = randomSalt();

        byte[] macDataDer = GostPkcs12Mac.compute(authSafe, password, ITERATIONS, salt);
        MacData macData = parseMacData(macDataDer);

        byte[] corrupted = Arrays.copyOf(authSafe, authSafe.length);
        if (corrupted.length > 0) {
            corrupted[0] ^= 0x01;
        }

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Mac.verify(macData, password, corrupted),
                "Повреждённые данные должны вызывать исключение проверки MAC");
    }

    // ---------------------------------------------------------------
    // Пустой пароль
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Пустой пароль (нулевая длина): compute -> verify проходит")
    void testEmptyPassword() {
        byte[] authSafe = authSafe();
        byte[] emptyPwd = new byte[0];
        byte[] salt = randomSalt();

        byte[] macDataDer = GostPkcs12Mac.compute(authSafe, emptyPwd, ITERATIONS, salt);
        MacData macData = parseMacData(macDataDer);

        assertDoesNotThrow(
                () -> GostPkcs12Mac.verify(macData, emptyPwd, authSafe),
                "Пустой пароль должен работать");
    }

    // ---------------------------------------------------------------
    // Неверный digestAlgorithm OID в MacData
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Неверный digestAlgorithm OID в MacData -> verify падает")
    void testWrongDigestAlgorithmOidFails() {
        byte[] authSafe = authSafe();
        byte[] password = pw("test-password");
        byte[] salt = randomSalt();

        byte[] macDataDer = GostPkcs12Mac.compute(authSafe, password, ITERATIONS, salt);
        MacData macData = parseMacData(macDataDer);

        // Создаём MacData с неверным OID
        MacData badMacData =
                new MacData(
                        macData.getSalt(),
                        macData.getIterations(),
                        "1.2.3.4.5.6.7.8.999",
                        macData.getDigestValue());

        assertThrows(
                IllegalArgumentException.class,
                () -> GostPkcs12Mac.verify(badMacData, password, authSafe),
                "Неизвестный digestAlgorithm OID должен вызывать исключение");
    }

    // ---------------------------------------------------------------
    // Форма MacData по RFC 9548 §7
    // ---------------------------------------------------------------

    @Test
    @DisplayName(
            "compute: DigestInfo содержит OID хэша 1.2.643.7.1.1.2.3 без параметров, MAC 64 байта")
    void testMacDataByteForm() {
        byte[] salt = new byte[GostOids.PBKDF2_SALT_LEN];
        byte[] macDataDer = GostPkcs12Mac.compute(authSafe(), pw("пароль"), ITERATIONS, salt);

        byte[][] macSeq = DerCodec.parseSequenceContents(macDataDer, 0);
        byte[][] digestInfo = DerCodec.parseSequenceContents(macSeq[0], 0);
        byte[][] algId = DerCodec.parseSequenceContents(digestInfo[0], 0);

        assertEquals(3, macSeq.length, "MacData: DigestInfo, salt, iterations");
        assertEquals(2, digestInfo.length, "DigestInfo: AlgorithmIdentifier и значение");
        assertEquals(1, algId.length, "параметры AlgorithmIdentifier должны быть опущены");
        assertEquals(
                GostOids.DIGEST_512,
                DerCodec.parseOid(algId[0], 0),
                "OID должен быть id-tc26-gost3411-12-512, а не OID HMAC");
        assertEquals(
                GostOids.STREEBOG_512_HASH_LEN,
                DerCodec.parseOctetString(digestInfo[1], 0).length,
                "MAC должен быть 64 байта");
        assertEquals(
                GostOids.PBKDF2_SALT_LEN,
                DerCodec.parseOctetString(macSeq[1], 0).length,
                "соль должна сохраняться как передана");
    }

    @Test
    @DisplayName("Соль 32 байта (рекомендация RFC 9548 §8): compute -> verify проходит")
    void testRoundtripSalt32() {
        byte[] salt = new byte[GostOids.PBKDF2_SALT_LEN];
        CryptoRandom.INSTANCE.nextBytes(salt);
        byte[] password = pw("Пароль для PFX");

        MacData macData =
                parseMacData(GostPkcs12Mac.compute(authSafe(), password, ITERATIONS, salt));

        assertDoesNotThrow(
                () -> GostPkcs12Mac.verify(macData, password, authSafe()),
                "кириллический пароль в UTF-8 и соль 32 байта должны проходить");
    }

    @Test
    @DisplayName("compute: соль вне диапазона 8..32 -> IllegalArgumentException")
    void testComputeSaltOutOfRange() {
        for (int length : new int[] {0, 7, 33}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostPkcs12Mac.compute(authSafe(), pw("p"), ITERATIONS, new byte[length]),
                    "соль длиной " + length + " вне диапазона RFC");
        }
    }

    // ---------------------------------------------------------------
    // Устаревшие и нестандартные OID: понятный отказ, без PBKDF2
    // ---------------------------------------------------------------

    private static MacData macDataWith(String oid, int digestLength, int iterations) {
        return new MacData(new byte[16], iterations, oid, new byte[digestLength]);
    }

    @Test
    @DisplayName("Старые OID HMAC и OID Стрибог-256 -> отказ с подсказкой перевыпустить PFX")
    void testLegacyOidsRejectedWithHint() {
        for (String oid :
                new String[] {
                    GostOids.HMAC_STREEBOG_512, GostOids.HMAC_STREEBOG_256, GostOids.DIGEST_256
                }) {
            IllegalArgumentException ex =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    GostPkcs12Mac.verify(
                                            macDataWith(oid, 64, ITERATIONS), pw("p"), authSafe()),
                            "OID " + oid + " не допускается RFC 9548");
            assertTrue(
                    ex.getMessage().contains("re-issue the PFX") && ex.getMessage().contains(oid),
                    "сообщение должно называть OID и предлагать перевыпуск: " + ex.getMessage());
        }
    }

    @Test
    @DisplayName("Длина MAC не 64 байта -> отказ")
    void testWrongMacLengthRejected() {
        for (int length : new int[] {0, 32, 63, 65}) {
            IllegalArgumentException ex =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    GostPkcs12Mac.verify(
                                            macDataWith(GostOids.DIGEST_512, length, ITERATIONS),
                                            pw("p"),
                                            authSafe()),
                            "длина MAC " + length + " недопустима");
            assertTrue(ex.getMessage().contains("must be 64"), ex.getMessage());
        }
    }

    @Test
    @DisplayName("Проверка OID и длины выполняется напрямую, до затратного PBKDF2")
    void testStructureCheckIsStandalone() {
        assertDoesNotThrow(
                () ->
                        GostPkcs12Mac.requireStandardMac(
                                macDataWith(GostOids.DIGEST_512, 64, ITERATIONS)),
                "корректная структура должна проходить без вычислений");
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostPkcs12Mac.requireStandardMac(
                                macDataWith(GostOids.HMAC_STREEBOG_512, 64, ITERATIONS)),
                "OID HMAC в MacData должен отвергаться без вычислений");
    }

    @Test
    @DisplayName(
            "Некорректный OID при максимальном числе итераций отвергается без выполнения PBKDF2")
    void testRejectionHappensBeforePbkdf2() {
        // При выполнении PBKDF2 с MAX_ITERATIONS тест не уложился бы в срок на порядки:
        // быстрый отказ доказывает, что структура проверяется до вывода ключа
        MacData nonstandardMacData =
                macDataWith(GostOids.HMAC_STREEBOG_512, 64, Pbkdf2Streebog.MAX_ITERATIONS);
        assertTimeoutPreemptively(
                Duration.ofSeconds(5),
                () ->
                        assertThrows(
                                IllegalArgumentException.class,
                                () ->
                                        GostPkcs12Mac.verify(
                                                nonstandardMacData, pw("p"), authSafe())),
                "отказ должен наступить до PBKDF2");
    }
}
