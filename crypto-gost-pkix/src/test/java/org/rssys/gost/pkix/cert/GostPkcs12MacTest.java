package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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

    @Test
    @DisplayName("Roundtrip Streebog-256: compute с hlen=32 -> verify")
    void testRoundtrip256() {
        byte[] authSafe = authSafe();
        byte[] password = pw("correct-password");
        byte[] salt = randomSalt();

        byte[] macDataDer =
                GostPkcs12Mac.compute(
                        authSafe,
                        password,
                        ITERATIONS,
                        salt,
                        org.rssys.gost.pkix.GostOids.STREEBOG_256_HASH_LEN);
        MacData macData = parseMacData(macDataDer);

        assertDoesNotThrow(
                () -> GostPkcs12Mac.verify(macData, password, authSafe),
                "Roundtrip Streebog-256: verify должен пройти");
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
}
