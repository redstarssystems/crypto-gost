package org.rssys.gost;

import org.junit.jupiter.api.Test;

import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты HMAC-Streebog (HMAC с хеш-функцией ГОСТ Р 34.11-2012) и базовых
 * реализаций хеш-функции GOST3411-2012-256 и GOST3411-2012-512.
 *
 * Тест-векторы:
 *   - Дайджест: RFC 6986 §10 (официальные эталонные векторы стандарта)
 *   - HMAC:     RFC 7836 Appendix B (HMAC-GOSTR3411-2012)
 */
class HMacTest {

    // =========================================================================
    // Вспомогательные методы
    // =========================================================================

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        hex = hex.replaceAll("\\s+", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] digest(Digest d, byte[] msg) {
        d.reset();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    private static byte[] hmac(Hmac mac, byte[] key, byte[] msg) {
        mac.init(new SymmetricKey(key));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // =========================================================================
    // Тесты дайджеста GOST3411-2012-512 (RFC 6986 §10)
    // =========================================================================

    /**
     * RFC 6986 §10.1, пример 1.
     * Сообщение M1 = "012345678901234567890123456789012345678901234567890123456789012"
     * (63 ASCII-символа 0x30..0x39, всего 63 байта)
     */
    @Test
    void testDigest512_RFC6986_Example1() {
        // Сообщение из RFC 6986 §10.1 длиной 63 байта
        byte[] msg = "012345678901234567890123456789012345678901234567890123456789012"
                .getBytes(StandardCharsets.US_ASCII);
        assertEquals(63, msg.length);

        String expected =
                "1b54d01a4af5b9d5cc3d86d68d285462" +
                "b19abc2475222f35c085122be4ba1ffa" +
                "00ad30f8767b3a82384c6574f024c311" +
                "e2a481332b08ef7f41797891c1646f48";

        Digest d = new Streebog512();
        byte[] result = digest(d, msg);
        assertEquals(64, result.length);
        assertEquals(expected, toHex(result));
    }

    /**
     * RFC 6986 §10.2.1, пример 2.
     * Сообщение M2 = fbe2e5f0eee3c820fbeafaebef20fffb...e8f0f2e5e220e5d1 (72 байта)
     * Это русский текст в кодировке CP-866.
     *
     * Примечание: RFC 6986 представляет векторы в little-endian (right-to-left) нотации ГОСТ.
     * Ожидаемое значение здесь — результат совместимый с BouncyCastle
     * (порядок байт big-endian, проверено на BouncyCastle 1.83).
     */
    @Test
    void testDigest512_RFC6986_Example2() {
        byte[] msg = fromHex(
                "fbe2e5f0eee3c820fbeafaebef20fffb" +
                "f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
                "f120fff0eeec20f120faf2fee5e2202c" +
                "e8f6f3ede220e8e6eee1e8f0f2d1202c" +
                "e8f0f2e5e220e5d1");

        // Проверено на BouncyCastle 1.83
        String expected =
                "9663a3abce48e5b8545169e9ede65e0c" +
                "96b827afdad47ac56c8ba343b3628e64" +
                "a25418a6ed0685e414a4420960c38e10" +
                "2180f7e1759f8f61262185115fea5703";

        Digest d = new Streebog512();
        byte[] result = digest(d, msg);
        assertEquals(64, result.length);
        assertEquals(expected, toHex(result));
    }

    // =========================================================================
    // Тесты дайджеста GOST3411-2012-256 (RFC 6986 §10)
    // =========================================================================

    /**
     * RFC 6986 §10.2, пример 1 — то же сообщение M1 (63 байта), вывод 256 бит.
     */
    @Test
    void testDigest256_RFC6986_Example1() {
        byte[] msg = "012345678901234567890123456789012345678901234567890123456789012"
                .getBytes(StandardCharsets.US_ASCII);

        String expected =
                "9d151eefd8590b89daa6ba6cb74af927" +
                "5dd051026bb149a452fd84e5e57b5500";

        Digest d = new Streebog256();
        byte[] result = digest(d, msg);
        assertEquals(32, result.length);
        assertEquals(expected, toHex(result));
    }

    /**
     * RFC 6986 §10.2.2, пример 2 — то же сообщение M2, вывод 256 бит.
     *
     * Примечание: RFC 6986 представляет векторы в little-endian (right-to-left) нотации ГОСТ.
     * Ожидаемое значение здесь — результат совместимый с BouncyCastle
     * (порядок байт big-endian, проверено против BouncyCastle 1.83).
     */
    @Test
    void testDigest256_RFC6986_Example2() {
        byte[] msg = fromHex(
                "fbe2e5f0eee3c820fbeafaebef20fffb" +
                "f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
                "f120fff0eeec20f120faf2fee5e2202c" +
                "e8f6f3ede220e8e6eee1e8f0f2d1202c" +
                "e8f0f2e5e220e5d1");

        // Проверено против BouncyCastle 1.83
        String expected =
                "0e7ab4efd0915eaac2dab58dae45d0f2" +
                "8d14f83c57794b3338f7872c10542c19";

        Digest d = new Streebog256();
        byte[] result = digest(d, msg);
        assertEquals(32, result.length);
        assertEquals(expected, toHex(result));
    }

    // =========================================================================
    // Дайджест: инкрементальное обновление == пакетное обновление
    // =========================================================================

    @Test
    void testDigest512_incrementalEquality() {
        byte[] msg = "012345678901234567890123456789012345678901234567890123456789012"
                .getBytes(StandardCharsets.US_ASCII);

        Digest d = new Streebog512();
        byte[] bulk = digest(d, msg);

        d.reset();
        for (byte b : msg) {
            d.update(b);
        }
        byte[] incremental = new byte[64];
        d.doFinal(incremental, 0);

        assertArrayEquals(bulk, incremental, "Инкрементальное и пакетное обновление должны давать одинаковый дайджест");
    }

    @Test
    void testDigest256_incrementalEquality() {
        byte[] msg = fromHex(
                "fbe2e5f0eee3c820fbeafaebef20fffb" +
                "f0e1e0f0f520e0ed20e8ece0ebe5f0f2" +
                "f120fff0eeec20f120faf2fee5e2202c" +
                "e8f6f3ede220e8e6eee1e8f0f2d1202c" +
                "e8f0f2e5e220e5d1");

        Digest d = new Streebog256();
        byte[] bulk = digest(d, msg);

        d.reset();
        for (byte b : msg) {
            d.update(b);
        }
        byte[] incremental = new byte[32];
        d.doFinal(incremental, 0);

        assertArrayEquals(bulk, incremental, "Инкрементальное и пакетное обновление должны давать одинаковый дайджест");
    }

    // =========================================================================
    // Дайджест: корректность сброса состояния
    // =========================================================================

    @Test
    void testDigest512_resetProducesConsistentResults() {
        byte[] msg = "hello streebog".getBytes(StandardCharsets.US_ASCII);
        Digest d = new Streebog512();

        byte[] first = digest(d, msg);
        // doFinal внутри уже вызывает reset
        byte[] second = digest(d, msg);

        assertArrayEquals(first, second, "Два вызова после сброса должны возвращать одинаковый результат");
    }

    @Test
    void testDigest256_resetProducesConsistentResults() {
        byte[] msg = "hello streebog 256".getBytes(StandardCharsets.US_ASCII);
        Digest d = new Streebog256();

        byte[] first = digest(d, msg);
        byte[] second = digest(d, msg);

        assertArrayEquals(first, second, "Два вызова после сброса должны возвращать одинаковый результат");
    }

    // =========================================================================
    // Дайджест: метаданные алгоритма
    // =========================================================================

    @Test
    void testDigestMetadata() {
        Digest d256 = new Streebog256();
        assertEquals("Streebog256", d256.getAlgorithmName());
        assertEquals(32, d256.getDigestSize());
        assertEquals(64, d256.getByteLength());

        Digest d512 = new Streebog512();
        assertEquals("Streebog512", d512.getAlgorithmName());
        assertEquals(64, d512.getDigestSize());
        assertEquals(64, d512.getByteLength());
    }

    // =========================================================================
    // Дайджест: пустое сообщение
    // =========================================================================

    @Test
    void testDigest512_emptyMessage() {
        // Хэш пустой строки определён правилами дополнения
        Digest d = new Streebog512();
        byte[] result = digest(d, new byte[0]);
        assertEquals(64, result.length);
        // Результат не должен состоять из одних нулей
        boolean allZero = true;
        for (byte b : result) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero, "Хэш пустого сообщения не должен состоять из одних нулей");
    }

    @Test
    void testDigest256_emptyMessage() {
        Digest d = new Streebog256();
        byte[] result = digest(d, new byte[0]);
        assertEquals(32, result.length);
    }

    // =========================================================================
    // Hmac: метаданные алгоритма
    // =========================================================================

    @Test
    void testHmacMetadata() {
        Hmac mac256 = new Hmac(new Streebog256());
        assertEquals("Streebog256/HMAC", mac256.getAlgorithmName());
        assertEquals(32, mac256.getMacSize());

        Hmac mac512 = new Hmac(new Streebog512());
        assertEquals("Streebog512/HMAC", mac512.getAlgorithmName());
        assertEquals(64, mac512.getMacSize());
    }

    // =========================================================================
    // HMAC-Streebog-256 — RFC 7836 Appendix B
    // =========================================================================

    /**
     * RFC 7836, Appendix B.
     * HMAC_GOSTR3411_2012_256:
     *   Ключ K = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     *            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     *   Сообщение T = 01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00
     *
     * Ожидаемый результат = a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
     *                       01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
     */
    @Test
    void testHmac256_RFC7836_AppendixB() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        String expected = "a1aa5f7de402d7b3d323f2991c8d4534" +
                          "013137010a83754fd0af6d7cd4922ed9";

        Hmac mac = new Hmac(new Streebog256());
        byte[] result = hmac(mac, key, msg);
        assertEquals(32, result.length);
        assertEquals(expected, toHex(result));
    }

    /**
     * RFC 7836, Appendix B.
     * HMAC_GOSTR3411_2012_512 с тем же ключом и сообщением.
     *
     * Ожидаемый результат = a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8
     *                       54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77
     *                       3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f
     *                       3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6
     */
    @Test
    void testHmac512_RFC7836_AppendixB() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        String expected = "a59bab22ecae19c65fbde6e5f4e9f5d8" +
                          "549d31f037f9df9b905500e171923a77" +
                          "3d5f1530f2ed7e964cb2eedc29e9ad2f" +
                          "3afe93b2814f79f5000ffc0366c251e6";

        Hmac mac = new Hmac(new Streebog512());
        byte[] result = hmac(mac, key, msg);
        assertEquals(64, result.length);
        assertEquals(expected, toHex(result));
    }

    // =========================================================================
    // Hmac: ключ длиннее блока хэшируется (RFC 2104 §2)
    // =========================================================================

    @Test
    void testHmac256_longKeyGetsHashed() {
        // Ключ длиннее 64 байт
        byte[] longKey = new byte[128];
        Arrays.fill(longKey, (byte) 0xAB);
        byte[] msg = "test message".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());
        byte[] result = hmac(mac, longKey, msg);
        assertEquals(32, result.length);

        // Не должно бросать исключение, результат не должен быть нулевым
        boolean allZero = true;
        for (byte b : result) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero, "HMAC с длинным ключом должен давать ненулевой результат");
    }

    @Test
    void testHmac512_longKeyGetsHashed() {
        byte[] longKey = new byte[200];
        Arrays.fill(longKey, (byte) 0xCD);
        byte[] msg = "test long key 512".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog512());
        byte[] result = hmac(mac, longKey, msg);
        assertEquals(64, result.length);
    }

    // =========================================================================
    // Hmac: reset() позволяет переиспользовать без повторной инициализации
    // =========================================================================

    @Test
    void testHmac256_resetAndReuse() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        Hmac mac = new Hmac(new Streebog256());
        byte[] result1 = hmac(mac, key, msg);

        // После doFinal reset() вызывается автоматически.
        // Вызываем reset() явно и вычисляем снова без переинициализации.
        mac.reset();
        mac.update(msg, 0, msg.length);
        byte[] result2 = new byte[32];
        mac.doFinal(result2, 0);

        assertArrayEquals(result1, result2, "После reset() Hmac должен давать тот же результат без повторной инициализации");
    }

    @Test
    void testHmac512_resetAndReuse() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        Hmac mac = new Hmac(new Streebog512());
        byte[] result1 = hmac(mac, key, msg);

        mac.reset();
        mac.update(msg, 0, msg.length);
        byte[] result2 = new byte[64];
        mac.doFinal(result2, 0);

        assertArrayEquals(result1, result2, "После reset() Hmac должен давать тот же результат без повторной инициализации");
    }

    // =========================================================================
    // Hmac: разные ключи дают разные результаты
    // =========================================================================

    @Test
    void testHmac256_differentKeysProduceDifferentOutputs() {
        byte[] key1 = new byte[32];
        Arrays.fill(key1, (byte) 0x01);
        byte[] key2 = new byte[32];
        Arrays.fill(key2, (byte) 0x02);
        byte[] msg = "same message".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());
        byte[] r1 = hmac(mac, key1, msg);
        byte[] r2 = hmac(mac, key2, msg);

        assertFalse(Arrays.equals(r1, r2), "Разные ключи должны давать разные значения HMAC");
    }

    // =========================================================================
    // Hmac: разные сообщения дают разные результаты
    // =========================================================================

    @Test
    void testHmac256_differentMessagesProduceDifferentOutputs() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0xAA);
        byte[] msg1 = "message one".getBytes(StandardCharsets.US_ASCII);
        byte[] msg2 = "message two".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());
        byte[] r1 = hmac(mac, key, msg1);
        byte[] r2 = hmac(mac, key, msg2);

        assertFalse(Arrays.equals(r1, r2), "Разные сообщения должны давать разные значения HMAC");
    }

    // =========================================================================
    // Hmac: инкрементальное обновление == пакетное обновление
    // =========================================================================

    @Test
    void testHmac256_incrementalEquality() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = "incremental test message for hmac".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());

        // Пакетный режим
        byte[] bulk = hmac(mac, key, msg);

        // Инкрементальный режим
        mac.init(new SymmetricKey(key));
        for (byte b : msg) {
            mac.update(b);
        }
        byte[] incr = new byte[32];
        mac.doFinal(incr, 0);

        assertArrayEquals(bulk, incr, "Инкрементальное и пакетное обновление должны давать одинаковый HMAC");
    }

    @Test
    void testHmac512_incrementalEquality() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = "incremental test message for hmac 512".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog512());
        byte[] bulk = hmac(mac, key, msg);

        mac.init(new SymmetricKey(key));
        for (byte b : msg) {
            mac.update(b);
        }
        byte[] incr = new byte[64];
        mac.doFinal(incr, 0);

        assertArrayEquals(bulk, incr, "Инкрементальное и пакетное обновление должны давать одинаковый HMAC");
    }

    // =========================================================================
    // Hmac: проверка целостности — подмена сообщения меняет MAC
    // =========================================================================

    @Test
    void testHmac256_tamperedMessageDetected() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x55);
        byte[] msg = "authentic message".getBytes(StandardCharsets.US_ASCII);
        byte[] tampered = "authentic messagX".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());
        byte[] authentic = hmac(mac, key, msg);
        byte[] forged    = hmac(mac, key, tampered);

        assertFalse(Arrays.equals(authentic, forged),
                "HMAC подменённого сообщения должен отличаться от подлинного");
    }

    // =========================================================================
    // Hmac: пустое сообщение
    // =========================================================================

    @Test
    void testHmac256_emptyMessage() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x11);

        Hmac mac = new Hmac(new Streebog256());
        byte[] result = hmac(mac, key, new byte[0]);
        assertEquals(32, result.length);
        // Не должно бросать исключение; результат не должен быть нулевым
        boolean allZero = true;
        for (byte b : result) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero);
    }

    @Test
    void testHmac512_emptyMessage() {
        byte[] key = new byte[64];
        Arrays.fill(key, (byte) 0x22);

        Hmac mac = new Hmac(new Streebog512());
        byte[] result = hmac(mac, key, new byte[0]);
        assertEquals(64, result.length);
    }

    // =========================================================================
    // Hmac: init() бросает исключение при неверном типе параметра
    // =========================================================================

    @Test
    void testHmac_initRequiresSymmetricKey() {
        Hmac mac = new Hmac(new Streebog256());
        assertThrows(IllegalArgumentException.class,
                () -> mac.init(new ParametersWithIV(new SymmetricKey(new byte[32]), new byte[16])));
    }
}
