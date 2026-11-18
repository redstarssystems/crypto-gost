package org.rssys.gost;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;

/**
 * Тесты HMAC-Streebog (HMAC с хеш-функцией ГОСТ Р 34.11-2012) и базовых
 * реализаций хеш-функции GOST3411-2012-256 и GOST3411-2012-512.
 *
 * Тест-векторы:
 *   - Дайджест: RFC 6986 §10 (официальные эталонные векторы стандарта)
 *   - HMAC:     RFC 7836 Appendix B (HMAC-GOSTR3411-2012)
 */
@DisplayName("HMAC-Стрибог и хэш-функция ГОСТ Р 34.11-2012: эталонные векторы и свойства")
class HMacTest {

    // =========================================================================
    // Вспомогательные методы
    // =========================================================================

    private static String toHex(byte[] bytes) {
        return TestHex.string(bytes);
    }

    private static byte[] fromHex(String hex) {
        return TestHex.bytes(hex);
    }

    private static byte[] digest(Digest d, byte[] msg) {
        d.reset();
        d.update(msg, 0, msg.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /** Стрибог с дайджестом {@code size} байт: 32 - Стрибог-256, 64 - Стрибог-512. */
    private static Digest streebog(int size) {
        return size == 32 ? new Streebog256() : new Streebog512();
    }

    private static boolean isAllZero(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] hmac(Hmac mac, byte[] key, byte[] msg) {
        mac.init(new SymmetricKey(key));
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // =========================================================================
    // Эталонные векторы RFC 6986 §10
    // =========================================================================

    /**
     * RFC 6986 печатает и сообщение, и дайджест как числа, у которых старший байт идёт первым, а
     * библиотека принимает и отдаёт байты младшим вперёд (так же, как BouncyCastle и OpenSSL).
     * Поэтому связь такая: {@code RFC_H = reverse(H(reverse(RFC_M)))}. Тест подаёт вход и сверяет
     * выход именно по записи стандарта, чтобы он проверял пример RFC, а не совпадение с другой
     * реализацией.
     */
    private static void assertRfcVector(Digest d, String rfcMessageHex, String rfcDigestHex) {
        byte[] message = reversed(fromHex(rfcMessageHex));
        byte[] result = digest(d, message);
        assertEquals(rfcDigestHex.length() / 2, result.length);
        assertEquals(rfcDigestHex, toHex(reversed(result)));
    }

    private static byte[] reversed(byte[] bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[bytes.length - 1 - i] = bytes[i];
        }
        return result;
    }

    // Сообщение M1 (RFC 6986 §10.1.1) — 63 байта, в записи RFC старшим байтом вперёд; в порядке
    // библиотеки это ASCII-строка «0123…012».
    private static final String RFC_M1 =
            "32313039383736353433323130393837"
                    + "36353433323130393837363534333231"
                    + "30393837363534333231303938373635"
                    + "343332313039383736353433323130";

    // Сообщение M2 (RFC 6986 §10.2.1) — 72 байта, в записи RFC старшим байтом вперёд; в порядке
    // библиотеки это текст «Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы
    // Игоревы» в кодировке CP1251.
    private static final String RFC_M2 =
            "fbe2e5f0eee3c820fbeafaebef20fffb"
                    + "f0e1e0f0f520e0ed20e8ece0ebe5f0f2"
                    + "f120fff0eeec20f120faf2fee5e2202c"
                    + "e8f6f3ede220e8e6eee1e8f0f2d1202c"
                    + "e8f0f2e5e220e5d1";

    /** RFC 6986 §10.1.1, пример 1 (M1), вывод 512 бит. */
    @Test
    @DisplayName("Стрибог-512: пример 1 из RFC 6986")
    void testDigest512_RFC6986_Example1() {
        assertRfcVector(
                new Streebog512(),
                RFC_M1,
                "486f64c1917879417fef082b3381a4e2"
                        + "11c324f074654c38823a7b76f830ad00"
                        + "fa1fbae42b1285c0352f227524bc9ab1"
                        + "6254288dd6863dccd5b9f54a1ad0541b");

        // То же значение в порядке байт библиотеки, для прямого сравнения с BC и OpenSSL.
        byte[] msg =
                "012345678901234567890123456789012345678901234567890123456789012"
                        .getBytes(StandardCharsets.US_ASCII);
        String expected =
                "1b54d01a4af5b9d5cc3d86d68d285462"
                        + "b19abc2475222f35c085122be4ba1ffa"
                        + "00ad30f8767b3a82384c6574f024c311"
                        + "e2a481332b08ef7f41797891c1646f48";
        assertEquals(expected, toHex(digest(new Streebog512(), msg)));
    }

    /** RFC 6986 §10.2.1, пример 2 (M2), вывод 512 бит. */
    @Test
    @DisplayName("Стрибог-512: пример 2 из RFC 6986")
    void testDigest512_RFC6986_Example2() {
        assertRfcVector(
                new Streebog512(),
                RFC_M2,
                "28fbc9bada033b1460642bdcddb90c3f"
                        + "b3e56c497ccd0f62b8a2ad4935e85f03"
                        + "7613966de4ee00531ae60f3b5a47f8da"
                        + "e06915d5f2f194996fcabf2622e6881e");
    }

    /** RFC 6986 §10.1.2, пример 1 (M1), вывод 256 бит. */
    @Test
    @DisplayName("Стрибог-256: пример 1 из RFC 6986")
    void testDigest256_RFC6986_Example1() {
        assertRfcVector(
                new Streebog256(),
                RFC_M1,
                "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d");

        // То же значение в порядке байт библиотеки, для прямого сравнения с BC и OpenSSL.
        byte[] msg =
                "012345678901234567890123456789012345678901234567890123456789012"
                        .getBytes(StandardCharsets.US_ASCII);
        String expected = "9d151eefd8590b89daa6ba6cb74af927" + "5dd051026bb149a452fd84e5e57b5500";
        assertEquals(expected, toHex(digest(new Streebog256(), msg)));
    }

    /** RFC 6986 §10.2.2, пример 2 (M2), вывод 256 бит. */
    @Test
    @DisplayName("Стрибог-256: пример 2 из RFC 6986")
    void testDigest256_RFC6986_Example2() {
        assertRfcVector(
                new Streebog256(),
                RFC_M2,
                "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d");
    }

    // =========================================================================
    // Дайджест: инкрементальное обновление == пакетное обновление
    // =========================================================================

    @Test
    @DisplayName("Стрибог-512: поэтапное обновление даёт тот же дайджест")
    void testDigest512_incrementalEquality() {
        byte[] msg =
                "012345678901234567890123456789012345678901234567890123456789012"
                        .getBytes(StandardCharsets.US_ASCII);

        Digest d = new Streebog512();
        byte[] bulk = digest(d, msg);

        d.reset();
        for (byte b : msg) {
            d.update(b);
        }
        byte[] incremental = new byte[64];
        d.doFinal(incremental, 0);

        assertArrayEquals(
                bulk,
                incremental,
                "Инкрементальное и пакетное обновление должны давать одинаковый дайджест");
    }

    @Test
    @DisplayName("Стрибог-256: поэтапное обновление даёт тот же дайджест")
    void testDigest256_incrementalEquality() {
        byte[] msg =
                fromHex(
                        "fbe2e5f0eee3c820fbeafaebef20fffb"
                                + "f0e1e0f0f520e0ed20e8ece0ebe5f0f2"
                                + "f120fff0eeec20f120faf2fee5e2202c"
                                + "e8f6f3ede220e8e6eee1e8f0f2d1202c"
                                + "e8f0f2e5e220e5d1");

        Digest d = new Streebog256();
        byte[] bulk = digest(d, msg);

        d.reset();
        for (byte b : msg) {
            d.update(b);
        }
        byte[] incremental = new byte[32];
        d.doFinal(incremental, 0);

        assertArrayEquals(
                bulk,
                incremental,
                "Инкрементальное и пакетное обновление должны давать одинаковый дайджест");
    }

    // =========================================================================
    // Дайджест: корректность сброса состояния
    // =========================================================================

    @Test
    @DisplayName("Стрибог-512: после reset() результат тот же")
    void testDigest512_resetProducesConsistentResults() {
        byte[] msg = "hello streebog".getBytes(StandardCharsets.US_ASCII);
        Digest d = new Streebog512();

        byte[] first = digest(d, msg);
        // doFinal внутри уже вызывает reset
        byte[] second = digest(d, msg);

        assertArrayEquals(
                first, second, "Два вызова после сброса должны возвращать одинаковый результат");
    }

    @Test
    @DisplayName("Стрибог-256: после reset() результат тот же")
    void testDigest256_resetProducesConsistentResults() {
        byte[] msg = "hello streebog 256".getBytes(StandardCharsets.US_ASCII);
        Digest d = new Streebog256();

        byte[] first = digest(d, msg);
        byte[] second = digest(d, msg);

        assertArrayEquals(
                first, second, "Два вызова после сброса должны возвращать одинаковый результат");
    }

    // =========================================================================
    // Дайджест: метаданные алгоритма
    // =========================================================================

    @Test
    @DisplayName("Стрибог: размер дайджеста, размер блока и имя алгоритма")
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

    @ParameterizedTest(name = "Стрибог с дайджестом {0} байт: пустое сообщение")
    @ValueSource(ints = {32, 64})
    void testDigest_emptyMessage(int digestSize) {
        // Хэш пустой строки определён правилами дополнения
        byte[] result = digest(streebog(digestSize), new byte[0]);
        assertEquals(digestSize, result.length);
        assertFalse(isAllZero(result), "Хэш пустого сообщения не должен состоять из одних нулей");
    }

    // =========================================================================
    // Hmac: метаданные алгоритма
    // =========================================================================

    @Test
    @DisplayName("Hmac: имя алгоритма и размер MAC")
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
    @DisplayName("HMAC-Стрибог-256: вектор RFC 7836, приложение B")
    void testHmac256_RFC7836_AppendixB() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        String expected = "a1aa5f7de402d7b3d323f2991c8d4534" + "013137010a83754fd0af6d7cd4922ed9";

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
    @DisplayName("HMAC-Стрибог-512: вектор RFC 7836, приложение B")
    void testHmac512_RFC7836_AppendixB() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        String expected =
                "a59bab22ecae19c65fbde6e5f4e9f5d8"
                        + "549d31f037f9df9b905500e171923a77"
                        + "3d5f1530f2ed7e964cb2eedc29e9ad2f"
                        + "3afe93b2814f79f5000ffc0366c251e6";

        Hmac mac = new Hmac(new Streebog512());
        byte[] result = hmac(mac, key, msg);
        assertEquals(64, result.length);
        assertEquals(expected, toHex(result));
    }

    // =========================================================================
    // Hmac: ключ длиннее блока хэшируется (RFC 2104 §2)
    // =========================================================================

    @Test
    @DisplayName("HMAC-Стрибог-256: ключ длиннее блока хэшируется")
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
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        assertFalse(allZero, "HMAC с длинным ключом должен давать ненулевой результат");
    }

    @Test
    @DisplayName("HMAC-Стрибог-512: ключ длиннее блока хэшируется")
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
    @DisplayName("HMAC-Стрибог-256: reset() позволяет переиспользовать объект")
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

        assertArrayEquals(
                result1,
                result2,
                "После reset() Hmac должен давать тот же результат без повторной инициализации");
    }

    @Test
    @DisplayName("HMAC-Стрибог-512: reset() позволяет переиспользовать объект")
    void testHmac512_resetAndReuse() {
        byte[] key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        Hmac mac = new Hmac(new Streebog512());
        byte[] result1 = hmac(mac, key, msg);

        mac.reset();
        mac.update(msg, 0, msg.length);
        byte[] result2 = new byte[64];
        mac.doFinal(result2, 0);

        assertArrayEquals(
                result1,
                result2,
                "После reset() Hmac должен давать тот же результат без повторной инициализации");
    }

    // =========================================================================
    // Hmac: разные ключи дают разные результаты
    // =========================================================================

    @Test
    @DisplayName("HMAC-Стрибог-256: разные ключи дают разные MAC")
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
    @DisplayName("HMAC-Стрибог-256: разные сообщения дают разные MAC")
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
    @DisplayName("HMAC-Стрибог-256: поэтапное обновление даёт тот же MAC")
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

        assertArrayEquals(
                bulk, incr, "Инкрементальное и пакетное обновление должны давать одинаковый HMAC");
    }

    @Test
    @DisplayName("HMAC-Стрибог-512: поэтапное обновление даёт тот же MAC")
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

        assertArrayEquals(
                bulk, incr, "Инкрементальное и пакетное обновление должны давать одинаковый HMAC");
    }

    // =========================================================================
    // Hmac: проверка целостности — изменение сообщения меняет MAC
    // =========================================================================

    @Test
    @DisplayName("HMAC-Стрибог-256: изменение сообщения меняет MAC")
    void testHmac256_modifiedMessageChangesMac() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x55);
        byte[] msg = "authentic message".getBytes(StandardCharsets.US_ASCII);
        byte[] modified = "authentic messagX".getBytes(StandardCharsets.US_ASCII);

        Hmac mac = new Hmac(new Streebog256());
        byte[] authentic = hmac(mac, key, msg);
        byte[] changed = hmac(mac, key, modified);

        assertFalse(
                Arrays.equals(authentic, changed),
                "HMAC изменённого сообщения должен отличаться от исходного");
    }

    // =========================================================================
    // Hmac: пустое сообщение
    // =========================================================================

    @ParameterizedTest(name = "HMAC-Стрибог с MAC {0} байт: пустое сообщение")
    @ValueSource(ints = {32, 64})
    void testHmac_emptyMessage(int macSize) {
        byte[] key = new byte[macSize];
        Arrays.fill(key, (byte) 0x11);

        byte[] result = hmac(new Hmac(streebog(macSize)), key, new byte[0]);
        assertEquals(macSize, result.length);
        // Не должно бросать исключение; результат не должен быть нулевым
        assertFalse(isAllZero(result), "MAC пустого сообщения не должен состоять из одних нулей");
    }

    // =========================================================================
    // Hmac: init() бросает исключение при неверном типе параметра
    // =========================================================================

    @Test
    @DisplayName("Hmac: init() требует SymmetricKey")
    void testHmac_initRequiresSymmetricKey() {
        Hmac mac = new Hmac(new Streebog256());
        assertThrows(
                IllegalArgumentException.class,
                () -> mac.init(new ParametersWithIV(new SymmetricKey(new byte[32]), new byte[16])));
    }

    // =========================================================================
    // Hmac: пустой ключ (RFC 2104 §2 — ключ любой длины, пустой разрешён)
    // =========================================================================

    @ParameterizedTest(name = "HMAC-Стрибог с MAC {0} байт: пустой ключ (RFC 2104 §2)")
    @ValueSource(ints = {32, 64})
    void testHmac_emptyKey(int macSize) {
        Hmac mac = new Hmac(streebog(macSize));
        mac.init(new byte[0]); // не должно бросать исключение
        mac.update("test".getBytes(StandardCharsets.UTF_8), 0, 4);
        byte[] result = new byte[macSize];
        mac.doFinal(result, 0);
        assertFalse(isAllZero(result), "HMAC с пустым ключом не должен давать нулевой результат");
    }
}
