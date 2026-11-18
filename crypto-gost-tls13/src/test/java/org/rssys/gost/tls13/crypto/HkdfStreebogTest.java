package org.rssys.gost.tls13.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.tls13.*;

/**
 * Тесты HKDF-Streebog (RFC 5869 + RFC 8446 §7.1).
 *
 * Проверяется:
 *   — HKDF-Extract против ручного HMAC-Streebog
 *   — HKDF-Expand против ручного HMAC с итеративной конструкцией
 *   — HKDF-Expand-Label с правильной кодировкой HkdfLabel
 *   — Derive-Secret
 *   — граничные случаи и исключения
 */
@DisplayName("HKDF-Streebog: извлечение, расширение, метка, порождение секрета")
class HkdfStreebogTest {

    /** Вычисляет HMAC-Streebog-256 напрямую для верификации */
    private static byte[] hmac256(byte[] key, byte[] msg) {
        Hmac mac = new Hmac(new Streebog256());
        mac.init(key);
        mac.update(msg, 0, msg.length);
        byte[] result = new byte[32];
        mac.doFinal(result, 0);
        mac.clear();
        return result;
    }

    /** Вычисляет HMAC-Streebog-512 напрямую для верификации */
    private static byte[] hmac512(byte[] key, byte[] msg) {
        Hmac mac = new Hmac(new Streebog512());
        mac.init(key);
        mac.update(msg, 0, msg.length);
        byte[] result = new byte[64];
        mac.doFinal(result, 0);
        mac.clear();
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // -----------------------------------------------------------------------
    // HKDF-Extract: null/пустая соль -> hashLen нулевых байт
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("extract: пустая соль равна null соли")
    void testextractEmptySaltEqualsNullSalt() {
        byte[] ikm = "test ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] prkNull = HkdfStreebog.extract(null, ikm, 32);
        byte[] prkEmpty = HkdfStreebog.extract(new byte[0], ikm, 32);
        assertArrayEquals(prkNull, prkEmpty);
    }

    @Test
    @DisplayName("extract: совпадает с ручным HMAC-Streebog-256")
    void testextractEqualsManualHmac256() {
        byte[] ikm = "verify extract".getBytes(StandardCharsets.US_ASCII);
        byte[] zeroSalt = new byte[32];
        byte[] expected = hmac256(zeroSalt, ikm);
        byte[] actual = HkdfStreebog.extract(null, ikm, 32);
        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("extract: совпадает с ручным HMAC-Streebog-512")
    void testextractEqualsManualHmac512() {
        byte[] ikm = "verify extract 512".getBytes(StandardCharsets.US_ASCII);
        byte[] zeroSalt = new byte[64];
        byte[] expected = hmac512(zeroSalt, ikm);
        byte[] actual = HkdfStreebog.extract(null, ikm, 64);
        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("extract: с явной солью = HMAC-Streebog-256(salt, IKM)")
    void testextractWithExplicitSalt() {
        byte[] ikm = "ikm data".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "explicit-salt".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hmac256(salt, ikm);
        byte[] actual = HkdfStreebog.extract(salt, ikm, 32);
        assertArrayEquals(expected, actual);
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand: тесты с известными ответами
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: нулевая длина -> пустой массив")
    void testexpandZeroLength() {
        byte[] prk = new byte[32];
        byte[] result = HkdfStreebog.expand(prk, new byte[0], 0, 32);
        assertEquals(0, result.length);
    }

    /**
     * expand с info=пусто, length=hashLen.
     * T(1) = HMAC-Streebog256(PRK, 0x01)
     * OKM = T(1)
     */
    @Test
    @DisplayName("expand: одна итерация, hashLen=32")
    void testexpandSingleIteration256() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0xAB);
        byte[] expected = hmac256(prk, new byte[] {1});
        byte[] actual = HkdfStreebog.expand(prk, new byte[0], 32, 32);
        assertArrayEquals(expected, actual);
    }

    /**
     * expand с info, length=2×hashLen.
     * T(1) = HMAC(PRK, info || 0x01)
     * T(2) = HMAC(PRK, T(1) || info || 0x02)
     * OKM = T(1) || T(2)
     */
    @Test
    @DisplayName("expand: две итерации, hashLen=32")
    void testexpandTwoIterations256() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0xCD);
        byte[] info = "info".getBytes(StandardCharsets.US_ASCII);

        byte[] t1 = hmac256(prk, concat(info, new byte[] {1}));
        byte[] t2 = hmac256(prk, concat(t1, concat(info, new byte[] {2})));

        byte[] expected = new byte[64];
        System.arraycopy(t1, 0, expected, 0, 32);
        System.arraycopy(t2, 0, expected, 32, 32);

        byte[] actual = HkdfStreebog.expand(prk, info, 64, 32);
        assertArrayEquals(expected, actual);
    }

    /**
     * expand с info, length=2×hashLen (512-битная версия).
     */
    @Test
    @DisplayName("expand: две итерации, hashLen=64")
    void testexpandTwoIterations512() {
        byte[] prk = new byte[64];
        Arrays.fill(prk, (byte) 0xEF);
        byte[] info = "info-512".getBytes(StandardCharsets.US_ASCII);

        byte[] t1 = hmac512(prk, concat(info, new byte[] {1}));
        byte[] t2 = hmac512(prk, concat(t1, concat(info, new byte[] {2})));

        byte[] expected = new byte[128];
        System.arraycopy(t1, 0, expected, 0, 64);
        System.arraycopy(t2, 0, expected, 64, 64);

        byte[] actual = HkdfStreebog.expand(prk, info, 128, 64);
        assertArrayEquals(expected, actual);
    }

    /**
     * Первые 16 байт OKM должны совпадать с первыми 16 байтами T(1).
     */
    @Test
    @DisplayName("expand: вывод короче hashLen — первые байты совпадают с T(1)")
    void testexpandOutputShorterThanHashLen() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0x11);
        byte[] result = HkdfStreebog.expand(prk, new byte[0], 16, 32);
        assertEquals(16, result.length);
        byte[] t1 = hmac256(prk, new byte[] {1});
        byte[] expected = Arrays.copyOf(t1, 16);
        assertArrayEquals(expected, result);
    }

    // -----------------------------------------------------------------------
    // Extract-затем-Expand: сквозной тест
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // HKDF-Expand-Label (RFC 8446 §7.1)
    // -----------------------------------------------------------------------

    /**
     * Проверка кодирования HkdfLabel:
     * длина(2) + длина_метки(1) + "tls13 label" + длина_контекста(1) + контекст
     */
    @ParameterizedTest(name = "hashLen={0}")
    @ValueSource(ints = {32, 64})
    @DisplayName("expandLabel: структура HkdfLabel корректна")
    void testexpandLabelStructure(int hashLen) {
        byte[] secret = new byte[hashLen];
        Arrays.fill(secret, (byte) 0xBB);
        byte[] ctx = "context".getBytes(StandardCharsets.US_ASCII);
        int length = 16;

        byte[] result = HkdfStreebog.expandLabel(secret, "label", ctx, length, hashLen);

        // ожидаемый HkdfLabel: 0x0010 + 0x0B + "tls13 label" + 0x07 + "context"
        // "tls13 label" = 11 байт
        byte[] expectedLabel = "tls13 label".getBytes(StandardCharsets.US_ASCII);
        assertEquals(11, expectedLabel.length);

        byte[] hkdfLabel = new byte[2 + 1 + 11 + 1 + 7];
        hkdfLabel[0] = 0x00;
        hkdfLabel[1] = 0x10;
        hkdfLabel[2] = 0x0B;
        System.arraycopy(expectedLabel, 0, hkdfLabel, 3, 11);
        hkdfLabel[14] = 0x07;
        System.arraycopy(ctx, 0, hkdfLabel, 15, 7);

        byte[] expected = HkdfStreebog.expand(secret, hkdfLabel, length, hashLen);
        assertArrayEquals(expected, result);
    }

    @Test
    @DisplayName("expandLabel: null context = пустой context")
    void testexpandLabelNullContext() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xDD);
        byte[] withNull = HkdfStreebog.expandLabel(secret, "test", null, 32, 32);
        byte[] withEmpty = HkdfStreebog.expandLabel(secret, "test", new byte[0], 32, 32);
        assertArrayEquals(withNull, withEmpty);
    }

    // -----------------------------------------------------------------------
    // Derive-Secret (RFC 8446 §7.1)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("deriveSecret: базовая работа, совпадает с expandLabel")
    void testderiveSecretBasic() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xFF);
        byte[] transcript = "transcript data".getBytes(StandardCharsets.US_ASCII);

        byte[] derived = HkdfStreebog.deriveSecret(secret, "derived", transcript, 32);
        assertEquals(32, derived.length);

        // Derive-Secret должен равняться expandLabel с transcript в качестве контекста
        byte[] expected = HkdfStreebog.expandLabel(secret, "derived", transcript, 32, 32);
        assertArrayEquals(expected, derived);
    }

    // -----------------------------------------------------------------------
    // Ошибочные ситуации
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("extract: null IKM -> исключение")
    void testextractNullIkmThrows() {
        assertThrows(
                IllegalArgumentException.class, () -> HkdfStreebog.extract(new byte[32], null, 32));
    }

    @Test
    @DisplayName("extract: неверный hashLen -> исключение")
    void testextractInvalidHashLenThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.extract(new byte[16], new byte[16], 16));
    }

    @Test
    @DisplayName("expand: null PRK -> исключение")
    void testexpandNullPrkThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expand(null, new byte[0], 32, 32));
    }

    @Test
    @DisplayName("expand: неверный hashLen -> исключение")
    void testexpandInvalidHashLenThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[16], new byte[0], 32, 16));
    }

    @Test
    @DisplayName("expand: отрицательная длина -> исключение")
    void testexpandNegativeLengthThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[32], new byte[0], -1, 32));
    }

    @Test
    @DisplayName("expand: длина > 255×hashLen -> исключение")
    void testexpandTooLargeOutputThrows() {
        // 257 > 255 (макс. итераций по RFC 5869 §2.3), поэтому исключение
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[32], new byte[0], 8193, 32));
    }

    @Test
    @DisplayName("expandLabel: null secret -> исключение")
    void testexpandLabelNullSecretThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expandLabel(null, "label", new byte[0], 32, 32));
    }

    @Test
    @DisplayName("expandLabel: null label -> исключение")
    void testexpandLabelNullLabelThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> HkdfStreebog.expandLabel(new byte[32], (String) null, new byte[0], 32, 32));
    }
}
