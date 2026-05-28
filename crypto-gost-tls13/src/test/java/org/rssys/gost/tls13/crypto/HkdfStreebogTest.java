package org.rssys.gost.tls13.crypto;
import org.rssys.gost.tls13.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

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
@DisplayName("HKDF-Streebog: extract, expand, expand-label, derive-secret")
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
    // HKDF-Extract: null/пустая соль → hashLen нулевых байт
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("extract: null salt → детерминированный вывод")
    void testextractNullSaltProducesConsistentOutput() {
        byte[] ikm = "test input key material".getBytes(StandardCharsets.US_ASCII);
        byte[] prk1 = HkdfStreebog.extract(null, ikm, 32);
        byte[] prk2 = HkdfStreebog.extract(null, ikm, 32);
        assertArrayEquals(prk1, prk2);
        assertEquals(32, prk1.length);
    }

    @Test
    @DisplayName("extract: пустая соль равна null соли")
    void testextractEmptySaltEqualsNullSalt() {
        byte[] ikm = "test ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] prkNull = HkdfStreebog.extract(null, ikm, 32);
        byte[] prkEmpty = HkdfStreebog.extract(new byte[0], ikm, 32);
        assertArrayEquals(prkNull, prkEmpty);
    }

    @Test
    @DisplayName("extract: null salt, hashLen=64")
    void testextractNullSalt512() {
        byte[] ikm = "test input key material for 512".getBytes(StandardCharsets.US_ASCII);
        byte[] prk = HkdfStreebog.extract(null, ikm, 64);
        assertEquals(64, prk.length);
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

    @Test
    @DisplayName("extract: разные соли → разные PRK")
    void testextractDifferentSaltGivesDifferentPrk() {
        byte[] ikm = "same ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] prk1 = HkdfStreebog.extract("salt1".getBytes(StandardCharsets.US_ASCII), ikm, 32);
        byte[] prk2 = HkdfStreebog.extract("salt2".getBytes(StandardCharsets.US_ASCII), ikm, 32);
        assertFalse(Arrays.equals(prk1, prk2));
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand: тесты с известными ответами
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: нулевая длина → пустой массив")
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
        byte[] expected = hmac256(prk, new byte[]{1});
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

        byte[] t1 = hmac256(prk, concat(info, new byte[]{1}));
        byte[] t2 = hmac256(prk, concat(t1, concat(info, new byte[]{2})));

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

        byte[] t1 = hmac512(prk, concat(info, new byte[]{1}));
        byte[] t2 = hmac512(prk, concat(t1, concat(info, new byte[]{2})));

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
        byte[] t1 = hmac256(prk, new byte[]{1});
        byte[] expected = Arrays.copyOf(t1, 16);
        assertArrayEquals(expected, result);
    }

    @Test
    @DisplayName("expand: детерминированность")
    void testexpandDeterministic() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0x42);
        byte[] info = "deterministic".getBytes(StandardCharsets.US_ASCII);
        byte[] r1 = HkdfStreebog.expand(prk, info, 48, 32);
        byte[] r2 = HkdfStreebog.expand(prk, info, 48, 32);
        assertArrayEquals(r1, r2);
    }

    @Test
    @DisplayName("expand: разные PRK → разные выводы")
    void testexpandDifferentPrkGivesDifferentOutput() {
        byte[] prk1 = new byte[32];
        Arrays.fill(prk1, (byte) 0x01);
        byte[] prk2 = new byte[32];
        Arrays.fill(prk2, (byte) 0x02);
        byte[] info = "diff".getBytes(StandardCharsets.US_ASCII);
        byte[] r1 = HkdfStreebog.expand(prk1, info, 32, 32);
        byte[] r2 = HkdfStreebog.expand(prk2, info, 32, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    @Test
    @DisplayName("expand: разный info → разные выводы")
    void testexpandDifferentInfoGivesDifferentOutput() {
        byte[] prk = new byte[32];
        Arrays.fill(prk, (byte) 0x55);
        byte[] r1 = HkdfStreebog.expand(prk, "info1".getBytes(StandardCharsets.US_ASCII), 32, 32);
        byte[] r2 = HkdfStreebog.expand(prk, "info2".getBytes(StandardCharsets.US_ASCII), 32, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    // -----------------------------------------------------------------------
    // Extract-затем-Expand: сквозной тест
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("extract-then-expand roundtrip, hashLen=32")
    void testextractThenExpandRoundtrip256() {
        byte[] ikm = "roundtrip test ikm".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "roundtrip salt".getBytes(StandardCharsets.US_ASCII);
        byte[] info = "roundtrip info".getBytes(StandardCharsets.US_ASCII);

        byte[] prk = HkdfStreebog.extract(salt, ikm, 32);
        assertEquals(32, prk.length);

        byte[] okm = HkdfStreebog.expand(prk, info, 48, 32);
        assertEquals(48, okm.length);

        // детерминированность
        byte[] prk2 = HkdfStreebog.extract(salt, ikm, 32);
        byte[] okm2 = HkdfStreebog.expand(prk2, info, 48, 32);
        assertArrayEquals(okm, okm2);
    }

    @Test
    @DisplayName("extract-then-expand roundtrip, hashLen=64")
    void testextractThenExpandRoundtrip512() {
        byte[] ikm = "roundtrip 512 ikm with more data for 512-bit hash"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "roundtrip salt 512".getBytes(StandardCharsets.US_ASCII);
        byte[] info = "roundtrip info 512".getBytes(StandardCharsets.US_ASCII);

        byte[] prk = HkdfStreebog.extract(salt, ikm, 64);
        assertEquals(64, prk.length);

        byte[] okm = HkdfStreebog.expand(prk, info, 96, 64);
        assertEquals(96, okm.length);

        byte[] prk2 = HkdfStreebog.extract(salt, ikm, 64);
        byte[] okm2 = HkdfStreebog.expand(prk2, info, 96, 64);
        assertArrayEquals(okm, okm2);
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand-Label (RFC 8446 §7.1)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expandLabel: базовая работа")
    void testexpandLabelBasic() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xAA);
        byte[] result = HkdfStreebog.expandLabel(secret, "test label", new byte[0], 32, 32);
        assertEquals(32, result.length);
    }

    /**
     * Проверка кодирования HkdfLabel:
     * длина(2) + длина_метки(1) + "tls13 label" + длина_контекста(1) + контекст
     */
    @Test
    @DisplayName("expandLabel: структура HkdfLabel корректна")
    void testexpandLabelStructure() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xBB);
        byte[] ctx = "context".getBytes(StandardCharsets.US_ASCII);
        int length = 16;

        byte[] result = HkdfStreebog.expandLabel(secret, "label", ctx, length, 32);

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

        byte[] expected = HkdfStreebog.expand(secret, hkdfLabel, length, 32);
        assertArrayEquals(expected, result);
    }

    @Test
    @DisplayName("expandLabel: разные метки → разные выводы")
    void testexpandLabelDifferentLabelsProduceDifferentOutput() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xCC);
        byte[] ctx = new byte[0];

        byte[] r1 = HkdfStreebog.expandLabel(secret, "first label", ctx, 32, 32);
        byte[] r2 = HkdfStreebog.expandLabel(secret, "second label", ctx, 32, 32);
        assertFalse(Arrays.equals(r1, r2));
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

    @Test
    @DisplayName("expandLabel: hashLen=64")
    void testexpandLabel512() {
        byte[] secret = new byte[64];
        Arrays.fill(secret, (byte) 0xEE);
        byte[] result = HkdfStreebog.expandLabel(secret, "label512", new byte[0], 64, 64);
        assertEquals(64, result.length);
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

    @Test
    @DisplayName("deriveSecret: разные метки → разные выводы")
    void testderiveSecretDifferentLabels() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0x01);
        byte[] transcript = new byte[32];

        byte[] cHsTraffic = HkdfStreebog.deriveSecret(
                secret, "c hs traffic", transcript, 32);
        byte[] sHsTraffic = HkdfStreebog.deriveSecret(
                secret, "s hs traffic", transcript, 32);
        assertFalse(Arrays.equals(cHsTraffic, sHsTraffic),
                "Разные метки deriveSecret должны давать разные выводы");
    }

    @Test
    @DisplayName("deriveSecret: детерминированность")
    void testderiveSecretDeterministic() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0x02);
        byte[] transcript = "transcript".getBytes(StandardCharsets.US_ASCII);

        byte[] d1 = HkdfStreebog.deriveSecret(secret, "test derive", transcript, 32);
        byte[] d2 = HkdfStreebog.deriveSecret(secret, "test derive", transcript, 32);
        assertArrayEquals(d1, d2);
    }

    @Test
    @DisplayName("deriveSecret: разный transcript → разные выводы")
    void testderiveSecretDifferentTranscript() {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0x03);

        byte[] d1 = HkdfStreebog.deriveSecret(secret, "label",
                "transcript A".getBytes(StandardCharsets.US_ASCII), 32);
        byte[] d2 = HkdfStreebog.deriveSecret(secret, "label",
                "transcript B".getBytes(StandardCharsets.US_ASCII), 32);
        assertFalse(Arrays.equals(d1, d2));
    }

    // -----------------------------------------------------------------------
    // Ошибочные ситуации
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("extract: null IKM → исключение")
    void testextractNullIkmThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.extract(new byte[32], null, 32));
    }

    @Test
    @DisplayName("extract: неверный hashLen → исключение")
    void testextractInvalidHashLenThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.extract(new byte[16], new byte[16], 16));
    }

    @Test
    @DisplayName("expand: null PRK → исключение")
    void testexpandNullPrkThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expand(null, new byte[0], 32, 32));
    }

    @Test
    @DisplayName("expand: неверный hashLen → исключение")
    void testexpandInvalidHashLenThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[16], new byte[0], 32, 16));
    }

    @Test
    @DisplayName("expand: отрицательная длина → исключение")
    void testexpandNegativeLengthThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[32], new byte[0], -1, 32));
    }

    @Test
    @DisplayName("expand: длина > 255×hashLen → исключение")
    void testexpandTooLargeOutputThrows() {
        // 257 > 255 (макс. итераций по RFC 5869 §2.3), поэтому исключение
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expand(new byte[32], new byte[0], 8193, 32));
    }

    @Test
    @DisplayName("expandLabel: null secret → исключение")
    void testexpandLabelNullSecretThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expandLabel(null, "label", new byte[0], 32, 32));
    }

    @Test
    @DisplayName("expandLabel: null label → исключение")
    void testexpandLabelNullLabelThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> HkdfStreebog.expandLabel(new byte[32], (String) null, new byte[0], 32, 32));
    }
}
