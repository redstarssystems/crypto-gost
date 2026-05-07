package org.rssys.gost.tls13.crypto;
import org.rssys.gost.tls13.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты KDF_GOST_R_3411_2012_256 (RFC 7836 раздел 4).
 */
@DisplayName("KDF_GOST_R_3411_2012_256 — RFC 7836")
class KdfGostR3411_2012_256Test {

    // -----------------------------------------------------------------------
    // Базовые тесты
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: нулевая длина возвращает пустой массив")
    void testExpandZeroLength() {
        byte[] key = new byte[32];
        byte[] label = new byte[0];
        byte[] seed = new byte[0];
        byte[] result = KdfGostR3411_2012_256.expand(key, label, seed, 0);
        assertEquals(0, result.length);
    }

    @Test
    @DisplayName("expand: детерминизм — одинаковые входы дают одинаковый выход")
    void testDeterminism() {
        byte[] key = new byte[32];
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = new byte[8];
        Arrays.fill(seed, (byte) 0x01);

        byte[] r1 = KdfGostR3411_2012_256.expand(key, label, seed, 32);
        byte[] r2 = KdfGostR3411_2012_256.expand(key, label, seed, 32);
        assertArrayEquals(r1, r2);
    }

    @Test
    @DisplayName("expand: разные ключи дают разный выход")
    void testDifferentKeys() {
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        key2[0] = 1;
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = new byte[8];

        byte[] r1 = KdfGostR3411_2012_256.expand(key1, label, seed, 32);
        byte[] r2 = KdfGostR3411_2012_256.expand(key2, label, seed, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    @Test
    @DisplayName("expand: разные label дают разный выход")
    void testDifferentLabels() {
        byte[] key = new byte[32];
        byte[] seed = new byte[8];

        byte[] r1 = KdfGostR3411_2012_256.expand(key, "a".getBytes(StandardCharsets.US_ASCII), seed, 32);
        byte[] r2 = KdfGostR3411_2012_256.expand(key, "b".getBytes(StandardCharsets.US_ASCII), seed, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    @Test
    @DisplayName("expand: разные seed дают разный выход")
    void testDifferentSeeds() {
        byte[] key = new byte[32];
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed1 = new byte[8];
        byte[] seed2 = new byte[8];
        seed2[0] = 1;

        byte[] r1 = KdfGostR3411_2012_256.expand(key, label, seed1, 32);
        byte[] r2 = KdfGostR3411_2012_256.expand(key, label, seed2, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    // -----------------------------------------------------------------------
    // Длина выходных данных
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: 32 байта — ровно один блок HMAC")
    void testOutput32Bytes() {
        byte[] key = new byte[32];
        byte[] label = new byte[0];
        byte[] seed = new byte[0];
        byte[] result = KdfGostR3411_2012_256.expand(key, label, seed, 32);
        assertEquals(32, result.length);
    }

    @Test
    @DisplayName("expand: 64 байта — два блока")
    void testOutput64Bytes() {
        byte[] key = new byte[32];
        byte[] label = new byte[0];
        byte[] seed = new byte[0];
        byte[] result = KdfGostR3411_2012_256.expand(key, label, seed, 64);
        assertEquals(64, result.length);
        // Два блока не равны (разные счётчики 0x01 и 0x02)
        byte[] block1 = Arrays.copyOfRange(result, 0, 32);
        byte[] block2 = Arrays.copyOfRange(result, 32, 64);
        assertFalse(Arrays.equals(block1, block2));
    }

    @Test
    @DisplayName("expand: 33 байта — два блока с усечением")
    void testOutput33Bytes() {
        byte[] key = new byte[32];
        byte[] label = new byte[0];
        byte[] seed = new byte[0];
        byte[] result = KdfGostR3411_2012_256.expand(key, label, seed, 33);
        assertEquals(33, result.length);
    }

    // -----------------------------------------------------------------------
    // Проверка структуры: label || 0x00 || seed || counter
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: структура label||0x00||seed||counter проверяется через детерминизм")
    void testLabelSeedStructure() {
        byte[] key = new byte[32];
        byte[] label = "label".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = "seed".getBytes(StandardCharsets.US_ASCII);

        byte[] result = KdfGostR3411_2012_256.expand(key, label, seed, 32);

        // Проверяем, что результат не совпадает с произвольными вариациями
        byte[] wrongLabel = KdfGostR3411_2012_256.expand(key, "wrong".getBytes(StandardCharsets.US_ASCII), seed, 32);
        byte[] wrongSeed = KdfGostR3411_2012_256.expand(key, label, "wrong".getBytes(StandardCharsets.US_ASCII), 32);
        assertFalse(Arrays.equals(result, wrongLabel));
        assertFalse(Arrays.equals(result, wrongSeed));
    }

    // -----------------------------------------------------------------------
    // Ошибки
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("expand: null key — IllegalArgumentException")
    void testNullKey() {
        assertThrows(IllegalArgumentException.class,
                () -> KdfGostR3411_2012_256.expand(null, new byte[0], new byte[0], 32));
    }

    @Test
    @DisplayName("expand: null label — IllegalArgumentException")
    void testNullLabel() {
        assertThrows(IllegalArgumentException.class,
                () -> KdfGostR3411_2012_256.expand(new byte[32], null, new byte[0], 32));
    }

    @Test
    @DisplayName("expand: null seed — IllegalArgumentException")
    void testNullSeed() {
        assertThrows(IllegalArgumentException.class,
                () -> KdfGostR3411_2012_256.expand(new byte[32], new byte[0], null, 32));
    }

    @Test
    @DisplayName("expand: отрицательная длина — IllegalArgumentException")
    void testNegativeLength() {
        assertThrows(IllegalArgumentException.class,
                () -> KdfGostR3411_2012_256.expand(new byte[32], new byte[0], new byte[0], -1));
    }

    @Test
    @DisplayName("expand: длина > 255*32 — IllegalArgumentException")
    void testTooLargeLength() {
        assertThrows(IllegalArgumentException.class,
                () -> KdfGostR3411_2012_256.expand(new byte[32], new byte[0], new byte[0], 256 * 32));
    }
}
