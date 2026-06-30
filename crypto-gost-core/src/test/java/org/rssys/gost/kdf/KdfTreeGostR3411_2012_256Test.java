package org.rssys.gost.kdf;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

/**
 * Тесты KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.5, RFC 9337 §5.1.1).
 *
 * <p>Верифицирует структуру буфера: label || 0x00 || seed || INT(i,4) || INT(L,4).
 */
@DisplayName("KdfTreeGostR3411_2012_256 — RFC 7836 §4.5")
class KdfTreeGostR3411_2012_256Test {

    private static byte[] fill(int len, int val) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) val);
        return b;
    }

    /** Вычисляет HMAC-Streebog-256 напрямую для верификации KDF_TREE. */
    private static byte[] hmac256(byte[] key, byte[] msg) {
        Hmac mac = new Hmac(new Streebog256());
        mac.init(key);
        mac.update(msg, 0, msg.length);
        byte[] out = new byte[32];
        mac.doFinal(out, 0);
        mac.clear();
        return out;
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
            (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value
        };
    }

    /** Строит буфер KDF_TREE и вычисляет эталонный HMAC. */
    private static byte[] computeKdfTreeBlock(
            byte[] kin, byte[] label, byte[] seed, int i, int keyLen) {
        byte[] buf = new byte[label.length + 1 + seed.length + 4 + 4];
        System.arraycopy(label, 0, buf, 0, label.length);
        buf[label.length] = 0;
        System.arraycopy(seed, 0, buf, label.length + 1, seed.length);
        System.arraycopy(intToBytes(i), 0, buf, label.length + 1 + seed.length, 4);
        System.arraycopy(intToBytes(keyLen), 0, buf, label.length + 1 + seed.length + 4, 4);
        return hmac256(kin, buf);
    }

    // ========================================================================
    // Верификация порядка полей через эталонный HMAC
    // ========================================================================

    @Test
    @DisplayName("Вектор 1: count=1, keyLen=32 — сверка с эталонным HMAC")
    void testVectorSingleBlock() {
        byte[] kin = fill(32, 0x01);
        byte[] label = "kdf tree".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = fill(8, 0x02);

        byte[] result = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 1, 32);
        byte[] expected = computeKdfTreeBlock(kin, label, seed, 1, 32);

        assertArrayEquals(expected, result);
        assertEquals(32, result.length);
    }

    @Test
    @DisplayName("Вектор 2: count=2, keyLen=16 — два блока, сверка с эталоном")
    void testVectorTwoBlocks() {
        byte[] kin = fill(32, 0x03);
        byte[] label = "kdf tree".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = fill(8, 0x04);

        byte[] result = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 2, 16);

        assertEquals(32, result.length); // 2 * 16

        byte[] expected1 = computeKdfTreeBlock(kin, label, seed, 1, 16);
        byte[] expected2 = computeKdfTreeBlock(kin, label, seed, 2, 16);

        byte[] expected = new byte[32];
        System.arraycopy(expected1, 0, expected, 0, 16);
        System.arraycopy(expected2, 0, expected, 16, 16);

        assertArrayEquals(expected, result);
    }

    // ========================================================================
    // Детерминизм и разнообразие выходов
    // ========================================================================

    @Test
    @DisplayName("Детерминизм: одинаковые входы -> одинаковый выход")
    void testDeterminism() {
        byte[] kin = fill(32, 0x01);
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = fill(8, (byte) 0xAA);

        byte[] r1 = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 1, 32);
        byte[] r2 = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 1, 32);
        assertArrayEquals(r1, r2);
    }

    @Test
    @DisplayName("Разные label -> разные выходы")
    void testDifferentLabels() {
        byte[] kin = fill(32, 0x01);
        byte[] seed = fill(8, (byte) 0xAA);

        byte[] r1 =
                KdfTreeGostR3411_2012_256.generate(
                        kin, "labelA".getBytes(StandardCharsets.US_ASCII), seed, 1, 32);
        byte[] r2 =
                KdfTreeGostR3411_2012_256.generate(
                        kin, "labelB".getBytes(StandardCharsets.US_ASCII), seed, 1, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    @Test
    @DisplayName("Разные seed -> разные выходы")
    void testDifferentSeeds() {
        byte[] kin = fill(32, 0x01);
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);

        byte[] r1 = KdfTreeGostR3411_2012_256.generate(kin, label, fill(8, (byte) 0x01), 1, 32);
        byte[] r2 = KdfTreeGostR3411_2012_256.generate(kin, label, fill(8, (byte) 0x02), 1, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    @Test
    @DisplayName("Разные K_in -> разные выходы")
    void testDifferentKin() {
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = fill(8, (byte) 0xAA);

        byte[] r1 = KdfTreeGostR3411_2012_256.generate(fill(32, (byte) 0x01), label, seed, 1, 32);
        byte[] r2 = KdfTreeGostR3411_2012_256.generate(fill(32, (byte) 0x02), label, seed, 1, 32);
        assertFalse(Arrays.equals(r1, r2));
    }

    // ========================================================================
    // Граничные случаи
    // ========================================================================

    @Test
    @DisplayName("count=1: один блок, ненулевой результат")
    void testCountOne() {
        byte[] kin = fill(32, 0x01);
        byte[] seed = fill(8, (byte) 0xAB);
        byte[] result =
                KdfTreeGostR3411_2012_256.generate(
                        kin, "test".getBytes(StandardCharsets.US_ASCII), seed, 1, 32);
        assertEquals(32, result.length);
        assertFalse(allZero(result));
    }

    @Test
    @DisplayName("count=255: максимальное значение, без исключения")
    void testCountMax() {
        byte[] result =
                KdfTreeGostR3411_2012_256.generate(
                        fill(32, (byte) 0x01),
                        "t".getBytes(StandardCharsets.US_ASCII),
                        fill(8, (byte) 0xAB),
                        255,
                        32);
        assertEquals(255 * 32, result.length);
        assertFalse(allZero(result));
    }

    @Test
    @DisplayName("keyLen=1: минимум, копируется 1 байт из HMAC")
    void testKeyLenMin() {
        byte[] result =
                KdfTreeGostR3411_2012_256.generate(
                        fill(32, (byte) 0x01),
                        "t".getBytes(StandardCharsets.US_ASCII),
                        fill(8, (byte) 0xAB),
                        1,
                        1);
        assertEquals(1, result.length);
    }

    @Test
    @DisplayName("keyLen=32: максимум по ограничению HASH_LEN")
    void testKeyLenMax() {
        byte[] result =
                KdfTreeGostR3411_2012_256.generate(
                        fill(32, (byte) 0x01),
                        "t".getBytes(StandardCharsets.US_ASCII),
                        fill(8, (byte) 0xAB),
                        1,
                        32);
        assertEquals(32, result.length);
    }

    // ========================================================================
    // Исключения
    // ========================================================================

    @Test
    @DisplayName("kin=null -> IllegalArgumentException")
    void testNullKin() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KdfTreeGostR3411_2012_256.generate(null, new byte[0], new byte[0], 1, 32));
    }

    @Test
    @DisplayName("label=null -> IllegalArgumentException")
    void testNullLabel() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KdfTreeGostR3411_2012_256.generate(new byte[32], null, new byte[0], 1, 32));
    }

    @Test
    @DisplayName("seed=null -> IllegalArgumentException")
    void testNullSeed() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KdfTreeGostR3411_2012_256.generate(new byte[32], new byte[0], null, 1, 32));
    }

    @Test
    @DisplayName("count=0 -> IllegalArgumentException")
    void testCountZero() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        KdfTreeGostR3411_2012_256.generate(
                                new byte[32], new byte[0], new byte[0], 0, 32));
    }

    @Test
    @DisplayName("count=256 -> IllegalArgumentException (превышение 255)")
    void testCountOverMax() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        KdfTreeGostR3411_2012_256.generate(
                                new byte[32], new byte[0], new byte[0], 256, 32));
    }

    @Test
    @DisplayName("keyLen=0 -> IllegalArgumentException")
    void testKeyLenZero() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        KdfTreeGostR3411_2012_256.generate(
                                new byte[32], new byte[0], new byte[0], 1, 0));
    }

    @Test
    @DisplayName("keyLen=33 -> IllegalArgumentException (превышение HASH_LEN=32)")
    void testKeyLenOverMax() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        KdfTreeGostR3411_2012_256.generate(
                                new byte[32], new byte[0], new byte[0], 1, 33));
    }

    // ========================================================================
    // helpers
    // ========================================================================

    private static boolean allZero(byte[] data) {
        for (byte b : data) if (b != 0) return false;
        return true;
    }
}
