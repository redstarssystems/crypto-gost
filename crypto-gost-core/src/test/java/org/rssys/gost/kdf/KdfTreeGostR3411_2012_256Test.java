package org.rssys.gost.kdf;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.TestHex;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

/**
 * Тесты KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.5, RFC 9337 §5.1.1).
 *
 * <p>Верифицирует структуру буфера: [i](1) || label || 0x00 || seed || [L]_b,
 * а также эталонный вектор RFC 7836 Appendix B.
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

    /** Минимальное big-endian без ведущих нулей — как [L]_b в RFC 7836. */
    private static byte[] bigEndianMinimal(int value) {
        if (value == 0) return new byte[] {0};
        int bits = 32 - Integer.numberOfLeadingZeros(value);
        int bytes = (bits + 7) / 8;
        byte[] result = new byte[bytes];
        for (int i = bytes - 1; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return result;
    }

    /**
     * Строит буфер KDF_TREE по RFC 7836 §4.5 и вычисляет эталонный HMAC.
     *
     * <p>Формат: {@code [i](1) || label || 0x00 || seed || [L]_b}, где {@code [L]_b}
     * — суммарная длина всего вывода в битах (count*keyLen*8), минимальное big-endian.
     */
    private static byte[] computeKdfTreeBlock(
            byte[] kin, byte[] label, byte[] seed, int i, int count, int keyLen) {
        byte[] lBytes = bigEndianMinimal(count * keyLen * 8);
        byte[] buf = new byte[1 + label.length + 1 + seed.length + lBytes.length];
        buf[0] = (byte) i;
        System.arraycopy(label, 0, buf, 1, label.length);
        buf[1 + label.length] = 0;
        System.arraycopy(seed, 0, buf, 1 + label.length + 1, seed.length);
        System.arraycopy(lBytes, 0, buf, 1 + label.length + 1 + seed.length, lBytes.length);
        return hmac256(kin, buf);
    }

    // ========================================================================
    // Authoritative KAT — эталонный вектор RFC 7836 Appendix B (KDF_TREE)
    // ========================================================================

    @Test
    @DisplayName("KAT RFC 7836 Appendix B: R=1, L=512 — байт-в-байт эталон")
    void testKatRfc7836AppendixB() {
        byte[] kin = new byte[32];
        for (int i = 0; i < 32; i++) kin[i] = (byte) i;
        byte[] label = {(byte) 0x26, (byte) 0xbd, (byte) 0xb8, (byte) 0x78};
        byte[] seed = {(byte) 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};

        byte[] expected =
                hex(
                        "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b"
                                + "074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9");

        byte[] result = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 2, 32);
        assertArrayEquals(
                expected, result, "KDF_TREE должен совпадать с эталоном RFC 7836 Appendix B");
    }

    private static byte[] hex(String s) {
        return TestHex.bytes(s);
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
        byte[] expected = computeKdfTreeBlock(kin, label, seed, 1, 1, 32);

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

        byte[] expected1 = computeKdfTreeBlock(kin, label, seed, 1, 2, 16);
        byte[] expected2 = computeKdfTreeBlock(kin, label, seed, 2, 2, 16);

        byte[] expected = new byte[32];
        System.arraycopy(expected1, 0, expected, 0, 16);
        System.arraycopy(expected2, 0, expected, 16, 16);

        assertArrayEquals(expected, result);
    }

    @Test
    @DisplayName(
            "Само-согласованность: [L] в 1 байт (L<256 бит) — не-KAT, ловушка на хардкод ширины [L]")
    void testSingleByteLengthEncoding() {
        // count=1, keyLen=31 -> L = 248 бит (0xF8) кодируется одним октетом.
        // Опубликованного вектора для L!=512 нет, поэтому сверяемся с независимым
        // пересчётом HMAC того же формата. Цель — поймать возможный «хардкод 2 байта»
        // в кодировании [L]_b, который эталонный вектор (L=512, 2 байта) не ловит.
        byte[] kin = fill(32, 0x05);
        byte[] label = "test".getBytes(StandardCharsets.US_ASCII);
        byte[] seed = fill(8, (byte) 0x06);

        byte[] result = KdfTreeGostR3411_2012_256.generate(kin, label, seed, 1, 31);
        byte[] expected = Arrays.copyOf(computeKdfTreeBlock(kin, label, seed, 1, 1, 31), 31);

        assertEquals(31, result.length);
        assertArrayEquals(expected, result, "Кодирование [L] в 1 байт должно совпасть с эталоном");
    }

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
