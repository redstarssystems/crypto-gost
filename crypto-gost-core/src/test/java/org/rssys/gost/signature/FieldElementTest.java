package org.rssys.gost.signature;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import org.rssys.gost.util.CryptoRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты FieldElement, в частности conditionalSubtract и граничные случаи арифметики поля.
 * Граница a == p — ключевой тест: ge в conditionalSubtract полагается на
 * выражение {@code 1L ^ (lt | gt)} для этого случая.
 */
@DisplayName("FieldElement")
class FieldElementTest {

    /** Модуль 256-битной кривой TC26-A (p = 2^256 - 0x268) */
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);

    /** 512-битный нечётный модуль для теста montMul ≡ montMulBuf.
     *  ВНИМАНИЕ: НЕ модуль p кривой TC26-A-512 (настоящая p оканчивается на …FDC7). */
    private static final BigInteger Q = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
      + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);

    private final FieldElement.MontgomeryParams mp = new FieldElement.MontgomeryParams(P);

    /**
     * a == p, overflow = 0 → результат должен быть 0.
     * Единственный случай, когда ge вычисляется через 1L ^ (lt | gt).
     */
    @Test
    @DisplayName("conditionalSubtract: a == p, overflow=0 → 0")
    void conditionalSubtractAPEqualsP() {
        long[] a = FieldElement.toLimbs(P, mp.n);
        long[] p = mp.p;

        long[] result = FieldElement.conditionalSubtract(a, p, 0L);

        assertArrayEquals(new long[mp.n], result,
            "a == p должен дать 0");
    }

    /**
     * a == p, overflow = 1 → тоже 0 (a == p уже включает вычитание).
     */
    @Test
    @DisplayName("conditionalSubtract: a == p, overflow=1 → 0")
    void conditionalSubtractAPEqualsPWithOverflow() {
        long[] a = FieldElement.toLimbs(P, mp.n);
        long[] p = mp.p;

        long[] result = FieldElement.conditionalSubtract(a, p, 1L);

        assertArrayEquals(new long[mp.n], result,
            "a == p с overflow=1 должен дать 0");
    }

    /**
     * a < p, overflow = 0 → a без изменений.
     */
    @Test
    @DisplayName("conditionalSubtract: a < p, overflow=0 → a")
    void conditionalSubtractALessThanP() {
        long[] a = FieldElement.toLimbs(P.subtract(BigInteger.ONE), mp.n);
        long[] p = mp.p;

        long[] result = FieldElement.conditionalSubtract(a, p, 0L);

        assertArrayEquals(a, result, "a < p должен вернуть a без изменений");
    }

    /**
     * a > p, overflow = 0 → a - p.
     */
    @Test
    @DisplayName("conditionalSubtract: a > p, overflow=0 → a - p")
    void conditionalSubtractAGreaterThanP() {
        long[] a = FieldElement.toLimbs(P.add(BigInteger.valueOf(42)), mp.n);
        long[] p = mp.p;

        long[] result = FieldElement.conditionalSubtract(a, p, 0L);

        assertArrayEquals(
            FieldElement.toLimbs(BigInteger.valueOf(42), mp.n),
            result, "a = p + 42 → a - p = 42");
    }

    /**
     * a = p + k (k < p) для разных k — проверка корректности conditionalSubtract.
     * k < 0x268 чтобы P + k не переполнил 256 бит.
     */
    @Test
    @DisplayName("conditionalSubtract: a = p + K для разных K")
    void conditionalSubtractVarious() {
        long[] p = mp.p;

        for (long k : new long[]{0L, 1L, 2L, 0x100L, 0x267L}) {
            BigInteger kBig = BigInteger.valueOf(k);
            long[] a = FieldElement.toLimbs(P.add(kBig), mp.n);
            long[] expected = FieldElement.toLimbs(kBig, mp.n);
            long[] result = FieldElement.conditionalSubtract(a, p, 0L);

            assertArrayEquals(expected, result,
                "a = p + " + k + " → a - p = " + k);
        }
    }

    /**
     * Эквивалентность: standalone montMul(a,b,mp) == montMulBuf(a,b,t,out,mp).
     * 100 случайных входов на 256-бит и 512-бит.
     * montMulBuf использует предвыделенные буферы — проверка что результат совпадает.
     */
    @Test
    @DisplayName("montMul ≡ montMulBuf для случайных входов")
    void montMulEqualsMontMulBuf() {
        for (BigInteger p : new BigInteger[]{P, Q}) {
            FieldElement.MontgomeryParams mp = new FieldElement.MontgomeryParams(p);
            int n = mp.n;
            for (int trial = 0; trial < 100; trial++) {
                BigInteger aVal = new BigInteger(p.bitLength(), CryptoRandom.INSTANCE).mod(p);
                BigInteger bVal = new BigInteger(p.bitLength(), CryptoRandom.INSTANCE).mod(p);
                long[] a = FieldElement.toLimbs(aVal, n);
                long[] b = FieldElement.toLimbs(bVal, n);
                long[] t = new long[n + 2];
                long[] out = new long[n];

                long[] standalone = FieldElement.montMul(a, b, mp);
                FieldElement.montMulBuf(a, b, t, out, mp);

                assertArrayEquals(standalone, out,
                    "montMulBuf != montMul на trial=" + trial);
            }
        }
    }

    /**
     * overflowBit не влияет на результат когда a > p — оба случая дают a - p.
     */
    @Test
    @DisplayName("conditionalSubtract: overflowBit irrelevant when a > p")
    void conditionalSubtractOverflowIrrelevant() {
        long[] a = FieldElement.toLimbs(P.add(BigInteger.ONE), mp.n);
        long[] p = mp.p;
        long[] expected = FieldElement.toLimbs(BigInteger.ONE, mp.n);

        assertArrayEquals(
            expected,
            FieldElement.conditionalSubtract(a, p, 0L),
            "a > p, overflow=0 → a - p");
        assertArrayEquals(
            expected,
            FieldElement.conditionalSubtract(a, p, 1L),
            "a > p, overflow=1 → a - p (тот же)");
    }
}
