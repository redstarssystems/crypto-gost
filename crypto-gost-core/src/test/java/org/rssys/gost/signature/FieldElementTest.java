package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты FieldElement, в частности conditionalSubtract и граничные случаи арифметики поля.
 * Граница a == p — ключевой тест: ge в conditionalSubtract полагается на
 * выражение {@code 1L ^ (lt | gt)} для этого случая.
 */
@DisplayName("FieldElement")
class FieldElementTest {

    /** Модуль 256-битной кривой TC26-A (p = 2^256 - 0x268) */
    private static final BigInteger P =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16);

    /** 512-битный нечётный модуль для теста montMul ≡ montMulBuf.
     *  ВНИМАНИЕ: НЕ модуль p кривой TC26-A-512 (настоящая p оканчивается на …FDC7). */
    private static final BigInteger Q =
            new BigInteger(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                            + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
                    16);

    private final FieldElement.MontgomeryParams mp = new FieldElement.MontgomeryParams(P);

    private static long[] conditionalSubtract(long[] a, long[] p, long overflowBit) {
        long[] out = new long[a.length];
        FieldElement.conditionalSubtract(a, p, overflowBit, out);
        return out;
    }

    /**
     * a == p, overflow = 0 -> результат должен быть 0.
     * Единственный случай, когда ge вычисляется через 1L ^ (lt | gt).
     */
    @Test
    @DisplayName("conditionalSubtract: a == p, overflow=0 -> 0")
    void conditionalSubtractAPEqualsP() {
        long[] a = FieldElement.toLimbs(P, mp.n);
        long[] p = mp.p;

        long[] result = conditionalSubtract(a, p, 0L);

        assertArrayEquals(new long[mp.n], result, "a == p должен дать 0");
    }

    /**
     * a == p, overflow = 1 -> тоже 0 (a == p уже включает вычитание).
     */
    @Test
    @DisplayName("conditionalSubtract: a == p, overflow=1 -> 0")
    void conditionalSubtractAPEqualsPWithOverflow() {
        long[] a = FieldElement.toLimbs(P, mp.n);
        long[] p = mp.p;

        long[] result = conditionalSubtract(a, p, 1L);

        assertArrayEquals(new long[mp.n], result, "a == p с overflow=1 должен дать 0");
    }

    /**
     * a < p, overflow = 0 -> a без изменений.
     */
    @Test
    @DisplayName("conditionalSubtract: a < p, overflow=0 -> a")
    void conditionalSubtractALessThanP() {
        long[] a = FieldElement.toLimbs(P.subtract(BigInteger.ONE), mp.n);
        long[] p = mp.p;

        long[] result = conditionalSubtract(a, p, 0L);

        assertArrayEquals(a, result, "a < p должен вернуть a без изменений");
    }

    /**
     * a > p, overflow = 0 -> a - p.
     */
    @Test
    @DisplayName("conditionalSubtract: a > p, overflow=0 -> a - p")
    void conditionalSubtractAGreaterThanP() {
        long[] a = FieldElement.toLimbs(P.add(BigInteger.valueOf(42)), mp.n);
        long[] p = mp.p;

        long[] result = conditionalSubtract(a, p, 0L);

        assertArrayEquals(
                FieldElement.toLimbs(BigInteger.valueOf(42), mp.n),
                result,
                "a = p + 42 -> a - p = 42");
    }

    /**
     * a = p + k (k < p) для разных k — проверка корректности conditionalSubtract.
     * k < 0x268 чтобы P + k не переполнил 256 бит.
     */
    @Test
    @DisplayName("conditionalSubtract: a = p + K для разных K")
    void conditionalSubtractVarious() {
        long[] p = mp.p;

        for (long k : new long[] {0L, 1L, 2L, 0x100L, 0x267L}) {
            BigInteger kBig = BigInteger.valueOf(k);
            long[] a = FieldElement.toLimbs(P.add(kBig), mp.n);
            long[] expected = FieldElement.toLimbs(kBig, mp.n);
            long[] result = conditionalSubtract(a, p, 0L);

            assertArrayEquals(expected, result, "a = p + " + k + " -> a - p = " + k);
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
        for (BigInteger p : new BigInteger[] {P, Q}) {
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

                assertArrayEquals(standalone, out, "montMulBuf != montMul на trial=" + trial);
            }
        }
    }

    /**
     * overflowBit не влияет на результат когда a > p — оба случая дают a - p.
     */
    @Test
    @DisplayName("conditionalSubtract: overflowBit не влияет при a > p")
    void conditionalSubtractOverflowIrrelevant() {
        long[] a = FieldElement.toLimbs(P.add(BigInteger.ONE), mp.n);
        long[] p = mp.p;
        long[] expected = FieldElement.toLimbs(BigInteger.ONE, mp.n);

        assertArrayEquals(expected, conditionalSubtract(a, p, 0L), "a > p, overflow=0 -> a - p");
        assertArrayEquals(
                expected, conditionalSubtract(a, p, 1L), "a > p, overflow=1 -> a - p (тот же)");
    }

    // -------------------------------------------------------------------------
    // add, subtract, shiftLeft и addInternal
    // -------------------------------------------------------------------------

    private static final int RANDOM_TRIALS = 20;

    /** Значения у границ поля и случайные: ноль, единица, p-1, p-2, середина и случайные. */
    private static List<BigInteger> sampleValues(BigInteger modulus) {
        List<BigInteger> values =
                new ArrayList<>(
                        List.of(
                                BigInteger.ZERO,
                                BigInteger.ONE,
                                BigInteger.TWO,
                                modulus.subtract(BigInteger.TWO),
                                modulus.subtract(BigInteger.ONE),
                                modulus.shiftRight(1),
                                modulus.shiftRight(1).add(BigInteger.ONE)));
        for (int i = 0; i < RANDOM_TRIALS; i++) {
            values.add(new BigInteger(modulus.bitLength() + 8, CryptoRandom.INSTANCE).mod(modulus));
        }
        return values;
    }

    private static List<BigInteger> moduli() {
        return List.of(P, Q);
    }

    @Test
    @DisplayName("add: совпадает с (a + b) mod p, включая a+a, a+0, a+(p-a), (p-1)+(p-1), (p-1)+1")
    void addMatchesBigInteger() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                for (BigInteger b : sampleValues(modulus)) {
                    FieldElement sum = FieldElement.of(a, params).add(FieldElement.of(b, params));
                    assertEquals(
                            a.add(b).mod(modulus),
                            sum.toBigInteger(),
                            "add: a=" + a.toString(16) + ", b=" + b.toString(16));
                }
            }
        }
    }

    @Test
    @DisplayName("add(x, x): тот же элемент на обоих операндах, исходный не меняется")
    void addSelfKeepsOperand() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                FieldElement element = FieldElement.of(a, params);
                FieldElement doubled = element.add(element);
                assertEquals(a.shiftLeft(1).mod(modulus), doubled.toBigInteger(), "a + a");
                assertEquals(a, element.toBigInteger(), "операнд изменился после add(a, a)");
            }
        }
    }

    @Test
    @DisplayName(
            "multiply и square: совпадают с (a * b) mod p, в том числе при старших битах лимбов")
    void multiplyMatchesBigInteger() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                for (BigInteger b : sampleValues(modulus)) {
                    FieldElement product =
                            FieldElement.of(a, params).multiply(FieldElement.of(b, params));
                    assertEquals(
                            a.multiply(b).mod(modulus),
                            product.toBigInteger(),
                            "multiply: a=" + a.toString(16) + ", b=" + b.toString(16));
                }
                assertEquals(
                        a.multiply(a).mod(modulus),
                        FieldElement.of(a, params).square().toBigInteger(),
                        "square: a=" + a.toString(16));
            }
        }
    }

    @Test
    @DisplayName("isEqualTo: равные значения равны, разные - нет")
    void isEqualToComparesValues() {
        FieldElement first = FieldElement.of(BigInteger.valueOf(12345), mp);
        FieldElement same = FieldElement.of(BigInteger.valueOf(12345), mp);
        FieldElement other = FieldElement.of(BigInteger.valueOf(12346), mp);
        assertTrue(first.isEqualTo(same), "равные значения должны быть равны");
        assertTrue(first.isEqualTo(first), "элемент равен самому себе");
        assertFalse(first.isEqualTo(other), "разные значения не должны быть равны");
    }

    @Test
    @DisplayName(
            "isEqualTo: одинаковое значение в полях с разным модулем и тем же числом лимбов не равно")
    void isEqualToDistinguishesFieldsOfSameSize() {
        BigInteger otherModulus = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        FieldElement.MontgomeryParams otherParams = new FieldElement.MontgomeryParams(otherModulus);
        assertEquals(mp.n, otherParams.n, "предпосылка теста: у полей одинаковое число лимбов");

        FieldElement inFirstField = FieldElement.of(BigInteger.valueOf(12345), mp);
        FieldElement inOtherField = FieldElement.of(BigInteger.valueOf(12345), otherParams);
        assertFalse(
                inFirstField.isEqualTo(inOtherField), "элементы разных полей не должны быть равны");

        FieldElement.MontgomeryParams sameModulus = new FieldElement.MontgomeryParams(P);
        assertTrue(
                inFirstField.isEqualTo(FieldElement.of(BigInteger.valueOf(12345), sameModulus)),
                "равные значения в равных по модулю полях должны быть равны");
    }

    @Test
    @DisplayName("subtract: совпадает с (a - b) mod p, результат всегда в [0, p)")
    void subtractMatchesBigInteger() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                for (BigInteger b : sampleValues(modulus)) {
                    FieldElement difference =
                            FieldElement.of(a, params).subtract(FieldElement.of(b, params));
                    assertEquals(
                            a.subtract(b).mod(modulus),
                            difference.toBigInteger(),
                            "subtract: a=" + a.toString(16) + ", b=" + b.toString(16));
                }
            }
            FieldElement zero = FieldElement.zero(params);
            assertTrue(zero.subtract(zero).isZero(), "0 - 0 = 0 в канонической форме");
            FieldElement one = FieldElement.of(BigInteger.ONE, params);
            assertTrue(one.subtract(one).isZero(), "a - a = 0 в канонической форме");
        }
    }

    @Test
    @DisplayName("shiftLeft(0..3): совпадает с a·2^bits mod p, в том числе у границы p")
    void shiftLeftMatchesBigInteger() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                FieldElement element = FieldElement.of(a, params);
                for (int bits = 0; bits <= 3; bits++) {
                    assertEquals(
                            a.shiftLeft(bits).mod(modulus),
                            element.shiftLeft(bits).toBigInteger(),
                            "shiftLeft(" + bits + "), a=" + a.toString(16));
                }
                assertEquals(a, element.toBigInteger(), "операнд изменился после shiftLeft");
            }
        }
    }

    @Test
    @DisplayName("addInternal: out == a == b даёт 2a mod p, в том числе у границы p")
    void addInternalWithFullAliasing() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                long[] buffer = FieldElement.toLimbs(a, params.n);
                FieldElement.addInternal(buffer, buffer, params, buffer);
                assertEquals(
                        a.shiftLeft(1).mod(modulus),
                        FieldElement.toBigInteger(buffer, params.n),
                        "addInternal(a, a, out = a), a=" + a.toString(16));
            }
        }
    }

    @Test
    @DisplayName("addInternal: out == a и out == b по отдельности дают (a + b) mod p")
    void addInternalWithPartialAliasing() {
        for (BigInteger modulus : moduli()) {
            FieldElement.MontgomeryParams params = new FieldElement.MontgomeryParams(modulus);
            for (BigInteger a : sampleValues(modulus)) {
                for (BigInteger b : sampleValues(modulus)) {
                    BigInteger expected = a.add(b).mod(modulus);
                    long[] outIsA = FieldElement.toLimbs(a, params.n);
                    FieldElement.addInternal(
                            outIsA, FieldElement.toLimbs(b, params.n), params, outIsA);
                    assertEquals(expected, FieldElement.toBigInteger(outIsA, params.n), "out == a");
                    long[] outIsB = FieldElement.toLimbs(b, params.n);
                    FieldElement.addInternal(
                            FieldElement.toLimbs(a, params.n), outIsB, params, outIsB);
                    assertEquals(expected, FieldElement.toBigInteger(outIsB, params.n), "out == b");
                }
            }
        }
    }
}
