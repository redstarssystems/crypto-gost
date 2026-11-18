package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.util.CryptoRandom;

/**
 * Лестница {@link ECPoint#multiply} и {@link ECPoint#addDistinct} против независимого
 * аффинного эталона {@link AffineReference}.
 *
 * <p>Входные точки малого порядка и смешанные точки строятся тоже эталоном: иначе при ошибке
 * в лестнице входная точка могла бы потерять нужный порядок, а тест пройти вхолостую.
 */
@DisplayName("ECPoint: лестница multiply и addDistinct")
class ECPointLadderTest {

    /** Число случайных скаляров на кривую сверх фиксированного набора. */
    private static final int RANDOM_SCALARS = 5;

    /** Сколько последовательных x перебираем в поиске точек порядка 2 и 4. */
    private static final int MAX_X_SEARCH = 500;

    static List<ECParameters> allCurves() {
        return List.of(
                ECParameters.tc26a256(),
                ECParameters.tc26a512(),
                ECParameters.tc26b512(),
                ECParameters.tc26c512(),
                ECParameters.cryptoProA(),
                ECParameters.cryptoProB(),
                ECParameters.cryptoProC());
    }

    static List<ECParameters> curvesWithCofactor() {
        List<ECParameters> result = new ArrayList<>();
        for (ECParameters params : allCurves()) {
            if (params.cofactor > 1) result.add(params);
        }
        return result;
    }

    static BigInteger[] basePoint(ECParameters params) {
        return new BigInteger[] {params.gx, params.gy};
    }

    /** Фиксированные граничные скаляры; {@code 2^bitLength(n) - 1} - все биты единицы. */
    private static List<BigInteger> edgeScalars(ECParameters params) {
        BigInteger n = params.n;
        BigInteger allOnes = BigInteger.ONE.shiftLeft(n.bitLength()).subtract(BigInteger.ONE);
        return List.of(
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.TWO,
                BigInteger.valueOf(3),
                BigInteger.ONE.shiftLeft(128),
                n.subtract(BigInteger.TWO),
                n.subtract(BigInteger.ONE),
                n,
                n.add(BigInteger.ONE),
                allOnes);
    }

    private static List<BigInteger> randomScalars(ECParameters params) {
        List<BigInteger> result = new ArrayList<>();
        for (int i = 0; i < RANDOM_SCALARS; i++) {
            result.add(new BigInteger(params.n.bitLength(), CryptoRandom.INSTANCE));
        }
        return result;
    }

    private static String describe(String curve, BigInteger k) {
        return "кривая " + curve + ", k = " + k.toString(16);
    }

    static void assertSamePoint(BigInteger[] expected, ECPoint actual, String message) {
        if (expected == null) {
            assertTrue(actual.isInfinity(), message + ": ожидалась бесконечность");
            return;
        }
        assertFalse(actual.isInfinity(), message + ": неожиданная бесконечность");
        ECPoint normalized = actual.normalize();
        assertEquals(expected[0], normalized.getX(), message + ": x");
        assertEquals(expected[1], normalized.getY(), message + ": y");
    }

    // -------------------------------------------------------------------------
    // Эталон сам по себе
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("эталон: n·G = ∞ и (n+1)·G = G")
    void referenceOrderOfBasePoint(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        assertNull(ref.multiply(params.n, basePoint(params)), "n·G должно быть бесконечностью");
        BigInteger[] nPlusOne = ref.multiply(params.n.add(BigInteger.ONE), basePoint(params));
        assertArrayEquals(basePoint(params), nPlusOne, "(n+1)·G должно совпасть с G");
    }

    // -------------------------------------------------------------------------
    // addDistinct
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("addDistinct: P + (-P), O + P, P + O, O + O и P + Q совпадают с эталоном")
    void addDistinctCornerCases(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] g = basePoint(params);
        BigInteger[] q = ref.multiply(BigInteger.valueOf(12345), g);
        ECPoint pointP = AffineReference.toEcPoint(g, params);
        ECPoint pointQ = AffineReference.toEcPoint(q, params);
        ECPoint minusP = AffineReference.toEcPoint(ref.negate(g), params);
        ECPoint infinity = ECPoint.infinity(params);

        assertTrue(pointP.addDistinct(minusP).isInfinity(), "P + (-P) = O");
        assertTrue(minusP.addDistinct(pointP).isInfinity(), "(-P) + P = O");
        assertSamePoint(g, infinity.addDistinct(pointP), "O + P");
        assertSamePoint(g, pointP.addDistinct(infinity), "P + O");
        assertTrue(infinity.addDistinct(infinity).isInfinity(), "O + O = O");
        assertSamePoint(ref.add(g, q), pointP.addDistinct(pointQ), "P + Q");
        assertSamePoint(ref.add(q, g), pointQ.addDistinct(pointP), "Q + P");
        // совпадает с полным сложением на различных точках
        assertSamePoint(
                AffineReference.fromEcPoint(pointP.add(pointQ)),
                pointP.addDistinct(pointQ),
                "addDistinct против add");
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("addDistinct: нарушение предусловия P == Q даёт бесконечность, а не 2P")
    void addDistinctEqualPointsDegenerate(ECParameters params) {
        ECPoint g = AffineReference.toEcPoint(basePoint(params), params);
        assertTrue(g.addDistinct(g).isInfinity(), "при P == Q результат - бесконечность");
    }

    // -------------------------------------------------------------------------
    // multiply: точки на подгруппе
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("multiply: граничные и случайные скаляры совпадают с эталоном")
    void multiplyMatchesReferenceOnBasePoint(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] g = basePoint(params);
        ECPoint point = AffineReference.toEcPoint(g, params);
        List<BigInteger> scalars = new ArrayList<>(edgeScalars(params));
        scalars.addAll(randomScalars(params));
        for (BigInteger k : scalars) {
            assertSamePoint(ref.multiply(k, g), point.multiply(k), describe("G", k));
        }
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("multiply: произвольная точка подгруппы и k = n даёт бесконечность")
    void multiplyMatchesReferenceOnArbitraryPoint(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] arbitrary =
                ref.multiply(
                        new BigInteger(120, CryptoRandom.INSTANCE).setBit(0), basePoint(params));
        ECPoint point = AffineReference.toEcPoint(arbitrary, params);
        for (BigInteger k : edgeScalars(params)) {
            assertSamePoint(ref.multiply(k, arbitrary), point.multiply(k), describe("Q", k));
        }
        assertTrue(point.multiply(params.n).isInfinity(), "n·Q = O для точки подгруппы");
        assertTrue(
                point.multiply(params.n.subtract(BigInteger.ONE)).add(point).isInfinity(),
                "(n-1)·Q + Q = O");
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("multiply: P = O для любого скаляра даёт бесконечность")
    void multiplyOfInfinity(ECParameters params) {
        ECPoint infinity = ECPoint.infinity(params);
        for (BigInteger k : edgeScalars(params)) {
            assertTrue(infinity.multiply(k).isInfinity(), "O·k = O, " + describe("O", k));
        }
    }

    // -------------------------------------------------------------------------
    // multiply: кривые с кофактором 4, точки малого порядка и смешанные точки
    // -------------------------------------------------------------------------

    /** Наименьший {@code k >= 1}, при котором {@code k·T = O}, но не более 4. */
    private static int smallOrder(AffineReference ref, BigInteger[] point) {
        BigInteger[] acc = point;
        for (int order = 1; order <= 4; order++) {
            if (acc == null) return order;
            acc = ref.add(acc, point);
        }
        return -1;
    }

    /**
     * Ищет точку заданного порядка (2 или 4) как {@code n·R} для точек R, подобранных по
     * последовательным x. Для p ≡ 3 (mod 4) корень берётся как {@code rhs^((p+1)/4)}.
     * Порядок проверяется эталоном, без ECPoint.
     */
    static BigInteger[] findSmallOrderPoint(ECParameters params, int wantedOrder) {
        AffineReference ref = new AffineReference(params);
        BigInteger exponent = params.p.add(BigInteger.ONE).shiftRight(2);
        assertEquals(3, params.p.mod(BigInteger.valueOf(4)).intValue(), "ожидалось p ≡ 3 (mod 4)");
        for (int xi = 1; xi <= MAX_X_SEARCH; xi++) {
            BigInteger x = BigInteger.valueOf(xi);
            BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(params.p);
            BigInteger y = rhs.modPow(exponent, params.p);
            if (!y.pow(2).mod(params.p).equals(rhs)) continue;
            BigInteger[] candidate = ref.multiply(params.n, new BigInteger[] {x, y});
            if (candidate != null && smallOrder(ref, candidate) == wantedOrder) return candidate;
        }
        return fail("точка порядка " + wantedOrder + " не найдена среди x <= " + MAX_X_SEARCH);
    }

    @ParameterizedTest
    @MethodSource("curvesWithCofactor")
    @DisplayName("multiply: точки порядка 2 и 4 совпадают с эталоном")
    void multiplyOnSmallOrderPoints(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        for (int order : new int[] {2, 4}) {
            BigInteger[] small = findSmallOrderPoint(params, order);
            assertTrue(ref.isOnCurve(small, params), "точка порядка " + order + " на кривой");
            ECPoint point = AffineReference.toEcPoint(small, params);
            for (BigInteger k : edgeScalars(params)) {
                assertSamePoint(
                        ref.multiply(k, small),
                        point.multiply(k),
                        "порядок " + order + ", " + describe("T", k));
            }
        }
    }

    @ParameterizedTest
    @MethodSource("curvesWithCofactor")
    @DisplayName(
            "multiply: смешанная точка Q_n + Q_2/Q_4 совпадает с эталоном, подгруппу не проходит")
    void multiplyOnMixedPoints(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] subgroupPoint =
                ref.multiply(BigInteger.valueOf(987654321L), basePoint(params));
        for (int order : new int[] {2, 4}) {
            BigInteger[] small = findSmallOrderPoint(params, order);
            BigInteger[] mixed = ref.add(subgroupPoint, small);
            assertTrue(ref.isOnCurve(mixed, params), "смешанная точка на кривой");
            ECPoint point = AffineReference.toEcPoint(mixed, params);
            for (BigInteger k : edgeScalars(params)) {
                assertSamePoint(
                        ref.multiply(k, mixed),
                        point.multiply(k),
                        "смешанная, порядок " + order + ", " + describe("M", k));
            }
            assertFalse(
                    point.multiply(params.n).isInfinity(),
                    "n·(Q_n + Q_" + order + ") не бесконечность");
            assertFalse(point.isValidPublicKey(), "смешанная точка вне подгруппы отвергается");
        }
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("isValidPublicKey: G проходит, n·G = O")
    void basePointIsValid(ECParameters params) {
        ECPoint g = AffineReference.toEcPoint(basePoint(params), params);
        assertTrue(g.isValidPublicKey(), "G принадлежит подгруппе");
        assertTrue(g.multiply(params.n).isInfinity(), "n·G = O");
    }

    @Test
    @DisplayName("поиск точек малого порядка находит и порядок 2, и порядок 4")
    void smallOrderPointsExist() {
        for (ECParameters params : curvesWithCofactor()) {
            assertNotNull(findSmallOrderPoint(params, 2), "порядок 2");
            assertNotNull(findSmallOrderPoint(params, 4), "порядок 4");
        }
    }

    // -------------------------------------------------------------------------
    // Проверка скаляра
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("multiply: null, отрицательный и слишком длинный скаляр отвергаются")
    void multiplyRejectsInvalidScalar(ECParameters params) {
        ECPoint g = AffineReference.toEcPoint(basePoint(params), params);
        int bitLength = params.n.bitLength();
        assertThrows(IllegalArgumentException.class, () -> g.multiply(null), "k = null");
        assertThrows(
                IllegalArgumentException.class,
                () -> g.multiply(BigInteger.ONE.negate()),
                "k = -1");
        assertThrows(
                IllegalArgumentException.class,
                () -> g.multiply(BigInteger.ONE.shiftLeft(bitLength)),
                "k = 2^bitLength(n)");
        assertThrows(
                IllegalArgumentException.class,
                () -> g.multiply(params.n.shiftLeft(bitLength)),
                "k сильно длиннее n");
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("multiply: k = n и k = n + 1 допустимы и не усекаются")
    void multiplyAcceptsOrderAndOrderPlusOne(ECParameters params) {
        ECPoint g = AffineReference.toEcPoint(basePoint(params), params);
        assertTrue(g.multiply(params.n).isInfinity(), "n·G = O");
        assertSamePoint(basePoint(params), g.multiply(params.n.add(BigInteger.ONE)), "(n+1)·G = G");
    }
}
