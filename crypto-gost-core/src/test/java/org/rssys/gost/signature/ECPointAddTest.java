package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.signature.ECPointLadderTest.assertSamePoint;
import static org.rssys.gost.signature.ECPointLadderTest.basePoint;
import static org.rssys.gost.signature.ECPointLadderTest.findSmallOrderPoint;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Полное сложение {@link ECPoint#add} против независимого аффинного эталона на всех
 * зарегистрированных кривых: и с {@code a = −3}, и с произвольным {@code a}.
 */
@DisplayName("ECPoint: полное сложение add")
class ECPointAddTest {

    private static final BigInteger SECOND_POINT_SCALAR = BigInteger.valueOf(12345);

    static List<ECParameters> allCurves() {
        return ECPointLadderTest.allCurves();
    }

    static List<ECParameters> curvesWithCofactor() {
        return ECPointLadderTest.curvesWithCofactor();
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("add: P + Q, Q + P и P + P совпадают с эталоном")
    void addDistinctAndEqualPoints(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] g = basePoint(params);
        BigInteger[] q = ref.multiply(SECOND_POINT_SCALAR, g);
        ECPoint pointP = AffineReference.toEcPoint(g, params);
        ECPoint pointQ = AffineReference.toEcPoint(q, params);

        assertSamePoint(ref.add(g, q), pointP.add(pointQ), "P + Q");
        assertSamePoint(ref.add(q, g), pointQ.add(pointP), "Q + P");
        assertSamePoint(ref.add(g, g), pointP.add(pointP), "P + P");
        assertSamePoint(ref.add(q, q), pointQ.add(pointQ), "Q + Q");
        assertSamePoint(ref.add(g, g), pointP.twice(), "twice(P)");
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("add: P + (-P), O + P, P + O, O + O")
    void addCornerCases(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] g = basePoint(params);
        ECPoint pointP = AffineReference.toEcPoint(g, params);
        ECPoint minusP = AffineReference.toEcPoint(ref.negate(g), params);
        ECPoint infinity = ECPoint.infinity(params);

        assertTrue(pointP.add(minusP).isInfinity(), "P + (-P) = O");
        assertTrue(minusP.add(pointP).isInfinity(), "(-P) + P = O");
        assertSamePoint(g, infinity.add(pointP), "O + P");
        assertSamePoint(g, pointP.add(infinity), "P + O");
        assertTrue(infinity.add(infinity).isInfinity(), "O + O = O");
    }

    @ParameterizedTest
    @MethodSource("curvesWithCofactor")
    @DisplayName("add: точки порядка 2 и 4 и смешанные точки совпадают с эталоном")
    void addOnSmallOrderPoints(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] subgroupPoint = ref.multiply(SECOND_POINT_SCALAR, basePoint(params));
        for (int order : new int[] {2, 4}) {
            BigInteger[] small = findSmallOrderPoint(params, order);
            BigInteger[] mixed = ref.add(subgroupPoint, small);
            ECPoint smallPoint = AffineReference.toEcPoint(small, params);
            ECPoint mixedPoint = AffineReference.toEcPoint(mixed, params);
            ECPoint subgroup = AffineReference.toEcPoint(subgroupPoint, params);

            // точка порядка 2 удваивается в бесконечность (y = 0), порядка 4 - в точку порядка 2
            assertSamePoint(
                    ref.add(small, small), smallPoint.add(smallPoint), "T + T, порядок " + order);
            assertSamePoint(
                    ref.add(mixed, mixed), mixedPoint.add(mixedPoint), "M + M, порядок " + order);
            assertSamePoint(
                    ref.add(mixed, small), mixedPoint.add(smallPoint), "M + T, порядок " + order);
            assertSamePoint(
                    ref.add(subgroupPoint, small),
                    subgroup.add(smallPoint),
                    "Q + T, порядок " + order);
        }
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("add: бесконечность вида (X, Y, 0) как операнд ведёт себя как O")
    void addInfinityWithNonZeroCoordinates(ECParameters params) {
        AffineReference ref = new AffineReference(params);
        BigInteger[] g = basePoint(params);
        BigInteger[] q = ref.multiply(SECOND_POINT_SCALAR, g);
        ECPoint pointP = AffineReference.toEcPoint(g, params);
        ECPoint pointQ = AffineReference.toEcPoint(q, params);
        // P + (-P): Z3 = 0 при произвольных X3, Y3; для A-256/C-512 раньше здесь были нули
        ECPoint infinity = pointP.add(AffineReference.toEcPoint(ref.negate(g), params));
        assertTrue(infinity.isInfinity(), "P + (-P) = O");
        // без ненулевых X/Y тест не отличался бы от случая (0, 0, 0) и не ловил возврат маски mNeg
        assertFalse(
                infinity.getX().signum() == 0 && infinity.getY().signum() == 0,
                "нужна бесконечность с ненулевыми X/Y, иначе тест не отличается от (0, 0, 0)");
        assertTrue(infinity.add(infinity).isInfinity(), "(X, Y, 0) + (X, Y, 0) = O");
        assertSamePoint(q, infinity.add(pointQ), "(X, Y, 0) + Q");
        assertSamePoint(q, pointQ.add(infinity), "Q + (X, Y, 0)");
        assertSamePoint(q, infinity.addDistinct(pointQ), "addDistinct: (X, Y, 0) + Q");
        assertSamePoint(q, pointQ.addDistinct(infinity), "addDistinct: Q + (X, Y, 0)");
    }
}
