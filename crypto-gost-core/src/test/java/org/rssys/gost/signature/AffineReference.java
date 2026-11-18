package org.rssys.gost.signature;

import java.math.BigInteger;

/**
 * Эталонная аффинная арифметика на {@link BigInteger} для проверки {@link ECPoint}.
 *
 * <p>Не использует {@code FieldElement} и {@code ECPoint}: иначе ошибка в проверяемой
 * арифметике (в частности в {@code twice()} и {@code add()}) попала бы и в ожидаемое значение.
 * Время выполнения не важно, поэтому ветвления по значениям допустимы. Бесконечность
 * представлена {@code null}.
 */
final class AffineReference {

    private final BigInteger p;
    private final BigInteger a;

    AffineReference(ECParameters params) {
        this.p = params.p;
        this.a = params.a;
    }

    /** Складывает две точки; корректно обрабатывает бесконечность, {@code P + (-P)} и {@code P == Q}. */
    BigInteger[] add(BigInteger[] first, BigInteger[] second) {
        if (first == null) return second;
        if (second == null) return first;
        BigInteger lambda;
        if (first[0].equals(second[0])) {
            // одинаковый x: либо P == -Q (в том числе y == 0), либо P == Q
            if (first[1].add(second[1]).mod(p).signum() == 0) return null;
            lambda =
                    first[0].pow(2)
                            .multiply(BigInteger.valueOf(3))
                            .add(a)
                            .multiply(first[1].shiftLeft(1).modInverse(p))
                            .mod(p);
        } else {
            lambda =
                    second[1]
                            .subtract(first[1])
                            .multiply(second[0].subtract(first[0]).mod(p).modInverse(p))
                            .mod(p);
        }
        BigInteger x3 = lambda.pow(2).subtract(first[0]).subtract(second[0]).mod(p);
        BigInteger y3 = lambda.multiply(first[0].subtract(x3)).subtract(first[1]).mod(p);
        return new BigInteger[] {x3, y3};
    }

    /** Вычисляет {@code k·P} обычным double-and-add слева направо. */
    BigInteger[] multiply(BigInteger k, BigInteger[] point) {
        BigInteger[] result = null;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            result = add(result, result);
            if (k.testBit(i)) result = add(result, point);
        }
        return result;
    }

    /** Точка {@code -P}. */
    BigInteger[] negate(BigInteger[] point) {
        if (point == null) return null;
        return new BigInteger[] {point[0], p.subtract(point[1]).mod(p)};
    }

    /** Проверяет принадлежность точки кривой (бесконечность считается принадлежащей). */
    boolean isOnCurve(BigInteger[] point, ECParameters params) {
        if (point == null) return true;
        BigInteger lhs = point[1].pow(2).mod(p);
        BigInteger rhs = point[0].pow(3).add(a.multiply(point[0])).add(params.b).mod(p);
        return lhs.equals(rhs);
    }

    /** Переводит эталонную точку в {@link ECPoint}; {@code null} превращается в бесконечность. */
    static ECPoint toEcPoint(BigInteger[] point, ECParameters params) {
        if (point == null) return ECPoint.infinity(params);
        return ECPoint.affine(point[0], point[1], params);
    }

    /** Переводит {@link ECPoint} в эталонное представление; бесконечность превращается в {@code null}. */
    static BigInteger[] fromEcPoint(ECPoint point) {
        if (point.isInfinity()) return null;
        ECPoint normalized = point.normalize();
        return new BigInteger[] {normalized.getX(), normalized.getY()};
    }
}
