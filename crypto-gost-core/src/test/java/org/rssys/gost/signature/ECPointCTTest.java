package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ECPoint constant-time: twice() без data-dependent ветвлений")
class ECPointCTTest {

    @Test
    @DisplayName("twice(∞) = ∞ — арифметика выполняется, результат корректен")
    void testTwiceInfinity() {
        ECParameters p = ECParameters.tc26a256();
        ECPoint inf = ECPoint.infinity(p);

        // После фикса twice() не имеет early-return,
        // но должен корректно возвращать ∞.
        ECPoint r = inf.twice();
        assertTrue(r.isInfinity(), "twice(∞) = ∞");
    }

    @Test
    @DisplayName("multiply: малый и большой скаляр — корректные результаты")
    void testMultiplyEdgeScalars() {
        ECParameters p = ECParameters.tc26a256();
        ECPoint G = ECPoint.affine(p.gx, p.gy, p);

        BigInteger k3 = BigInteger.valueOf(3);
        BigInteger kMid = BigInteger.ONE.shiftLeft(128);
        BigInteger kHigh = p.n.subtract(BigInteger.ONE);
        BigInteger kHalf = p.n.shiftRight(1);

        // (n-1)*G = -G -> нормализованный должен быть на кривой, не ∞
        // (n-1)*G + G = n*G = ∞ -> (n-1)*G != ∞
        ECPoint rHigh = G.multiply(kHigh).normalize();
        assertFalse(rHigh.isInfinity(), "(n-1)*G ≠ ∞");
        // (n-1)*G + G = ∞
        assertTrue(rHigh.add(G).normalize().isInfinity(), "(n-1)*G + G = ∞");

        // n/2 * G ≠ ∞
        ECPoint rHalf = G.multiply(kHalf).normalize();
        assertFalse(rHalf.isInfinity(), "(n/2)*G ≠ ∞");

        // 3*G ≠ ∞
        ECPoint r3 = G.multiply(k3).normalize();
        assertFalse(r3.isInfinity(), "3*G ≠ ∞");

        // 3*G + (n-4)*G = (n-1)*G = -G
        BigInteger kHigh2 = p.n.subtract(BigInteger.valueOf(4));
        ECPoint rHigh2 = G.multiply(kHigh2).normalize();
        ECPoint sum = r3.add(rHigh2).normalize();
        assertFalse(sum.isInfinity(), "3*G + (n-4)*G ≠ ∞");
        // (3*G + (n-4)*G) + G = n*G = ∞
        assertTrue(sum.add(G).normalize().isInfinity(), "3*G + (n-4)*G + G = ∞");

        // 2^128 * G ≠ ∞ (проверка что mid скаляр даёт корректную точку на кривой)
        ECPoint rMid = G.multiply(kMid).normalize();
        assertTrue(rMid.isOnCurve(), "2^128*G на кривой");
    }

    @Test
    @DisplayName("Все кривые: multiply(k) даёт точки на кривой")
    void testMultiplyOnAllCurves() {
        ECParameters[] curves = {
            ECParameters.tc26a256(),
            ECParameters.tc26a512(),
            ECParameters.tc26b512(),
            ECParameters.tc26c512(),
            ECParameters.cryptoProA(),
            ECParameters.cryptoProB(),
            ECParameters.cryptoProC()
        };
        BigInteger[] scalars = {
            BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.ONE.shiftLeft(128),
        };
        for (ECParameters p : curves) {
            ECPoint G = ECPoint.affine(p.gx, p.gy, p);
            for (BigInteger k : scalars) {
                if (k.compareTo(p.n) >= 0) continue;
                ECPoint r = G.multiply(k).normalize();
                assertTrue(
                        r.isOnCurve(),
                        "k*G на кривой: " + p.p.toString(16).substring(0, 8) + "... k=" + k);
            }
        }
    }

    @Test
    @DisplayName("multiply(k): n*G = ∞ для всех кривых")
    void testOrderOfBasePoint() {
        ECParameters[] curves = {
            ECParameters.tc26a256(),
            ECParameters.tc26a512(),
            ECParameters.tc26b512(),
            ECParameters.tc26c512(),
        };
        for (ECParameters p : curves) {
            ECPoint G = ECPoint.affine(p.gx, p.gy, p);
            ECPoint r = G.multiply(p.n).normalize();
            assertTrue(r.isInfinity(), "n*G = ∞: " + p.p.toString(16).substring(0, 8) + "...");
        }
    }
}
