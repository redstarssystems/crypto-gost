package org.rssys.gost.signature;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты граничных значений d в конструкторе {@link PrivateKeyParameters}.
 * <p>
 * Конструктор должен reject d ≤ 0 и d ≥ n, accept 0 < d < n.
 * Отрицательные d теряют знак при toByteArray() → нормализуются в положительные.
 */
@DisplayName("PrivateKeyParameters: граничные значения d")
class PrivateKeyParametersTest {

    private static final ECParameters[] CURVES = {
            ECParameters.cryptoProA(),
            ECParameters.tc26a256(),
            ECParameters.tc26c512()
    };

    // ========================================================================
    // reject: d вне допустимого диапазона
    // ========================================================================

    @Test
    @DisplayName("d = 0 → IllegalArgumentException")
    void testRejectDZero() {
        for (ECParameters p : CURVES) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(BigInteger.ZERO, p),
                    "d=0 должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = n → IllegalArgumentException")
    void testRejectDEqualsN() {
        for (ECParameters p : CURVES) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(p.n, p),
                    "d=n должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = n+1 → IllegalArgumentException")
    void testRejectDGreaterThanN() {
        for (ECParameters p : CURVES) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(p.n.add(BigInteger.ONE), p),
                    "d=n+1 должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = -1 → accept (toByteArray() теряет знак, 0xFF нормализуется в 255)")
    void testAcceptDNegativeNormalizes() {
        for (ECParameters p : CURVES) {
            PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.valueOf(-1), p);
            // -1 → [0xFF] → new BigInteger(1, [0xFF]) = 255
            assertEquals(255, priv.getD().intValue(),
                    "d=-1 после нормализации byte[] должен стать 255: " + p.n);
            priv.destroy();
        }
    }

    // ========================================================================
    // accept: d внутри допустимого диапазона
    // ========================================================================

    @Test
    @DisplayName("d = 1 → accept, getD() == 1")
    void testAcceptDOne() {
        for (ECParameters p : CURVES) {
            PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.ONE, p);
            assertEquals(0, BigInteger.ONE.compareTo(priv.getD()),
                    "getD() должен вернуть 1 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n-1 → accept, getD() == n-1")
    void testAcceptDNminus1() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.subtract(BigInteger.ONE);
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(0, d.compareTo(priv.getD()),
                    "getD() должен вернуть n-1 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n-2 → accept, getD() == n-2")
    void testAcceptDNminus2() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.subtract(BigInteger.valueOf(2));
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(0, d.compareTo(priv.getD()),
                    "getD() должен вернуть n-2 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = 2 → accept, getD() == 2")
    void testAcceptDTwo() {
        for (ECParameters p : CURVES) {
            PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.valueOf(2), p);
            assertEquals(0, BigInteger.valueOf(2).compareTo(priv.getD()),
                    "getD() должен вернуть 2 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n/2 → accept (типичное значение)")
    void testAcceptDHalf() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.shiftRight(1);
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(0, d.compareTo(priv.getD()),
                    "getD() должен вернуть n/2 для кривой: " + p.n);
            priv.destroy();
        }
    }
}
