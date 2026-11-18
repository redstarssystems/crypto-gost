package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты граничных значений d в конструкторе {@link PrivateKeyParameters}.
 * <p>
 * Конструктор должен reject d ≤ 0 и d ≥ n, accept 0 < d < n.
 * Диапазон проверяется по исходному значению: отрицательные и слишком длинные d отвергаются,
 * а не усекаются до rolen байт.
 */
@DisplayName("PrivateKeyParameters: граничные значения d")
class PrivateKeyParametersTest {

    private static final ECParameters[] CURVES = {
        ECParameters.cryptoProA(), ECParameters.tc26a256(), ECParameters.tc26c512()
    };

    // ========================================================================
    // reject: d вне допустимого диапазона
    // ========================================================================

    @Test
    @DisplayName("d = 0 -> IllegalArgumentException")
    void testRejectDZero() {
        for (ECParameters p : CURVES) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(BigInteger.ZERO, p),
                    "d=0 должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = n -> IllegalArgumentException")
    void testRejectDEqualsN() {
        for (ECParameters p : CURVES) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(p.n, p),
                    "d=n должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = n+1 -> IllegalArgumentException")
    void testRejectDGreaterThanN() {
        for (ECParameters p : CURVES) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(p.n.add(BigInteger.ONE), p),
                    "d=n+1 должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("d = -1 -> IllegalArgumentException (знак не теряется при нормализации)")
    void testRejectDNegative() {
        for (ECParameters p : CURVES) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(BigInteger.valueOf(-1), p),
                    "d=-1 должен быть отвергнут, а не превращён в 255: " + p.n);
        }
    }

    @Test
    @DisplayName("d = 2^(8·rolen)+5 -> IllegalArgumentException (старшие байты не усекаются)")
    void testRejectDOversizedNotTruncated() {
        for (ECParameters p : CURVES) {
            int rolen = (p.n.bitLength() + 7) / 8;
            BigInteger oversized = BigInteger.ONE.shiftLeft(8 * rolen).add(BigInteger.valueOf(5));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(oversized, p),
                    "d длиннее rolen байт должен быть отвергнут, а не усечён до 5: " + p.n);
        }
    }

    @Test
    @DisplayName(
            "маскированный I = K_M + M·2^(8n) на входе конструктора -> IllegalArgumentException")
    void testRejectDMaskedValueFromConstructor() {
        for (ECParameters p : CURVES) {
            int rolen = (p.n.bitLength() + 7) / 8;
            BigInteger km = p.n.subtract(BigInteger.TWO);
            BigInteger mask = BigInteger.valueOf(0x1234_5678L);
            BigInteger combined = mask.shiftLeft(8 * rolen).add(km);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PrivateKeyParameters(combined, p),
                    "значение K_M + M·2^(8n) не должно усекаться до K_M: " + p.n);
        }
    }

    @Test
    @DisplayName("d со старшим битом (toByteArray даёт ведущий 0x00) -> принимается без изменений")
    void testAcceptDWithHighBitSigned() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.subtract(BigInteger.ONE);
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(d, priv.getD(), "d = n-1 должен сохраниться без искажений: " + p.n);
            priv.destroy();
        }
    }

    // ========================================================================
    // accept: d внутри допустимого диапазона
    // ========================================================================

    @Test
    @DisplayName("d = 1 -> принимается, getD() == 1")
    void testAcceptDOne() {
        for (ECParameters p : CURVES) {
            PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.ONE, p);
            assertEquals(
                    0,
                    BigInteger.ONE.compareTo(priv.getD()),
                    "getD() должен вернуть 1 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n-1 -> принимается, getD() == n-1")
    void testAcceptDNminus1() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.subtract(BigInteger.ONE);
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(
                    0, d.compareTo(priv.getD()), "getD() должен вернуть n-1 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n-2 -> принимается, getD() == n-2")
    void testAcceptDNminus2() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.subtract(BigInteger.valueOf(2));
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(
                    0, d.compareTo(priv.getD()), "getD() должен вернуть n-2 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = 2 -> принимается, getD() == 2")
    void testAcceptDTwo() {
        for (ECParameters p : CURVES) {
            PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.valueOf(2), p);
            assertEquals(
                    0,
                    BigInteger.valueOf(2).compareTo(priv.getD()),
                    "getD() должен вернуть 2 для кривой: " + p.n);
            priv.destroy();
        }
    }

    @Test
    @DisplayName("d = n/2 -> accept (типичное значение)")
    void testAcceptDHalf() {
        for (ECParameters p : CURVES) {
            BigInteger d = p.n.shiftRight(1);
            PrivateKeyParameters priv = new PrivateKeyParameters(d, p);
            assertEquals(
                    0, d.compareTo(priv.getD()), "getD() должен вернуть n/2 для кривой: " + p.n);
            priv.destroy();
        }
    }
}
