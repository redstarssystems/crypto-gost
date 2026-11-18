package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPublicKeySpec;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;

/**
 * Координаты открытого ключа обязаны лежать в {@code [0, p)}: приведение по модулю p принимало бы
 * {@code (x + p, y)} и отрицательные значения как тот же ключ с другой кодировкой.
 */
@DisplayName("Канонические координаты открытого ключа: ECPoint.affine и KeyFactory")
@ExtendWith(JcaTestSupport.class)
class CanonicalPublicKeyCoordinatesTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    static Stream<Arguments> curves() {
        return Stream.of(
                Arguments.of(GostCurves.OID_TC26_A_256),
                Arguments.of(GostCurves.OID_CRYPTOPRO_A),
                Arguments.of(GostCurves.OID_CRYPTOPRO_B),
                Arguments.of(GostCurves.OID_CRYPTOPRO_C),
                Arguments.of(GostCurves.OID_TC26_A_512),
                Arguments.of(GostCurves.OID_TC26_B_512),
                Arguments.of(GostCurves.OID_TC26_C_512));
    }

    private static KeyFactory keyFactory() throws Exception {
        return KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
    }

    private static int bitsOf(ECParameters params) {
        return params.hlen * Byte.SIZE;
    }

    /**
     * Точка подгруппы n с малым x, чтобы {@code x + p} помещалось в поле байт. Для генераторов
     * с малым gx это сам G; для TC26-A-256 и TC26-C-512 точка ищется (у них p = 3 mod 4).
     */
    private static ECPoint pointWithSmallX(ECParameters params) {
        BigInteger limit = BigInteger.ONE.shiftLeft(bitsOf(params)).subtract(params.p);
        ECPoint generator = ECPoint.affine(params.gx, params.gy, params);
        if (params.gx.compareTo(limit) < 0) {
            return generator;
        }
        BigInteger p = params.p;
        assertEquals(3, p.mod(BigInteger.valueOf(4)).intValue(), "ожидается p = 3 (mod 4)");
        BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
        for (BigInteger x = BigInteger.ONE; x.compareTo(limit) < 0; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(p);
            BigInteger y = rhs.modPow(exponent, p);
            if (!y.multiply(y).mod(p).equals(rhs)) {
                continue;
            }
            ECPoint candidate = ECPoint.affine(x, y, params);
            if (candidate.isValidPublicKey()) {
                return candidate.normalize();
            }
        }
        fail("точка с малым x в подгруппе n не найдена");
        return null;
    }

    private static void assertKeyFactoryRejects(
            String curveOid, BigInteger x, BigInteger y, String message) throws Exception {
        KeyFactory factory = keyFactory();
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.generatePublic(new GostECPublicKeySpec(x, y, curveOid)),
                message);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("x + p отвергается и в affine, и в KeyFactory; исходная точка принимается")
    void xPlusPRejected(String curveOid) throws Exception {
        ECParameters params = GostCurves.byName(curveOid);
        ECPoint point = pointWithSmallX(params);
        BigInteger x = point.normalize().getX();
        BigInteger y = point.normalize().getY();
        assertTrue(
                x.add(params.p).bitLength() <= bitsOf(params),
                "предусловие: x + p помещается в поле байт");

        assertNotNull(
                keyFactory().generatePublic(new GostECPublicKeySpec(x, y, curveOid)),
                "каноническая точка должна приниматься");
        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(x.add(params.p), y, params),
                "affine принял x + p");
        assertKeyFactoryRejects(curveOid, x.add(params.p), y, "KeyFactory принял x + p");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("y + p отвергается на всех кривых: GostECPublicKeySpec не ограничивает длину")
    void yPlusPRejected(String curveOid) throws Exception {
        ECParameters params = GostCurves.byName(curveOid);
        BigInteger shiftedY = params.gy.add(params.p);

        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(params.gx, shiftedY, params),
                "affine принял y + p");
        assertKeyFactoryRejects(curveOid, params.gx, shiftedY, "KeyFactory принял y + p");
        assertNotNull(
                keyFactory()
                        .generatePublic(new GostECPublicKeySpec(params.gx, params.gy, curveOid)),
                "каноническая точка G должна приниматься");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("y = p и y = p + 1 отвергаются на всех кривых (границы, не зависящие от окна)")
    void yAtOrAboveModulusRejected(String curveOid) throws Exception {
        ECParameters params = GostCurves.byName(curveOid);
        for (BigInteger y : new BigInteger[] {params.p, params.p.add(BigInteger.ONE)}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> ECPoint.affine(params.gx, y, params),
                    "affine принял y >= p");
            assertKeyFactoryRejects(curveOid, params.gx, y, "KeyFactory принял y >= p");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("x = p, x = p + 1 и отрицательные координаты отвергаются")
    void modulusAndNegativeRejected(String curveOid) throws Exception {
        ECParameters params = GostCurves.byName(curveOid);
        assertKeyFactoryRejects(curveOid, params.p, params.gy, "KeyFactory принял x = p");
        assertKeyFactoryRejects(
                curveOid, params.p.add(BigInteger.ONE), params.gy, "KeyFactory принял x = p + 1");
        assertKeyFactoryRejects(
                curveOid, params.gx.negate().subtract(BigInteger.ONE), params.gy, "x < 0");
        assertKeyFactoryRejects(
                curveOid, params.gx, params.gy.negate().subtract(BigInteger.ONE), "y < 0");
        // границы прямо на affine: кривая здесь не проверяется, поэтому результат не зависит
        // от того, лежит ли точка на кривой
        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(BigInteger.valueOf(-1), params.gy, params),
                "affine принял x < 0");
        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(params.p, params.gy, params),
                "affine принял x = p");
        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(params.gx, BigInteger.valueOf(-1), params),
                "affine принял y < 0");
        assertNotNull(
                ECPoint.affine(params.p.subtract(BigInteger.ONE), params.gy, params),
                "affine отверг x = p - 1");
    }

    @Test
    @DisplayName("Границы диапазона 0 и p - 1 допустимы для affine (кривая не проверяется)")
    void coordinateRangeBoundariesAccepted() {
        ECParameters params = GostCurves.byName(GostCurves.OID_CRYPTOPRO_A);
        BigInteger last = params.p.subtract(BigInteger.ONE);
        assertNotNull(ECPoint.affine(last, last, params), "p - 1 лежит в диапазоне [0, p)");
        assertNotNull(
                ECPoint.affine(BigInteger.ZERO, BigInteger.ZERO, params),
                "0 лежит в диапазоне [0, p)");
    }
}
