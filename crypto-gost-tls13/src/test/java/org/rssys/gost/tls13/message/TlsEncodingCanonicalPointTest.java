package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.util.Pack;

/**
 * RFC 9367 §6.1.1.3: точка кодируется ровно как {@code X[coordinate_length] || Y[coordinate_length]}
 * в little-endian; координата не меньше модуля поля или лишние байты дали бы второе представление
 * того же ключа.
 */
@DisplayName("TlsEncoding.decodePoint: точная длина и канонические координаты")
class TlsEncodingCanonicalPointTest {

    static Stream<Arguments> curves() {
        return Stream.of(
                Arguments.of("TC26-A-256", ECParameters.tc26a256()),
                Arguments.of("CryptoPro-A", ECParameters.cryptoProA()),
                Arguments.of("CryptoPro-B", ECParameters.cryptoProB()),
                Arguments.of("CryptoPro-C", ECParameters.cryptoProC()),
                Arguments.of("TC26-A-512", ECParameters.tc26a512()),
                Arguments.of("TC26-B-512", ECParameters.tc26b512()),
                Arguments.of("TC26-C-512", ECParameters.tc26c512()));
    }

    private static byte[] wire(BigInteger x, BigInteger y, ECParameters params) {
        int hlen = params.hlen;
        byte[] result = new byte[2 * hlen];
        byte[] xLe = Pack.reverseBytes(Pack.toFixedLengthBigEndian(x, hlen));
        byte[] yLe = Pack.reverseBytes(Pack.toFixedLengthBigEndian(y, hlen));
        System.arraycopy(xLe, 0, result, 0, hlen);
        System.arraycopy(yLe, 0, result, hlen, hlen);
        return result;
    }

    /** Точка подгруппы n с малым x (у генераторов с малым gx это G; иначе поиск при p = 3 mod 4). */
    private static ECPoint pointWithSmallX(ECParameters params) {
        BigInteger limit = BigInteger.ONE.shiftLeft(params.hlen * Byte.SIZE).subtract(params.p);
        if (params.gx.compareTo(limit) < 0) {
            return ECPoint.affine(params.gx, params.gy, params).normalize();
        }
        BigInteger p = params.p;
        assertEquals(3, p.mod(BigInteger.valueOf(4)).intValue(), "ожидается p = 3 (mod 4)");
        BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
        for (BigInteger x = BigInteger.ONE; x.compareTo(limit) < 0; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(p);
            BigInteger y = rhs.modPow(exponent, p);
            if (y.multiply(y).mod(p).equals(rhs)) {
                ECPoint candidate = ECPoint.affine(x, y, params);
                if (candidate.isValidPublicKey()) {
                    return candidate.normalize();
                }
            }
        }
        fail("точка с малым x в подгруппе n не найдена");
        return null;
    }

    private static void assertAlert(
            byte expected, byte[] encoded, ECParameters params, String msg) {
        TlsException e =
                assertThrows(
                        TlsException.class, () -> TlsEncoding.decodePoint(encoded, params), msg);
        assertEquals(expected, e.getAlertCode(), msg + ": неверный код alert");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Каноническая точка принимается и кодируется обратно теми же байтами")
    void canonicalPointAccepted(String name, ECParameters params) throws Exception {
        ECPoint point = pointWithSmallX(params);
        byte[] encoded = wire(point.getX(), point.getY(), params);
        PublicKeyParameters decoded = TlsEncoding.decodePoint(encoded, params);
        assertArrayEquals(encoded, TlsEncoding.encodePoint(decoded), "кодирование не обратимо");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("x + p отвергается с handshake_failure")
    void xPlusPRejected(String name, ECParameters params) {
        ECPoint point = pointWithSmallX(params);
        BigInteger shiftedX = point.getX().add(params.p);
        assertTrue(
                shiftedX.bitLength() <= params.hlen * Byte.SIZE,
                "предусловие: x + p помещается в поле байт");
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(shiftedX, point.getY(), params),
                params,
                "x + p");
    }

    /** Точка на кривой с кофактором 4, не входящая в подгруппу n (p = 3 mod 4). */
    private static ECPoint pointOutsideSubgroup(ECParameters params) {
        BigInteger p = params.p;
        assertEquals(3, p.mod(BigInteger.valueOf(4)).intValue(), "ожидается p = 3 (mod 4)");
        BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
        for (BigInteger x = BigInteger.ONE; x.bitLength() < 32; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(p);
            BigInteger y = rhs.modPow(exponent, p);
            if (y.multiply(y).mod(p).equals(rhs)) {
                ECPoint candidate = ECPoint.affine(x, y, params);
                if (!candidate.multiply(params.n).isInfinity()) {
                    return candidate.normalize();
                }
            }
        }
        fail("точка вне подгруппы n не найдена");
        return null;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cofactorFourCurves")
    @DisplayName("Точка на кривой, но вне подгруппы n, отвергается с handshake_failure")
    void pointOutsideSubgroupRejected(String name, ECParameters params) {
        ECPoint point = pointOutsideSubgroup(params);
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(point.getX(), point.getY(), params),
                params,
                "точка вне подгруппы");
    }

    static Stream<Arguments> cofactorFourCurves() {
        return curves().filter(a -> ((ECParameters) a.get()[1]).cofactor == 4);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("x = p, y = p и y = p + 1 отвергаются с handshake_failure")
    void boundaryCoordinatesRejected(String name, ECParameters params) {
        ECPoint point = pointWithSmallX(params);
        BigInteger p = params.p;
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(p, point.getY(), params),
                params,
                "x = p");
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(point.getX(), p, params),
                params,
                "y = p");
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(point.getX(), p.add(BigInteger.ONE), params),
                params,
                "y = p + 1");
    }

    /** Кривые, где {@code gy + p} помещается в поле байт: у остальных другой кодировки нет. */
    static Stream<Arguments> curvesWithLargeYWindow() {
        return curves().filter(
                        arguments -> {
                            ECParameters params = (ECParameters) arguments.get()[1];
                            return params.gy.add(params.p).bitLength() <= params.hlen * Byte.SIZE;
                        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curvesWithLargeYWindow")
    @DisplayName("y + p отвергается там, где окно велико (малый gy)")
    void yPlusPRejectedWhereWindowIsLarge(String name, ECParameters params) {
        BigInteger shiftedY = params.gy.add(params.p);
        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                wire(params.gx, shiftedY, params),
                params,
                "y + p");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Короткая и длинная точка отвергаются с decode_error")
    void wrongLengthRejected(String name, ECParameters params) {
        ECPoint point = pointWithSmallX(params);
        byte[] valid = wire(point.getX(), point.getY(), params);
        byte[] shorter = new byte[valid.length - 1];
        System.arraycopy(valid, 0, shorter, 0, shorter.length);
        byte[] longer = new byte[valid.length + 1];
        System.arraycopy(valid, 0, longer, 0, valid.length);

        assertAlert(TlsConstants.ALERT_DECODE_ERROR, shorter, params, "короткая точка");
        assertAlert(TlsConstants.ALERT_DECODE_ERROR, longer, params, "лишний байт");
        assertAlert(TlsConstants.ALERT_DECODE_ERROR, new byte[0], params, "пустая точка");
    }
}
