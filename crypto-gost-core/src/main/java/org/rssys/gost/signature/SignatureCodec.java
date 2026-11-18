package org.rssys.gost.signature;

import java.math.BigInteger;
import java.util.Arrays;
import org.rssys.gost.util.Pack;

/**
 * Утилита кодирования/декодирования подписи ГОСТ Р 34.10-2012.
 *
 * <p>Формат: конкатенация s ∥ r в big-endian, каждая компонента занимает
 * {@code rolen = ceil(n.bitLength()/8)} байт.
 * Итоговая длина: 64 байта для 256-битных кривых, 128 байт для 512-битных.
 */
public final class SignatureCodec {

    private SignatureCodec() {}

    /**
     * Кодирует компоненты подписи r и s в X.509-формат s ∥ r big-endian.
     *
     * @param r      компонента r подписи
     * @param s      компонента s подписи
     * @param params параметры кривой (используется {@code n} для вычисления rolen)
     * @return байты подписи s ∥ r, длина {@code 2 * rolen}
     * @throws IllegalArgumentException если компонента отрицательна или не помещается в
     *     {@code rolen} байт (то есть не меньше {@code 2^(8*rolen)})
     */
    public static byte[] encode(BigInteger r, BigInteger s, ECParameters params) {
        int rolen = componentLength(params);
        byte[] out = new byte[2 * rolen];
        // Fail-closed: значение, не помещающееся в rolen байт, отвергается, а не усекается
        Pack.writeFixedLengthBigEndian(s, out, 0, rolen);
        Pack.writeFixedLengthBigEndian(r, out, rolen, rolen);
        return out;
    }

    /**
     * Проверяет, что подпись имеет длину {@code 2 * rolen} для заданной кривой. Длина подписи не
     * секрет, а подпись приходит из недоверенного источника, поэтому проверяющий получает
     * {@code false}, а не исключение (как для {@code r} и {@code s} вне диапазона).
     *
     * @param signature байты подписи или {@code null}
     * @param params    параметры кривой
     * @return {@code true} если подпись не {@code null} и её длина равна {@code 2 * rolen}
     */
    public static boolean hasValidLength(byte[] signature, ECParameters params) {
        return signature != null && signature.length == 2 * componentLength(params);
    }

    /** Длина одной компоненты подписи {@code rolen = ceil(n.bitLength() / 8)} в байтах. */
    private static int componentLength(ECParameters params) {
        return (params.n.bitLength() + 7) / 8;
    }

    /**
     * Декодирует подпись s ∥ r big-endian в компоненты {@link BigInteger}.
     *
     * @param signature байты подписи s ∥ r
     * @param params    параметры кривой
     * @return массив {@code [r, s]}
     * @throws IllegalArgumentException если длина подписи не равна {@code 2 * rolen}
     *         или {@code signature} равен {@code null}
     */
    public static BigInteger[] decode(byte[] signature, ECParameters params) {
        int rolen = componentLength(params);
        if (!hasValidLength(signature, params)) {
            throw new IllegalArgumentException(
                    "Invalid signature length: expected "
                            + (2 * rolen)
                            + " bytes, got "
                            + (signature == null ? "null" : signature.length));
        }
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 0, rolen));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, rolen, 2 * rolen));
        return new BigInteger[] {r, s};
    }
}
