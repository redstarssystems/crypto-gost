package org.rssys.gost.signature;

import java.math.BigInteger;
import java.util.Arrays;

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
     */
    public static byte[] encode(BigInteger r, BigInteger s, ECParameters params) {
        int rolen  = (params.n.bitLength() + 7) / 8;
        byte[] out = new byte[2 * rolen];
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        int rLen = Math.min(rBytes.length, rolen);
        int sLen = Math.min(sBytes.length, rolen);
        System.arraycopy(sBytes, Math.max(0, sBytes.length - sLen), out, rolen - sLen,     sLen);
        System.arraycopy(rBytes, Math.max(0, rBytes.length - rLen), out, 2 * rolen - rLen, rLen);
        return out;
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
        int rolen = (params.n.bitLength() + 7) / 8;
        if (signature == null || signature.length != 2 * rolen) {
            throw new IllegalArgumentException(
                "Invalid signature length: expected " + (2 * rolen) + " bytes, got "
                + (signature == null ? "null" : signature.length));
        }
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 0,     rolen));
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, rolen, 2 * rolen));
        return new BigInteger[]{r, s};
    }
}
