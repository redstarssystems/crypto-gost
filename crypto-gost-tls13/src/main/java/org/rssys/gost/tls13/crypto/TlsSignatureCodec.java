package org.rssys.gost.tls13.crypto;

import java.math.BigInteger;
import java.util.function.Supplier;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Кодек подписи ГОСТ Р 34.10-2012 для TLS 1.3 (RFC 9367 §3.2).
 *
 * <p>Формат подписи: фиксированная длина, little-endian:
 * {@code sgn = str_le(r) || str_le(s)}, где каждая компонента
 * занимает {@code rolen} байт (32 для 256-битных кривых).
 * В отличие от {@code SignatureCodec} (big-endian, переменная длина),
 * этот класс использует LE-формат, требуемый RFC 9367.
 */
public final class TlsSignatureCodec {
    private TlsSignatureCodec() {}

    /**
     * Кодирует компоненты подписи r и s в формат little-endian r ∥ s.
     *
     * @param r     компонента r подписи
     * @param s     компонента s подписи
     * @param rolen длина каждой компоненты в байтах (32 для 256-бит, 64 для 512-бит)
     * @return байты подписи r ∥ s в little-endian, длина {@code 2 * rolen}
     */
    public static byte[] encode(BigInteger r, BigInteger s, int rolen) {
        if (r == null || s == null || rolen <= 0) {
            throw new IllegalArgumentException("r and s must not be null, rolen > 0");
        }
        byte[] out = new byte[2 * rolen];
        byte[] rLe = toLE(r, rolen);
        byte[] sLe = toLE(s, rolen);
        System.arraycopy(rLe, 0, out, 0, rolen);
        System.arraycopy(sLe, 0, out, rolen, rolen);
        return out;
    }

    /**
     * Декодирует подпись r ∥ s little-endian в компоненты {@link BigInteger}.
     *
     * @param sig   байты подписи r ∥ s в little-endian
     * @param rolen длина каждой компоненты в байтах
     * @return массив {@code [r, s]}
     */
    public static BigInteger[] decode(byte[] sig, int rolen) {
        if (sig == null || sig.length != 2 * rolen) {
            throw new IllegalArgumentException(
                    "Signature must be exactly "
                            + (2 * rolen)
                            + " bytes, got "
                            + (sig == null ? "null" : sig.length));
        }
        byte[] rLe = new byte[rolen];
        byte[] sLe = new byte[rolen];
        System.arraycopy(sig, 0, rLe, 0, rolen);
        System.arraycopy(sig, rolen, sLe, 0, rolen);
        BigInteger r = new BigInteger(1, reverse(rLe));
        BigInteger s = new BigInteger(1, reverse(sLe));
        return new BigInteger[] {r, s};
    }

    /**
     * Подписывает хеш с использованием ГОСТ Р 34.10-2012.
     *
     * @param hash  хеш сообщения (Streebog-256, 32 байта)
     * @param priv  закрытый ключ
     * @param rolen длина каждой компоненты подписи в байтах
     * @return подпись r ∥ s в little-endian
     */
    public static byte[] sign(byte[] hash, PrivateKeyParameters priv, int rolen) {
        if (hash == null || priv == null || rolen <= 0) {
            throw new IllegalArgumentException("hash and priv must not be null, rolen > 0");
        }
        ECParameters params = priv.getParams();
        Supplier<org.rssys.gost.digest.Digest> factory = digestFactory(params);
        ECDSASigner rawSigner = new ECDSASigner(factory);
        rawSigner.init(true, priv);
        try {
            BigInteger[] rs = rawSigner.generateSignature(hash);
            return encode(rs[0], rs[1], rolen);
        } finally {
            rawSigner.destroy();
        }
    }

    /**
     * Верифицирует подпись ГОСТ Р 34.10-2012.
     *
     * @param hash    хеш сообщения (Streebog-256, 32 байта)
     * @param sigBytes подпись r ∥ s в little-endian
     * @param pub     открытый ключ
     * @param rolen   длина каждой компоненты подписи в байтах
     * @return true если подпись действительна
     */
    public static boolean verify(byte[] hash, byte[] sigBytes, PublicKeyParameters pub, int rolen) {
        if (hash == null || pub == null || rolen <= 0) {
            throw new IllegalArgumentException("hash, pub must not be null, rolen > 0");
        }
        ECParameters params = pub.getParams();
        Supplier<org.rssys.gost.digest.Digest> factory = digestFactory(params);
        ECDSASigner rawSigner = new ECDSASigner(factory);
        rawSigner.init(false, pub);
        try {
            BigInteger[] rs = decode(sigBytes, rolen);
            return rawSigner.verifySignature(hash, rs[0], rs[1]);
        } finally {
            rawSigner.destroy();
        }
    }

    /**
     * Преобразует BigInteger в little-endian массив фиксированной длины.
     * Старшие байты BigInteger (big-endian) реверсируются, недостающие
     * дополняются нулями, лишние обрезаются.
     *
     * @return little-endian массив фиксированной длины
     */
    private static byte[] toLE(BigInteger val, int len) {
        byte[] be = val.toByteArray();
        byte[] le = new byte[len];
        int copyLen = Math.min(be.length, len);
        for (int i = 0; i < copyLen; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }

    /**
     * Реверсирует порядок байт (big-endian <-> little-endian).
     *
     * @param src исходный массив
     * @return реверсированный массив
     */
    private static byte[] reverse(byte[] src) {
        byte[] dst = new byte[src.length];
        for (int i = 0; i < src.length; i++) {
            dst[i] = src[src.length - 1 - i];
        }
        return dst;
    }

    /**
     * Фабрика дайджестов по параметрам кривой: Streebog-256 для 256-bit, Streebog-512 для 512-bit.
     *
     * @param params параметры кривой
     * @return фабрика дайджестов
     */
    private static Supplier<org.rssys.gost.digest.Digest> digestFactory(ECParameters params) {
        return params.hlen == TlsConstants.STREEBOG_256_HASH_LEN
                ? Streebog256::new
                : Streebog512::new;
    }
}
