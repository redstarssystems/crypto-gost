package org.rssys.gost.tls13.message;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.util.Pack;

/**
 * Утилиты кодирования для TLS 1.3 с ГОСТ (RFC 9367).
 * <p>
 * ECDHE shared secret, кодирование точек, кодирование целых чисел.
 */
public final class TlsEncoding {

    private TlsEncoding() {}

    /**
     * Кодирует публичный ключ в TLS wire format.
     * RFC 9367 §3.4: X||Y, обе координаты в little-endian.
     *
     * @param pub публичный ключ
     * @return закодированная точка (X || Y, little-endian)
     */
    public static byte[] encodePoint(PublicKeyParameters pub) {
        ECPoint q = pub.getQ();
        byte[] x = Pack.reverseBytes(Pack.toFixedLengthBigEndian(q.getX(), pub.getParams().hlen));
        byte[] y = Pack.reverseBytes(Pack.toFixedLengthBigEndian(q.getY(), pub.getParams().hlen));
        byte[] result = new byte[x.length + y.length];
        System.arraycopy(x, 0, result, 0, x.length);
        System.arraycopy(y, 0, result, x.length, y.length);
        return result;
    }

    /**
     * Декодирует публичный ключ из TLS wire format.
     * RFC 9367 §6.1.1.3: ровно {@code X[coordinate_length] || Y[coordinate_length]}, обе
     * координаты в little-endian. Лишние байты и координаты вне {@code [0, p)} отвергаются:
     * иначе один ключ имел бы несколько кодировок.
     *
     * @param encoded закодированная точка (X || Y, little-endian)
     * @param params  параметры эллиптической кривой
     * @return публичный ключ
     * @throws TlsException decode_error, если длина не равна {@code 2·hlen}; handshake_failure,
     *                      если координата не меньше модуля поля, точка не на кривой или не
     *                      принадлежит подгруппе порядка n
     */
    public static PublicKeyParameters decodePoint(byte[] encoded, ECParameters params)
            throws TlsException {
        int hlen = params.hlen;
        if (encoded.length != 2 * hlen) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "ECDHE key has invalid length: "
                            + encoded.length
                            + " bytes, expected "
                            + (2 * hlen));
        }
        byte[] xLe = new byte[hlen];
        byte[] yLe = new byte[hlen];
        System.arraycopy(encoded, 0, xLe, 0, hlen);
        System.arraycopy(encoded, hlen, yLe, 0, hlen);
        byte[] xBe = Pack.reverseBytes(xLe);
        byte[] yBe = Pack.reverseBytes(yLe);
        BigInteger x = new BigInteger(1, xBe);
        BigInteger y = new BigInteger(1, yBe);
        ECPoint q;
        try {
            q = ECPoint.affine(x, y, params);
        } catch (IllegalArgumentException e) {
            // тот же алерт, что и для точки не на кривой: это недопустимый ключ, а не
            // нарушение формата сообщения
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "ECDHE public key coordinate is not less than the field modulus");
        }
        try {
            // принадлежность кривой и подгруппе проверяет конструктор PublicKeyParameters
            return new PublicKeyParameters(q, params);
        } catch (IllegalArgumentException e) {
            throw new TlsException(
                    TlsConstants.ALERT_HANDSHAKE_FAILURE,
                    "ECDHE public key point is not on the curve or not in the prime-order subgroup");
        }
    }

    /**
     * Кодирует 16-битное целое в big-endian (2 байта).
     * Используется для длин полей и type-кодов.
     *
     * @param out   выходной поток
     * @param value 16-битное значение
     */
    public static void encodeUint16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    /**
     * Кодирует 24-битное целое в big-endian (3 байта).
     * Используется для длины handshake-сообщений (RFC 8446 §4).
     *
     * @param out   выходной поток
     * @param value 24-битное значение
     */
    public static void encodeUint24(ByteArrayOutputStream out, int value) {
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    /**
     * Кодирует 32-битное целое в big-endian (4 байта).
     * Используется для ticket_lifetime, ticket_age_add и obfuscated_ticket_age.
     *
     * @param out   выходной поток
     * @param value 32-битное значение
     */
    static void encodeUint32(ByteArrayOutputStream out, long value) {
        out.write((int) (value >>> 24) & 0xFF);
        out.write((int) (value >>> 16) & 0xFF);
        out.write((int) (value >>> 8) & 0xFF);
        out.write((int) value & 0xFF);
    }

    /**
     * Кодирует TLS extension: type(2) || data_len(2) || data.
     * RFC 8446 §4.2: каждое расширение — это 2-байтовый type и 2-байтовая длина.
     *
     * @param out  выходной поток
     * @param type тип расширения
     * @param data тело расширения
     */
    static void encodeExtension(ByteArrayOutputStream out, int type, byte[] data) {
        encodeUint16(out, type);
        encodeUint16(out, data.length);
        out.write(data, 0, data.length);
    }

    /** Padding перед контекстной строкой CertificateVerify (RFC 8446 §4.4.3). */
    private static final int CV_PADDING_LEN = 64;

    /**
     * Строит sigContent для CertificateVerify с указанной контекстной строкой (RFC 8446 §4.4.3).
     * <p>
     * Позволяет выбрать серверный или клиентский контекст (RFC 8446 §4.4.3):
     * <pre>
     * sigContent = 0x20 * 64 || context_string || 0x00 || Transcript-Hash
     * </pre>
     *
     * @param transcriptHash Transcript-Hash handshake-сообщений до CertificateVerify
     * @param contextString контекстная строка (серверная или клиентская)
     * @return массив sigContent (CV_PADDING_LEN + ctx.length + 1 + hashLen)
     */
    public static byte[] buildSigContent(byte[] transcriptHash, String contextString) {
        byte[] ctx = contextString.getBytes(StandardCharsets.US_ASCII);
        byte[] sigContent = new byte[CV_PADDING_LEN + ctx.length + 1 + transcriptHash.length];
        Arrays.fill(sigContent, 0, CV_PADDING_LEN, (byte) 0x20);
        System.arraycopy(ctx, 0, sigContent, CV_PADDING_LEN, ctx.length);
        sigContent[CV_PADDING_LEN + ctx.length] = 0;
        System.arraycopy(
                transcriptHash,
                0,
                sigContent,
                CV_PADDING_LEN + ctx.length + 1,
                transcriptHash.length);
        return sigContent;
    }
}
