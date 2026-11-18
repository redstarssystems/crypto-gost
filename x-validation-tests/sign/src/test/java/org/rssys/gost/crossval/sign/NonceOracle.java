package org.rssys.gost.crossval.sign;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Независимый эталон выработки нонса {@code k} для подписи ГОСТ Р 34.10-2012.
 *
 * <p>Написан заново по RFC 6979 §3.2 и ГОСТ Р 34.10-2012 на {@code HMac} и Стрибоге из
 * BouncyCastle, без классов {@code org.rssys.gost.*}: порядок кривой {@code n} и длина хэша
 * приходят аргументами из BouncyCastle. Поэтому ошибка в нашей выработке нонса, в нашем реестре
 * кривых или в переводе хэша в число {@code e} не совпадёт с ошибкой эталона.
 *
 * <p>Отличий от RFC 6979 два, оба повторяют принятое в библиотеке. Первое: вместо
 * {@code bits2octets(h1)} во вход HMAC идёт {@code int2octets(e)}, где {@code e} - число из
 * уравнения подписи {@code s = r·d + k·e}. Хэш читается младшим байтом вперёд (RFC 7091 §5.3),
 * приводится по модулю {@code n}, нуль заменяется единицей. Эталон принимает именно БАЙТЫ ХЭША и
 * сам делает весь перевод: иначе он не поймал бы дефект, при котором затравка строилась из байт
 * хэша, а не из {@code e}.
 *
 * <p>Второе: после {@code int2octets(e)} во вход HMAC добавлен идентификатор кривой
 * ({@link #curveBinding}) - дополнительные данные {@code k'} по RFC 6979 §3.6, чтобы один
 * закрытый ключ на разных кривых одной длины не давал общий нонс. Идентификатор эталон считает
 * сам, от параметров кривой из BouncyCastle, по записанной раскладке: иначе ошибка «идентификатор
 * одинаков у всех кривых» совпала бы в обеих реализациях.
 */
final class NonceOracle {

    /**
     * Результат выработки нонса.
     *
     * @param k       нонс
     * @param e       число из уравнения подписи (после приведения по модулю n и замены 0 на 1)
     * @param rejected сколько кандидатов вне [1, n-1] отброшено до принятого
     * @param shift   на сколько бит сдвинут блок HMAC в {@code bits2int} (8·длина - qlen)
     */
    record Derived(BigInteger k, BigInteger e, int rejected, int shift) {}

    /** Метка домена идентификатора кривой: разделяет его хэш от любых других применений Стрибога. */
    private static final byte[] BINDING_LABEL =
            "org.rssys.gost.signature.nonce.curve-binding.v1".getBytes(StandardCharsets.US_ASCII);

    private NonceOracle() {}

    /**
     * Идентификатор кривой: Стрибог-256 от метки домена и значений {@code p, a, b, gx, gy, n}
     * (каждое - {@link BigInteger#toByteArray()} с 4-байтным префиксом длины, big-endian), затем
     * {@code hlen} и {@code cofactor} как 4-байтные целые big-endian. Значения берутся как есть,
     * без приведения по модулю, а ведущий нулевой байт {@code toByteArray()} входит в длину и в
     * хэш.
     */
    static byte[] curveBinding(
            BigInteger p,
            BigInteger a,
            BigInteger b,
            BigInteger gx,
            BigInteger gy,
            BigInteger n,
            int hlen,
            int cofactor) {
        byte[] record = BINDING_LABEL;
        for (BigInteger value : new BigInteger[] {p, a, b, gx, gy, n}) {
            byte[] encoded = value.toByteArray();
            record = concat(record, int32(encoded.length), encoded);
        }
        record = concat(record, int32(hlen), int32(cofactor));
        Digest digest = new GOST3411_2012_256Digest();
        digest.update(record, 0, record.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    private static byte[] int32(int value) {
        return new byte[] {
            (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        };
    }

    /** Детерминированный режим: без случайной добавки {@code Z}. */
    static Derived derive(BigInteger n, int hlen, BigInteger d, byte[] hash, byte[] binding) {
        return derive(n, hlen, d, hash, binding, null);
    }

    /**
     * Нонс по раскладке библиотеки. При {@code z == null} - детерминированный режим:
     * {@code V || 0x00/0x01 || int2octets(d) || int2octets(e) || curveBinding}. Иначе гибридный
     * режим по образцу черновика draft-irtf-cfrg-det-sigs-with-noise-05 §4:
     * {@code V || 0x00/0x01 || Z || 0..0 || int2octets(d) || 0..0 || int2octets(e) ||
     * curveBinding}, где нули дополняют {@code V || 0x00 || Z} и {@code int2octets(d)} до
     * наименьшего кратного длины блока хэш-функции, а {@code Z} - один и тот же на шагах d и f и
     * длиной {@code rolen}.
     */
    static Derived derive(
            BigInteger n, int hlen, BigInteger d, byte[] hash, byte[] binding, byte[] z) {
        int qlen = n.bitLength();
        int rolen = (qlen + 7) / 8;

        BigInteger e = new BigInteger(1, reverse(hash)).mod(n);
        if (e.signum() == 0) {
            e = BigInteger.ONE;
        }
        byte[] x = int2octets(d, rolen);
        byte[] h1 = int2octets(e, rolen);

        byte[] v = new byte[hlen];
        java.util.Arrays.fill(v, (byte) 0x01);
        byte[] k = new byte[hlen];

        // RFC 6979 §3.2 d-g; идентификатор кривой - данные в конце входа по образцу §3.6
        k = hmac(hlen, k, providedData(hlen, v, (byte) 0x00, x, h1, binding, z));
        v = hmac(hlen, k, v);
        k = hmac(hlen, k, providedData(hlen, v, (byte) 0x01, x, h1, binding, z));
        v = hmac(hlen, k, v);

        int rejected = 0;
        while (true) {
            // h.1-h.2: накопить блоки, пока не наберётся qlen бит
            byte[] t = new byte[0];
            while (t.length * 8 < qlen) {
                v = hmac(hlen, k, v);
                t = concat(t, v);
            }
            BigInteger candidate = bits2int(t, qlen);
            if (candidate.signum() > 0 && candidate.compareTo(n) < 0) {
                return new Derived(candidate, e, rejected, Math.max(0, t.length * 8 - qlen));
            }
            // h.3: кандидат вне [1, n-1]
            rejected++;
            k = hmac(hlen, k, concat(v, new byte[] {0x00}));
            v = hmac(hlen, k, v);
        }
    }

    /** Вход HMAC на шагах d и f после разделителя; раскладка описана в {@link #derive}. */
    private static byte[] providedData(
            int hlen, byte[] v, byte separator, byte[] x, byte[] h1, byte[] binding, byte[] z) {
        if (z == null) {
            return concat(v, new byte[] {separator}, x, h1, binding);
        }
        int blockSize = newDigest(hlen).getByteLength();
        byte[] head = concat(v, new byte[] {separator}, z);
        return concat(
                head,
                zeros(padToBlock(head.length, blockSize)),
                x,
                zeros(padToBlock(x.length, blockSize)),
                h1,
                binding);
    }

    /** Наименьшее неотрицательное число нулей, дополняющее длину до кратной блоку. */
    private static int padToBlock(int length, int blockSize) {
        return (blockSize - length % blockSize) % blockSize;
    }

    private static byte[] zeros(int count) {
        return new byte[count];
    }

    /** RFC 6979 §2.3.2: старшие qlen бит блока, прямой порядок байт. */
    private static BigInteger bits2int(byte[] block, int qlen) {
        BigInteger value = new BigInteger(1, block);
        int blockBits = block.length * 8;
        return blockBits > qlen ? value.shiftRight(blockBits - qlen) : value;
    }

    private static byte[] hmac(int hlen, byte[] key, byte[] data) {
        HMac mac = new HMac(newDigest(hlen));
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private static ExtendedDigest newDigest(int hlen) {
        return hlen == 32
                ? new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest()
                : new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();
    }

    /** RFC 6979 §2.3.3: целое big-endian ровно в rolen байт. */
    static byte[] int2octets(BigInteger value, int rolen) {
        byte[] raw = value.toByteArray();
        int offset = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        int length = raw.length - offset;
        if (length > rolen) {
            throw new IllegalArgumentException("значение длиннее rolen: " + length);
        }
        byte[] out = new byte[rolen];
        System.arraycopy(raw, offset, out, rolen - length, length);
        return out;
    }

    static byte[] reverse(byte[] source) {
        byte[] out = new byte[source.length];
        for (int i = 0; i < source.length; i++) {
            out[i] = source[source.length - 1 - i];
        }
        return out;
    }

    static byte[] concatBytes(byte[]... parts) {
        return concat(parts);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int position = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, position, part.length);
            position += part.length;
        }
        return out;
    }
}
