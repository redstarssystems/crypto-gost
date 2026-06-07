package org.rssys.gost.crossval.digestmac;

import org.rssys.gost.api.CmacApi;
import org.rssys.gost.api.Digest;
import org.rssys.gost.cipher.SymmetricKey;

import java.util.stream.Stream;

/**
 * Данные и алгоритмы для кросс-валидации хэшей и MAC.
 *
 * Набор размеров покрывает граничные условия:
 * — нулевое сообщение (0);
 * — меньше длины блока Streebog (1, 15);
 * — ровно длина блока 64 байта и ±1 (63, 64, 65);
 * — больше блока (127, 128, 129; 255, 256, 257);
 * — произвольный (1000);
 * — кратный и некратный размеру ключа Кузнечика — 16 байт (4096, 4097).
 */
public final class TestData {
    public static final int[] SIZES = {
            0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096, 4097
    };

    public enum Algo {
        STREEBOG256(false),
        STREEBOG512(false),
        HMAC256(true),
        HMAC512(true),
        CMAC(true);

        private final boolean needsKey;

        Algo(boolean needsKey) {
            this.needsKey = needsKey;
        }

        public boolean needKey() {
            return needsKey;
        }
    }

    public static final Algo[] ALGORITHMS = Algo.values();

    private TestData() {}

    public static byte[] msg(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) data[i] = (byte) (i & 0xFF);
        return data;
    }

    public static byte[] testKey() {
        return msg(32);
    }

    public static Stream<Object[]> macParams() {
        return java.util.Arrays.stream(ALGORITHMS)
                .flatMap(algo -> java.util.Arrays.stream(SIZES)
                        .mapToObj(size -> new Object[]{algo, size}));
    }

    /** Вычисляет хэш или MAC через crypto-gost. */
    public static byte[] computeGost(Algo algo, byte[] key, byte[] data) {
        switch (algo) {
            case STREEBOG256: return Digest.digest256(data);
            case STREEBOG512: return Digest.digest512(data);
            case HMAC256:     return Digest.hmac256(data, new SymmetricKey(key));
            case HMAC512:     return Digest.hmac512(data, new SymmetricKey(key));
            case CMAC:        return CmacApi.cmac(data, new SymmetricKey(key));
            default: throw new IllegalArgumentException("Неизвестный алгоритм: " + algo);
        }
    }

    /** Вычисляет хэш или MAC через BouncyCastle. */
    public static byte[] computeBc(Algo algo, byte[] key, byte[] data) {
        switch (algo) {
            case STREEBOG256: return BcMacHelper.bcDigest256(data);
            case STREEBOG512: return BcMacHelper.bcDigest512(data);
            case HMAC256:     return BcMacHelper.bcHmac256(key, data);
            case HMAC512:     return BcMacHelper.bcHmac512(key, data);
            case CMAC:        return BcMacHelper.bcCmac(key, data);
            default: throw new IllegalArgumentException("Неизвестный алгоритм: " + algo);
        }
    }
}
