package org.rssys.gost.crossval.digestmac;

import java.util.Arrays;

/**
 * Входные данные для плотной кросс-валидации Стрибога: три набора и список длин.
 *
 * Набор «все 0xFF» нужен для переноса в сумме блоков по модулю 2^512, псевдослучайный задаётся
 * собственным генератором (xorshift64 с фиксированным зерном), чтобы значения не зависели от
 * версии JDK и не требовали секретного генератора.
 */
public final class StreebogInputs {

    public enum Pattern {
        COUNTER,
        PSEUDO,
        FF
    }

    /** Все длины 0..300 подряд и окрестности границ 384, 512, 1024. */
    public static final int[] DENSE_LENGTHS = denseLengths();

    /** Разреженный набор для OpenSSL: каждый вызов — отдельный процесс. */
    public static final int[] SPARSE_LENGTHS = {
            0, 1, 17, 53, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257, 511, 512, 513, 1000
    };

    /** Длины ключа HMAC: пустой, короче блока, на границе блока (64), длиннее блока (65, 128). */
    public static final int[] HMAC_KEY_LENGTHS = {0, 32, 63, 64, 65, 128};

    private StreebogInputs() {}

    private static int[] denseLengths() {
        int[] extra = {383, 384, 385, 511, 512, 513, 1023, 1024, 1025};
        int[] result = new int[301 + extra.length];
        for (int i = 0; i <= 300; i++) {
            result[i] = i;
        }
        System.arraycopy(extra, 0, result, 301, extra.length);
        return result;
    }

    public static byte[] data(Pattern pattern, int length) {
        byte[] data = new byte[length];
        switch (pattern) {
            case COUNTER:
                for (int i = 0; i < length; i++) {
                    data[i] = (byte) i;
                }
                break;
            case FF:
                Arrays.fill(data, (byte) 0xFF);
                break;
            default:
                long state = 0x9E3779B97F4A7C15L;
                for (int i = 0; i < length; i++) {
                    state ^= state << 13;
                    state ^= state >>> 7;
                    state ^= state << 17;
                    data[i] = (byte) (state >>> 32);
                }
        }
        return data;
    }
}
