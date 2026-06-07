package org.rssys.gost.crossval.kuznyechik;

import org.rssys.gost.api.Cipher;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Данные и режимы для кросс-валидации шифрования Кузнечик.
 *
 * Размеры покрывают граничные условия: 0, меньше 16, ровно 16, ±1 от 16,
 * границы стыка буферов (4080–4097), 65535/65536 (граница unsigned short),
 * и крупные буферы (262144, 1048576, 1048577).
 *
 * IV для CTR — 8 байт (ГОСТ Р 34.13-2015 §4.4),
 * для CBC/CFB/OFB — 16 байт (полный блок Кузнечика).
 */
public final class TestData {
    public static final int[] SIZES = {
            0, 1, 15, 16, 17, 50, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257,
            1000, 4080, 4081, 4082, 4083, 4084, 4085, 4086, 4087, 4088, 4089, 4090,
            4091, 4092, 4093, 4094, 4095, 4096, 4097, 10000,
            65534, 65535, 65536, 65537, 262144, 1048576, 1048577
    };

    public static final Cipher.Mode[] CIPHER_MODES = {
            Cipher.Mode.CTR,
            Cipher.Mode.CBC,
            Cipher.Mode.CFB,
            Cipher.Mode.OFB
    };

    public static Cipher.Padding paddingFor(Cipher.Mode mode) {
        return mode == Cipher.Mode.CBC ? Cipher.Padding.PKCS7 : Cipher.Padding.NONE;
    }

    public static int ivLengthFor(Cipher.Mode mode) {
        return mode == Cipher.Mode.CTR ? 8 : 16;
    }

    public static int[] cbcNoPadSizes() {
        return Arrays.stream(SIZES).filter(sz -> sz > 0 && sz % 16 == 0).toArray();
    }

    public static byte[] randomBytes(int n, SecureRandom random) {
        byte[] bytes = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] bcDecrypt(Cipher.Mode mode, byte[] data, byte[] key, byte[] iv) {
        switch (mode) {
            case CTR:  return BcHelper.bcCtr(data, key, iv);
            case CBC:  return BcHelper.bcCbcPad(data, key, iv, false);
            case CFB:  return BcHelper.bcCfb(data, key, iv, false);
            case OFB:  return BcHelper.bcOfb(data, key, iv, false);
            default:   throw new IllegalArgumentException("Неподдерживаемый режим: " + mode);
        }
    }

    public static byte[] bcEncrypt(Cipher.Mode mode, byte[] data, byte[] key, byte[] iv) {
        switch (mode) {
            case CTR:  return BcHelper.bcCtr(data, key, iv);
            case CBC:  return BcHelper.bcCbcPad(data, key, iv, true);
            case CFB:  return BcHelper.bcCfb(data, key, iv, true);
            case OFB:  return BcHelper.bcOfb(data, key, iv, true);
            default:   throw new IllegalArgumentException("Неподдерживаемый режим: " + mode);
        }
    }

    public static Stream<Object[]> cipherModeParams() {
        return Arrays.stream(CIPHER_MODES)
                .flatMap(mode -> Arrays.stream(SIZES)
                        .mapToObj(size -> new Object[]{mode, size}));
    }
}
