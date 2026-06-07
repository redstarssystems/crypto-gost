package org.rssys.gost.kdf;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

import java.util.Arrays;

/**
 * KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.5).
 * <p>
 * Не путать с KDF_GOST_R_3411_2012_256 (RFC 7836 §4.4) из этого же пакета —
 * у них разный формат буфера и разное расположение полей.
 * <p>
 * KDF_TREE формат: HMAC(K_in, label || 0x00 || seed || INT(i, 4) || INT(L, 4))
 * где INT(x, 4) — 4 байта big-endian, L — длина ключа в байтах.
 * <p>
 * Применяется в CTR-ACPKM-OMAC (RFC 9337 §5.1.1) для вывода ключей шифрования
 * и аутентификации из основного ключа.
 */
public final class KdfTreeGostR3411_2012_256 {

    private static final int HASH_LEN = 32;
    private static final int INT_LEN = 4;

    private KdfTreeGostR3411_2012_256() {}

    /**
     * Вырабатывает один или несколько ключей по KDF_TREE.
     *
     * @param kin   входной ключ (K_in)
     * @param label метка (например, "kdf tree" в ASCII)
     * @param seed  затравка
     * @param count количество вырабатываемых ключей (R)
     * @param keyLen длина каждого ключа в байтах
     * @return конкатенация K(1) || K(2) || ... || K(count), длина = count * keyLen
     */
    public static byte[] generate(byte[] kin, byte[] label, byte[] seed, int count, int keyLen) {
        if (kin == null || label == null || seed == null) {
            throw new IllegalArgumentException("kin, label and seed must not be null");
        }
        if (count < 1 || count > 255) {
            throw new IllegalArgumentException("count must be in [1, 255]");
        }
        if (keyLen < 1) {
            throw new IllegalArgumentException("keyLen must be positive");
        }
        if (keyLen > HASH_LEN) {
            throw new IllegalArgumentException(
                "keyLen must be <= " + HASH_LEN + " (HMAC-Streebog-256 output size per RFC 7836 §4.5)");
        }

        int bufLen = label.length + 1 + seed.length + INT_LEN + INT_LEN;
        byte[] buf = new byte[bufLen];
        System.arraycopy(label, 0, buf, 0, label.length);
        buf[label.length] = 0;
        System.arraycopy(seed, 0, buf, label.length + 1, seed.length);

        byte[] lBytes = intToBytes(keyLen);
        int counterOff = label.length + 1 + seed.length;
        int lenOff = counterOff + INT_LEN;
        buf[lenOff]     = lBytes[0];
        buf[lenOff + 1] = lBytes[1];
        buf[lenOff + 2] = lBytes[2];
        buf[lenOff + 3] = lBytes[3];

        byte[] result = new byte[count * keyLen];
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init(kin);

        byte[] block = new byte[HASH_LEN];

        try {
            for (int i = 1; i <= count; i++) {
                buf[counterOff]     = (byte) (i >> 24);
                buf[counterOff + 1] = (byte) (i >> 16);
                buf[counterOff + 2] = (byte) (i >> 8);
                buf[counterOff + 3] = (byte) i;

                hmac.update(buf, 0, buf.length);
                hmac.doFinal(block, 0);

                int destOff = (i - 1) * keyLen;
                System.arraycopy(block, 0, result, destOff, keyLen);
            }

            return result;

        } finally {
            Arrays.fill(block, (byte) 0);
            hmac.clear();
        }
    }

    private static byte[] intToBytes(int value) {
        return new byte[]{
            (byte) (value >> 24),
            (byte) (value >> 16),
            (byte) (value >> 8),
            (byte) value
        };
    }
}
