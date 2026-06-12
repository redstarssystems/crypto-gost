package org.rssys.gost.kdf;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.mac.Mac;

import java.util.Arrays;

/**
 * PBKDF2 на основе HMAC-Streebog (RFC 9337 §4, RFC 2898 §5.2).
 *
 * <p>PRF: HMAC-GOSTR3411 — HMAC на базе Стрибог-512
 * (допускается также HMAC-Стрибог-256 для совместимости с gost-engine).
 *
 * <p>Пароль подаётся как UTF-8 (RFC 9337 §3).
 * Промежуточные буферы обнуляются в finally.
 */
public final class Pbkdf2Streebog {

    private Pbkdf2Streebog() {}

    /**
     * Вырабатывает ключ из пароля по PBKDF2 с PRF = HMAC-Streebog-512.
     *
     * @param password пароль (UTF-8)
     * @param salt     соль
     * @param c        количество итераций (≥ 1)
     * @param dkLen    требуемая длина ключа в байтах
     * @return производный ключ
     */
    public static byte[] generate(byte[] password, byte[] salt, int c, int dkLen) {
        Hmac hmac = new Hmac(new Streebog512());
        hmac.init(password);
        return pbkdf2(hmac, salt, c, dkLen);
    }

    /**
     * Вырабатывает ключ с заданной HMAC-функцией (Streebog-256 или -512).
     * Нужен для декодирования PFX, где PRF OID может быть 256-битным.
     *
     * @param hmac   инициализированный HMAC (PRF)
     * @param salt   соль
     * @param c      количество итераций (≥ 1)
     * @param dkLen  требуемая длина ключа в байтах
     * @return производный ключ
     */
    public static byte[] generate(Mac hmac, byte[] salt, int c, int dkLen) {
        return pbkdf2(hmac, salt, c, dkLen);
    }

    private static byte[] pbkdf2(Mac prf, byte[] salt, int c, int dkLen) {
        if (c < 1) throw new IllegalArgumentException("iteration count must be >= 1");
        if (dkLen < 1) throw new IllegalArgumentException("dkLen must be >= 1");

        int hLen = prf.getMacSize();
        // l ≤ Integer.MAX_VALUE < 2³²−1 — структурно гарантировано типом int dkLen (RFC 2898 §5.2)
        int l = (dkLen + hLen - 1) / hLen;
        int r = dkLen - (l - 1) * hLen;

        byte[] result = new byte[dkLen];
        byte[] U = new byte[hLen];
        byte[] T = new byte[hLen];
        byte[] tmp = new byte[salt.length + 4];

        try {
            System.arraycopy(salt, 0, tmp, 0, salt.length);

            for (int i = 1; i <= l; i++) {
                tmp[salt.length]     = (byte) (i >> 24);
                tmp[salt.length + 1] = (byte) (i >> 16);
                tmp[salt.length + 2] = (byte) (i >> 8);
                tmp[salt.length + 3] = (byte) i;

                prf.update(tmp, 0, tmp.length);
                prf.doFinal(U, 0);
                System.arraycopy(U, 0, T, 0, hLen);

                for (int j = 1; j < c; j++) {
                    prf.update(U, 0, U.length);
                    prf.doFinal(U, 0);
                    for (int k = 0; k < hLen; k++) T[k] ^= U[k];
                }

                int copyLen = (i == l) ? r : hLen;
                System.arraycopy(T, 0, result, (i - 1) * hLen, copyLen);
            }

            return result;

        } finally {
            Arrays.fill(U,   (byte) 0);
            Arrays.fill(T,   (byte) 0);
            Arrays.fill(tmp, (byte) 0);
        }
    }
}
