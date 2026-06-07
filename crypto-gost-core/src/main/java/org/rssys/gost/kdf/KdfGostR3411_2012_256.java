package org.rssys.gost.kdf;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

/**
 * KDF_GOST_R_3411_2012_256 (RFC 7836 раздел 4) на основе HMAC-Streebog-256.
 * <p>
 * В отличие от HKDF (RFC 5869) не имеет отдельной фазы Extract —
 * ключ используется напрямую в HMAC:
 * </p>
 * <pre>
 * K(i) = HMAC-Streebog256(K, [i]_b || label || 0x00 || seed || [L]_b)
 * result = K(1) || K(2) || ... || K(N)
 * </pre>
 * <p>
 * Всегда использует Streebog-256 (32-байтовый хеш).
 * Применяется в TLS 1.3 ГОСТ (RFC 9367) для TLSTREE-ре-кейинга.
 * </p>
 */
public final class KdfGostR3411_2012_256 {

    private static final int HASH_LEN = 32;

    private KdfGostR3411_2012_256() {}

    /**
     * Кодирует положительное целое в big-endian (без лидирующих нулей).
     *
     * @param value положительное целое
     * @return big-endian байты
     */
    private static byte[] bigEndian(int value) {
        if (value == 0) return new byte[]{0};
        int bits = 32 - Integer.numberOfLeadingZeros(value);
        int bytes = (bits + 7) / 8;
        byte[] result = new byte[bytes];
        for (int i = bytes - 1; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return result;
    }

    /**
     * KDF_GOST_R_3411_2012_256: вырабатывает ключевой материал.
     *
     * @param key          ключ (используется напрямую как HMAC-ключ)
     * @param label        метка
     * @param seed         затравка
     * @param outputLength требуемая длина выходных данных
     * @return ключевой материал
     */
    public static byte[] expand(byte[] key, byte[] label, byte[] seed, int outputLength) {
        if (key == null || label == null || seed == null) {
            throw new IllegalArgumentException("key, label and seed must not be null");
        }
        if (outputLength < 0) {
            throw new IllegalArgumentException("outputLength must be non-negative");
        }
        if (outputLength == 0) {
            return new byte[0];
        }

        int n = (outputLength + HASH_LEN - 1) / HASH_LEN;
        if (n > 255) {
            throw new IllegalArgumentException("outputLength too large");
        }

        byte[] result = new byte[outputLength];
        // L в битах для суффикса [L]_b (RFC 7836 §4.4)
        int lBits = outputLength * 8;
        byte[] lBytes = bigEndian(lBits);

        // Буфер: [i]_b(1) || label || 0x00 || seed || [L]_b
        // Для i = 1..n на месте [i]_b меняется только первый байт
        byte[] buf = new byte[1 + label.length + 1 + seed.length + lBytes.length];
        buf[0] = 1; // [1]_b для первой итерации
        System.arraycopy(label, 0, buf, 1, label.length);
        buf[1 + label.length] = 0;
        System.arraycopy(seed, 0, buf, 1 + label.length + 1, seed.length);
        System.arraycopy(lBytes, 0, buf, 1 + label.length + 1 + seed.length, lBytes.length);

        // Hmac один на весь цикл
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init(key);
        byte[] block = new byte[HASH_LEN];

        for (int i = 1; i <= n; i++) {
            buf[0] = (byte) i;                    // меняем только первый байт

            hmac.update(buf, 0, buf.length);
            hmac.doFinal(block, 0);                // перезаписывает block

            int copyLen = Math.min(HASH_LEN, outputLength - (i - 1) * HASH_LEN);
            System.arraycopy(block, 0, result, (i - 1) * HASH_LEN, copyLen);
        }

        hmac.clear();

        return result;
    }
}
