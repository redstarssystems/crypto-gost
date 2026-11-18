package org.rssys.gost.kdf;

import java.util.Arrays;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

/**
 * KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.5).
 * <p>
 * KDF_GOST_R_3411_2012_256 (RFC 7836) из этого же пакета — частный случай данной
 * функции при R=1, L=256; формат буфера у них общий.
 * <p>
 * Формат блока: {@code K(i) = HMAC(K_in, [i]_R || label || 0x00 || seed || [L]_b)}
 * где:
 * <ul>
 *   <li>{@code [i]_R} — счётчик итерации, стоит <b>первым</b>, ширина R октет;</li>
 *   <li>{@code [L]_b} — <b>суммарная</b> длина всего выходного материала в
 *       <b>битах</b>, минимальное big-endian без ведущих нулей;</li>
 * </ul>
 * {@code [L]_b} фиксирован для всех итераций, между блоками меняется только счётчик.
 * <p>
 * Применяется в CTR-ACPKM-OMAC (RFC 9337 §5.1.1) для вывода ключей шифрования
 * и аутентификации из основного ключа, а также в CMS KExp15 (обёртывание CEK).
 */
public final class KdfTreeGostR3411_2012_256 {

    private static final int HASH_LEN = 32;

    private KdfTreeGostR3411_2012_256() {}

    /**
     * Вырабатывает один или несколько ключей по KDF_TREE.
     *
     * @param kin   входной ключ (K_in)
     * @param label метка (например, "kdf tree" в ASCII)
     * @param seed  затравка
     * @param count количество вырабатываемых блоков (граница цикла по счётчику i).
     *              Это НЕ RFC-параметр R (ширина счётчика): ширина счётчика в буфере
     *              зафиксирована 1 октетом (R=1), поэтому count не может превышать 255.
     * @param keyLen длина каждого блока в байтах
     * @return конкатенация K(1) || K(2) || ... || K(count), длина = count * keyLen
     */
    public static byte[] generate(byte[] kin, byte[] label, byte[] seed, int count, int keyLen) {
        if (kin == null || label == null || seed == null) {
            throw new IllegalArgumentException("kin, label and seed must not be null");
        }
        // Счётчик [i]_R жёстко зашит в 1 октет (R=1), поэтому i не должен выходить
        // за пределы одного байта — иначе произошло бы тихое усечение счётчика.
        if (count < 1 || count > 255) {
            throw new IllegalArgumentException(
                    "count must be in [1, 255] (counter width is fixed at 1 octet, R=1)");
        }
        if (keyLen < 1) {
            throw new IllegalArgumentException("keyLen must be positive");
        }
        if (keyLen > HASH_LEN) {
            throw new IllegalArgumentException(
                    "keyLen must be <= "
                            + HASH_LEN
                            + " (HMAC-Streebog-256 output size per RFC 7836 §4.5)");
        }

        // [L]_b — суммарная длина ВСЕГО выходного материала в битах, минимальное
        // big-endian без ведущих нулей (RFC 7836 §4.5). Фиксирован для всех итераций.
        int outBits = count * keyLen * 8;
        byte[] lBytes = BigEndianEncoding.minimal(outBits);

        // Буфер: [i](1) || label || 0x00 || seed || [L]_b.
        // Счётчик стоит первым (RFC 7836 §4.5); между блоками меняется только buf[0].
        int bufLen = 1 + label.length + 1 + seed.length + lBytes.length;
        byte[] buf = new byte[bufLen];
        buf[0] = 1;
        System.arraycopy(label, 0, buf, 1, label.length);
        buf[1 + label.length] = 0;
        System.arraycopy(seed, 0, buf, 1 + label.length + 1, seed.length);
        System.arraycopy(lBytes, 0, buf, 1 + label.length + 1 + seed.length, lBytes.length);

        byte[] result = new byte[count * keyLen];
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init(kin);

        byte[] block = new byte[HASH_LEN];

        try {
            for (int i = 1; i <= count; i++) {
                buf[0] = (byte) i;

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
}
