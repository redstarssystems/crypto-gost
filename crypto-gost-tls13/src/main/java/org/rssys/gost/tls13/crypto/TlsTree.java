package org.rssys.gost.tls13.crypto;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import java.util.Arrays;

/**
 * TLSTREE — per-record внешний ре-кейинг ключей (RFC 9367 раздел 4.2).
 * <p>
 * Определяет трёхуровневое дерево KDF на основе
 * KDF_GOST_R_3411_2012_256 (RFC 7836) с per-cipher-suite битовыми масками
 * C1/C2/C3, которые выбирают определённые биты порядкового номера записи
 * для каждого уровня.
 * </p>
 * <pre>
 * TLSTREE(K_root, seqnum) = KDF_3(KDF_2(KDF_1(K_root, STR_8(seqnum &amp; C1)),
 *                                        STR_8(seqnum &amp; C2)),
 *                                  STR_8(seqnum &amp; C3))
 * </pre>
 * <p>
 * Все промежуточные ключи затираются после использования.
 * </p>
 */
public final class TlsTree {

    static final byte[] LABEL_LEVEL1 = b(TlsConstants.LABEL_TLSTREE_LEVEL1);
    static final byte[] LABEL_LEVEL2 = b(TlsConstants.LABEL_TLSTREE_LEVEL2);
    static final byte[] LABEL_LEVEL3 = b(TlsConstants.LABEL_TLSTREE_LEVEL3);

    private TlsTree() {}

    /**
     * Один уровень TLSTREE с переиспользуемым scratch-буфером для STR_8.
     *
     * @param inputKey входной ключ
     * @param label    метка
     * @param mask     битовая маска
     * @param seqNum   порядковый номер
     * @param scratch8 буфер 8 байт для STR_8 (seed KDF) — сохраняется в течении вызова
     * @return 32 байта ключевого материала
     */
    static byte[] expandLevel(byte[] inputKey, byte[] label, long mask, long seqNum,
                               byte[] scratch8) {
        be64(seqNum & mask, scratch8, 0);
        return KdfGostR3411_2012_256.expand(inputKey, label, scratch8, 32);
    }

    /**
     * Один уровень TLSTREE: KDF(input, label, STR_8(seqNum & mask), 32).
     * Аллоцирует новый byte[8] на каждый вызов.
     * Для горячего пути используйте {@link #expandLevel(byte[],byte[],long,long,byte[])}.
     *
     * @param inputKey входной ключ
     * @param label    метка
     * @param mask     битовая маска
     * @param seqNum   порядковый номер
     * @return 32 байта ключевого материала
     */
    static byte[] expandLevel(byte[] inputKey, byte[] label, long mask, long seqNum) {
        return expandLevel(inputKey, label, mask, seqNum, new byte[8]);
    }

    /**
     * TLSTREE: вырабатывает 32-байтовый ключ для заданного номера записи.
     * <p>
     * Три уровня KDF c битовыми масками C1/C2/C3 (RFC 9367 §4.2).
     * Промежуточные ключи затираются.
     *
     * @param rootKey начальный ключевой материал (K_start)
     * @param seqNum  порядковый номер записи
     * @param c1      битовая маска уровня 1
     * @param c2      битовая маска уровня 2
     * @param c3      битовая маска уровня 3
     * @return 32 байта ключевого материала
     */
    public static byte[] tlstree(byte[] rootKey, long seqNum,
                                  long c1, long c2, long c3) {
        byte[] level1 = expandLevel(rootKey, LABEL_LEVEL1, c1, seqNum);
        byte[] level2 = expandLevel(level1, LABEL_LEVEL2, c2, seqNum);
        byte[] level3 = expandLevel(level2, LABEL_LEVEL3, c3, seqNum);
        zero(level1);
        zero(level2);
        return level3;
    }

    /**
     * Вырабатывает ключ для защиты записи.
     *
     * @param startKey начальный ключевой материал K_start_key
     * @param seqNum   порядковый номер записи
     * @param c1       битовая маска уровня 1
     * @param c2       битовая маска уровня 2
     * @param c3       битовая маска уровня 3
     * @param keyLen   длина ключа (32 для Kuznyechik)
     * @return ключ
     */
    public static byte[] deriveKey(byte[] startKey, long seqNum,
                                    long c1, long c2, long c3, int keyLen) {
        byte[] full = tlstree(startKey, seqNum, c1, c2, c3);
        byte[] key = Arrays.copyOf(full, keyLen);
        TlsUtils.wipeArray(full);
        return key;
    }

    /**
     * Кодирует long в big-endian (8 байт) — STR_8 per RFC 9367 §3.
     * Записывает в переданный буфер — 0 аллокаций.
     *
     * @param value значение для кодирования
     * @param dest  буфер для записи
     * @param off   смещение в буфере
     */
    static void be64(long value, byte[] dest, int off) {
        dest[off]     = (byte) (value >>> 56);
        dest[off + 1] = (byte) (value >>> 48);
        dest[off + 2] = (byte) (value >>> 40);
        dest[off + 3] = (byte) (value >>> 32);
        dest[off + 4] = (byte) (value >>> 24);
        dest[off + 5] = (byte) (value >>> 16);
        dest[off + 6] = (byte) (value >>> 8);
        dest[off + 7] = (byte) (value);
    }

    /**
     * Кодирует строку в UTF-8 байты для меток TLSTREE.
     *
     * @param s строка
     * @return UTF-8 байты
     */
    private static byte[] b(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** Затирает массив (null-safe обёртка над TlsUtils.wipeArray). */
    private static void zero(byte[] data) {
        if (data != null) {
            TlsUtils.wipeArray(data);
        }
    }
}
