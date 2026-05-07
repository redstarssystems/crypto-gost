package org.rssys.gost.tls13.crypto;

import org.rssys.gost.tls13.TlsUtils;


/**
 * Кэш TLSTREE-ключей по RFC 9367 §4.2 (RECOMMENDED).
 * <p>
 * Кэширует промежуточные KDF_j(level_j, seqNum &amp; C_j) и пересчитывает
 * только те уровни, для которых изменилось маскированное значение seqNum.
 * Изменение на уровне j каскадно пересчитывает уровни j+1..3.
 * </p>
 */
public final class TlsTreeCache {

    private final byte[] startKey;
    private final long c1;
    private final long c2;
    private final long c3;

    private byte[] k1;
    private byte[] k2;
    private byte[] k3;
    private long m1;
    private long m2;
    private long m3;

    private final byte[] be64Buf = new byte[8];

    /**
     * @param startKey начальный ключевой материал K_start_key (без копирования);
     *                 caller гарантирует массив не модифицируется после передачи
     * @param c1       битовая маска уровня 1
     * @param c2       битовая маска уровня 2
     * @param c3       битовая маска уровня 3
     */
    public TlsTreeCache(byte[] startKey, long c1, long c2, long c3) {
        this.startKey = startKey;
        this.c1 = c1;
        this.c2 = c2;
        this.c3 = c3;
    }

    /**
     * То же что {@link #deriveKey(long)}, но копирует результат
     * в переданный буфер вместо аллокации нового массива.
     * Позволяет caller'у переиспользовать буфер и избежать аллокации на горячем пути.
     *
     * @param seqNum порядковый номер записи
     * @param dest   буфер для результата (должен быть &ge; 32 байт от offset)
     * @param off    смещение в dest
     * @return {@code true} если итоговый ключ изменился относительно
     *         предыдущего вызова, {@code false} если ключ остался тем же
     *         (только ICN изменился, cipher.init() можно пропустить)
     */
    public boolean deriveKeyInto(long seqNum, byte[] dest, int off) {
        long nm1 = seqNum & c1;
        long nm2 = seqNum & c2;
        long nm3 = seqNum & c3;

        boolean ch1 = k1 == null || nm1 != m1;
        boolean ch2 = ch1 || k2 == null || nm2 != m2;
        boolean ch3 = ch2 || k3 == null || nm3 != m3;

        if (ch1) {
            TlsUtils.wipeArray(k1);
            k1 = TlsTree.expandLevel(startKey, TlsTree.LABEL_LEVEL1, c1, seqNum, be64Buf);
            m1 = nm1;
        }
        if (ch2) {
            TlsUtils.wipeArray(k2);
            k2 = TlsTree.expandLevel(k1, TlsTree.LABEL_LEVEL2, c2, seqNum, be64Buf);
            m2 = nm2;
        }
        if (ch3) {
            TlsUtils.wipeArray(k3);
            k3 = TlsTree.expandLevel(k2, TlsTree.LABEL_LEVEL3, c3, seqNum, be64Buf);
            m3 = nm3;
        }
        System.arraycopy(k3, 0, dest, off, 32);
        return ch3;
    }

    /**
     * Обнуляет и освобождает все кэшированные ключи.
     * startKey не затирается здесь намеренно — владелец TlsRecord обнуляет его сам.
     * k1/k2/k3 — производные от startKey, принадлежат кэшу, затираются здесь.
     */
    public void destroy() {
        TlsUtils.wipeArray(k1); k1 = null;
        TlsUtils.wipeArray(k2); k2 = null;
        TlsUtils.wipeArray(k3); k3 = null;
    }
}
