package org.rssys.gost.util;

public class ISO7816d4Padding {
    public static int addPadding(byte[] in, int len) {
        in[len] = (byte) 0x80;
        for (int i = len + 1; i < in.length; i++) {
            in[i] = 0;
        }
        return len;
    }

    /**
     * Возвращает количество байт padding в последнем блоке (constant-time).
     */
    public static int padCount(byte[] in) {
        int markerPos = -1;
        for (int i = 0; i < in.length; i++) {
            if ((in[i] & 0xFF) == 0x80) {
                markerPos = i;
            }
        }
        if (markerPos == -1) {
            throw new IllegalStateException("padding block corrupted");
        }
        // Best-effort constant-time: проход фиксированной длины in.length (не зависит
        // от markerPos), все байты строго после маркера обязаны быть нулевыми.
        // Ранее длина цикла зависела от позиции маркера — это давало тайминг-утечку.
        // см. crypto-gost-core/doc/adr/adr-04.md
        int mismatch = 0;
        for (int i = 0; i < in.length; i++) {
            // afterMarker = 0xFFFFFFFF, если i > markerPos, иначе 0.
            int afterMarker = (markerPos - i) >> 31;
            mismatch |= (in[i] & 0xFF) & afterMarker;
        }
        if (mismatch != 0) {
            throw new IllegalStateException("padding block corrupted");
        }
        return in.length - markerPos;
    }
}
