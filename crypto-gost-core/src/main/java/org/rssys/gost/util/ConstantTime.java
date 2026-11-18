package org.rssys.gost.util;

/**
 * Сравнения за время, не зависящее от содержимого: для тегов и других значений, где ранний выход
 * по первому различающемуся байту раскрывал бы длину совпавшего префикса.
 */
public final class ConstantTime {

    private ConstantTime() {}

    /**
     * Сравнивает {@code len} байт двух массивов с заданных смещений без раннего выхода.
     *
     * <p>Границы диапазонов и {@code len} публичны: их нарушение - ошибка вызывающего, и оно
     * отвергается исключением до сравнения. Поэтому тег можно сравнивать прямо в пакете, не
     * копируя его в отдельный массив.
     *
     * @return {@code true}, если все {@code len} байт совпадают
     * @throws IllegalArgumentException если любой массив {@code null}, {@code len} или смещение
     *                                  отрицательны либо диапазон выходит за границы массива
     */
    public static boolean equals(byte[] a, int aOff, byte[] b, int bOff, int len) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Arrays must not be null");
        }
        if (len < 0 || aOff < 0 || bOff < 0 || len > a.length - aOff || len > b.length - bOff) {
            throw new IllegalArgumentException(
                    "Range out of bounds: len=" + len + ", aOff=" + aOff + ", bOff=" + bOff);
        }
        int diff = 0;
        for (int i = 0; i < len; i++) {
            diff |= a[aOff + i] ^ b[bOff + i];
        }
        return diff == 0;
    }
}
