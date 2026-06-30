package org.rssys.gost.crossval.util;

import java.util.Arrays;

/**
 * Утилиты кросс-валидации: сравнение байтовых массивов, hex-диагностика, логирование ошибок.
 */
public final class CrossValUtils {

    private CrossValUtils() {}

    /** Шестнадцатеричная строка байтов (строчные буквы). */
    public static String toHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    /** Парсит hex-строку в массив байт. Симметрично toHex(). */
    public static byte[] fromHex(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.isEmpty()) return new byte[0];
        if (hex.length() % 2 != 0)
            throw new IllegalArgumentException("Hex length is odd: " + hex.length());
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0)
                throw new IllegalArgumentException("Invalid hex at position " + (i * 2));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Индекс первого расходящегося байта, или -1 если массивы равны. */
    private static int firstDiff(byte[] a, byte[] b) {
        if (a == b) return -1;
        if (a == null || b == null) return 0;
        int len = Math.min(a.length, b.length);
        for (int i = 0; i < len; i++) if (a[i] != b[i]) return i;
        return a.length == b.length ? -1 : len;
    }

    /** Возвращает строку с hex-контекстом первого расхождения. */
    public static String diffContext(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return "a=" + a + " b=" + b;
        }
        int idx = firstDiff(a, b);
        String lenInfo = "a.length=" + a.length + " b.length=" + b.length;
        if (idx < 0) {
            if (a.length == b.length) {
                return lenInfo + " равны";
            }
            return lenInfo + " префикс совпадает, длины различаются";
        }
        if (idx >= a.length || idx >= b.length) {
            return lenInfo + " префикс совпадает, длины различаются";
        }
        int start = Math.max(0, idx - 2);
        int end = Math.min(a.length, idx + 3);
        StringBuilder sb = new StringBuilder();
        sb.append("firstDiff=").append(idx).append(" ").append(lenInfo).append(" expected: ");
        appendHexRange(sb, a, start, end, idx);
        sb.append(" actual: ");
        appendHexRange(sb, b, start, end, idx);
        return sb.toString();
    }

    private static void appendHexRange(
            StringBuilder sb, byte[] bytes, int start, int end, int idx) {
        for (int i = start; i < end; i++) {
            if (i == idx) sb.append('>');
            sb.append(String.format("%02x", bytes[i] & 0xff));
            if (i == idx) sb.append('<');
            if (i < end - 1) sb.append(' ');
        }
    }

    /** Склеивает несколько массивов строк в один. */
    public static String[] concat(String[]... arrays) {
        int total = 0;
        for (String[] a : arrays) total += a.length;
        String[] result = new String[total];
        int pos = 0;
        for (String[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    /** Склеивает два байтовых массива. */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
