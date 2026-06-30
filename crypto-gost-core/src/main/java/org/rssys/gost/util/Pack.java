package org.rssys.gost.util;

public abstract class Pack {

    /**
     * XOR блока {@code src} в {@code dst} (in-place), первые {@code len} байт.
     * Используется в Кузнечике, MGM, CMAC вместо инлайн-циклов.
     */
    public static void xorBlock(byte[] dst, byte[] src, int len) {
        for (int i = 0; i < len; i++) {
            dst[i] ^= src[i];
        }
    }

    /**
     * XOR блока {@code src[srcOff..]} в {@code dst[dstOff..]}, {@code len} байт.
     */
    public static void xorBlock(byte[] dst, int dstOff, byte[] src, int srcOff, int len) {
        for (int i = 0; i < len; i++) {
            dst[dstOff + i] ^= src[srcOff + i];
        }
    }

    /**
     * Реверс порядка байт массива (big-endian <-> little-endian).
     * Используется для интерпретации хэша по RFC 7091 §5.3 (LSB first).
     */
    public static byte[] reverseBytes(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }

    public static int bigEndianToInt(byte[] bs, int off) {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= bs[++off] & 0xff;
        return n;
    }

    public static void intToBigEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 24);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }

    public static long bigEndianToLong(byte[] bs, int off) {
        int hi = bigEndianToInt(bs, off);
        int lo = bigEndianToInt(bs, off + 4);
        return ((long) (hi & 0xffffffffL) << 32) | (long) (lo & 0xffffffffL);
    }

    public static void longToBigEndian(long n, byte[] bs, int off) {
        intToBigEndian((int) (n >>> 32), bs, off);
        intToBigEndian((int) (n & 0xffffffffL), bs, off + 4);
    }

    public static void longToLittleEndian(long n, byte[] bs, int off) {
        intToLittleEndian((int) (n & 0xffffffffL), bs, off);
        intToLittleEndian((int) (n >>> 32), bs, off + 4);
    }

    public static void intToLittleEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }

    public static int littleEndianToInt(byte[] bs, int off) {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static long littleEndianToLong(byte[] bs, int off) {
        int lo = littleEndianToInt(bs, off);
        int hi = littleEndianToInt(bs, off + 4);
        return ((long) (hi & 0xffffffffL) << 32) | (long) (lo & 0xffffffffL);
    }

    public static long littleEndianToLong(byte[] bs) {
        return littleEndianToLong(bs, 0);
    }

    public static byte[] longToLittleEndian(long n) {
        byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    public static int littleEndianToInt(byte[] bs) {
        return littleEndianToInt(bs, 0);
    }
}
