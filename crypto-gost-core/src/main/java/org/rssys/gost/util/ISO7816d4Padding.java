package org.rssys.gost.util;

public class ISO7816d4Padding {
    public static int addPadding(byte[] in, int len) {
        in[len] = (byte) 0x80;
        for (int i = len + 1; i < in.length; i++) {
            in[i] = 0;
        }
        return len;
    }

    public static int padCount(byte[] in) {
        int count = in.length - 1;
        while (count > 0 && in[count] == 0) {
            count--;
        }
        if (in[count] != (byte) 0x80) {
            throw new IllegalStateException("padding block corrupted");
        }
        return in.length - count;
    }
}
