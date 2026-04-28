package org.rssys.gost.digest;

import java.util.Arrays;

/**
 * Реализация хэш-функции ГОСТ Р 34.11-2012 (Стрибог) 256 бит.
 */
public class Streebog256 extends Streebog {

    /** Размер дайджеста в байтах (ГОСТ Р 34.11-2012, 256 бит). */
    public static final int DIGEST_SIZE = 32;

    private static final byte[] IV_256;

    static {
        IV_256 = new byte[64];
        Arrays.fill(IV_256, (byte) 0x01);
    }

    public Streebog256() {
        super(IV_256);
    }

    @Override
    public String getAlgorithmName() {
        return "Streebog256";
    }

    @Override
    public int getDigestSize() {
        return DIGEST_SIZE;
    }
}
