package org.rssys.gost.digest;

/**
 * Реализация хэш-функции ГОСТ Р 34.11-2012 (Стрибог) 512 бит.
 */
public class Streebog512 extends Streebog {

    /** Размер дайджеста в байтах (ГОСТ Р 34.11-2012, 512 бит). */
    public static final int DIGEST_SIZE = 64;

    private static final byte[] IV_512 = new byte[64];

    public Streebog512() {
        super(IV_512);
    }

    @Override
    public String getAlgorithmName() {
        return "Streebog512";
    }

    @Override
    public int getDigestSize() {
        return DIGEST_SIZE;
    }
}
