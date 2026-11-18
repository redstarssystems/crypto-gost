package org.rssys.gost.digest;

/**
 * Реализация хэш-функции ГОСТ Р 34.11-2012 (Стрибог) 512 бит.
 */
public final class Streebog512 extends Streebog {

    /** Размер дайджеста в байтах (ГОСТ Р 34.11-2012, 512 бит). */
    public static final int DIGEST_SIZE = 64;

    /** Значение каждого из 64 байт начального {@code h} (RFC 6986 §9, шаг 1). */
    private static final byte INITIAL_BYTE = 0x00;

    /** Создаёт хэш в начальном состоянии. */
    public Streebog512() {
        super(INITIAL_BYTE);
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
