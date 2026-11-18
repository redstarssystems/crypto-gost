package org.rssys.gost.digest;

/**
 * Реализация хэш-функции ГОСТ Р 34.11-2012 (Стрибог) 256 бит.
 */
public final class Streebog256 extends Streebog {

    /** Размер дайджеста в байтах (ГОСТ Р 34.11-2012, 256 бит). */
    public static final int DIGEST_SIZE = 32;

    /** Значение каждого из 64 байт начального {@code h} (RFC 6986 §9, шаг 1). */
    private static final byte INITIAL_BYTE = 0x01;

    /** Создаёт хэш в начальном состоянии. */
    public Streebog256() {
        super(INITIAL_BYTE);
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
