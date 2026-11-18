package org.rssys.gost.util;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Тестовый двойник датчика: отдаёт заданные байты и считает обращения либо бросает исключение.
 *
 * <p>Подкласс {@link SecureRandom} нужен затем, чтобы подать в подписант известную добавку
 * {@code Z} гибридного режима через стандартный параметр {@code SecureRandom} и проверить, что
 * датчик не вызывается или вызывается ровно один раз. В производственном коде датчик берётся из
 * {@link CryptoRandom#INSTANCE}.
 */
public final class FixedSecureRandom extends SecureRandom {

    private static final long serialVersionUID = 1L;

    private final byte[] bytes;
    private final boolean failing;
    private final AtomicInteger calls = new AtomicInteger();
    private volatile int lastRequestedLength = -1;

    private FixedSecureRandom(byte[] bytes, boolean failing) {
        this.bytes = bytes == null ? null : bytes.clone();
        this.failing = failing;
    }

    /** Датчик, при каждом обращении отдающий одни и те же байты ровно этой длины. */
    public static FixedSecureRandom returning(byte[] bytes) {
        return new FixedSecureRandom(bytes, false);
    }

    /** Датчик, бросающий исключение при любом обращении. */
    public static FixedSecureRandom failing() {
        return new FixedSecureRandom(null, true);
    }

    /** Датчик, который не должен вызываться: обращение считается и бросает исключение. */
    public static FixedSecureRandom forbidden() {
        return new FixedSecureRandom(null, true);
    }

    /** Сколько раз к датчику обратились. */
    public int calls() {
        return calls.get();
    }

    /** Длина массива, запрошенного при последнем обращении, или -1. */
    public int lastRequestedLength() {
        return lastRequestedLength;
    }

    @Override
    public void nextBytes(byte[] out) {
        calls.incrementAndGet();
        lastRequestedLength = out.length;
        if (failing) {
            throw new IllegalStateException("датчик не должен был вызываться или отказал");
        }
        if (bytes.length != out.length) {
            throw new IllegalStateException(
                    "запрошена добавка Z длиной " + out.length + ", ожидалась " + bytes.length);
        }
        System.arraycopy(bytes, 0, out, 0, out.length);
    }
}
