package org.rssys.gost.jsse.crl;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * Доступ тестов других пакетов к кэшу CRL с заменёнными часами. Лежит в тестовых исходниках
 * пакета библиотеки: тестовый конструктор {@code CrlCache} пакетный, и делать его публичным ради
 * тестов менеджера не нужно.
 */
public final class CrlCacheTestSupport {

    private CrlCacheTestSupport() {}

    /** Кэш с заданными часами: возраст и истечение записей считаются по ним. */
    public static CrlCache withClock(long maxBytes, Duration maxAge, LongSupplier clock) {
        return new CrlCache(maxBytes, maxAge, clock);
    }
}
