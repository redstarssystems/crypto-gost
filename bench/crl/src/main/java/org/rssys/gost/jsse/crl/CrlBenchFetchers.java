package org.rssys.gost.jsse.crl;

import java.time.Duration;

/**
 * Загрузчик без SSRF-проверки для замерщика.
 *
 * <p>Публичный конструктор {@link JdkHttpCrlFetcher} блокирует локальный адрес (защита от SSRF),
 * а замеру нужен локальный HTTP-сервер. Класс лежит в пакете библиотеки, чтобы вызвать пакетный
 * конструктор без рефлексии.</p>
 */
public final class CrlBenchFetchers {

    private CrlBenchFetchers() {}

    /** Загрузчик, разрешающий локальные адреса. */
    public static CrlFetcher allowLocal(Duration timeout, int maxResponseSize) {
        return new JdkHttpCrlFetcher(timeout, maxResponseSize, true);
    }
}
