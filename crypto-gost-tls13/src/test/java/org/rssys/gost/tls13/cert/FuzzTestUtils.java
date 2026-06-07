package org.rssys.gost.tls13.cert;

/**
 * Вспомогательные методы для fuzz-тестов пакета cert.
 * <p>
 * ПОЧЕМУ нужен rethrowIfBug: Jazzer детектирует баги (AIOOBE, NPE,
 * NegativeArraySizeException) только если они НЕ перехвачены тестом.
 * Пустой catch (RuntimeException e) скрывает находки от Jazzer.
 * Правильный паттерн — перебрасывать опасные исключения, а ожидаемые
 * (IllegalArgumentException, IllegalStateException) — проглатывать.
 */
final class FuzzTestUtils {

    private FuzzTestUtils() {
    }

    /**
     * Перебрасывает RuntimeException, если это баг (AIOOBE, NPE,
     * NegativeArraySizeException). Иначе — проглатывает (ожидаемо
     * для DER-парсинга на битом входе).
     */
    static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
