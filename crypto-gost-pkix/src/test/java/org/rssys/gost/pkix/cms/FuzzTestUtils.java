package org.rssys.gost.pkix.cms;

/**
 * Вспомогательные методы для fuzz-тестов пакета cms.
 * <p>
 * ПОЧЕМУ нужен rethrowIfBug: Jazzer детектирует баги (AIOOBE, NPE,
 * NegativeArraySizeException) только если они НЕ перехвачены тестом.
 * Пустой catch (RuntimeException e) скрывает находки от Jazzer.
 * Правильный паттерн — перебрасывать опасные исключения, а ожидаемые
 * (IllegalArgumentException, IllegalStateException) — проглатывать.
 */
final class FuzzTestUtils {

    private FuzzTestUtils() {}

    /**
     * Перебрасывает RuntimeException, если это баг (AIOOBE, NPE,
     * NegativeArraySizeException, IndexOutOfBoundsException,
     * ClassCastException, ArithmeticException, BufferOverflowException).
     * Иначе — проглатывает (ожидаемо для DER-парсинга на битом входе).
     */
    static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException
                || e instanceof ClassCastException
                || e instanceof ArithmeticException
                || e instanceof java.nio.BufferOverflowException) {
            throw e;
        }
    }
}
