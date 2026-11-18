package org.rssys.gost.util;

/**
 * Вспомогательные методы для fuzz-тестов.
 * <p>
 * ПОЧЕМУ нужен rethrowIfBug: Jazzer детектирует баги (IndexOutOfBoundsException
 * и его наследники, NPE, NegativeArraySizeException, ArithmeticException,
 * ClassCastException) только если они НЕ перехвачены тестом.
 * Пустой catch (RuntimeException e) скрывает находки от Jazzer.
 * Правильный паттерн — перебрасывать опасные исключения, а ожидаемые
 * (IllegalArgumentException, IllegalStateException) — проглатывать.
 */
public final class FuzzTestUtils {

    private FuzzTestUtils() {}

    /**
     * Перебрасывает RuntimeException, если это баг (IndexOutOfBoundsException с
     * наследниками AIOOBE и StringIndexOutOfBoundsException, NPE,
     * NegativeArraySizeException, ArithmeticException, ClassCastException).
     * Иначе — проглатывает (ожидаемо для DER-парсинга на битом входе).
     * <p>
     * {@code OutOfMemoryError} сюда не попадает ({@code Error}): его предотвращает проверка
     * границ в парсерах, а не перехват в тесте.
     */
    public static void rethrowIfBug(RuntimeException e) {
        if (e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException
                || e instanceof ArithmeticException
                || e instanceof ClassCastException) {
            throw e;
        }
    }
}
