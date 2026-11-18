package org.rssys.gost.pkix.util;

import java.nio.BufferOverflowException;

/**
 * Вспомогательные методы для fuzz-тестов модулей pkix и tls13.
 * <p>
 * Jazzer детектирует баги (выход за границы массива и буфера, NPE,
 * отрицательный размер массива и т. п.) только если они НЕ перехвачены тестом.
 * Пустой catch (RuntimeException e) скрывает находки от Jazzer.
 * Правильный паттерн - перебрасывать опасные исключения, а ожидаемые
 * (IllegalArgumentException, IllegalStateException) - проглатывать.
 * <p>
 * Класс публичный, потому что fuzz-тесты tls13 берут его из test-jar pkix.
 * Набор исключений шире, чем у копии в core: добавлен BufferOverflowException
 * (запись за границы буфера), который тоже означает ошибку расчёта размера в коде,
 * а не битый вход.
 */
public final class FuzzTestUtils {

    private FuzzTestUtils() {}

    /**
     * Перебрасывает RuntimeException, если это баг: IndexOutOfBoundsException
     * (с наследниками ArrayIndexOutOfBoundsException и StringIndexOutOfBoundsException),
     * NegativeArraySizeException, NullPointerException, ClassCastException,
     * ArithmeticException, BufferOverflowException. Иначе - проглатывает
     * (ожидаемо для DER-парсинга на битом входе).
     * <p>
     * {@code OutOfMemoryError} сюда не попадает ({@code Error}): его предотвращает
     * проверка границ в парсерах, а не перехват в тесте.
     */
    public static void rethrowIfBug(RuntimeException e) {
        if (e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException
                || e instanceof ClassCastException
                || e instanceof ArithmeticException
                || e instanceof BufferOverflowException) {
            throw e;
        }
    }
}
