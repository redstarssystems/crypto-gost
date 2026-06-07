package org.rssys.gost.crossval.util;

/**
 * Аналог {@link java.util.function.BiConsumer}, допускающий проверяемые исключения.
 */
@FunctionalInterface
public interface ThrowingBiConsumer<T, U> {
    void accept(T t, U u) throws Exception;
}
