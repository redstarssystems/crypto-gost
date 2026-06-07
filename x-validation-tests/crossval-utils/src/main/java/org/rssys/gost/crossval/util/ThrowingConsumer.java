package org.rssys.gost.crossval.util;

/**
 * Аналог {@link java.util.function.Consumer}, допускающий проверяемые исключения.
 */
@FunctionalInterface
public interface ThrowingConsumer<T> {
    void accept(T t) throws Exception;
}
