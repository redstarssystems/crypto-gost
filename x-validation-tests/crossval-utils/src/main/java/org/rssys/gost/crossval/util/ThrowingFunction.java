package org.rssys.gost.crossval.util;

/**
 * Аналог {@link java.util.function.Function}, допускающий проверяемые исключения.
 */
@FunctionalInterface
public interface ThrowingFunction<T, R> {
    R apply(T t) throws Exception;
}
