package org.rssys.gost.util;

import java.security.SecureRandom;

/**
 * Общий потокобезопасный экземпляр {@link SecureRandom} для всей библиотеки.
 *
 * <p>{@link SecureRandom} является потокобезопасным по спецификации JDK —
 * один экземпляр достаточен для всего приложения и позволяет избежать
 * лишних дорогостоящих инициализаций при каждом вызове.
 *
 * <p>Классы, которым нужна возможность подмены генератора (для тестирования),
 * сохраняют перегрузки с явным параметром {@code SecureRandom rng}.
 */
public final class CryptoRandom {

    /** Разделяемый потокобезопасный генератор случайных чисел. */
    public static final SecureRandom INSTANCE = new SecureRandom();

    private CryptoRandom() {}
}
