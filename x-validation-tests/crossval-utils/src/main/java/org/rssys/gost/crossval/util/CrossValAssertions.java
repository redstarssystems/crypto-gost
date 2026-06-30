package org.rssys.gost.crossval.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Сбор нескольких AssertionError в одно исключение с addSuppressed.
 * Аналог JUnit 5 {@code assertAll}, но для параметризованных сообщений.
 */
public final class CrossValAssertions {

    private CrossValAssertions() {}

    /**
     * Выполняет {@code assertion} для каждого сообщения из {@code messages}.
     * Все {@link AssertionError} собираются; если есть хотя бы одна ошибка —
     * первая выбрасывается с остальными в suppressed.
     */
    public static void assertForEachMessage(byte[][] messages, ThrowingConsumer<byte[]> assertion) {
        List<AssertionError> errors = new ArrayList<>();
        for (byte[] msg : messages) {
            try {
                assertion.accept(msg);
            } catch (AssertionError e) {
                errors.add(e);
            } catch (Exception e) {
                errors.add(new AssertionError("Исключение при проверке сообщения", e));
            }
        }
        if (!errors.isEmpty()) {
            AssertionError first = errors.get(0);
            for (int i = 1; i < errors.size(); i++) {
                first.addSuppressed(errors.get(i));
            }
            throw first;
        }
    }

    /**
     * Перегрузка с индексом сообщения. Позволяет включить {@code i} в сообщение об ошибке.
     */
    public static void assertForEachMessage(
            byte[][] messages, ThrowingBiConsumer<byte[], Integer> assertion) {
        List<AssertionError> errors = new ArrayList<>();
        for (int i = 0; i < messages.length; i++) {
            try {
                assertion.accept(messages[i], i);
            } catch (AssertionError e) {
                errors.add(e);
            } catch (Exception e) {
                errors.add(new AssertionError("Исключение при проверке сообщения [" + i + "]", e));
            }
        }
        if (!errors.isEmpty()) {
            AssertionError first = errors.get(0);
            for (int j = 1; j < errors.size(); j++) {
                first.addSuppressed(errors.get(j));
            }
            throw first;
        }
    }
}
