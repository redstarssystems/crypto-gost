package org.rssys.gost;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.digest.Streebog;

/**
 * Проверка внутреннего состояния {@link Streebog} через рефлексию.
 *
 * <p>Рефлексия нужна намеренно: затирание рабочих полей дайджеста не наблюдается через публичный
 * API, а без проверки замена {@code destroy()} на {@code reset()} прошла бы все остальные тесты.
 * Поля обходятся все сразу, без привязки к именам: добавленное в класс рабочее поле не
 * останется незамеченным. После {@code destroy()} каждое поле-массив должно совпадать с полем
 * свежего объекта того же класса (нулевые рабочие слова и начальное значение {@code h}).
 */
public final class StreebogStateProbe {

    private StreebogStateProbe() {}

    /** Сравнивает каждое поле-массив с полем свежего экземпляра; расхождение — ошибка. */
    public static void assertWipedLikeFresh(Object digest) throws Exception {
        Object fresh = digest.getClass().getDeclaredConstructor().newInstance();
        List<Field> fields = arrayFields();
        assertFalse(fields.isEmpty(), "у Streebog не найдено ни одного поля-массива");
        for (Field field : fields) {
            assertArrayEqualsUntyped(
                    field.get(fresh),
                    field.get(digest),
                    "поле " + field.getName() + " после destroy() не совпадает со свежим объектом");
        }
    }

    /** Истина, если хотя бы одно поле-массив отличается от поля свежего экземпляра. */
    public static boolean hasLeftoverState(Object digest) throws Exception {
        Object fresh = digest.getClass().getDeclaredConstructor().newInstance();
        for (Field field : arrayFields()) {
            if (!sameContent(field.get(fresh), field.get(digest))) {
                return true;
            }
        }
        return false;
    }

    private static List<Field> arrayFields() {
        List<Field> result = new ArrayList<>();
        for (Field field : Streebog.class.getDeclaredFields()) {
            boolean isArray = field.getType() == byte[].class || field.getType() == long[].class;
            if (isArray && !Modifier.isStatic(field.getModifiers())) {
                field.setAccessible(true);
                result.add(field);
            }
        }
        return result;
    }

    private static boolean sameContent(Object expected, Object actual) {
        if (expected instanceof byte[]) {
            return java.util.Arrays.equals((byte[]) expected, (byte[]) actual);
        }
        return java.util.Arrays.equals((long[]) expected, (long[]) actual);
    }

    private static void assertArrayEqualsUntyped(Object expected, Object actual, String message) {
        if (expected instanceof byte[]) {
            assertArrayEquals((byte[]) expected, (byte[]) actual, message);
        } else {
            assertArrayEquals((long[]) expected, (long[]) actual, message);
        }
    }

    /** Защита от пустой проверки: поля, в которых оседает вход, существуют. */
    public static void assertHasWorkFields() {
        assertTrue(arrayFields().size() >= 2, "ожидаются рабочие поля-массивы Streebog");
    }
}
