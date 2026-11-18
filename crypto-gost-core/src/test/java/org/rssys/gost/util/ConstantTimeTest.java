package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ConstantTime.equals: сравнение диапазонов без раннего выхода")
class ConstantTimeTest {

    @Test
    @DisplayName("Равные диапазоны с разных смещений равны, байты вне диапазона не учитываются")
    void equalRangesWithOffsets() {
        byte[] a = {9, 1, 2, 3, 9};
        byte[] b = {7, 7, 1, 2, 3};
        assertTrue(ConstantTime.equals(a, 1, b, 2, 3));
    }

    @Test
    @DisplayName("Различие в первом, среднем и последнем байте обнаруживается")
    void anyDifferingByteIsDetected() {
        for (int position = 0; position < 16; position++) {
            byte[] a = new byte[16];
            byte[] b = new byte[16];
            b[position] = 1;
            assertFalse(ConstantTime.equals(a, 0, b, 0, 16), "позиция " + position);
        }
    }

    @Test
    @DisplayName("Нулевая длина даёт true, в том числе на границе массива")
    void emptyRangeIsEqual() {
        assertTrue(ConstantTime.equals(new byte[2], 2, new byte[3], 3, 0));
    }

    @Test
    @DisplayName("null, отрицательные значения и выход за границы отвергаются исключением")
    void invalidArgumentsAreRejected() {
        byte[] a = new byte[4];
        byte[] b = new byte[4];
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(null, 0, b, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, 0, null, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, -1, b, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, 0, b, -1, 1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, 0, b, 0, -1));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, 2, b, 0, 3));
        assertThrows(IllegalArgumentException.class, () -> ConstantTime.equals(a, 0, b, 2, 3));
    }
}
