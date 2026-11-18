package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Строгое преобразование {@link BigInteger} в массив фиксированной длины: усечение слева
 * превращало {@code 2^(8·len) + 5} в {@code 5}, а потеря знака превращала {@code -1} в
 * {@code 255}, и ключ или координата молча становились другим числом.
 */
@DisplayName("Pack.toFixedLengthBigEndian: строгое преобразование BigInteger")
class PackBigIntegerTest {

    @Test
    @DisplayName("Точное совпадение длины")
    void exactLength() {
        BigInteger v = new BigInteger("1234567890abcdef1234567890abcdef", 16);
        byte[] result = Pack.toFixedLengthBigEndian(v, 16);
        assertEquals(16, result.length, "длина результата");
        assertEquals(v, new BigInteger(1, result), "значение не сохранилось");
    }

    @Test
    @DisplayName("Дополнение нулями слева")
    void padsLeftWithZeros() {
        assertArrayEquals(
                new byte[] {0x00, 0x00, 0x00, (byte) 0xFF},
                Pack.toFixedLengthBigEndian(BigInteger.valueOf(255), 4));
    }

    @Test
    @DisplayName("Ведущий знаковый нуль BigInteger не мешает: старший бит установлен")
    void leadingSignByteIsNotCounted() {
        BigInteger v = new BigInteger("80000000000000000000000000000000", 16);
        byte[] result = Pack.toFixedLengthBigEndian(v, 16);
        assertEquals(16, result.length, "длина результата");
        assertEquals(0x80, result[0] & 0xFF, "старший байт");
    }

    @Test
    @DisplayName("Ноль даёт массив нулей нужной длины")
    void zeroGivesZeroArray() {
        assertArrayEquals(new byte[4], Pack.toFixedLengthBigEndian(BigInteger.ZERO, 4));
    }

    @Test
    @DisplayName("Отрицательное значение отвергается, а не превращается в 255")
    void negativeRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.toFixedLengthBigEndian(BigInteger.valueOf(-1), 4));
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.toFixedLengthBigEndian(BigInteger.valueOf(-255), 4));
    }

    @Test
    @DisplayName("Значение шире len байт отвергается, а не усекается слева")
    void tooWideRejected() {
        BigInteger wide = BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(5));
        assertThrows(IllegalArgumentException.class, () -> Pack.toFixedLengthBigEndian(wide, 4));
        // граница: 2^32 - 1 помещается, 2^32 нет
        assertEquals(
                4,
                Pack.toFixedLengthBigEndian(
                                BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE), 4)
                        .length);
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.toFixedLengthBigEndian(BigInteger.ONE.shiftLeft(32), 4));
    }

    @Test
    @DisplayName("Длина не больше нуля отвергается")
    void nonPositiveLengthRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.toFixedLengthBigEndian(BigInteger.ONE, 0));
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.toFixedLengthBigEndian(BigInteger.ONE, -1));
    }

    @Test
    @DisplayName(
            "Каждый вызов возвращает новый массив, изменение результата не влияет на следующий")
    void returnsFreshArray() {
        BigInteger v = BigInteger.valueOf(0x0102030405L);
        byte[] first = Pack.toFixedLengthBigEndian(v, 8);
        first[7] = 0;
        byte[] second = Pack.toFixedLengthBigEndian(v, 8);
        assertNotSame(first, second, "вернулся один и тот же массив");
        assertEquals(0x05, second[7], "изменение результата повлияло на следующий вызов");
    }

    @Test
    @DisplayName(
            "writeFixedLengthBigEndian: пишет со смещением, затирает диапазон, соседние байты не трогает")
    void writesIntoRangeWithoutTouchingNeighbours() {
        byte[] out = new byte[8];
        java.util.Arrays.fill(out, (byte) 0x7E);
        Pack.writeFixedLengthBigEndian(BigInteger.valueOf(0x0102L), out, 2, 4);
        assertArrayEquals(
                new byte[] {0x7E, 0x7E, 0, 0, 0x01, 0x02, 0x7E, 0x7E},
                out,
                "запись должна занять ровно диапазон [2, 6) и обнулить его старшую часть");
    }

    @Test
    @DisplayName(
            "writeFixedLengthBigEndian: диапазон вне буфера и неверное значение отвергаются, буфер цел")
    void writeRejectsBadRange() {
        byte[] out = new byte[4];
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.writeFixedLengthBigEndian(BigInteger.ONE, out, 2, 4));
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.writeFixedLengthBigEndian(BigInteger.ONE, out, -1, 2));
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.writeFixedLengthBigEndian(BigInteger.valueOf(-1), out, 0, 4));
        assertThrows(
                IllegalArgumentException.class,
                () -> Pack.writeFixedLengthBigEndian(BigInteger.ONE.shiftLeft(32), out, 0, 4));
        assertArrayEquals(new byte[4], out, "отвергнутый вызов не должен менять буфер");
    }
}
