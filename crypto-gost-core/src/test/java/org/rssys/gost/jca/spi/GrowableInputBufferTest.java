package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GrowableInputBuffer: накопление ввода AEAD-шифров")
class GrowableInputBufferTest {

    private static byte[] filled(int len, int value) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static boolean allZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    @DisplayName("новый буфер пуст, пустое добавление ничего не выделяет")
    void emptyBuffer() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        byte[] initial = buffer.array();
        buffer.append(new byte[5], 0, 0);
        buffer.append(new byte[5], 0, -1);
        assertEquals(0, buffer.size(), "размер пуст");
        assertSame(initial, buffer.array(), "массив не выделялся");
    }

    @Test
    @DisplayName("добавленные порции идут подряд, смещение источника учитывается")
    void appendKeepsOrder() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        byte[] src = {9, 1, 2, 3, 9};
        buffer.append(src, 1, 3);
        buffer.append(src, 0, 1);
        assertEquals(4, buffer.size(), "размер");
        assertArrayEquals(
                new byte[] {1, 2, 3, 9}, Arrays.copyOf(buffer.array(), 4), "порядок байт");
    }

    @Test
    @DisplayName("ёмкость растёт удвоением, а не на каждую порцию")
    void capacityGrowsGeometrically() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        int reallocations = 0;
        byte[] previous = buffer.array();
        for (int i = 0; i < 100_000; i++) {
            buffer.append(new byte[] {(byte) i}, 0, 1);
            if (buffer.array() != previous) {
                reallocations++;
                previous = buffer.array();
            }
        }
        assertEquals(100_000, buffer.size(), "размер");
        // 64 -> 128 -> ... -> 131072: 12 выделений; побайтовое выделение дало бы 100000
        assertTrue(reallocations <= 20, "число выделений логарифмическое: " + reallocations);
        for (int i = 0; i < 100_000; i++) {
            assertEquals((byte) i, buffer.array()[i], "байт " + i);
        }
    }

    @Test
    @DisplayName("одна большая порция выделяет ровно нужное, а не удвоение пустого")
    void bigFirstAppendFitsExactly() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        buffer.append(filled(1000, 7), 0, 1000);
        assertEquals(1000, buffer.size(), "размер");
        assertEquals(1000, buffer.array().length, "ёмкость равна размеру первой порции");
    }

    @Test
    @DisplayName("при росте прежний массив затирается")
    void oldArrayWipedOnGrowth() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        buffer.append(filled(64, 0x5A), 0, 64);
        byte[] old = buffer.array();
        assertFalse(allZero(old), "до роста массив содержит данные");
        buffer.append(filled(1, 0x5A), 0, 1);
        assertNotSame(old, buffer.array(), "массив заменён");
        assertTrue(allZero(old), "прежний массив затёрт");
    }

    @Test
    @DisplayName("clear затирает массив целиком и возвращает пустое состояние")
    void clearWipes() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        buffer.append(filled(100, 0x33), 0, 100);
        byte[] held = buffer.array();
        buffer.clear();
        assertTrue(allZero(held), "массив затёрт");
        assertEquals(0, buffer.size(), "размер сброшен");
        assertEquals(0, buffer.array().length, "массив освобождён");
        buffer.append(filled(3, 1), 0, 3);
        assertEquals(3, buffer.size(), "буфер пригоден после clear");
    }

    @Test
    @DisplayName("предел размера: ровно предел принимается, больше - IllegalStateException")
    void maxSizeEnforced() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(10);
        buffer.append(filled(6, 1), 0, 6);
        buffer.append(filled(4, 2), 0, 4);
        assertEquals(10, buffer.size(), "ровно предел");
        assertEquals(10, buffer.array().length, "ёмкость не выше предела");
        assertThrows(
                IllegalStateException.class,
                () -> buffer.append(filled(1, 3), 0, 1),
                "превышение предела");
        assertEquals(10, buffer.size(), "размер не изменился после отказа");
        assertEquals(2, buffer.array()[9], "содержимое не повреждено после отказа");
    }

    @Test
    @DisplayName("огромная длина не переполняет int при проверке предела")
    void hugeLengthDoesNotOverflow() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(100);
        buffer.append(filled(50, 1), 0, 50);
        // size + len переполнил бы int и дал отрицательное число
        assertThrows(
                IllegalStateException.class,
                () -> buffer.append(new byte[1], 0, Integer.MAX_VALUE),
                "size + len переполняет int");
        assertEquals(50, buffer.size(), "размер не изменился");
    }

    @Test
    @DisplayName("диапазон вне источника - IndexOutOfBoundsException, буфер не меняется")
    void sourceBoundsChecked() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        buffer.append(filled(3, 4), 0, 3);
        byte[] before = buffer.array();
        assertThrows(
                IndexOutOfBoundsException.class,
                () -> buffer.append(new byte[4], 2, 3),
                "диапазон выходит за источник");
        assertThrows(
                IndexOutOfBoundsException.class,
                () -> buffer.append(new byte[4], -1, 2),
                "отрицательное смещение");
        assertEquals(3, buffer.size(), "размер не изменился");
        assertSame(before, buffer.array(), "рост не выполнялся до проверки границ");
    }

    @Test
    @DisplayName("недопустимый предел размера отвергается")
    void invalidMaxSizeRejected() {
        assertThrows(
                IllegalArgumentException.class, () -> new GrowableInputBuffer(-1), "отрицательный");
        assertThrows(
                IllegalArgumentException.class,
                () -> new GrowableInputBuffer(Integer.MAX_VALUE),
                "больше длины массива JVM");
    }

    @Test
    @DisplayName("после clear следующее, более короткое сообщение не видит остатков прежнего")
    void shorterMessageAfterClearHasNoLeftovers() {
        GrowableInputBuffer buffer = new GrowableInputBuffer(GrowableInputBuffer.MAX_SIZE);
        buffer.append(filled(200, 0x7E), 0, 200);
        buffer.clear();
        buffer.append(filled(5, 0x11), 0, 5);
        byte[] array = buffer.array();
        for (int i = 5; i < array.length; i++) {
            assertEquals(0, array[i], "хвост ёмкости обязан быть нулевым, байт " + i);
        }
    }

    @Test
    @DisplayName("nextCapacity: удвоение, нижняя граница, нужный размер и предел без переполнения")
    void nextCapacityBoundaries() {
        int max = GrowableInputBuffer.MAX_SIZE;
        assertEquals(64, GrowableInputBuffer.nextCapacity(0, 1, max), "первая ёмкость");
        assertEquals(1000, GrowableInputBuffer.nextCapacity(0, 1000, max), "первая порция больше");
        assertEquals(128, GrowableInputBuffer.nextCapacity(64, 65, max), "удвоение");
        assertEquals(
                500,
                GrowableInputBuffer.nextCapacity(64, 500, max),
                "нужный размер больше удвоения");
        assertEquals(
                max, GrowableInputBuffer.nextCapacity(max / 2 + 1, max / 2 + 2, max), "предел");
        // удвоение Integer.MAX_VALUE в int дало бы отрицательное число
        assertEquals(
                max,
                GrowableInputBuffer.nextCapacity(Integer.MAX_VALUE, max, max),
                "переполнение int");
        assertEquals(10, GrowableInputBuffer.nextCapacity(8, 9, 10), "малый предел");
    }
}
