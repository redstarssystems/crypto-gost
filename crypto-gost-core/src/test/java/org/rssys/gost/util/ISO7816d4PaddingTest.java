package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("ISO7816d4Padding")
class ISO7816d4PaddingTest {

    private static final int BLOCK = 16;

    @ParameterizedTest(name = "данных {0} байт")
    @ValueSource(ints = {0, 1, 7, 15, 16, 17, 31, 32})
    @DisplayName("добавление и снятие: roundtrip для всех длин, дополнение 1..16 байт")
    void roundtrip(int dataLength) {
        byte[] data = new byte[dataLength];
        Arrays.fill(data, (byte) 0x7E);
        int padLen = BLOCK - (dataLength % BLOCK);
        byte[] padded = Arrays.copyOf(data, dataLength + padLen);
        ISO7816d4Padding.writePadding(padded, dataLength);

        assertEquals(
                dataLength,
                ISO7816d4Padding.unpad(padded, BLOCK).length,
                "после снятия длина дополнения даёт исходную длину данных (" + padLen + " байт)");
    }

    @ParameterizedTest(name = "данных {0} байт")
    @ValueSource(ints = {0, 1, 7, 15, 16, 17, 31, 32})
    @DisplayName("pad и unpad: новый массив кратен блоку, снятие возвращает данные")
    void padAndUnpadRoundtrip(int dataLength) {
        byte[] data = new byte[dataLength];
        Arrays.fill(data, (byte) 0x7E);

        byte[] original = data.clone();
        byte[] padded = ISO7816d4Padding.pad(data, BLOCK);
        assertArrayEquals(original, data, "pad не изменяет переданный массив");

        assertEquals(0, padded.length % BLOCK, "длина кратна блоку");
        assertEquals(BLOCK - (dataLength % BLOCK), padded.length - dataLength, "длина дополнения");
        assertArrayEquals(data, ISO7816d4Padding.unpad(padded, BLOCK), "данные");
        assertNotSame(data, padded, "возвращается новый массив");
    }

    @Test
    @DisplayName(
            "pad и unpad: неверные аргументы и испорченное дополнение -> IllegalArgumentException")
    void padAndUnpadRejectBadInput() {
        assertThrows(IllegalArgumentException.class, () -> ISO7816d4Padding.pad(null, BLOCK));
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.pad(new byte[4], 0),
                "размер блока 0");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(new byte[BLOCK], BLOCK),
                "блок без маркера: как и у PKCS#7, испорченное дополнение даёт IllegalArgumentException");
    }

    @Test
    @DisplayName(
            "writePadding: len >= длины буфера и отрицательная длина -> IllegalArgumentException")
    void writePaddingRejectsNoRoomForMarker() {
        byte[] buf = new byte[BLOCK];
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.writePadding(buf, BLOCK),
                "len == длина буфера: места под маркер нет, вместо ArrayIndexOutOfBounds");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.writePadding(buf, BLOCK + 1),
                "len больше буфера");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.writePadding(buf, -1),
                "отрицательная длина данных");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.writePadding(null, 0),
                "буфер null");
    }

    @Test
    @DisplayName("unpad: дополнение длиннее блока отвергается (маркер не в последнем блоке)")
    void unpadRejectsPaddingLongerThanBlock() {
        // 0x80 во втором байте первого блока, затем нули до конца двух блоков: раньше принималось
        // как дополнение в 30 байт и отрезалось от открытого текста
        byte[] twoBlocks = new byte[2 * BLOCK];
        twoBlocks[2] = (byte) 0x80;
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(twoBlocks, BLOCK),
                "маркер вне последнего блока должен отвергаться");

        // Полностью нулевой последний блок тоже недопустим: полный блок дополнения начинается с
        // 0x80
        byte[] zeroLastBlock = new byte[2 * BLOCK];
        Arrays.fill(zeroLastBlock, 0, BLOCK, (byte) 0x11);
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(zeroLastBlock, BLOCK),
                "последний блок без маркера");
    }

    @Test
    @DisplayName("unpad: ненулевой байт после маркера и отсутствие маркера отвергаются")
    void unpadRejectsCorruptedTail() {
        byte[] nonZeroAfterMarker = new byte[BLOCK];
        nonZeroAfterMarker[3] = (byte) 0x80;
        nonZeroAfterMarker[9] = 1;
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(nonZeroAfterMarker, BLOCK),
                "ненулевой байт после маркера");

        byte[] noMarker = new byte[BLOCK];
        Arrays.fill(noMarker, (byte) 0x42);
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(noMarker, BLOCK),
                "нет маркера 0x80");
    }

    @Test
    @DisplayName("unpad: данные до последнего блока, содержащие 0x80, не влияют на результат")
    void unpadIgnoresEarlierBlocks() {
        byte[] data = new byte[2 * BLOCK];
        Arrays.fill(data, 0, BLOCK, (byte) 0x80);
        data[BLOCK] = (byte) 0x80; // полный блок дополнения: 0x80 и 15 нулей
        assertEquals(
                BLOCK,
                ISO7816d4Padding.unpad(data, BLOCK).length,
                "дополнение — весь последний блок: остаётся первый блок данных");
    }

    @Test
    @DisplayName("unpad: некорректные аргументы -> IllegalArgumentException")
    void unpadRejectsBadArguments() {
        assertThrows(
                IllegalArgumentException.class, () -> ISO7816d4Padding.unpad(null, BLOCK), "null");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(new byte[0], BLOCK),
                "пустой буфер");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(new byte[BLOCK + 1], BLOCK),
                "длина не кратна блоку");
        assertThrows(
                IllegalArgumentException.class,
                () -> ISO7816d4Padding.unpad(new byte[BLOCK], 0),
                "нулевой размер блока");
    }
}
