package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Pkcs7Padding: добавление и снятие PKCS#7 padding")
class Pkcs7PaddingTest {

    private static final int BLOCK = 16;

    @Test
    @DisplayName("Roundtrip: pad -> unpad возвращает оригинал (все длины остатка)")
    void roundtrip() {
        // Проверяем все возможные значения padLen от 1 (полный блок дополнения) до blockSize.
        for (int dataLen = 0; dataLen <= 3 * BLOCK; dataLen++) {
            byte[] data = new byte[dataLen];
            for (int i = 0; i < dataLen; i++) {
                data[i] = (byte) (i + 1);
            }
            byte[] padded = Pkcs7Padding.pad(data, BLOCK);
            assertEquals(0, padded.length % BLOCK, "дополненные данные кратны блоку");
            byte[] restored = Pkcs7Padding.unpad(padded, BLOCK);
            assertArrayEquals(data, restored, "roundtrip при dataLen=" + dataLen);
        }
    }

    @Test
    @DisplayName("unpad: последний байт вне [1, blockSize] -> исключение")
    void invalidLastByte() {
        byte[] data = new byte[BLOCK];
        data[BLOCK - 1] = 0; // padLen=0 недопустимо
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(data, BLOCK),
                "padLen=0 должен отклоняться");

        byte[] tooLarge = new byte[BLOCK];
        tooLarge[BLOCK - 1] = (byte) (BLOCK + 1); // padLen > blockSize
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(tooLarge, BLOCK),
                "padLen>blockSize должен отклоняться");
    }

    @Test
    @DisplayName("unpad: несогласованные padding-байты -> исключение")
    void inconsistentBytes() {
        byte[] data = new byte[BLOCK];
        // padLen=3, но один из padding-байтов не равен 3
        data[BLOCK - 1] = 3;
        data[BLOCK - 2] = 3;
        data[BLOCK - 3] = 2; // испорчен
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(data, BLOCK),
                "несогласованные padding-байты должны отклоняться");
    }

    @Test
    @DisplayName("unpad: граничный padLen=blockSize (весь блок — padding)")
    void fullBlockPadding() {
        byte[] data = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            data[i] = (byte) BLOCK;
        }
        byte[] restored = Pkcs7Padding.unpad(data, BLOCK);
        assertEquals(0, restored.length, "полный блок дополнения -> пустой результат");
    }

    @Test
    @DisplayName("unpad: граничный padLen=1")
    void singleBytePadding() {
        byte[] data = new byte[BLOCK];
        for (int i = 0; i < BLOCK - 1; i++) {
            data[i] = (byte) 0x77;
        }
        data[BLOCK - 1] = 1;
        byte[] restored = Pkcs7Padding.unpad(data, BLOCK);
        assertEquals(BLOCK - 1, restored.length, "padLen=1 -> снимается 1 байт");
    }

    @Test
    @DisplayName("unpad: длина не кратна блоку / пустой -> исключение")
    void malformedInput() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(new byte[BLOCK - 1], BLOCK),
                "некратная блоку длина должна отклоняться");
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(new byte[0], BLOCK),
                "пустой ввод должен отклоняться");
    }

    @Test
    @DisplayName(
            "unpad: размер блока вне 1..255 -> IllegalArgumentException, а не ArithmeticException")
    void invalidBlockSizeIsRejected() {
        byte[] data = new byte[BLOCK];
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs7Padding.unpad(data, 0),
                "нулевой размер блока раньше давал деление на ноль");
        assertThrows(IllegalArgumentException.class, () -> Pkcs7Padding.unpad(data, -1));
        assertThrows(IllegalArgumentException.class, () -> Pkcs7Padding.unpad(data, 256));
    }
}
