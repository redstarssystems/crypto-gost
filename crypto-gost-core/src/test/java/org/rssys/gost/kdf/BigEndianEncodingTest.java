package org.rssys.gost.kdf;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("BigEndianEncoding: минимальное big-endian кодирование для KDF")
class BigEndianEncodingTest {

    @Test
    @DisplayName("ноль кодируется одним нулевым байтом")
    void zeroIsSingleZeroByte() {
        assertArrayEquals(new byte[] {0}, BigEndianEncoding.minimal(0), "ноль");
    }

    @Test
    @DisplayName("границы по длине: без ведущих нулей, старший байт первым")
    void lengthBoundaries() {
        assertArrayEquals(new byte[] {1}, BigEndianEncoding.minimal(1), "1");
        assertArrayEquals(new byte[] {(byte) 0xFF}, BigEndianEncoding.minimal(255), "255");
        assertArrayEquals(new byte[] {1, 0}, BigEndianEncoding.minimal(256), "256");
        assertArrayEquals(
                new byte[] {(byte) 0xFF, (byte) 0xFF}, BigEndianEncoding.minimal(65535), "65535");
        assertArrayEquals(new byte[] {1, 0, 0}, BigEndianEncoding.minimal(65536), "65536");
        assertArrayEquals(new byte[] {1, 0, 0, 0}, BigEndianEncoding.minimal(1 << 24), "2^24");
        assertArrayEquals(
                new byte[] {0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
                BigEndianEncoding.minimal(Integer.MAX_VALUE),
                "Integer.MAX_VALUE");
    }

    @Test
    @DisplayName("типичные значения L в битах для 32 и 64 байт ключа")
    void typicalLengthValues() {
        assertArrayEquals(new byte[] {1, 0}, BigEndianEncoding.minimal(32 * 8), "L = 256 бит");
        assertArrayEquals(new byte[] {2, 0}, BigEndianEncoding.minimal(64 * 8), "L = 512 бит");
    }
}
