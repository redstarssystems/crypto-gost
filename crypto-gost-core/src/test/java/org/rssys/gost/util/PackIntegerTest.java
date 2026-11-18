package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** {@link Pack#writeInt}, {@link Pack#readInt}, {@link Pack#writeLong}, {@link Pack#readLong}. */
@DisplayName("Pack: целые в порядке big-endian")
class PackIntegerTest {

    @Test
    @DisplayName("writeInt пишет старший байт первым и не трогает соседние байты")
    void writeIntIsBigEndian() {
        byte[] out = new byte[6];
        Pack.writeInt(0x01020304, out, 1);
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 0}, out);
    }

    @Test
    @DisplayName("writeLong пишет старший байт первым и не трогает соседние байты")
    void writeLongIsBigEndian() {
        byte[] out = new byte[10];
        Pack.writeLong(0x0102030405060708L, out, 1);
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 0}, out);
    }

    @Test
    @DisplayName("readInt и readLong возвращают записанное значение, в том числе с битом знака")
    void readReturnsWrittenValue() {
        int[] ints = {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, 0x80000001, 0x7F00FF00};
        for (int value : ints) {
            byte[] buf = new byte[7];
            Pack.writeInt(value, buf, 3);
            assertEquals(value, Pack.readInt(buf, 3), "int " + value);
        }
        long[] longs = {0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, 0x8000000000000001L};
        for (long value : longs) {
            byte[] buf = new byte[11];
            Pack.writeLong(value, buf, 3);
            assertEquals(value, Pack.readLong(buf, 3), "long " + value);
        }
    }

    @Test
    @DisplayName("Чтение и запись за границей массива бросают IndexOutOfBoundsException")
    void outOfBoundsIsRejected() {
        assertThrows(IndexOutOfBoundsException.class, () -> Pack.writeInt(1, new byte[3], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Pack.readInt(new byte[4], 1));
        assertThrows(IndexOutOfBoundsException.class, () -> Pack.writeLong(1L, new byte[7], 0));
        assertThrows(IndexOutOfBoundsException.class, () -> Pack.readLong(new byte[8], 1));
    }
}
