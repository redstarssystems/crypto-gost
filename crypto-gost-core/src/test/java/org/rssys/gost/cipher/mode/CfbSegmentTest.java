package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;

@DisplayName("Cfb: размер сегмента и короткий сегмент по ГОСТ Р 34.13-2015")
class CfbSegmentTest {

    private static final int BLOCK = 16;
    private static final int DATA_LEN = 48; // кратно 1, 3, 8 и 16 байтам: целые сегменты для всех s
    private static final int CHUNK = 7; // не кратно ни одному сегменту: проверка потоковой нарезки

    private static byte[] pattern(int len, int seed) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (i * 31 + seed);
        }
        return out;
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 12, 136, 200, -1, -8, Integer.MIN_VALUE, Integer.MAX_VALUE})
    @DisplayName("недопустимый размер сегмента отвергается")
    void invalidSegmentRejected(int bits) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Cfb(new Kuznyechik(), bits),
                "размер сегмента " + bits + " бит должен быть отвергнут");
    }

    @ParameterizedTest
    @CsvSource({"8, CFB8", "24, CFB24", "64, CFB64", "128, CFB128"})
    @DisplayName("граничные и промежуточные размеры сегмента принимаются, имя отражает сегмент")
    void validSegmentAccepted(int bits, String suffix) {
        Cfb cfb = new Cfb(new Kuznyechik(), bits);
        assertEquals("GOST3412-2015/" + suffix, cfb.getAlgorithmName(), "имя режима");
        assertEquals(bits / 8, cfb.getBlockSize(), "размер сегмента в байтах");
    }

    @Test
    @DisplayName("конструктор по умолчанию - полный блок, имя CFB128")
    void defaultConstructorIsFullBlock() {
        Cfb cfb = new Cfb(new Kuznyechik());
        assertEquals("GOST3412-2015/CFB128", cfb.getAlgorithmName(), "имя режима");
        assertEquals(BLOCK, cfb.getBlockSize(), "сегмент равен блоку");
    }

    /**
     * Независимый расчёт CFB по определению: C = P xor MSB_s(E(MSB_n(R))),
     * R = LSB_{m-s}(R) || C, где C - шифртекст сегмента.
     */
    private static byte[] reference(
            byte[] key, byte[] iv, byte[] data, int segment, boolean encrypt) {
        Kuznyechik block = new Kuznyechik();
        block.init(true, new SymmetricKey(key));
        byte[] register = iv.clone();
        byte[] out = new byte[data.length];
        byte[] gamma = new byte[BLOCK];
        for (int off = 0; off < data.length; off += segment) {
            block.processBlock(register, 0, gamma, 0);
            byte[] cipherSegment = new byte[segment];
            for (int i = 0; i < segment; i++) {
                out[off + i] = (byte) (data[off + i] ^ gamma[i]);
                cipherSegment[i] = encrypt ? out[off + i] : data[off + i];
            }
            System.arraycopy(register, segment, register, 0, register.length - segment);
            System.arraycopy(cipherSegment, 0, register, register.length - segment, segment);
        }
        return out;
    }

    private static byte[] run(
            byte[] key, byte[] iv, byte[] data, int bits, boolean encrypt, int chunk) {
        Cfb cfb = new Cfb(new Kuznyechik(), bits);
        cfb.init(encrypt, new ParametersWithIV(new SymmetricKey(key), iv));
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += chunk) {
            int len = Math.min(chunk, data.length - off);
            cfb.processBytes(data, off, len, out, off);
        }
        return out;
    }

    @ParameterizedTest
    @CsvSource({"8, 16", "8, 32", "24, 16", "24, 32", "64, 16", "64, 32", "128, 16", "128, 32"})
    @DisplayName(
            "шифрование и расшифрование совпадают с расчётом по определению, в том числе по частям")
    void matchesReference(int bits, int registerLen) {
        byte[] key = pattern(32, 3);
        byte[] iv = pattern(registerLen, 11);
        byte[] plain = pattern(DATA_LEN, 77);
        int segment = bits / 8;

        byte[] expected = reference(key, iv, plain, segment, true);
        assertArrayEquals(
                expected, run(key, iv, plain, bits, true, DATA_LEN), "шифрование целиком");
        assertArrayEquals(expected, run(key, iv, plain, bits, true, CHUNK), "шифрование по частям");

        assertArrayEquals(
                plain,
                reference(key, iv, expected, segment, false),
                "расчёт по определению: расшифрование возвращает открытый текст");
        assertArrayEquals(
                plain,
                run(key, iv, expected, bits, false, DATA_LEN),
                "расшифрование целиком возвращает открытый текст");
        assertArrayEquals(
                plain,
                run(key, iv, expected, bits, false, CHUNK),
                "расшифрование по частям возвращает открытый текст");
        assertFalse(Arrays.equals(plain, expected), "шифртекст не равен открытому тексту");
    }

    @Test
    @DisplayName("reset() посреди сегмента возвращает режим к начальному состоянию")
    void resetInsideSegmentRestoresInitialState() {
        byte[] key = pattern(32, 5);
        byte[] iv = pattern(BLOCK, 9);
        byte[] plain = pattern(DATA_LEN, 21);
        int bits = 64;
        byte[] expected = reference(key, iv, plain, bits / 8, true);

        Cfb cfb = new Cfb(new Kuznyechik(), bits);
        cfb.init(true, new ParametersWithIV(new SymmetricKey(key), iv));
        // 3 байта из 8: сегмент не завершён, регистр ещё не сдвигался
        cfb.processBytes(plain, 0, 3, new byte[3], 0);
        cfb.reset();
        cfb.init(true, new ParametersWithIV(new SymmetricKey(key), iv));

        byte[] out = new byte[DATA_LEN];
        cfb.processBytes(plain, 0, DATA_LEN, out, 0);
        assertArrayEquals(expected, out, "после reset и init результат как у нового объекта");
    }

    @Test
    @DisplayName("processBlock обрабатывает ровно один сегмент и совпадает с потоковой обработкой")
    void processBlockHandlesOneSegment() {
        byte[] key = pattern(32, 5);
        byte[] iv = pattern(BLOCK, 9);
        byte[] plain = pattern(DATA_LEN, 21);
        int bits = 64;
        int segment = bits / 8;
        byte[] expected = reference(key, iv, plain, segment, true);

        Cfb cfb = new Cfb(new Kuznyechik(), bits);
        cfb.init(true, new ParametersWithIV(new SymmetricKey(key), iv));
        byte[] out = new byte[DATA_LEN];
        for (int off = 0; off < DATA_LEN; off += segment) {
            assertEquals(segment, cfb.processBlock(plain, off, out, off), "размер сегмента");
        }
        assertArrayEquals(expected, out, "processBlock по сегментам совпадает с расчётом");
    }
}
