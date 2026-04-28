package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.mac.Cmac;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CmacApi Tests")
class CmacApiTest {

    private static final byte[] MSG = "hello gost".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_BYTES = new byte[32];
    static { Arrays.fill(KEY_BYTES, (byte) 0x42); }
    private static final SymmetricKey KEY = new SymmetricKey(KEY_BYTES);

    // -----------------------------------------------------------------------
    // Корректность — совпадение с низкоуровневым Cmac
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("cmac: совпадает с низкоуровневым Cmac(Kuznyechik)")
    void testCmacMatchesLowLevel() {
        Cmac c = new Cmac(new Kuznyechik());
        c.init(KEY);
        c.update(MSG, 0, MSG.length);
        byte[] expected = new byte[16];
        c.doFinal(expected, 0);

        assertArrayEquals(expected, CmacApi.cmac(MSG, KEY));
    }

    // -----------------------------------------------------------------------
    // Длины вывода
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("cmac: длина полного тега — CMAC_TAG_SIZE байт")
    void testCmacFullLength() {
        assertEquals(CmacApi.CMAC_TAG_SIZE, CmacApi.cmac(MSG, KEY).length);
        assertEquals(Kuznyechik.BLOCK_SIZE, CmacApi.CMAC_TAG_SIZE);
    }

    @Test
    @DisplayName("cmac усечённый: длина = запрошенному tagBytes")
    void testCmacTruncatedLength() {
        assertEquals(8,  CmacApi.cmac(MSG, KEY, 8).length);
        assertEquals(1,  CmacApi.cmac(MSG, KEY, 1).length);
        assertEquals(16, CmacApi.cmac(MSG, KEY, 16).length);
    }

    @Test
    @DisplayName("cmac усечённый: первые N байт совпадают с полным тегом")
    void testCmacTruncatedIsPrefixOfFull() {
        byte[] mac8  = CmacApi.cmac(MSG, KEY, 8);
        byte[] mac16 = CmacApi.cmac(MSG, KEY, 16);
        assertArrayEquals(mac8, Arrays.copyOf(mac16, 8));
    }

    // -----------------------------------------------------------------------
    // Граничные случаи tagBytes
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("cmac: tagBytes = 0 → IllegalArgumentException")
    void testCmacTagBytesZero() {
        assertThrows(IllegalArgumentException.class,
            () -> CmacApi.cmac(MSG, KEY, 0));
    }

    @Test
    @DisplayName("cmac: tagBytes > 16 → IllegalArgumentException")
    void testCmacTagBytesTooLarge() {
        assertThrows(IllegalArgumentException.class,
            () -> CmacApi.cmac(MSG, KEY, 17));
    }

    @Test
    @DisplayName("cmac: tagBytes отрицательный → IllegalArgumentException")
    void testCmacTagBytesNegative() {
        assertThrows(IllegalArgumentException.class,
            () -> CmacApi.cmac(MSG, KEY, -1));
    }

    // -----------------------------------------------------------------------
    // Чувствительность к ключу и данным
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("cmac: разные ключи → разные теги")
    void testCmacKeySensitivity() {
        SymmetricKey key2 = new SymmetricKey(new byte[32]);
        byte[] m1 = CmacApi.cmac(MSG, KEY);
        byte[] m2 = CmacApi.cmac(MSG, key2);
        assertFalse(Arrays.equals(m1, m2));
    }

    @Test
    @DisplayName("cmac: разные данные → разные теги")
    void testCmacDataSensitivity() {
        byte[] m1 = CmacApi.cmac("hello".getBytes(StandardCharsets.UTF_8), KEY);
        byte[] m2 = CmacApi.cmac("world".getBytes(StandardCharsets.UTF_8), KEY);
        assertFalse(Arrays.equals(m1, m2));
    }

    // -----------------------------------------------------------------------
    // verifyMac — constant-time сравнение
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verifyMac: одинаковые теги → true")
    void testVerifyMacEqual() {
        byte[] mac = CmacApi.cmac(MSG, KEY);
        assertTrue(CmacApi.verifyMac(mac, CmacApi.cmac(MSG, KEY)));
    }

    @Test
    @DisplayName("verifyMac: подмена одного бита → false")
    void testVerifyMacTampered() {
        byte[] mac = CmacApi.cmac(MSG, KEY);
        byte[] tampered = mac.clone();
        tampered[0] ^= 0x01;
        assertFalse(CmacApi.verifyMac(mac, tampered));
    }

    @Test
    @DisplayName("verifyMac: разная длина → false")
    void testVerifyMacDifferentLength() {
        byte[] mac16 = CmacApi.cmac(MSG, KEY, 16);
        byte[] mac8  = CmacApi.cmac(MSG, KEY, 8);
        assertFalse(CmacApi.verifyMac(mac16, mac8));
    }

    @Test
    @DisplayName("verifyMac: null первый аргумент → false, не NPE")
    void testVerifyMacNullExpected() {
        byte[] mac = CmacApi.cmac(MSG, KEY);
        assertFalse(CmacApi.verifyMac(null, mac));
    }

    @Test
    @DisplayName("verifyMac: null второй аргумент → false, не NPE")
    void testVerifyMacNullActual() {
        byte[] mac = CmacApi.cmac(MSG, KEY);
        assertFalse(CmacApi.verifyMac(mac, null));
    }

    // -----------------------------------------------------------------------
    // verifyMac применим и для HMAC
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("verifyMac: работает с HMAC-тегами")
    void testVerifyMacWithHmac() {
        byte[] hmac = Digest.hmac256(MSG, KEY);
        assertTrue(CmacApi.verifyMac(hmac, Digest.hmac256(MSG, KEY)));

        byte[] tampered = hmac.clone();
        tampered[3] ^= 0xFF;
        assertFalse(CmacApi.verifyMac(hmac, tampered));
    }

    // -----------------------------------------------------------------------
    // Потоковый инстанс
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Инстанс: update по частям = статический cmac")
    void testStreamingEqualsStatic() {
        byte[] expected = CmacApi.cmac(MSG, KEY);

        byte[] actual = new CmacApi(KEY)
            .update(Arrays.copyOfRange(MSG, 0, 4))
            .update(Arrays.copyOfRange(MSG, 4, MSG.length))
            .digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Инстанс: update с offset/len = статический cmac")
    void testStreamingWithOffsetEqualsStatic() {
        byte[] expected = CmacApi.cmac(MSG, KEY);

        CmacApi c = new CmacApi(KEY);
        c.update(MSG, 0, 5);
        c.update(MSG, 5, MSG.length - 5);
        byte[] actual = c.digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Инстанс: повторное использование после digest()")
    void testStreamingReuseAfterDigest() {
        CmacApi c = new CmacApi(KEY);
        byte[] r1 = c.update(MSG).digest();
        byte[] r2 = c.update(MSG).digest();
        assertArrayEquals(r1, r2, "После digest() инстанс должен быть готов к повторному использованию");
    }

    @Test
    @DisplayName("Инстанс: reset() сбрасывает состояние")
    void testStreamingReset() {
        CmacApi c = new CmacApi(KEY);
        c.update(MSG);
        c.reset();
        // После reset без update — эквивалентно пустому сообщению
        byte[] afterReset  = c.digest();
        byte[] emptyDirect = CmacApi.cmac(new byte[0], KEY);
        assertArrayEquals(emptyDirect, afterReset,
            "После reset() без update digest() должен вернуть тег пустого сообщения");
    }

    @Test
    @DisplayName("Инстанс: пустой update = статический cmac от пустого массива")
    void testStreamingEmptyMessage() {
        byte[] expected = CmacApi.cmac(new byte[0], KEY);
        byte[] actual   = new CmacApi(KEY).digest();
        assertArrayEquals(expected, actual);
    }
}
