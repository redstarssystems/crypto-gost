package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.pkix.cert.GostDerParser.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Модульные тесты {@link GostDerParser}: граничные случаи парсинга DER-примитивов.
 */
@DisplayName("GostDerParser: граничные случаи парсинга DER")
class GostDerParserTest {

    // ========================================================================
    // parseTime: минимальная длина
    // ========================================================================

    @Test
    @DisplayName("parseTime: UTCTime длиной 1 символ (Z) -> IllegalArgumentException")
    void testParseTimeUtcTimeTooShort() {
        byte[] data = new byte[] {0x17, 0x01, 'Z'};
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(data, 0),
                "UTCTime с одним символом Z должен вызывать исключение");
    }

    @Test
    @DisplayName("parseTime: UTCTime длиной 12 символов -> IllegalArgumentException")
    void testParseTimeUtcTimeOneCharShort() {
        // 25010112000 — 11 символов, невалидная дата, но проверка длины сработает раньше
        byte[] content = "25010112000".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = new byte[2 + content.length];
        data[0] = 0x17; // UTCTime tag
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(data, 0),
                "UTCTime длиной 12 (на 1 меньше нормы) должен вызывать исключение");
    }

    @Test
    @DisplayName("parseTime: UTCTime длиной 14 символов -> IllegalArgumentException")
    void testParseTimeUtcTimeOneCharLong() {
        // 2501011200000Z — 13 символов даты + Z = 14, на 1 больше нормы
        byte[] content = "2501011200000Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = new byte[2 + content.length];
        data[0] = 0x17; // UTCTime tag
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(data, 0),
                "UTCTime длиной 14 (на 1 больше нормы) должен вызывать исключение");
    }

    @Test
    @DisplayName("parseTime: UTCTime ровно 13 символов — успешно")
    void testParseTimeUtcTimeValid() {
        byte[] content = "250101120000Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = new byte[2 + content.length];
        data[0] = 0x17; // UTCTime tag
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        assertDoesNotThrow(
                () -> GostDerParser.parseTime(data, 0),
                "UTCTime ровно 13 символов должен парситься без ошибок");
    }

    @Test
    @DisplayName("parseTime: GeneralizedTime длиной 1 символ (Z) -> IllegalArgumentException")
    void testParseTimeGeneralizedTimeTooShort() {
        byte[] data = new byte[] {0x18, 0x01, 'Z'};
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(data, 0),
                "GeneralizedTime с одним символом Z должен вызывать исключение");
    }

    @Test
    @DisplayName("parseTime: GeneralizedTime длиной 14 символов -> IllegalArgumentException")
    void testParseTimeGeneralizedTimeOneCharShort() {
        // 2025010112000 — 13 символов, невалидная дата, проверка длины сработает раньше
        byte[] content = "2025010112000".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = new byte[2 + content.length];
        data[0] = 0x18; // GeneralizedTime tag
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(data, 0),
                "GeneralizedTime длиной 14 (на 1 меньше нормы) должен вызывать исключение");
    }

    @Test
    @DisplayName("parseTime: GeneralizedTime ровно 15 символов — успешно")
    void testParseTimeGeneralizedTimeValid() {
        byte[] content = "20250101120000Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] data = new byte[2 + content.length];
        data[0] = 0x18; // GeneralizedTime tag
        data[1] = (byte) content.length;
        System.arraycopy(content, 0, data, 2, content.length);
        assertDoesNotThrow(
                () -> GostDerParser.parseTime(data, 0),
                "GeneralizedTime ровно 15 символов должен парситься без ошибок");
    }

    // ========================================================================
    // arrayRangeEquals
    // ========================================================================

    @Test
    @DisplayName("arrayRangeEquals: идентичные диапазоны в одном массиве")
    void testArrayRangeEqualsSame() {
        byte[] a = {1, 2, 3, 4, 5};
        assertTrue(
                GostDerParser.arrayRangeEquals(a, 0, 5, a, 0, 5),
                "Один и тот же диапазон должен быть равен самому себе");
    }

    @Test
    @DisplayName("arrayRangeEquals: разная длина -> false")
    void testArrayRangeEqualsDifferentLength() {
        byte[] a = {1, 2, 3};
        byte[] b = {1, 2, 3, 4};
        assertFalse(GostDerParser.arrayRangeEquals(a, 0, 3, b, 0, 4), "Разная длина -> false");
    }

    @Test
    @DisplayName("arrayRangeEquals: одинаковая длина, разное содержимое -> false")
    void testArrayRangeEqualsDifferentContent() {
        byte[] a = {1, 2, 3};
        byte[] b = {1, 2, 4};
        assertFalse(GostDerParser.arrayRangeEquals(a, 0, 3, b, 0, 3), "Разное содержимое -> false");
    }

    @Test
    @DisplayName("arrayRangeEquals: пустые диапазоны -> true")
    void testArrayRangeEqualsEmpty() {
        byte[] a = {1, 2, 3};
        byte[] b = {4, 5, 6};
        assertTrue(
                GostDerParser.arrayRangeEquals(a, 0, 0, b, 1, 0), "Пустые диапазоны всегда равны");
    }

    @Test
    @DisplayName("arrayRangeEquals: разные массивы, одинаковое содержимое -> true")
    void testArrayRangeEqualsDifferentArrays() {
        byte[] a = {10, 20, 30};
        byte[] b = {10, 20, 30};
        assertTrue(
                GostDerParser.arrayRangeEquals(a, 0, 3, b, 0, 3),
                "Разные массивы с одинаковым содержимым -> true");
    }

    @Test
    @DisplayName("arrayRangeEquals: смещение (off) корректно учитывается")
    void testArrayRangeEqualsOffset() {
        byte[] a = {0, 0, 1, 2, 3, 0};
        byte[] b = {9, 9, 1, 2, 3, 9};
        assertTrue(
                GostDerParser.arrayRangeEquals(a, 2, 3, b, 2, 3),
                "Смещение корректно — сравниваются байты 1,2,3 в обоих массивах");
        assertFalse(
                GostDerParser.arrayRangeEquals(a, 0, 3, b, 2, 3),
                "Разное начало -> разные значения -> false");
    }

    @Test
    @DisplayName("arrayRangeEquals: однобайтовые диапазоны")
    void testArrayRangeEqualsSingleByte() {
        byte[] a = {0x7F};
        byte[] b = {0x7F};
        byte[] c = {(byte) 0xFF};
        assertTrue(GostDerParser.arrayRangeEquals(a, 0, 1, b, 0, 1));
        assertFalse(GostDerParser.arrayRangeEquals(a, 0, 1, c, 0, 1));
    }

    // ========================================================================
    // oidBytesToDottedString
    // ========================================================================

    @Test
    @DisplayName("oidBytesToDottedString: STREEBOG256 -> 1.2.643.7.1.1.2.2")
    void testOidToStreebog256() {
        String result =
                GostDerParser.oidBytesToDottedString(
                        STREEBOG256_OID_BYTES, 0, STREEBOG256_OID_BYTES.length);
        assertEquals("1.2.643.7.1.1.2.2", result);
    }

    @Test
    @DisplayName("oidBytesToDottedString: STREEBOG512 -> 1.2.643.7.1.1.2.3")
    void testOidToStreebog512() {
        String result =
                GostDerParser.oidBytesToDottedString(
                        STREEBOG512_OID_BYTES, 0, STREEBOG512_OID_BYTES.length);
        assertEquals("1.2.643.7.1.1.2.3", result);
    }

    @Test
    @DisplayName("oidBytesToDottedString: KC1 -> 1.2.643.100.113.1")
    void testOidToKc1() {
        String result =
                GostDerParser.oidBytesToDottedString(KC1_OID_BYTES, 0, KC1_OID_BYTES.length);
        assertEquals("1.2.643.100.113.1", result);
    }

    @Test
    @DisplayName("oidBytesToDottedString: SAN -> 2.5.29.17 (двухкомпонентный начальный байт)")
    void testOidToSan() {
        String result =
                GostDerParser.oidBytesToDottedString(SAN_OID_BYTES, 0, SAN_OID_BYTES.length);
        assertEquals("2.5.29.17", result);
    }

    @Test
    @DisplayName("oidBytesToDottedString: пустой OID -> пустая строка")
    void testOidToEmpty() {
        String result = GostDerParser.oidBytesToDottedString(new byte[0], 0, 0);
        assertEquals("", result, "Пустой OID -> пустая строка");
    }

    @Test
    @DisplayName("oidBytesToDottedString: multi-byte компоненты (UID OID)")
    void testOidToMultiByte() {
        String result =
                GostDerParser.oidBytesToDottedString(UID_OID_BYTES, 0, UID_OID_BYTES.length);
        assertEquals(
                "0.9.2342.19200300.100.1.1", result, "UID OID с multi-byte компонентом 19200300");
    }
}
