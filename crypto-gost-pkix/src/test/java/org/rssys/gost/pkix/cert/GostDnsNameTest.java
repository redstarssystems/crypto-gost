package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GostDnsName: Unicode -> A-label")
class GostDnsNameTest {

    @Test
    @DisplayName("Кириллический домен -> punycode")
    void testCyrillicToPunycode() {
        assertEquals("xn--e1afmkfd.xn--p1ai", GostDnsName.toAsciiHostname("пример.рф"));
    }

    @Test
    @DisplayName("Регистр и завершающая точка нормализуются")
    void testNormalization() {
        assertEquals("xn--e1afmkfd.xn--p1ai", GostDnsName.toAsciiHostname("ПРИМЕР.РФ."));
        assertEquals("example.com", GostDnsName.toAsciiHostname(" Example.COM. "));
    }

    @Test
    @DisplayName("null -> null, пустая строка -> IllegalArgumentException")
    void testNullAndEmpty() {
        assertNull(GostDnsName.toAsciiHostname(null));
        assertThrows(IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname(""));
        assertThrows(IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("  .  "));
    }

    @Test
    @DisplayName("IDNA2003-неоднозначные символы отклоняются")
    void testIdna2003DeviationsRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("fa\u00DF.de"),
                "ß меняет домен в IDNA2003");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("\u03C2.gr"),
                "ς меняет домен в IDNA2003");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("a\u200Cb.ru"),
                "ZWNJ запрещён");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("a\u200Db.ru"),
                "ZWJ запрещён");
    }

    @Test
    @DisplayName("Подчёркивание в ASCII-имени разрешено")
    void testAsciiUnderscoreAllowed() {
        assertEquals("a_b.example.com", GostDnsName.toAsciiHostname("a_b.example.com"));
        assertEquals("project_service_1", GostDnsName.toAsciiHostname("project_service_1"));
        assertEquals("my_host.local", GostDnsName.toAsciiHostname("my_host.local"));
    }

    @Test
    @DisplayName("IP-литералы возвращаются без punycode")
    void testIpLiteralsUnchanged() {
        assertEquals("192.168.1.10", GostDnsName.toAsciiHostname("192.168.1.10"));
        assertEquals("::1", GostDnsName.toAsciiHostname("::1"));
        assertEquals("[::1]", GostDnsName.toAsciiHostname("[::1]"));
        assertEquals("fe80::1%eth0", GostDnsName.toAsciiHostname("fe80::1%eth0"));
    }

    @Test
    @DisplayName("Wildcard, пробел и пустые метки отклоняются")
    void testInvalidHostnameCharactersRejected() {
        assertThrows(
                IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("*.example.com"));
        assertThrows(
                IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("exa mple.com"));
        assertThrows(
                IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname(".example.com"));
        assertThrows(IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("a..b"));
    }

    @Test
    @DisplayName("NUL и управляющие символы по краям не срезаются, а отвергаются")
    void testControlCharactersRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("example.com\0"),
                "NUL нельзя молча отбрасывать");
        assertThrows(
                IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("\0example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("exa\u0085mple.com"),
                "не-ASCII управляющий символ U+0085");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("exa\u0090mple.com"),
                "не-ASCII управляющий символ U+0090");
    }

    @Test
    @DisplayName("Снимается ровно одна завершающая точка; две подряд - пустая метка")
    void testOnlyOneTrailingDotStripped() {
        assertEquals("example.com", GostDnsName.toAsciiHostname("example.com."));
        assertThrows(
                IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname("example.com.."));
        assertThrows(IllegalArgumentException.class, () -> GostDnsName.toAsciiHostname(".."));
    }

    @Test
    @DisplayName("Форматирующие символы и fullwidth, которые nameprep молча меняет, отвергаются")
    void testNamePrepMappedCharactersRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("exa\u00ADmple.com"),
                "soft hyphen");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("exa\u200Bmple.com"),
                "zero width space");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("exa\u2060mple.com"),
                "word joiner");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("\uFEFFexample.com"),
                "BOM");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("\uFF45xample.com"),
                "fullwidth e превратился бы в ASCII");
    }

    @Test
    @DisplayName("Кириллица в разложенной форме (NFD) принимается и даёт тот же punycode")
    void testDecomposedCyrillicAccepted() {
        // "й" в NFD: и + U+0306
        String decomposed = "\u0438\u0306.рф";
        String composed = "\u0439.рф";
        assertEquals(
                GostDnsName.toAsciiHostname(composed), GostDnsName.toAsciiHostname(decomposed));
    }

    @Test
    @DisplayName("Числовые формы IPv4 не являются ни IP-литералом, ни именем")
    void testNumericIpv4FormsRejected() {
        for (String form :
                new String[] {
                    "2130706433", "0x7f000001", "127.1", "1.2.3", "0177.0.0.1", "0X7F.0.0.1"
                }) {
            assertFalse(GostDnsName.isIpAddress(form), form + " не строгий IP-литерал");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostDnsName.toAsciiHostname(form),
                    form + " нельзя принимать как DNS-имя");
            assertTrue(
                    GostDnsName.isIpAddressOrNumericForm(form),
                    form + " обязан считаться IP там, где IP запрещён");
        }
        assertTrue(GostDnsName.isIpAddressOrNumericForm("127.0.0.+1"), "знак в октете");
        assertTrue(GostDnsName.isIpAddressOrNumericForm("127.0.0.1."), "точка не скрывает адрес");
    }

    @Test
    @DisplayName("Имена с нечисловой меткой не считаются числовой формой")
    void testNumericLastLabelWithNameIsNotAmbiguous() {
        assertEquals("host.123", GostDnsName.toAsciiHostname("host.123"));
        assertEquals("1.example.com", GostDnsName.toAsciiHostname("1.example.com"));
        assertFalse(GostDnsName.isIpAddressOrNumericForm("host.123"));
        assertFalse(GostDnsName.isIpAddressOrNumericForm("example.com"));
        assertFalse(GostDnsName.isIpAddressOrNumericForm(null));
    }

    @Test
    @DisplayName("Строгий IPv4: без знака, пустых частей, ведущих нулей и значений > 255")
    void testStrictIpv4() {
        assertTrue(GostDnsName.isIpAddress("127.0.0.1"));
        assertTrue(GostDnsName.isIpAddress("0.0.0.0"));
        assertFalse(GostDnsName.isIpAddress("127.0.0.+1"));
        assertFalse(GostDnsName.isIpAddress("127.0.0.-0"));
        assertFalse(GostDnsName.isIpAddress("127.0.0."));
        assertFalse(GostDnsName.isIpAddress("127.0.0.01"));
        assertFalse(GostDnsName.isIpAddress("256.0.0.1"));
        assertFalse(GostDnsName.isIpAddress("1.2.3.4.5"));
        assertFalse(GostDnsName.isIpAddress("\u0661.0.0.1"), "арабско-индийская цифра");
    }

    @Test
    @DisplayName("Разбор IPv6: сжатие, встроенный IPv4, скобки и зона; мусор - не IP")
    void testIpv6Parsing() {
        assertArrayEquals(
                new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                GostDnsName.parseIpAddress("::1"));
        assertArrayEquals(
                new byte[] {0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                GostDnsName.parseIpAddress("[2001:db8::1]"));
        assertArrayEquals(
                GostDnsName.parseIpAddress("fe80::1"), GostDnsName.parseIpAddress("fe80::1%eth0"));
        assertNull(GostDnsName.parseIpAddress("fe80::1%"), "пустая зона");
        assertNull(GostDnsName.parseIpAddress("127.0.0.1%eth0"), "зона только у IPv6");
        assertNull(GostDnsName.parseIpAddress("abc:1"), "слишком мало групп без сжатия");
        assertNull(GostDnsName.parseIpAddress("1::2::3"), "два сжатия");
        assertNull(GostDnsName.parseIpAddress(":1:2:3:4:5:6:7"), "одиночное двоеточие в начале");
        assertNull(GostDnsName.parseIpAddress("1:2:3:4:5:6:7:8:9"), "лишняя группа");
        assertNull(GostDnsName.parseIpAddress("12345::1"), "группа длиннее 4 цифр");
        assertNull(GostDnsName.parseIpAddress("::g"), "не hex-цифра");
        assertNull(GostDnsName.parseIpAddress("[::1"), "несбалансированные скобки");
        assertNull(GostDnsName.parseIpAddress("[127.0.0.1]"), "скобки допустимы только у IPv6");
        assertNull(GostDnsName.parseIpAddress("1:2:3:4:5:6:7::8"), "сжатие при полных 8 группах");
        assertEquals(
                16, GostDnsName.parseIpAddress("1:2:3:4:5:6:7::").length, "сжатие вместо одной");
        assertEquals(
                16,
                GostDnsName.parseIpAddress("::1.2.3.4").length,
                "IPv4-compatible не mapped: остаётся 16 байт");
    }

    @Test
    @DisplayName("IPv4-mapped IPv6 в любой записи разворачивается в 4 байта")
    void testIpv4MappedUnwrapped() {
        byte[] ipv4 = {1, 2, 3, 4};
        assertArrayEquals(ipv4, GostDnsName.parseIpAddress("::ffff:1.2.3.4"));
        assertArrayEquals(ipv4, GostDnsName.parseIpAddress("0:0:0:0:0:ffff:1.2.3.4"));
        assertArrayEquals(ipv4, GostDnsName.parseIpAddress("::ffff:102:304"));
        assertArrayEquals(ipv4, GostDnsName.parseIpAddress("[::FFFF:1.2.3.4]"));
    }

    @Test
    @DisplayName("Строка с двоеточием, не являющаяся IP, не считается ни IP, ни именем")
    void testColonStringIsNotIpAndNotName() {
        assertFalse(GostDnsName.isIpAddress("abc:1"));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnsName.toAsciiHostname("abc:1"),
                "двоеточие недопустимо в DNS-имени");
    }
}
