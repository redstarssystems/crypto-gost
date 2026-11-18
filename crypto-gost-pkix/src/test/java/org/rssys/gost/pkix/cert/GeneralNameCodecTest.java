package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Тесты {@link GeneralNameCodec}: кодирование всех типов GeneralName.
 */
@DisplayName("GeneralNameCodec: кодирование GeneralName")
class GeneralNameCodecTest {

    @Test
    @DisplayName("encodeDnsName: правильный тег dNSName [2] (0x82)")
    void testEncodeDnsNameTag() {
        byte[] gn = GeneralNameCodec.encodeDnsName("example.com");
        assertNotNull(gn);
        assertEquals(0x82, gn[0] & 0xFF, "dNSName должен кодироваться с тегом 0x82");
    }

    @Test
    @DisplayName("encodeIpAddress: правильный тег iPAddress [7] (0x87)")
    void testEncodeIpAddressTag() {
        byte[] gn = GeneralNameCodec.encodeIpAddress("127.0.0.1");
        assertNotNull(gn);
        assertEquals(0x87, gn[0] & 0xFF, "iPAddress должен кодироваться с тегом 0x87");
    }

    @Test
    @DisplayName("encodeDirectoryName: правильный тег directoryName [4] (0xA4)")
    void testEncodeDirectoryNameTag() {
        byte[] dnDer = GostDnParser.encodeDn("CN=Test CA");
        byte[] gn = GeneralNameCodec.encodeDirectoryName(dnDer);
        assertNotNull(gn);
        assertEquals(0xA4, gn[0] & 0xFF, "directoryName должен кодироваться с тегом 0xA4");
    }

    @Test
    @DisplayName("encodeGeneralNames(String[], String[]): совместимость с buildSanExtension")
    void testEncodeGeneralNamesWithStrings() {
        byte[] gnSeq =
                GeneralNameCodec.encodeGeneralNames(
                        new String[] {"example.com"}, new String[] {"127.0.0.1"});
        byte[] sanExt =
                GostCertificateBuilder.buildSanExtension(
                        new String[] {"example.com"},
                        new String[] {"127.0.0.1"},
                        null,
                        null,
                        null,
                        null);

        byte[][] sanParts = DerCodec.parseSequenceContents(sanExt, 0);
        byte[] sanValue = DerCodec.parseOctetString(sanParts[1], 0);
        assertArrayEquals(
                gnSeq,
                sanValue,
                "GeneralNameCodec должен давать те же байты, что и buildSanExtension");
    }

    @Test
    @DisplayName("encodeGeneralNames(byte[][]): кодирование нескольких GeneralName")
    void testEncodeGeneralNamesMultiple() {
        byte[] dns = GeneralNameCodec.encodeDnsName("example.com");
        byte[] dir = GeneralNameCodec.encodeDirectoryName(GostDnParser.encodeDn("CN=Issuer"));

        byte[] gnSeq = GeneralNameCodec.encodeGeneralNames(dns, dir);
        assertNotNull(gnSeq);
        assertEquals(0x30, gnSeq[0], "SEQUENCE OF GeneralName начинается с 0x30");
        assertTrue(gnSeq.length > 20);
    }

    @Test
    @DisplayName("encodeRfc822Name: правильный тег rfc822Name [1] (0x81)")
    void testEncodeRfc822NameTag() {
        byte[] gn = GeneralNameCodec.encodeRfc822Name("user@example.com");
        assertNotNull(gn);
        assertEquals(0x81, gn[0] & 0xFF, "rfc822Name должен кодироваться с тегом 0x81");
    }

    @Test
    @DisplayName("encodeUri: правильный тег URI [6] (0x86)")
    void testEncodeUriTag() {
        byte[] gn = GeneralNameCodec.encodeUri("https://example.com");
        assertNotNull(gn);
        assertEquals(0x86, gn[0] & 0xFF, "URI должен кодироваться с тегом 0x86");
    }

    @Test
    @DisplayName("encodeOtherName: IMPLICIT [0] — нет вложенного SEQUENCE")
    void testEncodeOtherNameImplicit() {
        byte[] upnValue = DerCodec.encodeUTF8String("user@domain.ru");
        byte[] gn = GeneralNameCodec.encodeOtherName(GostOids.ID_MS_UPN, upnValue);
        assertNotNull(gn);
        // Тег 0xA0 — IMPLICIT [0], заменяет SEQUENCE OtherName
        assertEquals(0xA0, gn[0] & 0xFF, "otherName должен кодироваться с тегом 0xA0");
        // Проверяем отсутствие вложенного SEQUENCE (0x30) на втором уровне:
        // После TLV-заголовка содержимое начинается с OID (0x06), не с SEQUENCE (0x30)
        // DER: A0 <len1> 06 <len2> <oid>
        int tlvHeaderEnd = 1;
        int firstLenByte = gn[tlvHeaderEnd] & 0xFF;
        int headerSize;
        if (firstLenByte < 0x80) {
            headerSize = 2; // тег + короткая длина
        } else if (firstLenByte == 0x81) {
            headerSize = 3;
        } else if (firstLenByte == 0x82) {
            headerSize = 4;
        } else {
            throw new AssertionError("Неожиданный формат длины: " + firstLenByte);
        }
        int contentStart = headerSize;
        assertTrue(contentStart < gn.length, "содержимое должно быть после заголовка");
        assertEquals(
                0x06,
                gn[contentStart] & 0xFF,
                "после заголовка должен быть OID (0x06), не SEQUENCE (0x30)");
    }

    @Test
    @DisplayName("encodeOtherNameUpn: UPN через convenience-метод")
    void testEncodeOtherNameUpn() {
        byte[] gn = GeneralNameCodec.encodeOtherNameUpn("user@domain.ru");
        assertNotNull(gn);
        assertEquals(0xA0, gn[0] & 0xFF, "UPN otherName должен кодироваться с тегом 0xA0");
        // Проверяем, что в DER есть ожидаемый OID в теле
        // DER: A0 <len> 06 <upn-oid-len> <upn-oid-bytes>
        // Ищем 0x06 (OID tag) после заголовка TLV
        assertTrue(gn.length > 10, "otherName должен быть достаточно длинным");
        boolean foundOidTag = false;
        for (int i = 2; i < gn.length - 1; i++) {
            if ((gn[i] & 0xFF) == 0x06) {
                foundOidTag = true;
                break;
            }
        }
        assertTrue(foundOidTag, "в теле otherName должен быть OID (0x06)");
    }

    @Test
    @DisplayName("encodeGeneralNames(byte[][]): все типы вместе")
    void testEncodeGeneralNamesAllTypes() {
        byte[] dns = GeneralNameCodec.encodeDnsName("example.com");
        byte[] ip = GeneralNameCodec.encodeIpAddress("127.0.0.1");
        byte[] rfc822 = GeneralNameCodec.encodeRfc822Name("user@example.com");
        byte[] uri = GeneralNameCodec.encodeUri("https://example.com");
        byte[] other = GeneralNameCodec.encodeOtherNameUpn("user@domain.ru");
        byte[] dirName = GeneralNameCodec.encodeDirectoryName(GostDnParser.encodeDn("CN=Test"));

        byte[] gnSeq = GeneralNameCodec.encodeGeneralNames(dns, ip, rfc822, uri, dirName, other);
        assertNotNull(gnSeq);
        assertEquals(0x30, gnSeq[0], "SEQUENCE OF GeneralName начинается с 0x30");
        assertTrue(gnSeq.length > 50, "должно быть >50 байт для 6 имён");
    }

    // ========================================================================
    // Строгое кодирование: литералы без DNS, A-label, ASCII
    // ========================================================================

    private static byte[] value(byte[] generalName) {
        return java.util.Arrays.copyOfRange(generalName, 2, generalName.length);
    }

    private static String dnsValue(byte[] generalName) {
        return new String(value(generalName), java.nio.charset.StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("encodeIpAddress: IPv4 и IPv6 кодируются 4 и 16 байтами")
    void ipAddressLengths() {
        assertArrayEquals(
                new byte[] {10, 0, 0, 1}, value(GeneralNameCodec.encodeIpAddress("10.0.0.1")));
        assertEquals(16, value(GeneralNameCodec.encodeIpAddress("2001:db8::1")).length);
        assertEquals(16, value(GeneralNameCodec.encodeIpAddress("[2001:db8::1]")).length);
    }

    @Test
    @DisplayName("encodeIpAddress: IPv4-mapped литерал кодируется как IPv4 (4 байта)")
    void ipv4MappedLiteralEncodedAsIpv4() {
        assertArrayEquals(
                new byte[] {10, 0, 0, 1},
                value(GeneralNameCodec.encodeIpAddress("::ffff:10.0.0.1")));
        assertArrayEquals(
                new byte[] {10, 0, 0, 1}, value(GeneralNameCodec.encodeIpAddress("::ffff:a00:1")));
    }

    @Test
    @DisplayName(
            "encodeIpAddress: не литерал (имя хоста) и адрес с зоной - IllegalArgumentException")
    void nonLiteralIpAddressRejected() {
        for (String bad : new String[] {"localhost", "example.com", "10.0.0", "fe80::1%eth0", ""}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GeneralNameCodec.encodeIpAddress(bad),
                    "Не IP-литерал должен отвергаться без обращения к DNS: " + bad);
        }
    }

    @Test
    @DisplayName("encodeIpConstraint: mapped CIDR /104 становится IPv4 10.0.0.0/8")
    void mappedCidrEncodedAsIpv4() {
        assertArrayEquals(
                new byte[] {10, 0, 0, 0, (byte) 0xFF, 0, 0, 0},
                value(GeneralNameCodec.encodeIpConstraint("::ffff:10.0.0.0/104")));
        assertThrows(
                IllegalArgumentException.class,
                () -> GeneralNameCodec.encodeIpConstraint("::ffff:0:0/80"),
                "Префикс короче /96 в 4 байтах не выразим");
        assertEquals(32, value(GeneralNameCodec.encodeIpConstraint("2001:db8::/32")).length);
        assertThrows(
                IllegalArgumentException.class,
                () -> GeneralNameCodec.encodeIpConstraint("example.com/24"));
    }

    @Test
    @DisplayName("encodeDnsName: регистр, завершающая точка, wildcard и IDN приводятся к A-label")
    void dnsNameNormalized() {
        assertEquals("example.com", dnsValue(GeneralNameCodec.encodeDnsName("Example.COM.")));
        assertEquals("*.example.com", dnsValue(GeneralNameCodec.encodeDnsName("*.Example.com")));
        assertEquals(
                "xn--e1afmkfd.xn--p1ai",
                dnsValue(GeneralNameCodec.encodeDnsName("пример.рф")),
                "Unicode-имя кодируется как punycode, а не заменой символов на '?'");
    }

    @Test
    @DisplayName("encodeDnsName: пустое имя и пустая метка отвергаются")
    void invalidDnsNameRejected() {
        for (String bad : new String[] {"", "a..b", "example.com..", "*.", "exa mple.com"}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GeneralNameCodec.encodeDnsName(bad),
                    "Некорректное dNSName должно отвергаться: " + bad);
        }
    }

    @Test
    @DisplayName("encodeRfc822Name и encodeUri: не-ASCII отвергается, а не заменяется на '?'")
    void nonAsciiRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GeneralNameCodec.encodeRfc822Name("юзер@example.com"));
        assertThrows(
                IllegalArgumentException.class,
                () -> GeneralNameCodec.encodeUri("https://пример.рф/"));
        assertEquals(
                "user@example.com",
                new String(
                        value(GeneralNameCodec.encodeRfc822Name("user@example.com")),
                        java.nio.charset.StandardCharsets.US_ASCII));
    }
}
