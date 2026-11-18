package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostDnParser}: encodeDn <-> parseDnString roundtrip.
 */
@DisplayName("GostDnParser: encodeDn -> parseDnString — обратимость")
class GostDnParserTest {

    @Test
    @DisplayName("encodeDn -> parseDnString: обратимость CN")
    void testEncodeDnCnRoundtrip() {
        byte[] der = GostDnParser.encodeDn("CN=Test Cert 42");
        assertNotNull(der);
        assertTrue(der.length > 10);

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r.dnString);
        assertTrue(
                r.dnString.contains("Test Cert 42"), "DN должен содержать значение: " + r.dnString);
    }

    @Test
    @DisplayName("encodeDn -> parseDnString: multi-attribute DN")
    void testEncodeDnMultiAttr() {
        byte[] der = GostDnParser.encodeDn("CN=Server,O=MyOrg,OU=Dev");
        assertNotNull(der);

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r.dnString);
        assertTrue(r.dnString.contains("Server"));
        assertTrue(r.dnString.contains("MyOrg"));
        assertTrue(r.dnString.contains("Dev"));
        assertEquals(3, r.fields.size(), "Ожидается 3 поля");
    }

    @Test
    @DisplayName("encodeDn: все поддерживаемые атрибуты")
    void testEncodeDnAllAttributes() {
        byte[] der = GostDnParser.encodeDn("CN=User,O=Org,OU=Unit,L=City,ST=Region,C=RU");
        assertNotNull(der);

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertEquals(6, r.fields.size());
    }

    @Test
    @DisplayName("encodeDn: российские атрибуты (INN, OGRN, SNILS, OGRNIP, INNLE)")
    void testEncodeDnRussianAttributes() {
        byte[] der =
                GostDnParser.encodeDn(
                        "CN=Тест,INN=123456789012,OGRN=1027700012345,SNILS=12345678901,OGRNIP=304770001234567,INNLE=7707083893");
        assertNotNull(der);

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r.dnString);
        assertEquals(6, r.fields.size());
    }

    @Test
    @DisplayName("encodeDn -> parseDnString: UNIQUE_IDENTIFIER roundtrip")
    void testEncodeDnUniqueIdentifier() {
        byte[] der = GostDnParser.encodeDn("CN=Test,UNIQUE_IDENTIFIER=uid-123");
        assertNotNull(der);

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r.dnString);
        assertTrue(r.dnString.contains("uid-123"));
        assertEquals(2, r.fields.size());
    }

    @Test
    @DisplayName("encodeDn: emailAddress кодируется IA5String")
    void testEncodeDnEmailIa5() {
        byte[] der = GostDnParser.encodeDn("CN=User,EMAILADDRESS=user@example.com");
        assertNotNull(der);
        assertDoesNotThrow(
                () -> DirectoryNameSubtree.parse(der),
                "emailAddress должен проходить строгий разбор как IA5String");

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r);
        String email =
                r.fields.stream()
                        .filter(f -> GostOids.ATTR_EMAIL.equals(f.oid))
                        .findFirst()
                        .orElseThrow()
                        .value;
        assertEquals("user@example.com", email);
    }

    @Test
    @DisplayName("encodeDn: не-ASCII emailAddress отклоняется")
    void testEncodeDnNonAsciiEmailRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnParser.encodeDn("EMAILADDRESS=тест@example.com"),
                "emailAddress обязан быть ASCII");
    }

    @Test
    @DisplayName("Показ DN терпим к кириллице в PrintableString")
    void testDisplayToleratesLegacyCyrillic() {
        // Windows-1251 «Прив» в PrintableString: невалидно по X.680, но такие
        // сертификаты встречаются. Показ не должен отказывать.
        byte[] legacyCyrillic = {(byte) 0xCF, (byte) 0xF0, (byte) 0xE8, (byte) 0xE2, (byte) 0xF2};
        byte[] der =
                DerCodec.encodeSequence(
                        DerCodec.encodeSetOf(
                                DerCodec.encodeSequence(
                                        DerCodec.encodeOid(GostOids.ATTR_CN),
                                        DerCodec.encodeTlv(0x13, legacyCyrillic))));

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r, "показ DN не должен падать на legacy-кодировке");
        assertThrows(
                PkixException.class,
                () -> DirectoryNameSubtree.parse(der),
                "NameConstraints обязан отклонять невалидный PrintableString");
    }

    @Test
    @DisplayName("Кириллица в UTF8String разбирается и показывается")
    void testCyrillicUtf8Accepted() {
        byte[] der = GostDnParser.encodeDn("CN=ООО Ромашка");
        assertDoesNotThrow(() -> DirectoryNameSubtree.parse(der));

        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertNotNull(r);
        assertEquals("ООО Ромашка", r.fields.get(0).value);
    }

    @Test
    @DisplayName("encodeDn: countryName — PrintableString по RFC 5280")
    void testCountryNamePrintableString() {
        byte[] der = GostDnParser.encodeDn("CN=User,C=RU");
        byte[] value = findAttributeValue(der, GostOids.ATTR_C);

        assertEquals(0x13, value[0] & 0xFF, "countryName должен быть PrintableString");
        assertArrayEquals(
                "RU".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                java.util.Arrays.copyOfRange(value, 2, value.length),
                "countryName должен содержать код страны");
    }

    @Test
    @DisplayName("encodeDn: serialNumber DN — PrintableString по X.520")
    void testDnSerialNumberPrintableString() {
        byte[] der = GostDnParser.encodeDn("CN=User,SERIALNUMBER=ABC-123");
        byte[] value = findAttributeValue(der, GostOids.ATTR_SERIALNUMBER);

        assertEquals(0x13, value[0] & 0xFF, "serialNumber DN должен быть PrintableString");
    }

    @ParameterizedTest
    @CsvSource({"ru", "RUU", "R", "РУ", "12"})
    @DisplayName("encodeDn: невалидный countryName отклоняется")
    void testInvalidCountryNameRejected(String country) {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnParser.encodeDn("C=" + country),
                "countryName обязан быть двумя заглавными ASCII-буквами");
    }

    @Test
    @DisplayName("encodeDn: serialNumber DN длиннее 64 символов отклоняется")
    void testDnSerialNumberTooLongRejected() {
        String longSerial = "A".repeat(65);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnParser.encodeDn("SERIALNUMBER=" + longSerial),
                "serialNumber DN ограничен 64 символами");
    }

    @Test
    @DisplayName("encodeDn: кириллица в CN остаётся UTF8String")
    void testCnCyrillicStaysUtf8() {
        byte[] der = GostDnParser.encodeDn("CN=ООО Ромашка");
        byte[] value = findAttributeValue(der, GostOids.ATTR_CN);

        assertEquals(0x0C, value[0] & 0xFF, "CN — DirectoryString, UTF8String допустим");
    }

    @Test
    @DisplayName("encodeDn: неизвестный атрибут -> IllegalArgumentException")
    void testEncodeDnUnknownKey() {
        IllegalArgumentException ex =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostDnParser.encodeDn("XYZ=Something"),
                        "Неизвестный DN-атрибут должен вызывать исключение");
        assertTrue(
                ex.getMessage().contains("XYZ"),
                "Сообщение должно содержать имя неизвестного атрибута: " + ex.getMessage());
    }

    @ParameterizedTest
    @CsvSource({
        "1.2.643.3.131.1.1, INN",
        "1.2.643.100.5,     OGRNIP",
        "1.2.643.100.1,     OGRN",
        "1.2.643.100.3,     SNILS",
        "1.2.643.100.4,     INNLE",
    })
    @DisplayName("GOST DN OID-константы: байты == encodeOid() и lookupOidName")
    void testGostDnOidConstants(String expectedOid, String expectedName) {
        // Проверка байтов: константа == результат encodeOid (без TLV-обёртки)
        byte[] encoded = DerCodec.encodeOid(expectedOid);
        int[] tlv = GostDerParser.readTlv(encoded, 0);
        byte[] expectedBytes = Arrays.copyOfRange(encoded, tlv[0], tlv[1]);
        byte[] constantBytes = getOidConstantByName(expectedName);
        assertArrayEquals(
                expectedBytes,
                constantBytes,
                "Байты константы " + expectedName + " должны кодировать OID " + expectedOid);

        // Проверка lookupOidName: константа распознаётся с правильным именем
        byte[] der = DerCodec.encodeTlv(DerCodec.TAG_OID, constantBytes);
        int[] oidTlv = GostDerParser.readTlv(der, 0);
        String name = GostDnParser.lookupOidName(der, oidTlv[0], oidTlv[1] - oidTlv[0]);
        assertEquals(expectedName, name, "lookupOidName должен вернуть " + expectedName);
    }

    /** Возвращает полный TLV значения атрибута DN (с тегом и длиной). */
    private static byte[] findAttributeValue(byte[] dnDer, String oid) {
        for (byte[] rdn : DerCodec.parseSequenceContents(dnDer, 0)) {
            for (byte[] attr : DerCodec.parseSetContents(rdn, 0)) {
                byte[][] parts = DerCodec.parseSequenceContents(attr, 0);
                if (oid.equals(DerCodec.parseOid(parts[0], 0))) {
                    return parts[1];
                }
            }
        }
        throw new AssertionError("Атрибут " + oid + " не найден в DN");
    }

    @Test
    @DisplayName("encodeDn: управляющий символ отвергается в начале, в конце и в середине")
    void testEncodeDnRejectsControlCharacters() {
        // trim() срезал бы NUL и переводы строк по краям: проверка идёт до обрезки.
        for (String bad :
                new String[] {
                    "CN=\0abc",
                    "CN=abc\0",
                    "CN=a\0bc",
                    "CN=abc\n",
                    "CN=abc\t",
                    "CN=a\u007fbc",
                    "CN=a\u0085bc",
                    "\0CN=abc",
                    "C\0N=abc",
                    "CN=abc,\nO=Org"
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostDnParser.encodeDn(bad),
                    "управляющий символ в DN должен отвергаться");
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDnParser.encodeDn("CN=Test,emailAddress=a\0b@example.com"),
                "управляющий символ в email должен отвергаться");
    }

    @Test
    @DisplayName("encodeDn: знак = внутри значения сохраняется")
    void testEncodeDnKeepsEqualsSignInValue() throws Exception {
        byte[] der = GostDnParser.encodeDn("CN=a=b");
        GostDnParser.DnParseResult r = GostDnParser.parseDnString(der, 0, der.length);
        assertEquals(1, r.fields.size(), "ожидается одно поле");
        assertEquals("a=b", r.fields.get(0).value, "значение поля должно сохранить a=b");
    }

    private static byte[] getOidConstantByName(String name) {
        switch (name) {
            case "INN":
                return GostDerParser.INN_OID_BYTES;
            case "OGRNIP":
                return GostDerParser.OGRNIP_OID_BYTES;
            case "OGRN":
                return GostDerParser.OGRN_OID_BYTES;
            case "SNILS":
                return GostDerParser.SNILS_OID_BYTES;
            case "INNLE":
                return GostDerParser.INNLE_OID_BYTES;
            default:
                throw new IllegalArgumentException("Неизвестное имя константы: " + name);
        }
    }
}
