package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
