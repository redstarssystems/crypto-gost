package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.util.DerCodec;

/**
 * Тесты {@link GeneralNameCodec}: кодирование GeneralName (DNS, IP, directoryName).
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
                        new String[] {"example.com"}, new String[] {"127.0.0.1"});

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
}
