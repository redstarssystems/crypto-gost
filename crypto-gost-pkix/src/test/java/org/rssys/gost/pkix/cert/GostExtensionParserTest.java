package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostExtensionParser}: изолированный парсинг расширений X.509v3
 * без зависимости от {@link GostCertificate}.
 */
@DisplayName("GostExtensionParser: изолированный парсинг расширений")
class GostExtensionParserTest {

    // ---------------------------------------------------------------
    // Вспомогательные методы сборки DER-расширений
    // ---------------------------------------------------------------

    /** BOOLEAN DER: tag=0x01, length=0x01, value. */
    private static byte[] boolDer(boolean v) {
        return DerCodec.encodeTlv(TAG_BOOLEAN, new byte[] {(byte) (v ? 0xFF : 0x00)});
    }

    /** [2] IA5String — dNSName (примитивный контекстно-зависимый тег 0x82). */
    private static byte[] dnsName(String name) {
        return DerCodec.encodeTlv(TAG_DNS_NAME, name.getBytes(StandardCharsets.US_ASCII));
    }

    /** [7] OCTET STRING — iPAddress (примитивный контекстно-зависимый тег 0x87). */
    private static byte[] ipAddress(byte... octets) {
        return DerCodec.encodeTlv(TAG_IP_ADDRESS, octets);
    }

    /** [6] IA5String — uniformResourceIdentifier. */
    private static byte[] uriName(String uri) {
        return DerCodec.encodeTlv(0x86, uri.getBytes(StandardCharsets.US_ASCII));
    }

    /** Сборка одного Extension: SEQUENCE { OID [BOOLEAN] OCTET STRING { value } }. */
    private static byte[] extension(byte[] oidBytes, boolean critical, byte[] extValue) {
        byte[] oidDer = DerCodec.encodeTlv(TAG_OID, oidBytes);
        byte[] extInner;
        if (critical) {
            extInner =
                    DerCodec.encodeSequence(
                            oidDer, boolDer(true), DerCodec.encodeOctetString(extValue));
        } else {
            extInner = DerCodec.encodeSequence(oidDer, DerCodec.encodeOctetString(extValue));
        }
        return extInner;
    }

    /** Сборка одного Extension без critical. */
    private static byte[] extension(byte[] oidBytes, byte[] extValue) {
        return extension(oidBytes, false, extValue);
    }

    /** Оборачивает одно или несколько Extension в Extensions SEQUENCE. */
    private static byte[] extensionsSeq(byte[]... exts) {
        return DerCodec.encodeSequence(exts);
    }

    /** Сборка [3] EXPLICIT Extensions: A3 LL 30 LL ... */
    private static byte[] extBlock(byte[] extensionsDer) {
        return DerCodec.encodeContextConstructed(3, extensionsDer);
    }

    // ---------------------------------------------------------------
    // Пустой SEQUENCE
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Пустая SEQUENCE {} -> ExtensionsResult.empty()")
    void testEmptySequence() {
        byte[] der = DerCodec.encodeSequence();
        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(der, 0);
        assertNull(r.sanDnsNames, "пустые расширения -> sanDnsNames=null");
        assertNull(r.sanIpAddresses);
        assertFalse(r.isCA);
        assertEquals(-1, r.pathLen);
        assertFalse(r.hasUnknownCritical);
        assertTrue(r.keyUsageValid);
        assertTrue(r.ekuValid);
        assertTrue(r.presentExtensionOids.isEmpty());
    }

    @Test
    @DisplayName("Пустой [3] блок -> ExtensionsResult.empty()")
    void testEmptyExtBlock() {
        // [3] { SEQUENCE {} } — внутренняя SEQUENCE пустая
        byte[] block = DerCodec.encodeContextConstructed(3, DerCodec.encodeSequence());
        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseFromExtensionsBlock(block, 0);
        assertNull(r.sanDnsNames, "пустой [3] блок -> sanDnsNames=null");
        assertNull(r.sanIpAddresses);
        assertFalse(r.isCA);
        assertEquals(-1, r.pathLen);
        assertFalse(r.hasUnknownCritical);
        assertTrue(r.keyUsageValid);
        assertTrue(r.ekuValid);
        assertTrue(r.presentExtensionOids.isEmpty());
    }

    // ---------------------------------------------------------------
    // SubjectAltName: dNSName
    // ---------------------------------------------------------------

    @Test
    @DisplayName("SAN: один dNSName")
    void testSanDnsNameSingle() {
        byte[] sanValue = DerCodec.encodeSequence(dnsName("example.com"));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.sanDnsNames, "sanDnsNames не null");
        assertEquals(1, r.sanDnsNames.length, "один dNSName");
        assertEquals("example.com", r.sanDnsNames[0]);
        assertNull(r.sanIpAddresses, "нет IP адресов");
        assertTrue(r.presentExtensionOids.contains("2.5.29.17"), "OID в presentExtensionOids");
    }

    @Test
    @DisplayName("SAN: несколько dNSName")
    void testSanDnsNameMultiple() {
        byte[] sanValue = DerCodec.encodeSequence(dnsName("host1.org"), dnsName("host2.org"));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(2, r.sanDnsNames.length);
        assertEquals("host1.org", r.sanDnsNames[0]);
        assertEquals("host2.org", r.sanDnsNames[1]);
    }

    // ---------------------------------------------------------------
    // SubjectAltName: iPAddress
    // ---------------------------------------------------------------

    @Test
    @DisplayName("SAN: IPv4 адрес")
    void testSanIpv4() {
        byte[] sanValue =
                DerCodec.encodeSequence(ipAddress((byte) 192, (byte) 168, (byte) 1, (byte) 1));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.sanIpAddresses, "sanIpAddresses не null");
        assertEquals(1, r.sanIpAddresses.length);
        assertArrayEquals(
                new byte[] {(byte) 192, (byte) 168, 1, 1}, r.sanIpAddresses[0], "IPv4 адрес");
    }

    @Test
    @DisplayName("SAN: IPv4 и IPv6 адреса вместе")
    void testSanMixedIp() {
        byte[] ipv6 = new byte[16];
        ipv6[0] = 0x20;
        ipv6[1] = 0x01;
        ipv6[15] = 1;
        byte[] sanValue =
                DerCodec.encodeSequence(
                        ipAddress((byte) 10, (byte) 0, (byte) 0, (byte) 1), ipAddress(ipv6));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(2, r.sanIpAddresses.length);
        assertEquals(4, r.sanIpAddresses[0].length); // v4
        assertEquals(16, r.sanIpAddresses[1].length); // v6
    }

    @Test
    @DisplayName("SAN: iPAddress невалидной длины игнорируется")
    void testSanMalformedIpIgnored() {
        byte[] sanValue = DerCodec.encodeSequence(ipAddress((byte) 1, (byte) 2, (byte) 3));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNull(r.sanIpAddresses, "iPAddress 3 байта — невалидная длина, игнорируется");
    }

    // ---------------------------------------------------------------
    // KeyUsage
    // ---------------------------------------------------------------

    @Test
    @DisplayName("KeyUsage: digitalSignature установлен")
    void testKuDigitalSignature() {
        byte[] bsContent = new byte[] {0x00, (byte) KU_DIGITAL_SIGNATURE};
        byte[] bitString = DerCodec.encodeTlv(TAG_BIT_STRING, bsContent);
        byte[] ext = extension(KU_OID_BYTES, true, bitString);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.keyUsageValid, "digitalSignature установлен -> KU валиден");
        assertEquals(
                KU_DIGITAL_SIGNATURE, r.keyUsageBits, "keyUsageBits содержит digitalSignature");
        assertTrue(r.presentExtensionOids.contains("2.5.29.15"), "OID KU в presentExtensionOids");
    }

    @Test
    @DisplayName("KeyUsage: digitalSignature не установлен -> keyUsageValid=false")
    void testKuNoDigitalSignature() {
        byte[] bsContent = new byte[] {0x00, KU_KEY_CERT_SIGN}; // только keyCertSign
        byte[] bitString = DerCodec.encodeTlv(TAG_BIT_STRING, bsContent);
        byte[] ext = extension(KU_OID_BYTES, true, bitString);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertFalse(r.keyUsageValid, "digitalSignature отсутствует -> keyUsageValid=false");
        assertTrue(r.keyCertSign, "keyCertSign установлен");
    }

    @Test
    @DisplayName("KeyUsage: отсутствует -> значения по умолчанию (permissive)")
    void testKuAbsent() {
        byte[] sanValue = DerCodec.encodeSequence(dnsName("test"));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.keyUsageValid, "KU отсутствует -> все использования разрешены");
        assertTrue(r.keyCertSign, "KU отсутствует -> keyCertSign = true по умолчанию");
        assertEquals(0, r.keyUsageBits, "keyUsageBits = 0 при отсутствии KU");
    }

    // ---------------------------------------------------------------
    // ExtendedKeyUsage — параметризованный
    // ---------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("ekuCases")
    @DisplayName("EKU: валидация специфичных OID'ов")
    void testEku(
            byte[] oidBytes,
            boolean expectedEkuValid,
            boolean expectedEkuClientAuth,
            boolean expectedEkuOcspSigning) {
        byte[] ekuValue = DerCodec.encodeSequence(DerCodec.encodeTlv(TAG_OID, oidBytes));
        byte[] ext = extension(EKU_OID_BYTES, ekuValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(expectedEkuValid, r.ekuValid, "ekuValid");
        assertEquals(expectedEkuClientAuth, r.ekuClientAuth, "ekuClientAuth");
        assertEquals(expectedEkuOcspSigning, r.ekuOcspSigning, "ekuOcspSigning");
    }

    static Stream<Arguments> ekuCases() {
        return Stream.of(
                Arguments.of(SERVER_AUTH_OID_BYTES, true, false, false),
                Arguments.of(CLIENT_AUTH_OID_BYTES, false, true, false),
                Arguments.of(OCSP_SIGNING_OID_BYTES, false, false, true),
                Arguments.of(ANY_EKU_OID_BYTES, false, false, true));
    }

    @Test
    @DisplayName("EKU: отсутствует -> значения по умолчанию")
    void testEkuAbsent() {
        byte[] sanValue = DerCodec.encodeSequence(dnsName("test"));
        byte[] ext = extension(SAN_OID_BYTES, sanValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.ekuValid, "EKU отсутствует -> ekuValid=true");
        assertTrue(r.ekuClientAuth, "EKU отсутствует -> ekuClientAuth=true");
        assertTrue(r.ekuOcspSigning, "EKU отсутствует -> ekuOcspSigning=true");
    }

    // ---------------------------------------------------------------
    // BasicConstraints
    // ---------------------------------------------------------------

    @Test
    @DisplayName("BasicConstraints: CA=true, pathLen=2")
    void testBcCaWithPathLen() {
        byte[] bcValue = DerCodec.encodeSequence(boolDer(true), DerCodec.encodeInteger(2));
        byte[] ext = extension(BC_OID_BYTES, true, bcValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.isCA, "isCA=true");
        assertEquals(2, r.pathLen, "pathLen=2");
        assertTrue(r.presentExtensionOids.contains("2.5.29.19"), "OID BC в presentExtensionOids");
    }

    @Test
    @DisplayName("BasicConstraints: CA=true без pathLen -> pathLen=-1")
    void testBcCaWithoutPathLen() {
        byte[] bcValue = DerCodec.encodeSequence(boolDer(true));
        byte[] ext = extension(BC_OID_BYTES, true, bcValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.isCA);
        assertEquals(-1, r.pathLen, "pathLen не установлен -> -1");
    }

    @Test
    @DisplayName("BasicConstraints: cA=FALSE (по умолчанию) — leaf-сертификат")
    void testBcNotCa() {
        byte[] bcValue = DerCodec.encodeSequence(); // пустая SEQUENCE — cA=FALSE по умолчанию
        byte[] ext = extension(BC_OID_BYTES, bcValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertFalse(r.isCA, "cA=FALSE (по умолчанию)");
        assertEquals(-1, r.pathLen, "pathLen не применим");
    }

    // ---------------------------------------------------------------
    // SubjectKeyIdentifier
    // ---------------------------------------------------------------

    @Test
    @DisplayName("SKI: извлекает keyIdentifier")
    void testSki() {
        byte[] keyId =
                new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        byte[] skiValue = DerCodec.encodeOctetString(keyId);
        byte[] ext = extension(SKI_OID_BYTES, skiValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.skiBytes, "skiBytes не null");
        assertArrayEquals(keyId, r.skiBytes, "keyIdentifier совпадает");
    }

    // ---------------------------------------------------------------
    // AuthorityKeyIdentifier
    // ---------------------------------------------------------------

    @Test
    @DisplayName("AKI: извлекает [0] keyIdentifier")
    void testAki() {
        byte[] keyId = new byte[] {10, 20, 30, 40};
        byte[] akiInner =
                DerCodec.encodeSequence(DerCodec.encodeTlv(DerCodec.TAG_CTX_PRIMITIVE_0, keyId));
        byte[] ext = extension(AKI_OID_BYTES, akiInner);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.akiBytes, "akiBytes не null");
        assertArrayEquals(keyId, r.akiBytes);
    }

    // ---------------------------------------------------------------
    // AuthorityInfoAccess
    // ---------------------------------------------------------------

    @Test
    @DisplayName("AIA: OCSP URI")
    void testAiaOcsp() {
        byte[] aiaValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(TAG_OID, AD_OCSP_OID_BYTES),
                                uriName("http://ocsp.example.com")));
        byte[] ext = extension(AIA_OID_BYTES, aiaValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.aiaUris, "aiaUris не null");
        assertEquals(1, r.aiaUris.length);
        assertEquals("http://ocsp.example.com", r.aiaUris[0]);
        assertNotNull(r.ocspUris);
        assertEquals(1, r.ocspUris.length);
        assertEquals("http://ocsp.example.com", r.ocspUris[0]);
        assertNull(r.caIssuersUris, "нет caIssuers");
    }

    @Test
    @DisplayName("AIA: caIssuers URI")
    void testAiaCaIssuers() {
        byte[] aiaValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(TAG_OID, AD_CA_ISSUERS_OID_BYTES),
                                uriName("http://ca.example.com/cert.p7c")));
        byte[] ext = extension(AIA_OID_BYTES, aiaValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(1, r.caIssuersUris.length);
        assertEquals("http://ca.example.com/cert.p7c", r.caIssuersUris[0]);
        assertNull(r.ocspUris, "нет OCSP");
    }

    @Test
    @DisplayName("AIA: OCSP + caIssuers вместе")
    void testAiaBoth() {
        byte[] aiaValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(TAG_OID, AD_OCSP_OID_BYTES),
                                uriName("http://ocsp.example.com")),
                        DerCodec.encodeSequence(
                                DerCodec.encodeTlv(TAG_OID, AD_CA_ISSUERS_OID_BYTES),
                                uriName("http://ca.example.com")));
        byte[] ext = extension(AIA_OID_BYTES, aiaValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(2, r.aiaUris.length);
        assertEquals(1, r.ocspUris.length);
        assertEquals(1, r.caIssuersUris.length);
    }

    // ---------------------------------------------------------------
    // CRLDistributionPoints
    // ---------------------------------------------------------------

    @Test
    @DisplayName("CDP: один URI")
    void testCdpSingleUri() {
        byte[] cdpValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(
                                DerCodec.encodeContextConstructed(
                                        0, // distributionPoint [0]
                                        DerCodec.encodeContextConstructed(
                                                0, // fullName [0]
                                                DerCodec.encodeSequence(
                                                        uriName(
                                                                "http://crl.example.com/crl.crl"))))));
        byte[] ext = extension(CDP_OID_BYTES, cdpValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.cdpUris, "cdpUris не null");
        assertEquals(1, r.cdpUris.length);
        assertEquals("http://crl.example.com/crl.crl", r.cdpUris[0]);
    }

    // ---------------------------------------------------------------
    // CertificatePolicies
    // ---------------------------------------------------------------

    @Test
    @DisplayName("CertificatePolicies: один OID политики")
    void testCpSingleOid() {
        byte[] cpValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(DerCodec.encodeTlv(TAG_OID, KC1_OID_BYTES)));
        byte[] ext = extension(CP_OID_BYTES, cpValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertNotNull(r.certPolicyOids, "certPolicyOids не null");
        assertEquals(1, r.certPolicyOids.length);
        assertNotNull(r.cpOids, "cpOids не null");
        assertEquals(1, r.cpOids.length);
        assertArrayEquals(KC1_OID_BYTES, r.cpOids[0], "сырые DER-байты OID");
    }

    @Test
    @DisplayName("CertificatePolicies: несколько OID политик")
    void testCpMultipleOids() {
        byte[] cpValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(DerCodec.encodeTlv(TAG_OID, KC1_OID_BYTES)),
                        DerCodec.encodeSequence(DerCodec.encodeTlv(TAG_OID, KC2_OID_BYTES)));
        byte[] ext = extension(CP_OID_BYTES, cpValue);
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals(2, r.certPolicyOids.length);
        assertEquals(2, r.cpOids.length);
        assertTrue(r.presentExtensionOids.contains("2.5.29.32"), "OID CP в presentExtensionOids");
    }

    // ---------------------------------------------------------------
    // Неизвестное critical-расширение
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Неизвестное critical-расширение -> hasUnknownCritical=true")
    void testUnknownCriticalExtension() {
        byte[] unknownOid = new byte[] {1, 2, 3, 4, 5};
        byte[] ext =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(TAG_OID, unknownOid),
                        boolDer(true),
                        DerCodec.encodeOctetString(new byte[] {0x30, 0x00}));
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertTrue(r.hasUnknownCritical, "Неизвестное critical-расширение должно быть отвергнуто");
    }

    @Test
    @DisplayName("Неизвестное non-critical расширение — игнорируется")
    void testUnknownNonCriticalExtensionIgnored() {
        byte[] unknownOid = new byte[] {1, 2, 3, 4, 5};
        byte[] ext =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(TAG_OID, unknownOid),
                        DerCodec.encodeOctetString(new byte[] {0x30, 0x00}));
        byte[] seq = extensionsSeq(ext);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertFalse(r.hasUnknownCritical, "Non-critical неизвестное — игнорируется");
    }

    // ---------------------------------------------------------------
    // Несколько расширений вместе
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Несколько расширений: SAN + KU + EKU + BC — все поля корректны")
    void testMultipleExtensions() {
        byte[] sanValue = DerCodec.encodeSequence(dnsName("multi.example.com"));
        byte[] sanExt = extension(SAN_OID_BYTES, sanValue);

        byte[] kuBsContent = new byte[] {0x00, (byte) (KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN)};
        byte[] kuValue = DerCodec.encodeTlv(TAG_BIT_STRING, kuBsContent);
        byte[] kuExt = extension(KU_OID_BYTES, true, kuValue);

        byte[] ekuValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeTlv(TAG_OID, SERVER_AUTH_OID_BYTES),
                        DerCodec.encodeTlv(TAG_OID, CLIENT_AUTH_OID_BYTES));
        byte[] ekuExt = extension(EKU_OID_BYTES, ekuValue);

        byte[] bcValue = DerCodec.encodeSequence(boolDer(true), DerCodec.encodeInteger(0));
        byte[] bcExt = extension(BC_OID_BYTES, true, bcValue);

        byte[] seq = extensionsSeq(sanExt, kuExt, ekuExt, bcExt);

        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(seq, 0);

        assertEquals("multi.example.com", r.sanDnsNames[0]);
        assertTrue(r.keyUsageValid);
        assertTrue(r.keyCertSign);
        assertTrue(r.ekuValid);
        assertTrue(r.ekuClientAuth);
        assertTrue(r.isCA);
        assertEquals(0, r.pathLen);
        assertEquals(4, r.presentExtensionOids.size(), "4 OID в presentExtensionOids");
    }

    // ---------------------------------------------------------------
    // Битый DER
    // ---------------------------------------------------------------

    @Test
    @DisplayName("Битый DER: truncated — исключение")
    void testTruncatedDer() {
        byte[] truncated = new byte[] {0x30, 0x05}; // SEQUENCE длиной 5, но данных нет
        assertThrows(
                IllegalArgumentException.class,
                () -> GostExtensionParser.parseExtensionsFromSequence(truncated, 0),
                "Усечённый DER должен вызывать исключение");
    }

    @Test
    @DisplayName("Не-SEQUENCE на входе parseExtensionsFromSequence — возвращает empty()")
    void testNonSequenceInput() {
        byte[] notSeq = new byte[] {0x01, 0x01, 0x00}; // BOOLEAN
        GostExtensionParser.ExtensionsResult r =
                GostExtensionParser.parseExtensionsFromSequence(notSeq, 0);
        assertSame(
                GostExtensionParser.ExtensionsResult.empty(),
                r,
                "Не-SEQUENCE на входе — возврат пустого результата");
    }
}
