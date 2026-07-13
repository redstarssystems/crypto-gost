package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostCsrParser}: разбор PKCS#10 CSR.
 */
@DisplayName("GostCsrParser: разбор PKCS#10 CSR")
class GostCsrParserTest {

    // ========================================================================
    // Roundtrip: Builder -> Parser
    // ========================================================================

    @Test
    @DisplayName("Обратимость: GostCsrBuilder -> GostCsrParser, все поля совпадают")
    void testBuilderToParserRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        String dn = "CN=TestParser,O=Org,OU=Dev,C=RU";

        byte[] csrDer = GostCsrBuilder.create(dn, kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertEquals(0, parsed.getVersion(), "Версия CSR должна быть 0 (v1)");
        // GostDnParser при разборе DN добавляет пробелы после запятых
        assertTrue(parsed.getSubjectDn().contains("CN=TestParser"));
        assertTrue(parsed.getSubjectDn().contains("O=Org"));
        assertTrue(parsed.getSubjectDn().contains("OU=Dev"));
        assertTrue(parsed.getSubjectDn().contains("C=RU"));
        assertNotNull(parsed.getPublicKey());
        assertNotNull(parsed.getSignatureAlgorithmOid());
        assertFalse(parsed.getSignatureAlgorithmOid().isEmpty());
        assertTrue(parsed.getSignatureValue().length > 0);
        assertNotNull(parsed.getEncoded());
        assertTrue(parsed.verifySelf(), "Proof-of-possession: CSR должен быть самоподписан");

        // GostCsrBuilder не добавляет атрибуты -> extensions пусты
        assertFalse(
                parsed.hasExtensions(),
                "GostCsrBuilder не добавляет extensionRequest -> extensions пусты");
    }

    @Test
    @DisplayName("Обратимость: 512-битная кривая")
    void testRoundtrip512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=Test512", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertEquals("CN=Test512", parsed.getSubjectDn());
        assertTrue(parsed.verifySelf());
    }

    // ========================================================================
    // verifySelf и verify
    // ========================================================================

    @Test
    @DisplayName("verifySelf: proof-of-possession — CSR подписан своим ключом")
    void testVerifySelf() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create("CN=VerifySelf", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertTrue(parsed.verifySelf(), "CSR должен быть самоподписан");
    }

    @Test
    @DisplayName("verify: проверка чужим ключом возвращает false")
    void testVerifyWrongKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        KeyPair otherKp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=WrongKey", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertFalse(
                parsed.verify(otherKp.getPublic()), "Проверка чужим ключом должна вернуть false");
    }

    // ========================================================================
    // PEM roundtrip
    // ========================================================================

    @Test
    @DisplayName("PEM обратимость: toPem -> fromPemOrDer")
    void testToPemFromPem() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=PemTest", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser original = GostCsrParser.fromDer(csrDer);

        String pem = original.toPem();
        assertTrue(
                pem.contains("-----BEGIN CERTIFICATE REQUEST-----"),
                "PEM должен содержать заголовок CERTIFICATE REQUEST");
        assertTrue(pem.contains("-----END CERTIFICATE REQUEST-----"));

        // Чтение из PEM (с CERTIFICATE REQUEST заголовком)
        GostCsrParser fromPem =
                GostCsrParser.fromPemOrDer(
                        pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals(original.getSubjectDn(), fromPem.getSubjectDn());
        assertTrue(fromPem.verifySelf());
    }

    @Test
    @DisplayName("PEM: fromPemOrDer читает и CERTIFICATE заголовок")
    void testPemLabelCertificate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=CertLabel", kp.getPublic()).sign(kp.getPrivate());
        // Кодируем как CERTIFICATE (устойчивость: pemToDer игнорирует заголовок)
        String pem = GostPemUtils.toPem(csrDer, "CERTIFICATE");
        GostCsrParser parsed =
                GostCsrParser.fromPemOrDer(
                        pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        assertEquals("CN=CertLabel", parsed.getSubjectDn());
        assertTrue(parsed.verifySelf());
    }

    // ========================================================================
    // DN с несколькими атрибутами
    // ========================================================================

    @Test
    @DisplayName("DN с несколькими атрибутами: lookup по OID")
    void testMultiAttrDn() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create(
                                "CN=Server,O=MyOrg,OU=Dev,L=City,ST=Region,C=RU", kp.getPublic())
                        .sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        String dn = parsed.getSubjectDn();
        assertNotNull(dn);
        assertTrue(dn.contains("CN=Server"));
        assertTrue(dn.contains("O=MyOrg"));
        assertTrue(dn.contains("C=RU"));

        // Lookup по OID
        String[] cn = parsed.getSubjectDnField("2.5.4.3");
        assertEquals(1, cn.length);
        assertEquals("Server", cn[0]);

        String[] c = parsed.getSubjectDnField("2.5.4.6");
        assertEquals(1, c.length);
        assertEquals("RU", c[0]);
    }

    // ========================================================================
    // Расширения (extensionRequest) — вручную собранный DER
    // ========================================================================

    @Test
    @DisplayName("extensionRequest: ручная сборка CSR с SAN расширением через DerCodec")
    void testExtensionRequest() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        // Собираем расширение SubjectAltName: dNSName=test.example.com
        // SAN ::= GeneralNames ::= SEQUENCE OF GeneralName
        // GeneralName dNSName [2] IMPLICIT IA5String
        byte[] dnsName =
                DerCodec.encodeTlv(
                        0x82,
                        "test.example.com".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] sanExtValue =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.29.17"), // SAN OID
                        DerCodec.encodeTlv(
                                DerCodec.TAG_BOOLEAN, new byte[] {(byte) 0xFF}), // critical = TRUE
                        DerCodec.encodeOctetString( // extnValue
                                DerCodec.encodeSequence(dnsName) // GeneralNames SEQUENCE
                                ));

        // Extensions ::= SEQUENCE OF Extension
        byte[] extensions = DerCodec.encodeSequence(sanExtValue);

        // Attribute ::= SEQUENCE { type OID, values SET { Extensions } }
        byte[] attrValues = DerCodec.encodeSet(extensions);
        byte[] extensionRequestAttr =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("1.2.840.113549.1.9.14"), // extensionRequest OID
                        attrValues);

        // Attributes ::= [0] IMPLICIT SET OF Attribute
        byte[] attributes =
                DerCodec.encodeContextConstructed(0, DerCodec.encodeSet(extensionRequestAttr));

        // Собираем TBS
        byte[] spki = GostDerCodec.encodePublicKey(kp.getPublic());
        ByteArrayOutputStream tbsOut = new ByteArrayOutputStream();
        tbsOut.write(DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {0x00})); // version
        tbsOut.write(GostDnParser.encodeDn("CN=SanTest")); // DN
        tbsOut.write(spki); // SPKI
        tbsOut.write(attributes); // attributes
        byte[] tbs = DerCodec.encodeSequence(tbsOut.toByteArray());

        byte[] sigValue = Signature.sign(tbs, kp.getPrivate());
        byte[] csrDer =
                DerCodec.encodeSequence(
                        tbs,
                        GostSignatureHelper.buildAlgId(params),
                        DerCodec.encodeBitString(sigValue));

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertEquals("CN=SanTest", parsed.getSubjectDn());
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertNotNull(ext.sanDnsNames);
        assertEquals(1, ext.sanDnsNames.length);
        assertEquals("test.example.com", ext.sanDnsNames[0]);
    }

    // ========================================================================
    // fromDer / fromPemOrDer
    // ========================================================================

    @Test
    @DisplayName("fromDer: парсит DER напрямую")
    void testFromDer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=FromDer", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        assertEquals("CN=FromDer", parsed.getSubjectDn());
        assertTrue(Arrays.equals(csrDer, parsed.getEncoded()));
    }

    @Test
    @DisplayName("fromPemOrDer: auto-detect DER")
    void testFromPemOrDerWithDer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=AutoDer", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromPemOrDer(csrDer);

        assertEquals("CN=AutoDer", parsed.getSubjectDn());
    }

    // ========================================================================
    // toString — без ключевого материала
    // ========================================================================

    @Test
    @DisplayName("toString: не содержит ключевого материала")
    void testToStringNoSecrets() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create("CN=SecretTest", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

        String s = parsed.toString();
        assertNotNull(s);
        assertTrue(s.contains("CN=SecretTest"));
        assertTrue(s.contains("256bit"));
        // Не должно содержать raw-ключ
        assertFalse(s.contains("priv"), "toString не должен содержать ключевой материал");
    }

    @Test
    @DisplayName("equals: одинаковые DER-байты -> равны")
    void testEqualsAndHashCode() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=EqTest", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser a = GostCsrParser.fromDer(csrDer);
        GostCsrParser b = GostCsrParser.fromDer(csrDer);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    @DisplayName("equals: разные CSR -> не равны")
    void testNotEquals() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=A", kp.getPublic()).sign(kp.getPrivate());
        byte[] csrDer2 = GostCsrBuilder.create("CN=B", kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser a = GostCsrParser.fromDer(csrDer);
        GostCsrParser b = GostCsrParser.fromDer(csrDer2);

        assertNotEquals(a, b);
    }

    // ========================================================================
    // getSubjectDnDer
    // ========================================================================

    @Test
    @DisplayName(
            "getSubjectDnDer: базовый round-trip через parseDnString совпадает с getSubjectDn()")
    void testGetSubjectDnDerRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer =
                GostCsrBuilder.create("CN=RoundTrip,O=Example", kp.getPublic())
                        .sign(kp.getPrivate());
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);

        byte[] dnDer = csr.getSubjectDnDer();
        assertNotNull(dnDer);
        assertTrue(dnDer.length > 0);

        GostDnParser.DnParseResult reparsed = GostDnParser.parseDnString(dnDer, 0, dnDer.length);
        assertEquals(
                csr.getSubjectDn(),
                reparsed.dnString,
                "Перепарсенный из DER DN должен совпадать с getSubjectDn()");
    }

    @Test
    @DisplayName("getSubjectDnDer: байтово-точное сохранение PrintableString")
    void testGetSubjectDnDerPrintableString() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        // Вручную собираем DER DN с PrintableString (тег 0x13) вместо UTF8String (0x0C)
        byte[] cnAttr =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.4.3"),
                        DerCodec.encodeTlv(
                                DerCodec.TAG_PRINTABLE_STRING,
                                "TestCN".getBytes(StandardCharsets.US_ASCII)));
        byte[] oAttr =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("2.5.4.10"),
                        DerCodec.encodeTlv(
                                DerCodec.TAG_PRINTABLE_STRING,
                                "TestOrg".getBytes(StandardCharsets.US_ASCII)));
        byte[] handcraftedDn =
                DerCodec.encodeSequence(DerCodec.encodeSet(cnAttr), DerCodec.encodeSet(oAttr));

        byte[] csrDer = GostCsrBuilder.create(handcraftedDn, kp.getPublic()).sign(kp.getPrivate());
        GostCsrParser csr = GostCsrParser.fromDer(csrDer);

        byte[] dnDer = csr.getSubjectDnDer();
        assertArrayEquals(
                handcraftedDn,
                dnDer,
                "getSubjectDnDer должен вернуть байтово идентичный исходный DER с PrintableString");

        // PrintableString поддерживается парсером — строка должна корректно читаться
        String dn = csr.getSubjectDn();
        assertNotNull(dn);
        assertTrue(dn.contains("TestCN"));
        assertTrue(dn.contains("TestOrg"));
        assertTrue(csr.verifySelf());
    }
}
