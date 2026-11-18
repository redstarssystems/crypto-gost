package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.SignedDerTestSupport;
import org.rssys.gost.signature.ECParameters;

/**
 * Модульные тесты {@link GostCsrBuilder}: построение PKCS#10 CSR.
 */
@DisplayName("GostCsrBuilder: построение PKCS#10 CSR")
class GostCsrBuilderTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();

    // ========================================================================
    // Старые тесты — обратная совместимость статических методов
    // ========================================================================

    @Test
    @DisplayName("buildCsr: обратимость — собираем CSR с DN")
    void testBuildCsrRoundtrip() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=Test,OU=Dev", kp.getPublic()).sign(kp.getPrivate());

        assertNotNull(csrDer);
        assertTrue(csrDer.length > 100, "CSR должен быть ненулевой длины");
    }

    @Test
    @DisplayName("buildCsr: 512-битная кривая")
    void testBuildCsr512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);

        byte[] csrDer = GostCsrBuilder.create("CN=Test512", kp.getPublic()).sign(kp.getPrivate());
        assertNotNull(csrDer);
        assertTrue(csrDer.length > 200);
    }

    @Test
    @DisplayName("buildCsr: DN с несколькими атрибутами")
    void testBuildCsrMultiAttrDn() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create(
                                "CN=Server,O=MyOrg,OU=Dev,L=City,ST=Region,C=RU", kp.getPublic())
                        .sign(kp.getPrivate());
        assertNotNull(csrDer);
    }

    @Test
    @DisplayName("buildCsr: разные ключи дают разный CSR")
    void testBuildCsrDifferentKeys() throws Exception {
        KeyPair kp1 = KeyGenerator.generateKeyPair(PARAMS_256);
        KeyPair kp2 = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csr1 = GostCsrBuilder.create("CN=Test", kp1.getPublic()).sign(kp1.getPrivate());
        byte[] csr2 = GostCsrBuilder.create("CN=Test", kp2.getPublic()).sign(kp2.getPrivate());

        assertFalse(java.util.Arrays.equals(csr1, csr2), "CSR от разных ключей должны различаться");
    }

    // ========================================================================
    // Новые тесты — factory create + builder без расширений
    // ========================================================================

    @Test
    @DisplayName("create: builder без расширений — hasExtensions() = false")
    void testBuilderWithoutExtensions() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
        GostCsrBuilder builder = GostCsrBuilder.create("CN=NoExt,O=Org", kp.getPublic());
        byte[] csrDer = builder.sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertFalse(
                parsed.hasExtensions(),
                "Builder без fluent-сеттеров не должен добавлять extensionRequest");
    }

    // ========================================================================
    // Тест №10: байт-в-байт регрессия старого статического пути
    // ========================================================================

    @Test
    @DisplayName("Байт-в-байт регрессия: старый static-метод == builder без расширений")
    void testStaticMethodByteIdenticalToBuilderWithoutExtensions() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] fromStatic =
                GostCsrBuilder.create("CN=StaticVsBuilder", kp.getPublic()).sign(kp.getPrivate());
        byte[] fromBuilder =
                GostCsrBuilder.create("CN=StaticVsBuilder", kp.getPublic()).sign(kp.getPrivate());

        SignedDerTestSupport.assertSameExceptSignature(
                "Старый static-метод должен давать тот же CSR, что и create()+buildCsr() (без значения подписи)",
                fromStatic,
                fromBuilder);
    }

    // ========================================================================
    // Тест №1: Round-trip SAN (dNSName)
    // ========================================================================

    @Test
    @DisplayName("Round-trip: SAN dNSName")
    void testRoundtripSanDns() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=SanDns", kp.getPublic())
                        .sanDns("example.com", "www.example.com")
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertNotNull(ext.sanDnsNames);
        assertEquals(2, ext.sanDnsNames.length);
        boolean hasExample = false;
        boolean hasWww = false;
        for (String name : ext.sanDnsNames) {
            if ("example.com".equals(name)) hasExample = true;
            if ("www.example.com".equals(name)) hasWww = true;
        }
        assertTrue(hasExample, "SAN должен содержать example.com");
        assertTrue(hasWww, "SAN должен содержать www.example.com");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_SAN));
    }

    // ========================================================================
    // Тест №2: Round-trip SAN (iPAddress)
    // ========================================================================

    @Test
    @DisplayName("Round-trip: SAN iPAddress")
    void testRoundtripSanIp() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=SanIp", kp.getPublic())
                        .sanIp("192.168.1.1", "10.0.0.1")
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertNotNull(ext.sanIpAddresses);
        assertEquals(2, ext.sanIpAddresses.length);
        // 192.168.1.1
        assertArrayEquals(new byte[] {(byte) 192, (byte) 168, 1, 1}, ext.sanIpAddresses[0]);
        // 10.0.0.1
        assertArrayEquals(new byte[] {10, 0, 0, 1}, ext.sanIpAddresses[1]);
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_SAN));
    }

    // ========================================================================
    // Тест №3: Round-trip KeyUsage
    // ========================================================================

    @Test
    @DisplayName("Round-trip: KeyUsage")
    void testRoundtripKeyUsage() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=KuTest", kp.getPublic())
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                                GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();

        assertEquals(
                0x80 | 0x20,
                ext.keyUsageBits,
                "Битовая маска должна совпадать: digitalSignature + keyEncipherment");
        assertTrue((ext.keyUsageBits & 0x80) != 0, "Бит digitalSignature должен быть установлен");
        assertTrue((ext.keyUsageBits & 0x20) != 0, "Бит keyEncipherment должен быть установлен");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_KU));
    }

    // ========================================================================
    // Тест №4: Round-trip ExtendedKeyUsage
    // ========================================================================

    @Test
    @DisplayName("Round-trip: ExtendedKeyUsage")
    void testRoundtripEku() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=EkuTest", kp.getPublic())
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH, GostOids.EXT_CLIENT_AUTH)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertNotNull(ext.ekuOids);
        assertEquals(2, ext.ekuOids.length, "Должно быть два EKU OID");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_EKU));
    }

    // ========================================================================
    // Тест №5: Round-trip BasicConstraints (isCA=true, pathLen=0)
    // ========================================================================

    @Test
    @DisplayName("Round-trip: BasicConstraints isCA=true, pathLen=0")
    void testRoundtripBasicConstraintsCaWithPathLen() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=CaBc", kp.getPublic())
                        .basicConstraints(true, 0)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertTrue(ext.isCA, "isCA должно быть true");
        assertEquals(0, ext.pathLen, "pathLen должно быть 0");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_BC));
    }

    // ========================================================================
    // Тест №6: Round-trip BasicConstraints (isCA=true, pathLen=null)
    // ========================================================================

    @Test
    @DisplayName("Round-trip: BasicConstraints isCA=true без pathLen")
    void testRoundtripBasicConstraintsCaWithoutPathLen() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=CaNoPath", kp.getPublic())
                        .basicConstraints(true, null)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertTrue(ext.isCA, "isCA должно быть true");
        assertEquals(-1, ext.pathLen, "pathLen должно быть -1 (отсутствует)");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_BC));
    }

    // ========================================================================
    // Тест №7: Round-trip SubjectKeyIdentifier
    // ========================================================================

    @Test
    @DisplayName("Round-trip: SubjectKeyIdentifier")
    void testRoundtripSki() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=SkiTest", kp.getPublic()).ski().sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertNotNull(ext.skiBytes, "SKI байты должны быть не null");
        assertTrue(ext.skiBytes.length > 0, "SKI байты должны быть непустыми");
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_SKI));
    }

    // ========================================================================
    // Тест №8: Round-trip множественные расширения
    // ========================================================================

    @Test
    @DisplayName("Round-trip: SAN + KU + EKU + SKI одновременно")
    void testRoundtripMultipleExtensions() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=MultiExt", kp.getPublic())
                        .sanDns("multi.example.com")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(GostOids.EXT_SERVER_AUTH)
                        .ski()
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();

        assertNotNull(ext.sanDnsNames);
        assertEquals(1, ext.sanDnsNames.length);
        assertEquals("multi.example.com", ext.sanDnsNames[0]);

        assertTrue((ext.keyUsageBits & 0x80) != 0, "Бит digitalSignature должен быть установлен");
        assertNotNull(ext.ekuOids);
        assertTrue(ext.ekuOids.length > 0);
        assertNotNull(ext.skiBytes);
        assertTrue(ext.skiBytes.length > 0);

        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_SAN));
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_KU));
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_EKU));
        assertTrue(ext.presentExtensionOids.contains(GostOids.EXT_SKI));
    }

    // ========================================================================
    // Тест №9: additionalExtensions passthrough
    // ========================================================================

    @Test
    @DisplayName("Round-trip: additionalExtensions — сырой DER")
    void testAdditionalExtensionsPassthrough() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        // Собираем сырой блок Extension для CertificatePolicies
        byte[] cpExt =
                GostCertificateBuilder.buildCertificatePoliciesExtension(
                        new String[] {"1.3.6.1.4.1.311.21.10"});

        byte[] csrDer =
                GostCsrBuilder.create("CN=AddExt", kp.getPublic())
                        .additionalExtensions(cpExt)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());

        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
        assertTrue(
                ext.presentExtensionOids.contains(GostOids.EXT_CP),
                "CertificatePolicies должно быть в списке расширений");
    }

    // ========================================================================
    // Тест №12: разные ключи + одинаковые расширения -> CSR различаются
    // ========================================================================

    @Test
    @DisplayName("Разные ключи + одинаковые расширения -> CSR различаются")
    void testDifferentKeysSameExtensions() throws Exception {
        KeyPair kp1 = KeyGenerator.generateKeyPair(PARAMS_256);
        KeyPair kp2 = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csr1 =
                GostCsrBuilder.create("CN=DiffKey", kp1.getPublic())
                        .sanDns("test.example.com")
                        .sign(kp1.getPrivate());

        byte[] csr2 =
                GostCsrBuilder.create("CN=DiffKey", kp2.getPublic())
                        .sanDns("test.example.com")
                        .sign(kp2.getPrivate());

        assertFalse(
                java.util.Arrays.equals(csr1, csr2),
                "CSR от разных ключей с одинаковыми расширениями должны различаться");
    }

    // ========================================================================
    // Тест №13: негативный — pathLen без isCA
    // ========================================================================

    @Test
    @DisplayName("Негативный: pathLen без isCA=true -> IllegalArgumentException")
    void testPathLenWithoutIsCa() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        assertThrows(
                IllegalArgumentException.class,
                () -> GostCsrBuilder.create("CN=BadBc", kp.getPublic()).basicConstraints(false, 0),
                "pathLen без isCA=true должен выбрасывать IllegalArgumentException");
    }

    // ========================================================================
    // Тест: factory create с byte[] DN
    // ========================================================================

    @Test
    @DisplayName("create(byte[]): DER-кодированный DN")
    void testCreateWithDerDn() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
        byte[] dnDer = GostDnParser.encodeDn("CN=DerDn,O=Test");

        byte[] csrDer =
                GostCsrBuilder.create(dnDer, kp.getPublic())
                        .sanDns("der.example.com")
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertEquals("CN=DerDn, O=Test", parsed.getSubjectDn());
        assertTrue(parsed.hasExtensions());
    }

    @Test
    @DisplayName("CSR: только sanUpn() без других полей -> extensionRequest собран")
    void testCsrWithSanUpnOnly() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=UPN Only", kp.getPublic())
                        .sanUpn("user@domain.ru")
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(
                parsed.hasExtensions(),
                "extensionRequest должен быть собран даже с одним sanUpn()");
    }

    // ========================================================================
    // CertificatePolicies — запрос в CSR
    // ========================================================================

    @Test
    @DisplayName("Round-trip: certificatePolicies(String...) через CSR")
    void testRoundtripCertificatePoliciesOidsOnly() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

        byte[] csrDer =
                GostCsrBuilder.create("CN=CpCsrTest", kp.getPublic())
                        .certificatePolicies(GostOids.POLICY_KC1, GostOids.POLICY_KC2)
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());
        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();

        assertNotNull(ext.certPolicyOids);
        assertEquals(2, ext.certPolicyOids.length);
        assertEquals(GostOids.POLICY_KC1, ext.certPolicyOids[0]);
        assertEquals(GostOids.POLICY_KC2, ext.certPolicyOids[1]);

        assertNotNull(ext.certPolicies);
        assertEquals(2, ext.certPolicies.length);
        assertNull(ext.certPolicies[0].cpsUri());
    }

    @Test
    @DisplayName("Round-trip: certificatePolicyInfos(CertificatePolicy...) с CPS через CSR")
    void testRoundtripCertificatePolicyInfosWithCps() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
        String cpsUri = "https://ca.example.com/cps.html";

        byte[] csrDer =
                GostCsrBuilder.create("CN=CpCsrCpsTest", kp.getPublic())
                        .certificatePolicyInfos(new CertificatePolicy(GostOids.POLICY_KC1, cpsUri))
                        .sign(kp.getPrivate());

        GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
        assertTrue(parsed.verifySelf());
        assertTrue(parsed.hasExtensions());
        GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();

        assertNotNull(ext.certPolicies);
        assertEquals(1, ext.certPolicies.length);
        assertEquals(GostOids.POLICY_KC1, ext.certPolicies[0].policyOid());
        assertEquals(cpsUri, ext.certPolicies[0].cpsUri());
    }
}
