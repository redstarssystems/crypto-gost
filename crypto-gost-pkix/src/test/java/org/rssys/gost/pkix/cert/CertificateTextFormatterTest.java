package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;

@DisplayName("CertificateTextFormatter: человекочитаемый вывод сертификата")
class CertificateTextFormatterTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate fullCert;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        fullCert = buildFullCert(PARAMS);
    }

    private static GostCertificate buildFullCert(ECParameters params) {
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Test Subject, O=Новая Организация, C=RU");
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA, O=Новый УЦ, C=RU");
        return GostCertificateBuilder.create(params, subjectDn)
                .issuerDn(issuerDn)
                .publicKey(kp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("21010101000000Z")
                .serial(BigInteger.valueOf(9999))
                .sanDns("test.example.com", "alt.example.org")
                .sanIp("127.0.0.1", "::1")
                .keyUsage(
                        GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE,
                        GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT)
                .extendedKeyUsage(GostOids.EXT_SERVER_AUTH, GostOids.EXT_CLIENT_AUTH)
                .basicConstraints(false, null)
                .ski()
                .aki(kp.getPublic())
                .ocspResponder("http://ocsp.example.com")
                .caIssuer("http://ca.example.com/cert.cer")
                .crlDistributionPoints("http://crl.example.com/crl.crl")
                .additionalExtensions(
                        GostCertificateBuilder.buildCertificatePoliciesExtension(
                                new String[] {GostOids.POLICY_KC1}))
                .sign(kp.getPrivate());
    }

    @Test
    @DisplayName("null-сертификат -> IllegalArgumentException")
    void nullCertThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CertificateTextFormatter.format(null),
                "форматтер не должен принимать null");
    }

    @Test
    @DisplayName("Базовые поля: версия, серийный номер, DN, сроки, ключ")
    void basicFieldsPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("Версия"), "версия");
        assertTrue(out.contains("Серийный номер"), "серийный номер");
        assertTrue(out.contains("Издатель (Issuer)"), "Issuer DN");
        assertTrue(out.contains("Субъект (Subject)"), "Subject DN");
        assertTrue(out.contains("Действителен с"), "Not Before");
        assertTrue(out.contains("Действителен по"), "Not After");
        assertTrue(out.contains("Открытый ключ"), "алгоритм ключа");
        assertTrue(out.contains("Test Subject"), "subject DN без усечения");
    }

    @Test
    @DisplayName("Расширения: Basic Constraints, Key Usage, EKU — присутствуют с расшифровкой")
    void extensionsPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("Basic Constraints"), "BasicConstraints");
        assertTrue(out.contains("CA=FALSE"), "CA=FALSE");
        assertTrue(out.contains("Key Usage"), "KeyUsage");
        assertTrue(out.contains("digitalSignature"), "digitalSignature");
        assertTrue(out.contains("keyEncipherment"), "keyEncipherment");
        assertTrue(out.contains("Extended Key Usage"), "EKU");
        assertTrue(out.contains("serverAuth"), "serverAuth EKU");
        assertTrue(out.contains("clientAuth"), "clientAuth EKU");
    }

    @Test
    @DisplayName("SAN: DNS и IP-адреса")
    void sanPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("Subject Alt Name"), "SAN");
        assertTrue(out.contains("DNS:test.example.com"), "DNS SAN");
        assertTrue(out.contains("DNS:alt.example.org"), "второй DNS");
        assertTrue(out.contains("IP:127.0.0.1"), "IPv4 SAN");
        assertTrue(out.contains("IP:::1"), "IPv6 loopback со сжатием");
    }

    @Test
    @DisplayName("SKI/AKI — hex-значения")
    void skiAkiPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("Subject Key Identifier"), "SKI");
        assertTrue(out.contains("Authority Key Identifier"), "AKI");
        // AKI из ключа содержит октеты — hex с разделителем :
        assertTrue(
                out.matches("(?s).*Authority Key Identifier: [0-9a-f:]{10,}.*"),
                "AKI в hex-формате");
    }

    @Test
    @DisplayName("AIA: OCSP и CA Issuers")
    void aiaPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("OCSP"), "заголовок OCSP");
        assertTrue(out.contains("http://ocsp.example.com"), "OCSP URI");
        assertTrue(out.contains("CA Issuers"), "заголовок CA Issuers");
        assertTrue(out.contains("http://ca.example.com/cert.cer"), "caIssuers URI");
    }

    @Test
    @DisplayName("CRL Distribution Points")
    void cdpPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("CRL Distribution Points"), "CDP заголовок");
        assertTrue(out.contains("http://crl.example.com/crl.crl"), "CDP URI");
    }

    @Test
    @DisplayName("Certificate Policies — OID расшифровывается через displayName")
    void policyPresent() {
        String out = CertificateTextFormatter.format(fullCert);

        assertTrue(out.contains("Certificate Policies"), "заголовок политик");
        assertTrue(out.contains("class-kc1"), "расшифрованная политика KC1");
    }

    @Test
    @DisplayName("DN не усечён (в отличие от toString)")
    void dnNotTruncated() {
        // toString() усекает DN до 256: здесь же длинный DN должен быть полностью
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        String longOu =
                "ОченьДлинноеНазваниеПодразделенияКотороеТочно_Больше_256_Символов_"
                        + "1234567890_1234567890_1234567890_1234567890"
                        + "1234567890_1234567890_1234567890_1234567890"
                        + "1234567890_1234567890_1234567890_1234567890"
                        + "1234567890_1234567890_1234567890_1234567890"
                        + "1234567890_1234567890_1234567890_1234567890";
        byte[] subjectDn = GostDnParser.encodeDn("CN=LongCert,O=Org,OU=" + longOu + ",C=RU");
        GostCertificate longCert =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(42))
                        .sign(kp.getPrivate());

        String out = CertificateTextFormatter.format(longCert);
        // Полный DN (без усечения) содержит и CN, и весь длинный OU
        assertTrue(out.contains("LongCert"), "CN должен быть в DN");
        assertTrue(out.contains(longOu), "длинный OU не должен быть усечён");
        assertFalse(
                longCert.toString().contains(longOu),
                "toString() должен усекать длинный DN — контраст с форматтером");
    }

    @Test
    @DisplayName("Самоподписанный сертификат — явная пометка")
    void selfSignedLabel() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Self,O=Org,C=RU");
        GostCertificate self =
                GostCertificateBuilder.create(PARAMS, dn)
                        .issuerDn(dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(1))
                        .basicConstraints(true, 0)
                        .sign(kp.getPrivate());

        String out = CertificateTextFormatter.format(self);
        assertTrue(out.contains("Самоподписанный: да"), "самоподписанный — явная пометка");
    }

    @Test
    @DisplayName("Без расширений — секция Расширения тоже должна быть")
    void minimalCertHasExtensionsSection() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=Minimal,O=Org,C=RU");
        GostCertificate minimal =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(1))
                        .sign(kp.getPrivate());

        String out = CertificateTextFormatter.format(minimal);
        assertTrue(out.contains("Расширения"), "секция расширений должна быть");
        // Не должно падать — пустой сертификат корректен.
    }

    @Test
    @DisplayName("OCSP-ответ (stapled) — строка факта, без сырых байт")
    void ocspStapledShowsPresence() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = GostDnParser.encodeDn("CN=OcspCert,O=Org,C=RU");
        GostCertificate cert =
                GostCertificateBuilder.create(PARAMS, dn)
                        .publicKey(kp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("21010101000000Z")
                        .serial(BigInteger.valueOf(1))
                        .sign(kp.getPrivate());
        cert.setOcspResponse(new byte[100]);

        String out = CertificateTextFormatter.format(cert);
        assertTrue(out.contains("OCSP-ответ"), "заголовок OCSP");
        assertTrue(out.contains("присутствует (100 байт)"), "факт и размер");
        assertFalse(out.contains("30"), "hex-байты OCSP не должны утекать в вывод");
    }

    @Test
    @DisplayName("Unknown critical extension — предупреждение")
    void unknownCriticalWarning() {
        // unknownCritical проставляется только если в сертификате реально есть такое расширение.
        // Тест-объект без такого расширения: проверяем, что для обычного сертификата
        // этого предупреждения нет.
        String out = CertificateTextFormatter.format(fullCert);
        assertFalse(
                out.contains("неизвестное критичное расширение"),
                "обычный сертификат без unknown critical ext. не должен иметь предупреждение");
    }

    @Test
    @DisplayName("Все поля с русскими метками")
    void fieldLabelsAreRussian() {
        String out = CertificateTextFormatter.format(fullCert);

        assertFalse(out.contains("Version:"), "не английскими метками");
        assertTrue(out.contains("Версия"), "русская метка Версия");
        assertTrue(out.contains("Серийный номер"), "русская метка серийного номера");
        assertTrue(out.contains("Расширения"), "русская метка расширений");
    }

    // ========================================================================
    // CertificatePolicies — отображение CPS
    // ========================================================================

    private static GostCertificate certWithCps() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=CpsCert Test");
        byte[] issuerDn = GostDnParser.encodeDn("CN=CpsCA Test");
        String cpsUri = "https://ca.example.com/cps/russian-ca.html";
        return GostCertificateBuilder.create(PARAMS, subjectDn)
                .issuerDn(issuerDn)
                .publicKey(kp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("21010101000000Z")
                .serial(BigInteger.valueOf(7777))
                .certificatePolicyInfos(
                        new CertificatePolicy(GostOids.POLICY_KC1, cpsUri),
                        new CertificatePolicy(GostOids.POLICY_KC2))
                .sign(kp.getPrivate());
    }

    @Test
    @DisplayName("CertificatePolicies: отображение CPS URI в текстовом выводе")
    void certificatePoliciesShowsCpsUri() {
        String out = CertificateTextFormatter.format(certWithCps());

        assertTrue(out.contains("Certificate Policies"), "заголовок Certificate Policies");
        assertTrue(
                out.contains("class-kc1") || out.contains("1.2.643.100.113.1"), "OID политики KC1");
        assertTrue(
                out.contains("CPS: https://ca.example.com/cps/russian-ca.html"),
                "CPS URI должен отображаться");
        assertTrue(
                out.contains("class-kc2") || out.contains("1.2.643.100.113.2"),
                "OID политики KC2 без CPS");
    }

    @Test
    @DisplayName("hex(): побайтовое совпадение с HexFormat")
    void hexVsHexFormat() {
        HexFormat hf = HexFormat.of();
        HexFormat hfDelim = HexFormat.of().withDelimiter(":");
        byte[][] cases = {
            new byte[0],
            new byte[] {0x00},
            new byte[] {(byte) 0xFF},
            new byte[] {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF},
            "Hello, ГОСТ!".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        };
        for (byte[] data : cases) {
            assertEquals(hf.formatHex(data), CertificateTextFormatter.hex(data, false), "без дел.");
            assertEquals(hfDelim.formatHex(data), CertificateTextFormatter.hex(data, true), "с :");
        }
    }
}
