package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("GostPkcs7.formatText: человекочитаемый дамп контейнера .p7b")
class GostPkcs7FormatTextTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate cert1;
    private static GostCertificate cert2;
    private static GostCertificate cert3;
    private static GostCrl crlWithRevoked;
    private static PrivateKeyParameters crlIssuerPriv;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        cert1 = newCert("Cert One", 1001);
        cert2 = newCert("Cert Two", 1002);
        cert3 = newCert("Cert Three", 1003);
        buildCrlWithRevoked();
    }

    private static GostCertificate newCert(String cn, int serial) {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        return CmsTestUtils.createSelfSignedCertWithDn(
                kp.getPrivate(), kp.getPublic(), BigInteger.valueOf(serial), cn);
    }

    private static void buildCrlWithRevoked() {
        KeyPair crlKp = KeyGenerator.generateKeyPair(PARAMS);
        crlIssuerPriv = crlKp.getPrivate();
        byte[] crlIssuerDn = GostDnParser.encodeDn("CN=Test CRL Issuer,O=Org,C=RU");
        byte[] dummySerial = BigInteger.valueOf(12345).toByteArray();
        byte[] crlDer =
                GostCrlBuilder.create(crlIssuerDn)
                        .addRevoked(dummySerial, "260701120000Z")
                        .nextUpdate("270601120000Z")
                        .sign(crlKp.getPrivate());
        crlWithRevoked = GostCrl.fromDer(crlDer);
    }

    @Test
    @DisplayName("formatText с одним сертификатом без CRL")
    void formatSingleCert() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1);
        String out = GostPkcs7.formatText(p7b);

        assertTrue(out.contains("=== PKCS#7 / .p7b контейнер"), "заголовок контейнера");
        assertTrue(out.contains("ВНИМАНИЕ: данные не верифицированы"), "дисклеймер первой строкой");
        assertTrue(out.contains("Сертификатов: 1"), "один сертификат");
        assertTrue(out.contains("Cert One"), "subject DN");
    }

    @Test
    @DisplayName("formatText с несколькими сертификатами — все в дампе")
    void formatMultipleCerts() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1, cert2, cert3);
        String out = GostPkcs7.formatText(p7b);

        assertTrue(out.contains("Сертификатов: 3"), "три сертификата");
        assertTrue(out.contains("Сертификат [0]"), "индекс 0");
        assertTrue(out.contains("Сертификат [1]"), "индекс 1");
        assertTrue(out.contains("Сертификат [2]"), "индекс 2");
    }

    @Test
    @DisplayName("formatText с CRL — метаданные CRL и строка-заглушка")
    void formatWithCrl() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(crlWithRevoked), cert1);
        String out = GostPkcs7.formatText(p7b);

        assertTrue(out.contains("Сертификатов: 1, CRL: 1"), "один сертификат, один CRL");
        assertTrue(out.contains("CRL [0]"), "индекс CRL");
        assertTrue(out.contains("Test CRL Issuer"), "CRL issuer DN");
        assertTrue(out.contains("This Update:"), "thisUpdate");
        assertTrue(out.contains("Next Update:"), "nextUpdate");
        // CRL в формате без verify() — строка-заглушка вместо серийников.
        assertTrue(
                out.contains("доступны после криптографической проверки"),
                "строка-заглушка о необходимости verify()");
        assertDoesNotThrow(
                () -> GostPkcs7.formatText(p7b),
                "не должен падать с IllegalStateException при попытке доступа к отозванным");
    }

    @Test
    @DisplayName("formatText с несколькими CRL — все пронумерованы")
    void formatMultipleCrls() throws PkixException {
        byte[] crlIssuerDn2 = GostDnParser.encodeDn("CN=Second CRL Issuer");
        byte[] crlDer2 =
                GostCrlBuilder.create(crlIssuerDn2).nextUpdate("270601120000Z").sign(crlIssuerPriv);
        GostCrl crl2 = GostCrl.fromDer(crlDer2);

        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(crlWithRevoked, crl2), cert1);
        String out = GostPkcs7.formatText(p7b);

        assertTrue(out.contains("CRL [0]"), "первый CRL");
        assertTrue(out.contains("CRL [1]"), "второй CRL");
        assertTrue(out.contains("Test CRL Issuer"), "первый CRL — issuer");
        assertTrue(out.contains("Second CRL Issuer"), "второй CRL — issuer");
    }

    @Test
    @DisplayName("PEM-вход (-----BEGIN PKCS7-----) — formatText корректно парсит")
    void formatFromPem() throws PkixException {
        byte[] der = GostPkcs7.buildCertsOnly(cert1, cert2);
        byte[] pem = org.rssys.gost.pkix.cert.GostPemUtils.toPem(der, "PKCS7").getBytes();

        String out = GostPkcs7.formatText(pem);
        assertTrue(out.contains("Сертификатов: 2"), "PEM-вход распарсился");
    }

    @Test
    @DisplayName("Самоподписанный сертификат — помечен в дампе")
    void selfSignedLabel() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(cert1);
        String out = GostPkcs7.formatText(p7b);
        assertTrue(out.contains("Самоподписанный: да"), "самоподписанный в дампе");
    }

    @Test
    @DisplayName("buildCertsOnly -> formatText: round-trip, все поля на месте")
    void roundTrip() throws PkixException {
        byte[] p7b = GostPkcs7.buildCertsOnly(List.of(crlWithRevoked), cert1, cert2);
        String out = GostPkcs7.formatText(p7b);

        // Заголовок и дисклеймер
        assertTrue(out.startsWith("=== PKCS#7"));
        assertTrue(out.contains("ВНИМАНИЕ"));

        // Сертификаты
        assertTrue(out.contains("Сертификат [0]"));
        assertTrue(out.contains("Сертификат [1]"));
        assertTrue(out.contains("Cert One"));
        assertTrue(out.contains("Cert Two"));

        // Секция расширений сертификата
        assertTrue(out.contains("Расширения"));
        assertTrue(out.contains("Basic Constraints"));

        // CRL
        assertTrue(out.contains("CRL [0]"));
        assertTrue(out.contains("Test CRL Issuer"));
    }

    // ========================================================================
    // Negatively-tested: fail-closed
    // ========================================================================

    @Test
    @DisplayName("Не signedData contentType -> fail-closed PkixException")
    void wrongContentType() {
        byte[] bogus = CmsContentInfo.encode(GostOids.PKCS7_DATA, DerCodec.encodeInteger(1));
        assertThrows(
                PkixException.class,
                () -> GostPkcs7.formatText(bogus),
                "не-signedData должен отклоняться fail-closed");
    }

    @Test
    @DisplayName("null/пустой вход -> PkixException")
    void nullAndEmpty() {
        assertThrows(PkixException.class, () -> GostPkcs7.formatText(null));
        assertThrows(PkixException.class, () -> GostPkcs7.formatText(new byte[0]));
    }

    @Test
    @DisplayName("Случайные байты -> PkixException (не unchecked)")
    void randomBytes() {
        assertThrows(
                PkixException.class,
                () -> GostPkcs7.formatText(new byte[] {0x01, 0x02, 0x03, 0x04}),
                "мусорные байты: ожидаем PkixException, а не крах");
    }

    @Test
    @DisplayName("formatText на переполненном .p7b (>MAX_P7B_CERTS) -> PkixException (fail-closed)")
    void exceedMaxCertsFailsClosed() {
        // buildCertsOnly сам блокирует создание такого входа, поэтому переполненный
        // контейнер собираем вручную через сырой DER и проверяем именно formatText().
        byte[] oversized = buildRawP7bWithCertCopies(cert1, CmsConstants.MAX_P7B_CERTS + 1);

        assertThrows(
                PkixException.class,
                () -> GostPkcs7.formatText(oversized),
                "formatText должен fail-closed при числе сертификатов > MAX_P7B_CERTS");
    }

    /** Собирает certs-only .p7b с N копиями одного cert DER — минуя защиту buildCertsOnly. */
    private static byte[] buildRawP7bWithCertCopies(GostCertificate cert, int copies) {
        byte[] certDer = cert.getEncoded();
        byte[][] certDers = new byte[copies][];
        java.util.Arrays.fill(certDers, certDer);
        byte[] certsField = DerCodec.encodeContextConstructed(0, DerCodec.concat(certDers));

        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgs = DerCodec.encodeSetOf(new byte[0][]);
        byte[] encapContent = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.PKCS7_DATA));
        byte[] emptySignerInfos = DerCodec.encodeSetOf(new byte[0][]);
        byte[] signedData =
                DerCodec.encodeSequence(
                        version, digestAlgs, encapContent, certsField, emptySignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
    }
}
