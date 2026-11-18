package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Разбор настоящих CRL чужих кодировщиков.
 *
 * <p>Кросс-валидация проверяет только путь «библиотека -> openssl»: все её CRL выпускает
 * {@link GostCrlBuilder}. Здесь же строгий разбор получает CRL, закодированные не нами.</p>
 *
 * <p>Подлинную подпись библиотека проверяет только у CRL на ГОСТ Р 34.10-2012 с известным
 * издателем (ИнфоТеКС). CRL с другими алгоритмами (ГОСТ-2001/34.11-94, RSA) и без найденного
 * издателя переподписываются тестовым ключом: берётся настоящий {@code tbsCertList} чужого
 * кодировщика, подпись заменяется. Это проверка формата разбора, а не приёма CRL этого УЦ.
 * Продакшен-код при этом не меняется, инвариант «сначала подпись, потом разбор» сохраняется.</p>
 */
@DisplayName("GostCrl: настоящие CRL чужих кодировщиков")
class ForeignCrlCompatibilityTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static KeyPair testKeyPair;

    @BeforeAll
    static void setUp() {
        testKeyPair = KeyGenerator.generateKeyPair(PARAMS);
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream in = ForeignCrlCompatibilityTest.class.getResourceAsStream(name)) {
            assertNotNull(in, "Нет тестового ресурса " + name);
            return in.readAllBytes();
        }
    }

    /** Заменяет подпись чужого CRL подписью тестового ключа, сохраняя его tbsCertList как есть. */
    private static byte[] resign(byte[] foreignCrl) {
        byte[][] parts = DerCodec.parseSequenceContents(foreignCrl, 0);
        return RawCrlTestSupport.sign(testKeyPair.getPrivate(), PARAMS, parts[0], new byte[0]);
    }

    /** Разбор без проверки сроков: чужие CRL со временем истекают. */
    private static GostCrl parseResigned(String name) throws Exception {
        GostCrl crl = new GostCrl(resign(resource(name)));
        crl.verifySignatureAndParse(testKeyPair.getPublic(), false);
        return crl;
    }

    @Test
    @DisplayName(
            "ИнфоТеКС: настоящая подпись ГОСТ-2012, cRLNumber 16 октетов, AKI, чужое расширение")
    void infotecsRealSignature() throws Exception {
        GostCertificate issuer =
                GostCertificate.fromDer(resource("/infotecs_test/infotecs-test-ca.der"));
        GostCrl crl = new GostCrl(resource("/infotecs_test/infotecs-test.crl"));
        // Срок CRL истекает, поэтому публичный verify не используем; из сертификата издателя
        // берём только открытый ключ (его срок тоже ограничен)
        crl.verifySignatureAndParse(issuer.getPublicKey(), false);

        assertEquals(
                new BigInteger("2473342839657750735926009234719047681"),
                crl.getCrlNumber(),
                "cRLNumber в 16 октетов должен приниматься");
        assertArrayEquals(
                HexFormat.of()
                        .parseHex("8b66b272bea0b710531102f70979575 77d985332".replace(" ", "")),
                crl.getAuthorityKeyIdentifier(),
                "keyIdentifier AKI");
        assertTrue(
                crl.getIssuerDn().contains("Тестовый УЦ ИнфоТеКС"),
                "DN издателя с кириллицей и street должен читаться");
        assertTrue(crl.getRevokedCertificates().isEmpty(), "В CRL нет отозванных сертификатов");
        assertFalse(crl.isIdp(), "В CRL нет IssuingDistributionPoint");
    }

    @Test
    @DisplayName("ГУЦ Минцифры: настоящая подпись ГОСТ-2012, 40 записей, AKI с authorityCertIssuer")
    void mintsifryGucRealSignature() throws Exception {
        GostCertificate issuer =
                GostCertificate.fromDer(resource("/foreign_crl/mintsifry-guc2022-ca.crt"));
        GostCrl crl = new GostCrl(resource("/foreign_crl/mintsifry-guc2022.crl"));
        // Срок CRL ограничен (около месяца), поэтому публичный verify однажды уронит тест
        crl.verifySignatureAndParse(issuer.getPublicKey(), false);

        assertEquals(40, crl.getRevokedCertificates().size(), "Сорок записей об отзыве");
        assertArrayEquals(
                HexFormat.of().parseHex("c91358b14ca7623a7ed23f3ca6e7147c9d70a386"),
                crl.getAuthorityKeyIdentifier(),
                "keyIdentifier; рядом в AKI стоят authorityCertIssuer и serial");
        assertTrue(crl.getIssuerDn().contains("Минцифры России"), "DN издателя читается");
        assertFalse(crl.isIdp(), "IDP в этом CRL нет");
    }

    @Test
    @DisplayName(
            "Сертум-Про: настоящая подпись ГОСТ-2012, 4594 записи с reasonCode и расширения Microsoft")
    void sertumProRealSignatureWithEntries() throws Exception {
        GostCertificate issuer =
                GostCertificate.fromDer(resource("/foreign_crl/sertum-pro-q2025-ca.cer"));
        GostCrl crl = new GostCrl(resource("/foreign_crl/sertum-pro-q2025.crl"));
        // Срок CRL — несколько дней, поэтому публичный verify однажды уронит тест
        crl.verifySignatureAndParse(issuer.getPublicKey(), false);

        assertEquals(4594, crl.getRevokedCertificates().size(), "Число записей об отзыве");
        assertEquals(new BigInteger("1552"), crl.getCrlNumber(), "cRLNumber");
        assertArrayEquals(
                HexFormat.of().parseHex("97794bd75fe1651ec78ac4a608448d6c23a91bfd"),
                crl.getAuthorityKeyIdentifier(),
                "keyIdentifier совпадает с SKI издателя");
        byte[] firstSerial = HexFormat.of().parseHex("132F5808F8E10AAF4351E5F7019AE3D0");
        assertTrue(crl.isRevoked(firstSerial), "Первая запись найдена по серийному номеру");
        assertEquals(ReasonCode.SUPERSEDED, crl.getReason(firstSerial), "reasonCode первой записи");
        assertFalse(crl.isIdp(), "IDP в этом CRL нет");
    }

    @Test
    @DisplayName("OpenSSL (ГОСТ-провайдер): настоящая подпись, critical IDP, записи с reasonCode")
    void openSslGostIdpRealSignature() throws Exception {
        // CRL выпущен командой openssl ca -gencrl (чужой кодировщик) с critical IDP
        // (fullName + onlyuser) и reasonCode в записях; ключ тестового УЦ не сохранён
        GostCertificate issuer =
                GostCertificate.fromDer(resource("/foreign_crl/openssl-gost-idp-ca.der"));
        GostCrl crl = new GostCrl(resource("/foreign_crl/openssl-gost-idp.crl"));
        crl.verifySignatureAndParse(issuer.getPublicKey(), false);

        assertTrue(crl.isIdp(), "IDP присутствует");
        assertTrue(crl.isOnlyContainsUserCerts(), "onlyContainsUserCerts");
        assertArrayEquals(
                new String[] {"http://crl.example.test/spike.crl"},
                crl.getIdpDistributionPointUris(),
                "URI distributionPoint");
        assertEquals(2, crl.getRevokedCertificates().size(), "Две записи об отзыве");
        assertEquals(ReasonCode.KEY_COMPROMISE, crl.getReason(new byte[] {0x01}), "reasonCode 1");
        assertEquals(ReasonCode.SUPERSEDED, crl.getReason(new byte[] {0x02}), "reasonCode 2");
        assertArrayEquals(
                HexFormat.of()
                        .parseHex("0493ca9f26d6b4841c7cd1421497 74f6a36214f2".replace(" ", "")),
                crl.getAuthorityKeyIdentifier(),
                "keyIdentifier AKI");
    }

    @Test
    @DisplayName("Казначейство ГОСТ-2001: critical IDP с distributionPoint и записи с reasonCode")
    void roskaznaGost2001() throws Exception {
        GostCrl crl = parseResigned("/foreign_crl/ucfk.crl");

        assertTrue(crl.isIdp(), "IDP присутствует");
        assertArrayEquals(
                new String[] {"http://crl.roskazna.ru/crl/ucfk.crl"},
                crl.getIdpDistributionPointUris(),
                "URI distributionPoint");
        assertFalse(crl.isOnlyContainsUserCerts() || crl.isOnlyContainsCACerts(), "Флагов нет");

        List<RevokedEntry> entries = crl.getRevokedCertificates();
        assertEquals(4, entries.size(), "Четыре записи об отзыве");
        assertEquals(
                ReasonCode.SUPERSEDED,
                entries.get(0).reason(),
                "reasonCode первой записи (рядом invalidityDate, non-critical)");
        assertEquals(
                ReasonCode.CESSATION_OF_OPERATION,
                entries.get(1).reason(),
                "reasonCode второй записи");
        assertNotNull(crl.getAuthorityKeyIdentifier(), "AKI разобран");
    }

    @Test
    @DisplayName("Казначейство ГОСТ-2012: записи с reasonCode и invalidityDate")
    void roskaznaGost2012() throws Exception {
        // Сертификат издателя (AKI C0:D6:D6:0A...) не найден: переподпись, как у остальных
        GostCrl crl = parseResigned("/foreign_crl/ucfk_gost12.crl");

        assertEquals(2, crl.getRevokedCertificates().size(), "Две записи об отзыве");
        assertFalse(crl.isIdp(), "IDP в этом CRL нет");
        assertNotNull(crl.getCrlNumber(), "cRLNumber разобран");
    }

    @Test
    @DisplayName("Let's Encrypt R11: IDP в порядке A0, затем 81 (distributionPoint, onlyUserCerts)")
    void letsEncryptUserCertsPartition() throws Exception {
        GostCrl crl = parseResigned("/foreign_crl/letsencrypt-r11.crl");

        assertTrue(crl.isIdp(), "IDP присутствует");
        assertTrue(crl.isOnlyContainsUserCerts(), "onlyContainsUserCerts");
        assertArrayEquals(
                new String[] {"http://r11.c.lencr.org/1.crl"},
                crl.getIdpDistributionPointUris(),
                "URI distributionPoint");
        assertTrue(crl.getRevokedCertificates().isEmpty(), "Записей нет");
    }

    @Test
    @DisplayName("Let's Encrypt ISRG Root X1: IDP onlyContainsCACerts без distributionPoint")
    void letsEncryptCaCertsPartition() throws Exception {
        GostCrl crl = parseResigned("/foreign_crl/letsencrypt-x1.crl");

        assertTrue(crl.isIdp(), "IDP присутствует");
        assertTrue(crl.isOnlyContainsCACerts(), "onlyContainsCACerts");
        assertFalse(crl.isIdpDistributionPointPresent(), "distributionPoint нет");
        assertEquals(2, crl.getRevokedCertificates().size(), "Две записи об отзыве");
    }
}
