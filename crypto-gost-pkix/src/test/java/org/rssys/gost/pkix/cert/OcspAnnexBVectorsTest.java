package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Примеры приложения В Р 1323565.1.059-2024: три сертификата, подписанный запрос и ответ
 * службы OCSP. Внешний эталон для разбора, подписей и вычисления CertID.
 *
 * <p>Текст нормы взят в виде, пригодном для чтения машиной, и содержит ошибки распознавания
 * (путаются {@code 1}, {@code l}, {@code I}, {@code i}, {@code 0}, {@code O}). Ниже в
 * константах Base64 исправлены именно они; нумерация символов — с нуля в Base64-строке блока,
 * склеенной без переносов. Верность исправлений подтверждена тем, что подписи всех пяти
 * объектов сходятся, а ключи совпадают с напечатанными в приложении значениями.
 * <ul>
 *   <li>Сертификат УЦ, символ 90: {@code l -> I} (notBefore: {@code 2111029p4959Z} ->
 *       {@code 211102204959Z}).
 *   <li>Сертификат УЦ, символ 296: {@code I -> i} (длина SEQUENCE расширений: {@code 0x20} ->
 *       {@code 0x88}).
 *   <li>Проверяемый сертификат, символ 534: {@code 1 -> l} (значение подписи, байт
 *       {@code 0xbd} -> {@code 0xb9}).
 *   <li>Сертификат службы, символ 255: {@code 0 -> O} и символ 264: {@code O -> 0} (координата Y
 *       открытого ключа: байты {@code 0x74} -> {@code 0x4e} и {@code 0x39} -> {@code 0xd1});
 *       итоговое значение совпадает с напечатанным {@code Yq}.
 *   <li>Сертификат службы, символ 373: {@code l -> 1} (OID BasicConstraints: длина {@code 0x02} ->
 *       {@code 0x03}, т.е. {@code 2.5.29.19}).
 *   <li>Сертификат службы, символ 458: {@code l -> 1} (имя УЦ в AuthorityKeyIdentifier:
 *       {@code ExaipleCA} -> {@code ExampleCA}).
 *   <li>Запрос и ответ: Base64 в норме напечатан верно (хвост ответа {@code ===} читается как
 *       {@code =}). Ошибки есть только в шестнадцатеричных дампах ASN.1: {@code FI -> F1},
 *       {@code El -> E1}, {@code DI -> D1}, {@code ID -> 1D}; тест сверяет CertID с
 *       исправленными значениями из дампа.
 * </ul>
 */
@DisplayName("Р 1323565.1.059-2024, приложение В: примеры запроса и ответа OCSP")
class OcspAnnexBVectorsTest {

    private static final String CA_CERT_BASE64 =
            "MIIBsjCCAV+gAwIBAgIIUgEF/cyNL7swCgYIKoUDBwEBAwIwFDESMBAGA1UEAxMJRXhhbXBsZUNB"
                    + "MB4XDTIxMTEwMjIwNDk1OVoXDTQyMTAyODIwNDk1OVowFDESMBAGA1UEAxMJRXhhbXBsZUNBMGgw"
                    + "IQYIKoUDBwEBAQEwFQYJKoUDBwECAQEBBggqhQMHAQECAgNDAARABZaQRjw5FoKjKJeq+PRoojqv"
                    + "bSLT60RKeaiHIhqGc7qre7O92ridPqFMMHGuGCAiIk4K550YBCWWg+tNhIFh5aOBizCBiDAdBgNV"
                    + "HQ4EFgQUyfZzqnFI6AzP3Opl5hu3/Wi5/iYwDgYDVR0PAQH/BAQDAgH+MBIGA1UdEwEB/wQIMAYB"
                    + "Af8CAQEwQwYDVR0jBDwwOoAUyfZzqnFI6AzP3Opl5hu3/Wi5/iahGKQWMBQxEjAQBgNVBAMTCUV4"
                    + "YW1wbGVDQYIIUgEF/cyNL7swCgYIKoUDBwEBAwIDQQAtaycJR+WUCul17CKh4ah1AMI9AIGE6yEA"
                    + "XDZt/DqaPA1ILgAi6Zhu1dTcwrKdh2+b4I8Es4ORITIsizpTVUgL";

    private static final String TESTED_CERT_BASE64 =
            "MIIBsDCCAV2gAwIBAgIBAjAKBggqhQMHAQEDAjAUMRIwEAYDVQQDEwlFeGFtcGxlQ0EwHhcNMjEx"
                    + "MTI4MTQ0NDM2WhcNNDIxMDI4MTQ0NDM2WjAUMRIwEAYDVQQDEwlTZXJ2ZXJUTFMwXjAXBggqhQMH"
                    + "AQEBATALBgkqhQMHAQIBAQIDQwAEQCbq3kYBdV4pNi3Xt2MX7uQ0g4wA7XU8M3JZoIWfpPDUmBzU"
                    + "Lffy1gjM67tbFEPWq1ihb7wSwRktmPm/5tyINuWjgZowgZcwHQYDVR0OBBYEFICwaDpHKbAsRWB8"
                    + "12hG6blB/VPWMA4GA1UdDwEB/wQEAwIB/jATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8E"
                    + "AjAAMEMGA1UdIwQ8MDqAFMn2c6pxSOgMz9zqZeYbt/1ouf4moRikFjAUMRIwEAYDVQQDEwlFeGFt"
                    + "cGxlQ0GCCFIBBf3MjS+7MAoGCCqFAwcBAQMCA0EAL9OWI7BTH4csA0gZg+dKmBsZWrMrTgSgPv7G"
                    + "J7l826YOm3PmBUtC2+DQT8ghZQGcdLk14j3LQ7vpK/q5eLimvw==";

    private static final String RESPONDER_CERT_BASE64 =
            "MIIBsjCCAV+gAwIBAgIBATAKBggqhQMHAQEDAjAUMRIwEAYDVQQDEwlFeGFtcGxlQ0EwHhcNMjEx"
                    + "MTI4MTQ0NDU4WhcNNDIxMDI4MTQ0NDU4WjAWMRQwEgYDVQQDEwtPQ1NQU2VydmljZTBeMBcGCCqF"
                    + "AwcBAQEBMAsGCSqFAwcBAgEBAgNDAARA+xPUdwMP8NtarpmT89Puzav9rQ40Cq8I1ypZhnskujBH"
                    + "Tjh7yAmElARwrkwikQ/jGMTLjAROKHFnn3VV0QCQHqOBmjCBlzAdBgNVHQ4EFgQUJoSrectbwJGG"
                    + "OPk3ry/VrNz1C+gwDgYDVR0PAQH/BAQDAgH+MBMGA1UdJQQMMAoGCCsGAQUFBwMJMAwGA1UdEwEB"
                    + "/wQCMAAwQwYDVR0jBDwwOoAUyfZzqnFI6AzP3Opl5hu3/Wi5/iahGKQWMBQxEjAQBgNVBAMTCUV4"
                    + "YW1wbGVDQYIIUgEF/cyNL7swCgYIKoUDBwEBAwIDQQAxYabb+sAabCgl5bCrdPUhsDpRZ3/lHazI"
                    + "FiBpVPB+5iN5vD/sX0JFYAsizF0TjxWEXb1PDSdH/qJx9Zmd2cCo";

    private static final String REQUEST_BASE64 =
            "MIHNMHigAwIBAKEYpBYwFDESMBAGA1UEAxMJU2VydmVyVExTMFcwVTBTMAoGCCqFAwcBAQICBCDm"
                    + "TWrxEdpyazvWe2aRUqVf2Z+PMdsu82G/wFpi+xHH7gQgDSOCRrllRSM1K9NzrZfbs/Q0WMWHHA9K"
                    + "ae4TdfOdU7sCAQKgUTBPMAoGCCqFAwcBAQMCA0EAx/wN3I094SsNT472ZFZGeu3RZhc2F54hMcaD"
                    + "oqulI6JoX+hNA+fCzQgHuPNGZm0FdsDV52AdWUkJRVLElada0w==";

    private static final String RESPONSE_BASE64 =
            "MIIBCQoBAKCCAQIwgf8GCSsGAQUFBzABAQSB8TCB7jCBnKADAgEAoRgwFjEUMBIGA1UEAxMLT0NT"
                    + "UFNlcnZpY2UYDzIwMjIwNDIxMTIwMDAwWjBqMGgwUzAKBggqhQMHAQECAgQg5k1q8RHacms71ntm"
                    + "kVKlX9mfjzHbLvNhv8BaYvsRx+4EIA0jgka5ZUUjNSvTc62X27P0NFjFhxwPSmnuE3XznVO7AgEC"
                    + "gAAYDzIwMjIwNDIxMTIwMDAwWjAKBggqhQMHAQEDAgNBAPmtB/qwuYXzRz1zAYBszxb4CcfQTS9E"
                    + "grLy5ODTIkuMaF/oTQPnws0IB7jzRmZtBXbA1edgHVlJCUVSxJWnWtM=";

    /**
     * Закрытые и открытые ключи приложения В напечатаны от младшего байта к старшему; суффикс
     * {@code 16} в конце каждого значения — основание системы счисления, не данные.
     *
     * <p>Ключи лежат на разных кривых: у УЦ параметры из сертификата 1.2.643.7.1.2.1.1.1, у
     * проверяемого сертификата и службы — 1.2.643.7.1.2.1.1.2, поэтому {@code d·G} считается на
     * кривой самого сертификата.
     */
    private static final String TESTED_D_LE =
            "62DD7FCD96B4028493A7F78CFC65E59ED959AFA77B83E0055E8B89E27CE9E603";

    private static final String TESTED_X_LE =
            "26EADE4601755E29362DD7B76317EEE434838C00ED753C337259A0859FA4F0D4";

    private static final String TESTED_Y_LE =
            "981CD42DF7F2D608CCEBBB5B1443D6AB58A16FBC12C1192D98F9BFE6DC8836E5";
    private static final String RESPONDER_D_LE =
            "84D9AE62ECC2A97960068A9EE61724593FCE2B6A5FE54506064528D22B6E844C";
    private static final String RESPONDER_X_LE =
            "FB13D477030FF0DB5AAE9993F3D3EECDABFDAD0E340AAF08D72A59867B24BA30";
    private static final String RESPONDER_Y_LE =
            "474E387BC80984940470AE4C22910FE318C4CB8C044E2871679F7555D100901E";
    private static final String CA_D_LE =
            "9C85418F6353B11D7A8F7DC831CA6A82A45C2D9EAC2273DBAF3351A448C36427";
    private static final String CA_X_LE =
            "059690463C391682A32897AAF8F468A23AAF6D22D3EB444A79A887221A8673BA";
    private static final String CA_Y_LE =
            "AB7BB3BDDAB89D3EA14C3071AE182022224E0AE79D1804259683EB4D848161E5";

    /** CertID из дампов ASN.1 запроса (В.2) и ответа (В.3) с исправленными ошибками распознавания. */
    private static final String CERT_ID_NAME_HASH =
            "E64D6AF111DA726B3BD67B669152A55FD99F8F31DB2EF361BFC05A62FB11C7EE";

    private static final String CERT_ID_KEY_HASH =
            "0D238246B9654523352BD373AD97DBB3F43458C5871C0F4A69EE1375F39D53BB";

    private static final HexFormat HEX = HexFormat.of();

    private static GostCertificate caCert;
    private static GostCertificate testedCert;
    private static GostCertificate responderCert;
    private static byte[] requestDer;
    private static byte[] responseDer;

    @BeforeAll
    static void setUp() {
        Base64.Decoder decoder = Base64.getDecoder();
        caCert = new GostCertificate(decoder.decode(CA_CERT_BASE64));
        testedCert = new GostCertificate(decoder.decode(TESTED_CERT_BASE64));
        responderCert = new GostCertificate(decoder.decode(RESPONDER_CERT_BASE64));
        requestDer = decoder.decode(REQUEST_BASE64);
        responseDer = decoder.decode(RESPONSE_BASE64);
    }

    @Test
    @DisplayName("В.1: сертификаты разбираются, подписи УЦ сходятся")
    void certificatesParseAndChain() {
        assertEquals("CN=ExampleCA", caCert.getSubjectDn(), "Имя УЦ");
        assertEquals("CN=ServerTLS", testedCert.getSubjectDn(), "Имя проверяемого сертификата");
        assertEquals("CN=OCSPService", responderCert.getSubjectDn(), "Имя службы OCSP");
        assertArrayEquals(new byte[] {0x02}, testedCert.getSerialNumber(), "Серийный номер");
        assertArrayEquals(new byte[] {0x01}, responderCert.getSerialNumber(), "Серийный номер");

        assertTrue(caCert.verifySignature(caCert.getPublicKey()), "Сертификат УЦ самоподписан");
        assertTrue(
                testedCert.verifySignature(caCert.getPublicKey()),
                "Проверяемый сертификат подписан УЦ");
        assertTrue(
                responderCert.verifySignature(caCert.getPublicKey()),
                "Сертификат службы подписан УЦ");
        assertTrue(responderCert.isOcspSigning(), "Сертификат службы имеет id-kp-OCSPSigning");
    }

    @Test
    @DisplayName("В.1: открытые ключи сертификатов совпадают с напечатанными в приложении")
    void publicKeysMatchPrinted() {
        assertSpkiKeyBits(caCert, CA_X_LE, CA_Y_LE);
        assertSpkiKeyBits(testedCert, TESTED_X_LE, TESTED_Y_LE);
        assertSpkiKeyBits(responderCert, RESPONDER_X_LE, RESPONDER_Y_LE);
    }

    @Test
    @DisplayName("В.1: открытый ключ Q = d·G на кривой сертификата совпадает с напечатанным")
    void privateKeysDeriveToPrintedPublicKeys() {
        assertDerivesTo(caCert, CA_D_LE, CA_X_LE, CA_Y_LE);
        assertDerivesTo(testedCert, TESTED_D_LE, TESTED_X_LE, TESTED_Y_LE);
        assertDerivesTo(responderCert, RESPONDER_D_LE, RESPONDER_X_LE, RESPONDER_Y_LE);
    }

    @Test
    @DisplayName("CertID: хэши от имени и ключа УЦ совпадают со значениями из дампов В.2 и В.3")
    void certIdHashesMatchAnnex() {
        // issuerKeyHash считается от 04 40 || x || y, без октета неиспользуемых бит
        assertEquals(
                CERT_ID_NAME_HASH,
                HEX.formatHex(CertIdHasher.hashIssuerName(caCert)).toUpperCase(Locale.ROOT),
                "issuerNameHash от DER-имени УЦ");
        assertEquals(
                CERT_ID_KEY_HASH,
                HEX.formatHex(CertIdHasher.hashIssuerPublicKey(caCert)).toUpperCase(Locale.ROOT),
                "issuerKeyHash от subjectPublicKey УЦ");
    }

    @Test
    @DisplayName("В.2: запрос подписан ключом проверяемого сертификата, CertID совпадает")
    void requestIsSignedAndCertIdMatches() throws Exception {
        GostOcspRequest request = new GostOcspRequest(requestDer);

        assertTrue(request.isSigned(), "Запрос подписан");
        request.verifySignature(testedCert.getPublicKey());
        assertTrue(request.isSignatureVerified(), "Подпись запроса проверена");
        assertThrows(
                PkixException.class,
                () -> new GostOcspRequest(requestDer).verifySignature(caCert.getPublicKey()),
                "Подпись запроса не должна проверяться ключом УЦ");

        List<CertId> certIds = request.getCertIds();
        assertEquals(1, certIds.size(), "В запросе один CertID");
        CertId certId = certIds.get(0);
        assertEquals(GostOids.DIGEST_256, certId.hashAlgOid(), "Хэш CertID — Стрибог-256");
        assertEquals(
                CERT_ID_NAME_HASH,
                HEX.formatHex(certId.issuerNameHash()).toUpperCase(Locale.ROOT),
                "issuerNameHash в запросе");
        assertEquals(
                CERT_ID_KEY_HASH,
                HEX.formatHex(certId.issuerKeyHash()).toUpperCase(Locale.ROOT),
                "issuerKeyHash в запросе");
        assertArrayEquals(testedCert.getSerialNumber(), certId.serialNumber(), "Серийный номер");
    }

    @Test
    @DisplayName("В.3: ответ подписан ключом службы, статус good, CertID совпадает")
    void responseIsSignedByResponderAndGood() throws Exception {
        GostOcspResponse response = new GostOcspResponse(responseDer);

        assertTrue(response.isSuccessful(), "Статус ответа successful");
        response.verify(responderCert.getPublicKey());
        assertThrows(
                PkixException.class,
                () -> new GostOcspResponse(responseDer).verify(caCert.getPublicKey()),
                "Подпись ответа не проверяется ключом УЦ: ответ подписан службой");
        assertEquals(
                GostOcspResponse.ResponderIdType.BY_NAME,
                response.getResponderIdType(),
                "Служба названа по имени");

        assertEquals(1, response.getResponses().size(), "В ответе одна запись");
        SingleOcspResponse single = response.getResponses().get(0);
        assertTrue(single.isGood(), "Статус сертификата good");
        assertEquals(Instant.parse("2022-04-21T12:00:00Z"), single.thisUpdate(), "thisUpdate");
        assertNull(single.nextUpdate(), "nextUpdate в примере не задан");
        assertEquals(
                CERT_ID_NAME_HASH,
                HEX.formatHex(single.issuerNameHash()).toUpperCase(Locale.ROOT),
                "issuerNameHash в ответе");
        assertEquals(
                CERT_ID_KEY_HASH,
                HEX.formatHex(single.issuerKeyHash()).toUpperCase(Locale.ROOT),
                "issuerKeyHash в ответе");
        assertArrayEquals(
                testedCert.getSerialNumber(), single.certSerialNumber(), "Серийный номер");
    }

    @Test
    @DisplayName("В.3: полная проверка ответа с сертификатом службы как недоверенным кандидатом")
    void responseVerifiesAgainstCa() throws Exception {
        // Ответ примера не несёт сертификата службы, а срок «свежести» истёк давно,
        // поэтому проверяем в окне момента выпуска ответа
        Instant produced = Instant.parse("2022-04-21T12:00:00Z");
        EvidenceFreshness freshness =
                OcspVerifier.verifyEvidence(
                        responseDer,
                        testedCert.getSerialNumber(),
                        caCert,
                        new RevocationEvidenceWindow(produced, produced),
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        List.of(responderCert));
        assertEquals(EvidenceFreshness.IN_WINDOW, freshness, "Ответ примера принимается");
    }

    private static void assertSpkiKeyBits(GostCertificate cert, String xLe, String yLe) {
        byte[] expected = HEX.parseHex("0440" + xLe.toLowerCase() + yLe.toLowerCase());
        assertArrayEquals(
                expected,
                cert.getSpkiKeyBits(),
                "subjectPublicKey = 04 40 || x || y для " + cert.getSubjectDn());
    }

    private static void assertDerivesTo(GostCertificate cert, String dLe, String xLe, String yLe) {
        // Кривая берётся из сертификата: у ключей приложения В она не одна и та же
        ECParameters params = cert.getPublicKey().getParams();
        PrivateKeyParameters priv = new PrivateKeyParameters(littleEndian(dLe), params);
        PublicKeyParameters pub = priv.derivePublicKey();
        ECPoint q = pub.getQ();
        assertEquals(littleEndian(xLe), q.getX(), "Координата x открытого ключа");
        assertEquals(littleEndian(yLe), q.getY(), "Координата y открытого ключа");
    }

    private static BigInteger littleEndian(String hex) {
        byte[] le = HEX.parseHex(hex.toLowerCase());
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }
}
