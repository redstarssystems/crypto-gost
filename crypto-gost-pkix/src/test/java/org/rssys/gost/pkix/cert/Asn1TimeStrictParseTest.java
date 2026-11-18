package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crl;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedList;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Строгий разбор ASN.1-времени (RFC 5280 §4.1.2.5): несуществующая дата отвергается, а не
 * нормализуется. Прежний разбор через {@code DateTimeFormatter} в режиме SMART молча превращал
 * 30 февраля в 28 февраля, а {@code 240000} - в начало следующих суток.
 */
@DisplayName("ASN.1 Time: строгий разбор без нормализации дат")
class Asn1TimeStrictParseTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static KeyPair keyPair;
    private static byte[] issuerDn;

    @BeforeAll
    static void setUp() {
        keyPair = KeyGenerator.generateKeyPair(PARAMS);
        issuerDn = GostDnParser.encodeDn("CN=Test CA");
    }

    private static byte[] timeTlv(int tag, String content) {
        return DerCodec.encodeTlv(tag, content.getBytes(StandardCharsets.UTF_8));
    }

    private static Instant parseDer(String content) {
        int tag =
                content.length() > 13
                        ? GostDerParser.TAG_GENERALIZED_TIME
                        : GostDerParser.TAG_UTC_TIME;
        return GostDerParser.parseTime(timeTlv(tag, content), 0);
    }

    // ------------------------------------------------------------------------
    // Существующие даты принимаются
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0} -> {1}")
    @DisplayName("Существующие даты разбираются в точный момент")
    @CsvSource({
        // граница века UTCTime: 49 -> 2049, 50 -> 1950
        "491231235959Z, 2049-12-31T23:59:59Z",
        "500101000000Z, 1950-01-01T00:00:00Z",
        // 29 февраля: високосные 2000 (делится на 400) и 2024, 2096 (делится на 4)
        "000229000000Z, 2000-02-29T00:00:00Z",
        "20240229235959Z, 2024-02-29T23:59:59Z",
        "20960229120000Z, 2096-02-29T12:00:00Z",
        // последние сутки месяцев и года
        "20230430235959Z, 2023-04-30T23:59:59Z",
        "20231231235959Z, 2023-12-31T23:59:59Z",
        "99991231235959Z, 9999-12-31T23:59:59Z",
        "00010101000000Z, 0001-01-01T00:00:00Z",
        "19700101000000Z, 1970-01-01T00:00:00Z",
        // до эпохи
        "19691231235959Z, 1969-12-31T23:59:59Z"
    })
    void validDatesParse(String content, String expected) {
        assertEquals(Instant.parse(expected), parseDer(content), "Момент времени должен совпасть");
        assertEquals(
                Instant.parse(expected),
                GostSignatureHelper.parseAsn1Time(content),
                "Строковый разбор должен давать тот же момент, что и DER");
    }

    // ------------------------------------------------------------------------
    // Несуществующие и неверные даты отвергаются
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @DisplayName("Недействительные значения отвергаются в обоих разборах")
    @ValueSource(
            strings = {
                // несуществующие дни
                "20230230000000Z", // 30 февраля
                "20230229000000Z", // 29 февраля невисокосного года
                "21000229000000Z", // 2100 не високосный (делится на 100, не на 400)
                "20230431000000Z", // 31 апреля
                "20230600000000Z", // нулевой день
                "20230100000000Z",
                // месяц
                "20230001000000Z",
                "20231301000000Z",
                // время суток
                "20230101240000Z", // час 24 ровно: раньше превращался в следующие сутки
                "20230101240001Z",
                "20230101006000Z", // минута 60
                "20230101000060Z", // секунда 60 (високосная секунда в ASN.1-времени не нужна)
                // год 0000
                "00000101000000Z",
                // нецифры, знаки и пробелы
                "2023010100000AZ",
                "2023-101000000Z",
                "+0230101000000Z",
                "2023 101000000Z",
                // нет Z, смещение вместо Z, дробные секунды
                "20230101000000+",
                "20230101000000.5Z",
                // неверная длина
                "2023010100000Z",
                "202301010000000Z",
                "2301010000Z"
            })
    void invalidValuesRejected(String content) {
        // тег выбирается по длине; для неверной длины проверяется любой из двух
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostDerParser.parseTime(
                                timeTlv(GostDerParser.TAG_GENERALIZED_TIME, content), 0),
                "GeneralizedTime '" + content + "' должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(timeTlv(GostDerParser.TAG_UTC_TIME, content), 0),
                "UTCTime '" + content + "' должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.parseAsn1Time(content),
                "Строка '" + content + "' должна отвергаться");
    }

    @ParameterizedTest(name = "UTCTime {0}")
    @DisplayName("UTCTime: 30 февраля, 24:00 и несуществующие дни отвергаются")
    @ValueSource(
            strings = {
                "230230000000Z",
                "230229000000Z",
                "230431000000Z",
                "230101240000Z",
                "230101000060Z",
                "231301000000Z"
            })
    void invalidUtcTimeRejected(String content) {
        assertThrows(
                IllegalArgumentException.class,
                () -> parseDer(content),
                "UTCTime '" + content + "' должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.parseAsn1Time(content),
                "Строка '" + content + "' должна отвергаться");
    }

    @Test
    @DisplayName("Байт больше 0x7F на месте цифры при верной длине отвергается")
    void nonAsciiByteInsteadOfDigitRejected() {
        byte[] content = "20230101000000Z".getBytes(StandardCharsets.US_ASCII);
        content[6] = (byte) 0xB1; // не ASCII-цифра; длина содержимого остаётся 15 байт
        byte[] der = DerCodec.encodeTlv(GostDerParser.TAG_GENERALIZED_TIME, content);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(der, 0),
                "Нецифровой байт при верной длине должен отвергаться проверкой цифр");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.parseAsn1Time("20230101٠00000Z"),
                "Не-ASCII символ в строке должен отвергаться");
    }

    @Test
    @DisplayName("Теги, отличные от UTCTime и GeneralizedTime, отвергаются")
    void unknownTagRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerParser.parseTime(timeTlv(0x04, "230101000000Z"), 0),
                "Тег OCTET STRING не время");
    }

    @Test
    @DisplayName("parseAsn1Time(null) и строка без Z отвергаются")
    void nullAndMissingZRejected() {
        assertThrows(IllegalArgumentException.class, () -> GostSignatureHelper.parseAsn1Time(null));
        assertThrows(IllegalArgumentException.class, () -> GostSignatureHelper.parseAsn1Time(""));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.parseAsn1Time("230101000000"));
    }

    // ------------------------------------------------------------------------
    // Дата записи CRL
    // ------------------------------------------------------------------------

    private static byte[] entryWithDate(byte[] dateTlv) {
        return DerCodec.encodeSequence(DerCodec.encodeInteger(BigInteger.valueOf(0x1234)), dateTlv);
    }

    private static GostCrl parseCrlWithEntryDate(byte[] dateTlv) throws Exception {
        byte[] der =
                crl(keyPair.getPrivate(), PARAMS, issuerDn, revokedList(entryWithDate(dateTlv)));
        GostCrl crl = new GostCrl(der);
        crl.verify(keyPair.getPublic());
        return crl;
    }

    @Test
    @DisplayName("Запись CRL: несуществующая дата отзыва -> PARSE_ERROR, весь CRL отвергается")
    void entryWithImpossibleDateRejected() {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                parseCrlWithEntryDate(
                                        timeTlv(
                                                GostDerParser.TAG_GENERALIZED_TIME,
                                                "20230230000000Z")),
                        "30 февраля в дате записи должно отвергаться как PkixException");
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), "Причина - ошибка разбора");
    }

    @Test
    @DisplayName("Запись CRL: час 24 в дате UTCTime -> PARSE_ERROR")
    void entryWithHour24Rejected() {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                parseCrlWithEntryDate(
                                        timeTlv(GostDerParser.TAG_UTC_TIME, "260601240000Z")),
                        "Час 24 в дате записи должен отвергаться");
        assertEquals(PkixException.Reason.PARSE_ERROR, e.reason(), "Причина - ошибка разбора");
    }

    @Test
    @DisplayName(
            "Запись CRL: строка даты отзыва сохраняется как раньше (UTCTime и GeneralizedTime)")
    void entryDateStringUnchanged() throws Exception {
        GostCrl fromUtc =
                parseCrlWithEntryDate(timeTlv(GostDerParser.TAG_UTC_TIME, "260601123456Z"));
        assertEquals(
                "20260601123456Z",
                fromUtc.getRevokedCertificates().get(0).revocationDate(),
                "UTCTime 2026 должен достраиваться веком 20");

        GostCrl fromUtc1999 =
                parseCrlWithEntryDate(timeTlv(GostDerParser.TAG_UTC_TIME, "991231235959Z"));
        assertEquals(
                "19991231235959Z",
                fromUtc1999.getRevokedCertificates().get(0).revocationDate(),
                "UTCTime 99 должен достраиваться веком 19");

        GostCrl fromGeneralized =
                parseCrlWithEntryDate(
                        timeTlv(GostDerParser.TAG_GENERALIZED_TIME, "20240229000000Z"));
        assertEquals(
                "20240229000000Z",
                fromGeneralized.getRevokedCertificates().get(0).revocationDate(),
                "GeneralizedTime переносится без изменений");
    }

    @Test
    @DisplayName("Запись CRL без даты получает прежнее значение по умолчанию")
    void entryWithoutDateKeepsDefault() throws Exception {
        byte[] entryWithoutDate = DerCodec.encodeSequence(DerCodec.encodeInteger(BigInteger.TEN));
        byte[] der = crl(keyPair.getPrivate(), PARAMS, issuerDn, revokedList(entryWithoutDate));
        GostCrl crl = new GostCrl(der);
        crl.verify(keyPair.getPublic());
        assertEquals(
                "19700101000000Z",
                crl.getRevokedCertificates().get(0).revocationDate(),
                "Запись без даты - начало эпохи, как раньше");
    }

    // ------------------------------------------------------------------------
    // Остальные пути, где разбирается время: CRL, сертификат, OCSP
    // ------------------------------------------------------------------------

    /** Заменяет первое вхождение ASCII-строки той же длины; без вхождения тест не имеет смысла. */
    private static byte[] patch(byte[] der, String from, String to) {
        byte[] src = from.getBytes(StandardCharsets.US_ASCII);
        byte[] dst = to.getBytes(StandardCharsets.US_ASCII);
        byte[] copy = der.clone();
        outer:
        for (int i = 0; i + src.length <= copy.length; i++) {
            for (int j = 0; j < src.length; j++) {
                if (copy[i + j] != src[j]) {
                    continue outer;
                }
            }
            System.arraycopy(dst, 0, copy, i, dst.length);
            return copy;
        }
        throw new AssertionError("В DER не найдена строка времени " + from);
    }

    @Test
    @DisplayName("CRL: несуществующие thisUpdate и nextUpdate отвергаются при разборе")
    void crlHeaderDatesRejected() {
        byte[] ok = crl(keyPair.getPrivate(), PARAMS, issuerDn, revokedList());
        GostCrl parsed = new GostCrl(ok);
        String thisUpdate = GostSignatureHelper.formatGeneralizedTime(parsed.getThisUpdate());

        byte[] badThis =
                patch(
                        ok,
                        thisUpdate,
                        thisUpdate.substring(0, 4) + "0230" + thisUpdate.substring(8));
        assertThrows(
                IllegalArgumentException.class,
                () -> new GostCrl(badThis),
                "30 февраля в thisUpdate должно отвергаться");

        // nextUpdate в помощнике зашит как 20990601120000Z
        byte[] badNext = patch(ok, "20990601120000Z", "20990631120000Z");
        assertThrows(
                IllegalArgumentException.class,
                () -> new GostCrl(badNext),
                "31 июня в nextUpdate должно отвергаться");
    }

    @Test
    @DisplayName("Сертификат: несуществующие notBefore и notAfter отвергаются при разборе")
    void certificateValidityDatesRejected() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] subjectDn = GostDnParser.encodeDn("CN=Time Cert");
        byte[] tbs =
                GostCertificateBuilder.create(PARAMS, subjectDn)
                        .publicKey(kp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(subjectDn)
                        .randomSerial()
                        .buildTbs();
        byte[] ok = GostCertificateBuilder.sign(tbs, GostSigner.of(kp.getPrivate())).getEncoded();
        assertEquals(
                Instant.parse("2106-01-01T12:00:00Z"),
                GostCertificate.fromDer(ok).getNotAfter(),
                "Исходный сертификат должен разбираться");

        byte[] badAfter = patch(ok, "21060101120000Z", "21060230120000Z");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.fromDer(badAfter),
                "30 февраля в notAfter должно отвергаться");
        byte[] badBefore = patch(ok, "240501120000Z", "240501240000Z");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.fromDer(badBefore),
                "Час 24 в notBefore должен отвергаться, а не переходить на следующие сутки");
    }

    @Test
    @DisplayName("OCSP: несуществующие producedAt, thisUpdate и nextUpdate отвергаются")
    void ocspTimesRejected() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] ok =
                GostOcspResponseBuilder.create(new byte[] {0x01})
                        .issuerDn(issuerDn)
                        .producedAt("20250102000000Z")
                        .thisUpdate("20250103000000Z")
                        .nextUpdate("20250104000000Z")
                        .sign(kp.getPrivate());
        assertEquals(
                Instant.parse("2025-01-02T00:00:00Z"),
                GostOcspResponse.fromDer(ok).getProducedAt(),
                "Исходный ответ должен разбираться");

        for (String field :
                new String[] {"20250102000000Z", "20250103000000Z", "20250104000000Z"}) {
            byte[] bad = patch(ok, field, "20250230000000Z");
            assertThrows(
                    PkixException.class,
                    () -> GostOcspResponse.fromDer(bad),
                    "30 февраля вместо " + field + " должно отвергаться");
        }
    }

    @Test
    @DisplayName("Построители: несуществующая дата в строке разработчика отвергается")
    void buildersRejectImpossibleDates() {
        byte[] subjectDn = GostDnParser.encodeDn("CN=Time Cert");
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCertificateBuilder.create(PARAMS, subjectDn)
                                .publicKey(kp.getPublic())
                                .notBefore("20260230120000Z")
                                .notAfter("21060101120000Z")
                                .issuerDn(subjectDn)
                                .randomSerial()
                                .buildTbs(),
                "30 февраля в notBefore должно отвергаться построителем сертификата");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSignatureHelper.parseAsn1Time("20260431120000Z"),
                "31 апреля должно отвергаться общим разбором строки");
    }

    @Test
    @DisplayName("Сообщение об ошибке не содержит управляющих символов из недоверенных данных")
    void errorMessageHasNoControlCharacters() {
        byte[] content = "20230101000000Z".getBytes(StandardCharsets.US_ASCII);
        content[3] = 0x01; // управляющий байт на месте цифры при верной длине
        content[5] = 0x0A; // перевод строки: основа подделки записи журнала
        byte[] der = DerCodec.encodeTlv(GostDerParser.TAG_GENERALIZED_TIME, content);
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostDerParser.parseTime(der, 0),
                        "Управляющий байт на месте цифры должен отвергаться");
        for (char c : e.getMessage().toCharArray()) {
            assertTrue(c >= ' ' && c < 0x7F, "В сообщении недопустимый символ с кодом " + (int) c);
        }
    }

    @Test
    @DisplayName("Построитель CRL: несуществующая дата thisUpdate отвергается")
    void crlBuilderRejectsImpossibleThisUpdate() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostCrlBuilder.create("CN=Test CA")
                                .thisUpdate("20230230000000Z")
                                .nextUpdateDays(1),
                "30 февраля в thisUpdate должно отвергаться построителем CRL");
    }
}
