package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_AKI;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_CERTIFICATE_ISSUER;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_CRL_NUMBER;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_DELTA_CRL_INDICATOR;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_FRESHEST_CRL;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_IDP;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_REASON_CODE;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.OID_UNKNOWN;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.concat;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crl;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.crlExtensions;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.extension;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.extensionList;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.integerValue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.reasonCodeValue;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedEntry;
import static org.rssys.gost.pkix.cert.RawCrlTestSupport.revokedList;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("GostCrl: строгий разбор расширений, записей и границ структуры")
class GostCrlStrictParsingTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final BigInteger SERIAL = BigInteger.valueOf(0x1234);
    private static final byte[] NULL_VALUE = DerCodec.encodeNull();

    private static KeyPair keyPair;
    private static byte[] issuerDn;

    @BeforeAll
    static void setUp() {
        keyPair = KeyGenerator.generateKeyPair(PARAMS);
        issuerDn = GostDnParser.encodeDn("CN=Test CA");
    }

    // ------------------------------------------------------------------------
    // Вспомогательные методы
    // ------------------------------------------------------------------------

    private static byte[] crlWithExtensions(byte[]... extensions) {
        return crl(keyPair.getPrivate(), PARAMS, issuerDn, crlExtensions(extensions));
    }

    private static byte[] crlWithRevoked(byte[]... entries) {
        return crl(keyPair.getPrivate(), PARAMS, issuerDn, revokedList(entries));
    }

    private static GostCrl verified(byte[] crlDer) throws Exception {
        GostCrl crl = new GostCrl(crlDer);
        crl.verify(keyPair.getPublic());
        return crl;
    }

    private static PkixException.Reason reasonOf(byte[] crlDer) {
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> verified(crlDer),
                        "CRL должен отвергаться как PkixException, а не unchecked-исключением");
        return e.reason();
    }

    private static void assertParseError(byte[] crlDer, String message) {
        assertEquals(PkixException.Reason.PARSE_ERROR, reasonOf(crlDer), message);
    }

    private static byte[] tlv(int tag, byte... value) {
        return DerCodec.encodeTlv(tag, value);
    }

    private static byte[] idpValue(byte[]... fields) {
        return DerCodec.encodeSequence(concat(fields));
    }

    private static byte[] fullNameField(String uri) {
        byte[] generalName = tlv(0x86, uri.getBytes(StandardCharsets.US_ASCII));
        return tlv(0xA0, tlv(0xA0, generalName));
    }

    // ------------------------------------------------------------------------
    // Расширения уровня CRL
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Неизвестное non-critical расширение игнорируется")
    void unknownNonCriticalIgnored() {
        byte[] crl = crlWithExtensions(extension(OID_UNKNOWN, false, NULL_VALUE));
        assertDoesNotThrow(() -> verified(crl), "Неизвестное non-critical расширение допустимо");
    }

    @Test
    @DisplayName("Неизвестное critical-расширение -> UNKNOWN_CRITICAL_EXTENSION")
    void unknownCriticalRejected() {
        byte[] crl = crlWithExtensions(extension(OID_UNKNOWN, true, NULL_VALUE));
        assertEquals(
                PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                reasonOf(crl),
                "CRL с неизвестным critical-расширением использовать нельзя (RFC 5280 §5.2)");
    }

    @Test
    @DisplayName("critical freshestCRL -> UNKNOWN_CRITICAL_EXTENSION")
    void criticalFreshestCrlRejected() {
        byte[] value = DerCodec.encodeSequence();
        byte[] crl = crlWithExtensions(extension(OID_FRESHEST_CRL, true, value));
        assertEquals(
                PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                reasonOf(crl),
                "freshestCRL обязан быть non-critical (RFC 5280 §5.2.6)");
    }

    @Test
    @DisplayName("critical на IDP и cRLNumber допустим, critical deltaCRLIndicator разбирается")
    void criticalKnownExtensionsAccepted() throws Exception {
        byte[] crl =
                crlWithExtensions(
                        extension(OID_CRL_NUMBER, true, integerValue(BigInteger.TEN)),
                        extension(OID_IDP, true, idpValue()));
        GostCrl parsed = verified(crl);
        assertEquals(BigInteger.TEN, parsed.getCrlNumber(), "cRLNumber должен быть разобран");
        assertTrue(parsed.isIdp(), "Пустой IDP принимается как полный CRL");

        byte[] delta =
                crlWithExtensions(
                        extension(OID_CRL_NUMBER, false, integerValue(BigInteger.TWO)),
                        extension(OID_DELTA_CRL_INDICATOR, true, integerValue(BigInteger.ONE)));
        GostCrl parsedDelta = new GostCrl(delta);
        parsedDelta.verify(keyPair.getPublic(), true);
        assertEquals(BigInteger.ONE, parsedDelta.getBaseCrlNumber(), "BaseCRLNumber разобран");
    }

    @Test
    @DisplayName("Расширение без OID -> PARSE_ERROR")
    void extensionWithoutOidRejected() {
        byte[] noOid = DerCodec.encodeSequence(DerCodec.encodeOctetString(NULL_VALUE));
        assertParseError(crlWithExtensions(noOid), "Расширение без OID нельзя пропускать молча");
    }

    @Test
    @DisplayName("Блок crlExtensions не SEQUENCE -> PARSE_ERROR")
    void extensionsBlockNotSequenceRejected() {
        byte[] block = tlv(0xA0, DerCodec.encodeInteger(1));
        assertParseError(
                crl(keyPair.getPrivate(), PARAMS, issuerDn, block), "Блок не SEQUENCE нельзя");
    }

    @Test
    @DisplayName("Хвост внутри блока crlExtensions -> PARSE_ERROR")
    void trailingDataInExtensionsBlockRejected() {
        byte[] list = extensionList(extension(OID_UNKNOWN, false, NULL_VALUE));
        byte[] block = tlv(0xA0, concat(list, DerCodec.encodeNull()));
        assertParseError(
                crl(keyPair.getPrivate(), PARAMS, issuerDn, block), "Хвост в блоке недопустим");
    }

    @Test
    @DisplayName("Данные после crlExtensions в TBS -> PARSE_ERROR")
    void trailingDataAfterExtensionsRejected() {
        byte[] block = crlExtensions(extension(OID_UNKNOWN, false, NULL_VALUE));
        assertParseError(
                crl(keyPair.getPrivate(), PARAMS, issuerDn, block, DerCodec.encodeNull()),
                "После crlExtensions TBS обязан закончиться");
    }

    @Test
    @DisplayName("Лишнее поле после списка отозванных -> PARSE_ERROR")
    void unexpectedFieldAfterRevokedListRejected() {
        byte[] list = revokedList(revokedEntry(SERIAL, null));
        assertParseError(
                crl(keyPair.getPrivate(), PARAMS, issuerDn, list, DerCodec.encodeNull()),
                "Поле с иным тегом после списка отозванных нельзя пропускать");
    }

    @Test
    @DisplayName("Расширение, заявляющее длину за пределы своего блока -> PARSE_ERROR")
    void extensionOverrunningItsBlockRejected() {
        // Заявленная длина 0x40 уводит за блок и дальше в подпись, но внутри буфера
        byte[] overrun = {0x30, 0x40, 0x06, 0x03, 0x55, 0x1D, 0x14};
        byte[] block = tlv(0xA0, DerCodec.encodeTlv(0x30, overrun));
        assertParseError(
                crl(keyPair.getPrivate(), PARAMS, issuerDn, block),
                "Расширение не вправе выходить за свой блок");
    }

    @Test
    @DisplayName("Дубликат расширения уровня CRL -> PARSE_ERROR")
    void duplicateExtensionRejected() {
        byte[] number = extension(OID_CRL_NUMBER, false, integerValue(BigInteger.ONE));
        assertParseError(crlWithExtensions(number, number), "Повтор расширения запрещён");
        byte[] unknown = extension(OID_UNKNOWN, false, NULL_VALUE);
        assertParseError(
                crlWithExtensions(unknown, unknown), "Повтор неизвестного расширения тоже");
    }

    @Test
    @DisplayName("Число расширений уровня CRL ограничено")
    void tooManyExtensionsRejected() {
        byte[][] extensions = new byte[GostOids.MAX_CRL_EXTENSIONS + 1][];
        for (int i = 0; i < extensions.length; i++) {
            extensions[i] = extension(OID_UNKNOWN + "." + i, false, NULL_VALUE);
        }
        assertParseError(crlWithExtensions(extensions), "Превышение предела числа расширений");
    }

    // ------------------------------------------------------------------------
    // cRLNumber и BaseCRLNumber
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("cRLNumber: 16 октетов и 20 октетов величины принимаются")
    void longCrlNumberAccepted() throws Exception {
        BigInteger sixteenOctets = BigInteger.ONE.shiftLeft(120).add(BigInteger.valueOf(12345));
        GostCrl first =
                verified(
                        crlWithExtensions(
                                extension(OID_CRL_NUMBER, false, integerValue(sixteenOctets))));
        assertEquals(sixteenOctets, first.getCrlNumber(), "16-октетный номер должен приниматься");

        // 20 октетов величины со старшим битом кодируются 21 байтом (ведущий 0x00)
        BigInteger twentyOctets = BigInteger.ONE.shiftLeft(159).add(BigInteger.ONE);
        GostCrl second =
                verified(
                        crlWithExtensions(
                                extension(OID_CRL_NUMBER, false, integerValue(twentyOctets))));
        assertEquals(twentyOctets, second.getCrlNumber(), "20 октетов величины допустимы");
    }

    @Test
    @DisplayName("cRLNumber и BaseCRLNumber: 21 октет величины -> PARSE_ERROR")
    void tooLongCrlNumberRejected() {
        BigInteger twentyOneOctets = BigInteger.ONE.shiftLeft(160);
        assertParseError(
                crlWithExtensions(extension(OID_CRL_NUMBER, false, integerValue(twentyOneOctets))),
                "Номер длиннее 20 октетов величины отвергается");
        assertParseError(
                crlWithExtensions(
                        extension(OID_CRL_NUMBER, false, integerValue(BigInteger.TWO)),
                        extension(OID_DELTA_CRL_INDICATOR, true, integerValue(twentyOneOctets))),
                "Для BaseCRLNumber действует тот же предел");
    }

    @Test
    @DisplayName("Отрицательный cRLNumber -> PARSE_ERROR")
    void negativeCrlNumberRejected() {
        byte[] negative = DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[] {(byte) 0xFF});
        assertParseError(
                crlWithExtensions(extension(OID_CRL_NUMBER, false, negative)),
                "cRLNumber неотрицателен (RFC 5280 §5.2.3)");
    }

    @Test
    @DisplayName("Кривое значение cRLNumber (не INTEGER, хвост, пусто) -> PARSE_ERROR")
    void malformedCrlNumberValueRejected() {
        assertParseError(
                crlWithExtensions(extension(OID_CRL_NUMBER, false, NULL_VALUE)),
                "Не INTEGER: защита от отката не должна молча исчезать");
        assertParseError(
                crlWithExtensions(
                        extension(
                                OID_CRL_NUMBER,
                                false,
                                concat(integerValue(BigInteger.ONE), NULL_VALUE))),
                "Хвост после INTEGER");
        assertParseError(
                crlWithExtensions(
                        extension(
                                OID_CRL_NUMBER,
                                false,
                                DerCodec.encodeTlv(DerCodec.TAG_INTEGER, new byte[0]))),
                "Пустой INTEGER");
    }

    // ------------------------------------------------------------------------
    // AKI
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("AKI: keyIdentifier 0x80 разбирается; constructed A0 и не-SEQUENCE отвергаются")
    void akiStrictness() throws Exception {
        byte[] keyId = {1, 2, 3, 4};
        byte[] good = DerCodec.encodeSequence(tlv(0x80, keyId));
        GostCrl parsed = verified(crlWithExtensions(extension(OID_AKI, false, good)));
        assertArrayEquals(keyId, parsed.getAuthorityKeyIdentifier(), "keyIdentifier извлечён");

        byte[] constructed = DerCodec.encodeSequence(tlv(0xA0, DerCodec.encodeOctetString(keyId)));
        assertParseError(
                crlWithExtensions(extension(OID_AKI, false, constructed)),
                "Constructed-форма keyIdentifier не принимается");
        assertParseError(
                crlWithExtensions(extension(OID_AKI, false, NULL_VALUE)),
                "AKI обязан быть SEQUENCE");
        assertParseError(
                crlWithExtensions(
                        extension(
                                OID_AKI,
                                false,
                                DerCodec.encodeSequence(
                                        tlv(0x82, new byte[] {1}), tlv(0x80, keyId)))),
                "Нарушение порядка полей AKI");
    }

    // ------------------------------------------------------------------------
    // IssuingDistributionPoint
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("IDP: порядок полей считается по номеру, A0 затем 81 принимается")
    void idpFieldOrderByNumber() throws Exception {
        byte[] idp = idpValue(fullNameField("http://crl.example/a.crl"), tlv(0x81, (byte) 0xFF));
        GostCrl parsed = verified(crlWithExtensions(extension(OID_IDP, true, idp)));
        assertTrue(parsed.isOnlyContainsUserCerts(), "onlyContainsUserCerts разобран");
        assertArrayEquals(
                new String[] {"http://crl.example/a.crl"},
                parsed.getIdpDistributionPointUris(),
                "URI distributionPoint разобран");

        byte[] wrongOrder =
                idpValue(tlv(0x81, (byte) 0xFF), fullNameField("http://crl.example/a.crl"));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, wrongOrder)),
                "Нарушение порядка полей IDP");
    }

    @Test
    @DisplayName("IDP: повтор поля -> PARSE_ERROR (последнее значение не побеждает)")
    void idpRepeatedFieldRejected() {
        byte[] idp = idpValue(tlv(0x82, (byte) 0xFF), tlv(0x82, (byte) 0x00));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, idp)), "Повтор поля IDP недопустим");
    }

    @Test
    @DisplayName("IDP: тег 80, A3 и A5 -> PARSE_ERROR")
    void idpNonCanonicalTagsRejected() {
        for (int tag : new int[] {0x80, 0xA3, 0xA5, 0x86}) {
            byte[] idp = idpValue(tlv(tag, (byte) 0xFF));
            assertParseError(
                    crlWithExtensions(extension(OID_IDP, true, idp)),
                    "Неканонический или неизвестный тег IDP: " + Integer.toHexString(tag));
        }
    }

    @Test
    @DisplayName("IDP: примитивные 83 и 85 разбираются (отказ позже, при проверке области)")
    void idpPrimitiveReasonsAndAttributeFlagsParsed() throws Exception {
        byte[] idp = idpValue(tlv(0x83, (byte) 0x06, (byte) 0x40), tlv(0x85, (byte) 0x00));
        GostCrl parsed = verified(crlWithExtensions(extension(OID_IDP, true, idp)));
        assertTrue(parsed.isOnlySomeReasons(), "onlySomeReasons разобран");
        assertTrue(
                parsed.isOnlyContainsAttributeCerts(),
                "Наличие onlyContainsAttributeCerts даёт true даже для FALSE (fail-closed)");
    }

    @Test
    @DisplayName("IDP: EXPLICIT BOOLEAN принимается строго")
    void idpExplicitBooleanStrict() throws Exception {
        byte[] accepted = idpValue(tlv(0xA2, (byte) 0x01, (byte) 0x01, (byte) 0xFF));
        GostCrl parsed;
        try (LogCapture log = LogCapture.start(LogCapture.PKIX)) {
            parsed = verified(crlWithExtensions(extension(OID_IDP, true, accepted)));

            // Кодировку выбирает издатель CRL: оператору нечего исправить, запись только на DEBUG
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "нестрогая кодировка не даёт WARNING");
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(m -> m.contains("non-canonical EXPLICIT BOOLEAN")),
                    "факт терпимого разбора виден на DEBUG: " + log.messages(Level.FINE));
        }
        assertTrue(parsed.isOnlyContainsCACerts(), "EXPLICIT BOOLEAN FF = true");

        byte[] trailing =
                idpValue(
                        tlv(0xA2, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x05, (byte) 0x00));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, trailing)),
                "Хвост после EXPLICIT BOOLEAN");
        byte[] badValue = idpValue(tlv(0xA2, (byte) 0x01, (byte) 0x01, (byte) 0x01));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, badValue)),
                "Значение BOOLEAN не 0x00/0xFF");
    }

    @Test
    @DisplayName("IDP: BOOLEAN не из одного октета и не-SEQUENCE -> PARSE_ERROR")
    void idpMalformedValueRejected() {
        assertParseError(
                crlWithExtensions(
                        extension(OID_IDP, true, idpValue(tlv(0x81, (byte) 0xFF, (byte) 0xFF)))),
                "Два октета в BOOLEAN");
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, NULL_VALUE)),
                "Битый IDP больше не считается отсутствующим");
    }

    @Test
    @DisplayName("IDP: distributionPoint допускает только fullName (A0) и nameRelative (A1)")
    void idpDistributionPointNameTags() throws Exception {
        byte[] nameRelative = idpValue(tlv(0xA0, tlv(0xA1, (byte) 0x00)));
        GostCrl parsed = verified(crlWithExtensions(extension(OID_IDP, true, nameRelative)));
        assertTrue(parsed.isIdpNameRelativeToCrlIssuer(), "nameRelativeToCRLIssuer разобран");

        byte[] primitiveName = idpValue(tlv(0xA0, tlv(0x80, (byte) 0x00)));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, primitiveName)),
                "Тег 80 внутри distributionPoint неканоничен");
        byte[] emptyPoint = idpValue(tlv(0xA0));
        assertParseError(
                crlWithExtensions(extension(OID_IDP, true, emptyPoint)),
                "Пустой distributionPoint");
    }

    @Test
    @DisplayName("IDP: indirectCRL по-прежнему IDP_NOT_SUPPORTED")
    void idpIndirectRejected() {
        byte[] idp = idpValue(tlv(0x84, (byte) 0xFF));
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                reasonOf(crlWithExtensions(extension(OID_IDP, true, idp))),
                "indirect CRL не поддерживается");
    }

    // ------------------------------------------------------------------------
    // Записи об отзыве и их расширения
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("reasonCode разбирается; неизвестное число трактуется как отсутствие причины")
    void reasonCodeParsed() throws Exception {
        byte[] withReason =
                revokedEntry(
                        SERIAL,
                        extensionList(extension(OID_REASON_CODE, false, reasonCodeValue(1))));
        GostCrl parsed = verified(crlWithRevoked(withReason));
        assertEquals(
                ReasonCode.KEY_COMPROMISE,
                parsed.getReason(SERIAL.toByteArray()),
                "reasonCode извлечён");

        byte[] unknownReason =
                revokedEntry(
                        SERIAL,
                        extensionList(extension(OID_REASON_CODE, false, reasonCodeValue(99))));
        GostCrl unknown = verified(crlWithRevoked(unknownReason));
        assertTrue(unknown.isRevoked(SERIAL.toByteArray()), "Запись остаётся отозванной");
        assertNull(unknown.getReason(SERIAL.toByteArray()), "Неизвестная причина = нет причины");
    }

    @Test
    @DisplayName("reasonCode не ENUMERATED или не из одного октета -> PARSE_ERROR")
    void malformedReasonCodeRejected() {
        byte[] notEnum = extension(OID_REASON_CODE, false, NULL_VALUE);
        assertParseError(
                crlWithRevoked(revokedEntry(SERIAL, extensionList(notEnum))), "Не ENUMERATED");
        byte[] twoOctets =
                extension(
                        OID_REASON_CODE,
                        false,
                        DerCodec.encodeTlv(DerCodec.TAG_ENUMERATED, new byte[] {1, 2}));
        assertParseError(
                crlWithRevoked(revokedEntry(SERIAL, extensionList(twoOctets))),
                "ENUMERATED из двух октетов");
    }

    @Test
    @DisplayName("Запись: неизвестное critical-расширение -> UNKNOWN_CRITICAL_EXTENSION")
    void entryUnknownCriticalRejected() {
        byte[] ext = extension(OID_UNKNOWN, true, NULL_VALUE);
        assertEquals(
                PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                reasonOf(crlWithRevoked(revokedEntry(SERIAL, extensionList(ext)))),
                "RFC 5280 §5.3: CRL с неподдержанным critical-расширением записи не использовать");
    }

    @Test
    @DisplayName(
            "Запись: certificateIssuer (даже critical) -> IDP_NOT_SUPPORTED, не unknown critical")
    void entryCertificateIssuerIsIndirectCrl() {
        byte[] generalNames = DerCodec.encodeSequence(tlv(0xA4, GostDnParser.encodeDn("CN=Other")));
        byte[] ext = extension(OID_CERTIFICATE_ISSUER, true, generalNames);
        assertEquals(
                PkixException.Reason.IDP_NOT_SUPPORTED,
                reasonOf(crlWithRevoked(revokedEntry(SERIAL, extensionList(ext)))),
                "certificateIssuer — признак indirect CRL, а не неизвестное расширение");
    }

    @Test
    @DisplayName("Запись: расширения не SEQUENCE, хвост, дубликат, превышение числа -> PARSE_ERROR")
    void entryExtensionsMalformedRejected() {
        // Вместо SEQUENCE расширений — произвольный тег: под ним мог скрыться critical-признак
        byte[] notSequence =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(SERIAL),
                        DerCodec.encodeTime("260601000000Z"),
                        DerCodec.encodeNull());
        assertParseError(crlWithRevoked(notSequence), "Расширения записи не SEQUENCE");

        byte[] unknown = extension(OID_UNKNOWN, false, NULL_VALUE);
        byte[] trailing =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(SERIAL),
                        DerCodec.encodeTime("260601000000Z"),
                        extensionList(unknown),
                        DerCodec.encodeNull());
        assertParseError(crlWithRevoked(trailing), "Хвост после расширений записи");

        assertParseError(
                crlWithRevoked(revokedEntry(SERIAL, extensionList(unknown, unknown))),
                "Дубликат расширения записи");

        byte[][] many = new byte[GostOids.MAX_CRL_ENTRY_EXTENSIONS + 1][];
        for (int i = 0; i < many.length; i++) {
            many[i] = extension(OID_UNKNOWN + "." + i, false, NULL_VALUE);
        }
        assertParseError(
                crlWithRevoked(revokedEntry(SERIAL, extensionList(many))),
                "Превышение предела числа расширений записи");
    }

    // ------------------------------------------------------------------------
    // Внешняя структура
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Хвост после CertificateList -> IllegalArgumentException в конструкторе")
    void trailingDataAfterCertificateListRejected() {
        byte[] withTrailer =
                RawCrlTestSupport.sign(
                        keyPair.getPrivate(), PARAMS, validTbs(), new byte[] {0x05, 0x00});
        assertThrows(
                IllegalArgumentException.class,
                () -> new GostCrl(withTrailer),
                "Хвост за CertificateList не принадлежит подписанной структуре");
    }

    @Test
    @DisplayName("extractCrlNumber находит и critical cRLNumber (метаданные кэша не теряются)")
    void extractCrlNumberHandlesCriticalExtension() {
        BigInteger number = BigInteger.valueOf(42);
        byte[] critical = crlWithExtensions(extension(OID_CRL_NUMBER, true, integerValue(number)));
        byte[] nonCritical =
                crlWithExtensions(extension(OID_CRL_NUMBER, false, integerValue(number)));
        assertEquals(number, CrlVerifier.extractCrlNumber(critical), "critical cRLNumber");
        assertEquals(number, CrlVerifier.extractCrlNumber(nonCritical), "non-critical cRLNumber");
    }

    @Test
    @DisplayName("Повторный verify того же GostCrl даёт тот же результат")
    void repeatedVerifyIsStable() throws Exception {
        byte[] crl =
                crlWithExtensions(
                        extension(OID_CRL_NUMBER, false, integerValue(BigInteger.valueOf(7))),
                        extension(OID_IDP, true, idpValue(tlv(0x81, (byte) 0xFF))));
        GostCrl parsed = new GostCrl(crl);
        parsed.verify(keyPair.getPublic());
        parsed.verify(keyPair.getPublic());
        assertEquals(BigInteger.valueOf(7), parsed.getCrlNumber(), "cRLNumber после повтора");
        assertTrue(parsed.isOnlyContainsUserCerts(), "IDP после повторного verify");
    }

    private static byte[] validTbs() {
        byte[] tbsOut =
                concat(
                        DerCodec.encodeTlv(0x02, new byte[] {0x01}),
                        GostSignatureHelper.buildAlgId(PARAMS),
                        issuerDn,
                        DerCodec.encodeTime(GostSignatureHelper.nowGeneralizedTime()),
                        DerCodec.encodeTime("20990601120000Z"));
        return DerCodec.encodeSequence(tbsOut);
    }
}
