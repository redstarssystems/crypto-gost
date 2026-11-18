package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Строгий разбор статуса ответа и версии OCSP (RFC 6960 §4.2.1, §4.1.1, §4.2.2.3).
 *
 * <p>Отрицательные случаи строятся от полностью корректных ответа и запроса, в которых заменён
 * только проверяемый фрагмент, и проверяют текст сообщения: иначе тест мог бы пройти по
 * постороннему сбою разбора.</p>
 */
@DisplayName("OCSP: строгая проверка статуса ответа и версии (ответ и запрос)")
class OcspStrictStatusVersionTest {

    private static final byte[] VERSION_V1 = {(byte) 0xA0, 0x03, 0x02, 0x01, 0x00};

    private static byte[] validResponse;
    private static byte[] validRequest;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ECParameters params = ECParameters.tc26a256();
        KeyPair caKeys = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        validResponse =
                GostOcspResponseBuilder.create(new byte[] {0x2A})
                        .issuerDn(caDn)
                        .sign(caKeys.getPrivate());

        GostCertificate ca =
                GostCertificateBuilder.create(params, "CN=Test CA")
                        .publicKey(caKeys.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("20351231235959Z")
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .randomSerial()
                        .sign(caKeys.getPrivate());
        KeyPair leafKeys = KeyGenerator.generateKeyPair(params);
        GostCertificate leaf =
                GostCertificateBuilder.create(params, "CN=Leaf")
                        .publicKey(leafKeys.getPublic())
                        .issuerDn(ca.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20261231235959Z")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .randomSerial()
                        .sign(caKeys.getPrivate());
        validRequest =
                GostOcspRequestBuilder.create()
                        .targetCert(leaf.getEncoded())
                        .issuerCert(ca.getEncoded())
                        .build();
    }

    // ------------------------------------------------------------------
    // Статус ответа
    // ------------------------------------------------------------------

    /** Ответ без responseBytes с заданным статусом: {@code 30 03 0A 01 SS}. */
    private static byte[] statusOnly(int status) {
        return DerCodec.encodeSequence(new byte[] {0x0A, 0x01, (byte) status});
    }

    /** Корректный ответ, у которого заменён только статус (responseBytes сохранён). */
    private static byte[] withStatusBytes(byte[] statusTlv) {
        byte[][] response = DerCodec.parseSequenceContents(validResponse, 0);
        return DerCodec.encodeSequence(statusTlv, response[1]);
    }

    private static void assertRejected(Executable call, String messagePart, String why) {
        PkixException ex = assertThrows(PkixException.class, call, why);
        assertTrue(
                ex.getMessage().contains(messagePart),
                why + ": ожидался текст «" + messagePart + "», получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Статусы 1, 2, 3, 5, 6 без responseBytes разбираются, ответ не успешен")
    void allowedErrorStatusesParse() throws Exception {
        for (int status : new int[] {1, 2, 3, 5, 6}) {
            GostOcspResponse parsed = new GostOcspResponse(statusOnly(status));
            assertEquals(status, parsed.getResponseStatus(), "статус " + status);
            assertFalse(parsed.isSuccessful(), "статус " + status + " не успешный");
        }
    }

    @Test
    @DisplayName("Успешный ответ (статус 0) разбирается как раньше")
    void successfulStatusParses() throws Exception {
        GostOcspResponse parsed = new GostOcspResponse(validResponse);
        assertEquals(0, parsed.getResponseStatus());
        assertTrue(parsed.isSuccessful());
    }

    @Test
    @DisplayName("Статусы 4 (не используется), 7 и 255 -> PkixException")
    void unsupportedStatusesRejected() {
        for (int status : new int[] {4, 7, 255}) {
            assertRejected(
                    () -> new GostOcspResponse(statusOnly(status)),
                    "unsupported responseStatus " + status,
                    "статус " + status);
        }
    }

    @Test
    @DisplayName("Пустой ENUMERATED (0A 00) -> PkixException, а не успех")
    void emptyEnumeratedRejected() {
        byte[] ocsp = withStatusBytes(new byte[] {0x0A, 0x00});

        assertRejected(() -> new GostOcspResponse(ocsp), "empty ENUMERATED", "пустой ENUMERATED");
    }

    @Test
    @DisplayName("ENUMERATED длиннее 1 байта -> прежнее сообщение «too long»")
    void longEnumeratedKeepsMessage() {
        byte[] ocsp = withStatusBytes(new byte[] {0x0A, 0x02, 0x00, 0x00});

        assertRejected(() -> new GostOcspResponse(ocsp), "too long", "ENUMERATED из 2 байт");
    }

    @Test
    @DisplayName("Статус не 0 вместе с responseBytes -> PkixException")
    void errorStatusWithResponseBytesRejected() {
        byte[] ocsp = withStatusBytes(new byte[] {0x0A, 0x01, 0x01});

        assertRejected(
                () -> new GostOcspResponse(ocsp),
                "responseBytes must be absent",
                "статус 1 с responseBytes");
    }

    @Test
    @DisplayName("Статус 0 без responseBytes -> PkixException (как раньше)")
    void successfulStatusWithoutResponseBytesRejected() {
        assertRejected(
                () -> new GostOcspResponse(statusOnly(0)),
                "responseBytes",
                "статус 0 без responseBytes");
    }

    @Test
    @DisplayName("Значение статуса за границей OCSPResponse (30 02 0A 01 05) -> PkixException")
    void statusBeyondOuterSequenceRejected() {
        byte[] ocsp = {0x30, 0x02, 0x0A, 0x01, 0x05};

        assertRejected(
                () -> new GostOcspResponse(ocsp),
                "Malformed OCSP response",
                "значение статуса лежит за концом внешней SEQUENCE");
    }

    // ------------------------------------------------------------------
    // Версия ответа
    // ------------------------------------------------------------------

    /** Корректный ответ, у которого в tbsResponseData первым элементом вставлено поле версии. */
    private static byte[] responseWithVersionField(byte[] versionField) {
        byte[][] response = DerCodec.parseSequenceContents(validResponse, 0);
        int[] explicitLen = DerCodec.decodeLength(response[1], 1);
        byte[][] responseBytes = DerCodec.parseSequenceContents(response[1], 1 + explicitLen[1]);
        byte[][] basic =
                DerCodec.parseSequenceContents(DerCodec.parseOctetString(responseBytes[1], 0), 0);
        byte[][] tbs = DerCodec.parseSequenceContents(basic[0], 0);

        byte[][] newTbs = new byte[tbs.length + 1][];
        newTbs[0] = versionField;
        System.arraycopy(tbs, 0, newTbs, 1, tbs.length);
        basic[0] = DerCodec.encodeSequence(newTbs);
        responseBytes[1] = DerCodec.encodeOctetString(DerCodec.encodeSequence(basic));
        return DerCodec.encodeSequence(
                response[0],
                DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(responseBytes)));
    }

    @Test
    @DisplayName("Ответ: версия отсутствует или явный 0 (как в примере В.3) -> принимается")
    void responseVersionAbsentOrZeroAccepted() {
        assertDoesNotThrow(() -> new GostOcspResponse(validResponse), "версии нет");
        assertDoesNotThrow(
                () -> new GostOcspResponse(responseWithVersionField(VERSION_V1)), "явная версия 0");
    }

    @Test
    @DisplayName("Ответ: версия не v1 и неверное устройство поля -> PkixException")
    void responseInvalidVersionRejected() {
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x03, 0x02, 0x01, 0x01})),
                "unsupported version",
                "версия 1");
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x04, 0x02, 0x02, 0x00, 0x00})),
                "unsupported version",
                "INTEGER из 2 байт");
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x03, 0x04, 0x01, 0x00})),
                "must be an INTEGER",
                "не INTEGER");
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(new byte[] {(byte) 0xA0, 0x00})),
                "must be an INTEGER",
                "пустое [0]");
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(
                                        new byte[] {
                                            (byte) 0xA0, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01
                                        })),
                "unexpected data after version",
                "лишний элемент после INTEGER");
    }

    @Test
    @DisplayName("Ответ: INTEGER версии выходит за границу [0] (A0 01 02 01 00) -> PkixException")
    void responseVersionIntegerBeyondFieldRejected() {
        assertRejected(
                () ->
                        new GostOcspResponse(
                                responseWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x01, 0x02, 0x01, 0x00})),
                "Malformed OCSP response",
                "INTEGER длиннее содержимого [0]");
    }

    // ------------------------------------------------------------------
    // Версия запроса
    // ------------------------------------------------------------------

    /** Корректный запрос, у которого в TBSRequest первым элементом вставлено поле версии. */
    private static byte[] requestWithVersionField(byte[] versionField) {
        byte[][] request = DerCodec.parseSequenceContents(validRequest, 0);
        byte[][] tbs = DerCodec.parseSequenceContents(request[0], 0);

        byte[][] newTbs = new byte[tbs.length + 1][];
        newTbs[0] = versionField;
        System.arraycopy(tbs, 0, newTbs, 1, tbs.length);
        request[0] = DerCodec.encodeSequence(newTbs);
        return DerCodec.encodeSequence(request);
    }

    @Test
    @DisplayName("Запрос: версия отсутствует или явный 0 (как в примере В.2) -> принимается")
    void requestVersionAbsentOrZeroAccepted() {
        assertDoesNotThrow(() -> GostOcspRequest.fromDer(validRequest), "версии нет");
        assertDoesNotThrow(
                () -> GostOcspRequest.fromDer(requestWithVersionField(VERSION_V1)),
                "явная версия 0");
    }

    @Test
    @DisplayName("Запрос: версия не v1 и неверное устройство поля -> PkixException")
    void requestInvalidVersionRejected() {
        assertRejected(
                () ->
                        GostOcspRequest.fromDer(
                                requestWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x03, 0x02, 0x01, 0x01})),
                "unsupported version",
                "версия 1");
        assertRejected(
                () ->
                        GostOcspRequest.fromDer(
                                requestWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x04, 0x02, 0x02, 0x00, 0x00})),
                "unsupported version",
                "INTEGER из 2 байт");
        assertRejected(
                () ->
                        GostOcspRequest.fromDer(
                                requestWithVersionField(
                                        new byte[] {(byte) 0xA0, 0x03, 0x04, 0x01, 0x00})),
                "must be an INTEGER",
                "не INTEGER");
        assertRejected(
                () ->
                        GostOcspRequest.fromDer(
                                requestWithVersionField(new byte[] {(byte) 0xA0, 0x00})),
                "must be an INTEGER",
                "пустое [0]");
        assertRejected(
                () ->
                        GostOcspRequest.fromDer(
                                requestWithVersionField(
                                        new byte[] {
                                            (byte) 0xA0, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01
                                        })),
                "unexpected data after version",
                "лишний элемент после INTEGER");
    }
}
