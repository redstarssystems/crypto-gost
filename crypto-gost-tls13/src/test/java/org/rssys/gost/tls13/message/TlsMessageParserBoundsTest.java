package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Границы контейнеров и certificate_request_context в разборе Certificate,
 * CertificateRequest и status_request (RFC 8446 §4.2, §4.3.2, §4.4.2; RFC 6066 §8).
 */
@DisplayName("TlsMessageParser: границы контейнеров, контекст, status_request")
class TlsMessageParserBoundsTest {

    private static final byte[] FAKE_DER = {0x30, 0x00};

    /** Корректный CertificateStatus: ocsp, uint24(5), OCSPResponse. */
    private static final byte[] STAPLE = {0x01, 0x00, 0x00, 0x05, 0x30, 0x03, 0x0A, 0x01, 0x00};

    private static byte[] uint16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }

    private static byte[] ext(int type, byte[] data) {
        return cat(uint16(type), uint16(data.length), data);
    }

    /** CertificateEntry с произвольным блоком расширений (длина блока задаётся явно). */
    private static byte[] entry(int declaredExtLen, byte[] extBytes) {
        return cat(
                new byte[] {0, 0, (byte) FAKE_DER.length},
                FAKE_DER,
                uint16(declaredExtLen),
                extBytes);
    }

    private static byte[] certificate(int contextLen, byte[] list) {
        return cat(
                new byte[] {(byte) contextLen},
                new byte[] {0, (byte) (list.length >>> 8), (byte) list.length},
                list);
    }

    private static TlsException parseCertFails(byte[] body) {
        return assertThrows(
                TlsException.class,
                () ->
                        TlsMessageParser.parseCertificate(
                                body, Set.of(TlsConstants.EXT_STATUS_REQUEST)));
    }

    // ---------------------------------------------------------------- Certificate

    @Test
    @DisplayName("Certificate: непустой certificate_request_context -> illegal_parameter")
    // Иначе байты контекста читались бы как длина certificate_list.
    void nonEmptyCertificateContextRejected() {
        byte[] body = cat(new byte[] {1, 0x55}, new byte[] {0, 0, 0});
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, parseCertFails(body).getAlertCode());
    }

    @Test
    @DisplayName("Certificate: байты после certificate_list -> decode_error")
    void trailingBytesAfterCertificateListRejected() {
        byte[] body = cat(certificate(0, new byte[0]), new byte[] {0x01});
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseCertFails(body).getAlertCode());
    }

    @Test
    @DisplayName("Certificate: cert_len за концом списка -> decode_error")
    void certLenBeyondListRejected() {
        byte[] body = certificate(0, new byte[] {0, 0, 50, 0x30, 0x00});
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, parseCertFails(body).getAlertCode());
    }

    @Test
    @DisplayName("Certificate: расширение выходит за блок extensions записи -> decode_error")
    // Расширение заявляет 6 байт данных, блок extensions записи - 4: хвост принадлежит
    // следующей записи и не должен читаться как данные этого расширения.
    void extensionBeyondEntryExtensionsRejected() {
        byte[] overlong = cat(uint16(TlsConstants.EXT_STATUS_REQUEST), uint16(6));
        byte[] next = cat(new byte[] {0, 0, 2}, FAKE_DER, uint16(0));
        byte[] list = cat(entry(overlong.length, overlong), next);
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                parseCertFails(certificate(0, list)).getAlertCode());
    }

    @Test
    @DisplayName("Certificate: дубль status_request в записи -> illegal_parameter")
    void duplicateExtensionInEntryRejected() {
        byte[] one = ext(TlsConstants.EXT_STATUS_REQUEST, STAPLE);
        byte[] exts = cat(one, one);
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                parseCertFails(certificate(0, entry(exts.length, exts))).getAlertCode());
    }

    // --------------------------------------------------------- CertificateRequest

    private static byte[] certificateRequest() {
        return TlsMessageBuilder.buildCertificateRequest();
    }

    @Test
    @DisplayName("CertificateRequest: корректное сообщение разбирается")
    void validCertificateRequestParsed() throws TlsException {
        var request = TlsMessageParser.parseCertificateRequest(certificateRequest());

        // SIG_ALG_EXT билдера: семь схем TC26 с кодами 0x0709..0x070F
        assertArrayEquals(
                new int[] {0x0709, 0x070A, 0x070B, 0x070C, 0x070D, 0x070E, 0x070F},
                request.signatureSchemes(),
                "Схемы подписи из расширения signature_algorithms");
        assertTrue(request.caDns().isEmpty(), "Список certificate_authorities не передавался");
    }

    @Test
    @DisplayName("CertificateRequest: непустой certificate_request_context -> illegal_parameter")
    void nonEmptyRequestContextRejected() {
        byte[] body = cat(new byte[] {1, 0x55}, certificateRequest());
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parseCertificateRequest(body));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ex.getAlertCode());
    }

    @Test
    @DisplayName("CertificateRequest: байты после extensions -> decode_error")
    void trailingBytesInCertificateRequestRejected() {
        byte[] body = cat(certificateRequest(), new byte[] {0x00});
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parseCertificateRequest(body));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("CertificateRequest: расширение шире блока extensions -> decode_error")
    void extensionBeyondRequestExtensionsRejected() {
        // блок extensions объявлен в 4 байта, внутри расширение заявляет 20 байт данных
        byte[] body =
                cat(
                        new byte[] {0},
                        uint16(4),
                        uint16(TlsConstants.EXT_SIGNATURE_ALGORITHMS),
                        uint16(20),
                        new byte[20]);
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parseCertificateRequest(body));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    // ------------------------------------------------------------- status_request

    /** Минимальный ClientHello: без cipher_suites-значимых данных, только структура. */
    private static byte[] clientHello(byte[] extensions) {
        return cat(
                new byte[] {0x03, 0x03},
                new byte[TlsConstants.RANDOM_LENGTH],
                new byte[] {0},
                uint16(2),
                new byte[] {0x13, 0x01},
                new byte[] {1, 0},
                uint16(extensions.length),
                extensions);
    }

    private static final byte[] OCSP_REQUEST = {1, 0, 0, 0, 0};

    private static TlsException stapleFails(byte[] statusRequestBody) {
        byte[] extBlock = ext(TlsConstants.EXT_STATUS_REQUEST, statusRequestBody);
        byte[] body = certificate(0, entry(extBlock.length, extBlock));
        // FAKE_DER не разбирается как сертификат, но ошибка staple возникает раньше этого шага.
        return parseCertFails(body);
    }

    @Test
    @DisplayName("CertificateStatus: legacy-формат без uint24-длины -> decode_error")
    // 01 || DER: длину ответа пришлось бы угадывать по байтам DER (30 03 0A) - разборщики разошлись
    // бы.
    void legacyStapleWithoutLengthRejected() {
        byte[] legacy = {0x01, 0x30, 0x03, 0x0A, 0x01, 0x00};
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, stapleFails(legacy).getAlertCode());
    }

    @Test
    @DisplayName("CertificateStatus: пустое расширение и обрезанное поле длины -> decode_error")
    void truncatedStapleRejected() {
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, stapleFails(new byte[0]).getAlertCode());
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                stapleFails(new byte[] {0x01, 0x00, 0x00}).getAlertCode());
    }

    @Test
    @DisplayName("CertificateStatus: uint24 больше остатка расширения -> decode_error")
    void oversizedStapleLengthRejected() {
        byte[] bad = {0x01, 0x00, 0x00, 0x09, 0x30, 0x03, 0x0A, 0x01, 0x00};
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, stapleFails(bad).getAlertCode());
    }

    @Test
    @DisplayName("CertificateStatus: uint24 меньше остатка (лишние байты) -> decode_error")
    void trailingBytesInStapleRejected() {
        byte[] bad = {0x01, 0x00, 0x00, 0x05, 0x30, 0x03, 0x0A, 0x01, 0x00, 0x7F};
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, stapleFails(bad).getAlertCode());
    }

    @Test
    @DisplayName("CertificateStatus: нулевая длина ответа -> decode_error")
    void zeroLengthStapleRejected() {
        byte[] bad = {0x01, 0x00, 0x00, 0x00};
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, stapleFails(bad).getAlertCode());
    }

    @Test
    @DisplayName("clientHelloRequestsOcsp: расширение status_request(ocsp) -> true")
    void ocspRequested() throws TlsException {
        byte[] ch = clientHello(ext(TlsConstants.EXT_STATUS_REQUEST, OCSP_REQUEST));
        assertTrue(TlsMessageParser.clientHelloRequestsOcsp(ch), "запрос OCSP должен быть замечен");
    }

    @Test
    @DisplayName("clientHelloRequestsOcsp: расширения нет -> false")
    void ocspNotRequestedWithoutExtension() throws TlsException {
        byte[] ch = clientHello(ext(TlsConstants.EXT_SUPPORTED_GROUPS, new byte[] {0, 0}));
        assertFalse(TlsMessageParser.clientHelloRequestsOcsp(ch), "запроса OCSP нет");
    }

    @Test
    @DisplayName("clientHelloRequestsOcsp: неизвестный status_type -> false без ошибки")
    // RFC 8446 §4.2: неизвестные варианты игнорируются, а не рвут соединение.
    void unknownStatusTypeIgnored() throws TlsException {
        byte[] ch = clientHello(ext(TlsConstants.EXT_STATUS_REQUEST, new byte[] {2, 0x7F}));
        assertFalse(TlsMessageParser.clientHelloRequestsOcsp(ch));
    }

    @Test
    @DisplayName("clientHelloRequestsOcsp: байты после request_extensions -> decode_error")
    void trailingBytesInStatusRequestRejected() {
        byte[] ch =
                clientHello(ext(TlsConstants.EXT_STATUS_REQUEST, new byte[] {1, 0, 0, 0, 0, 0x55}));
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.clientHelloRequestsOcsp(ch));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName(
            "clientHelloRequestsOcsp: обрезанная структура и пустое расширение -> decode_error")
    void truncatedStatusRequestRejected() {
        for (byte[] data : new byte[][] {{1, 0}, {1, 0, 5, 0}, {}}) {
            byte[] ch = clientHello(ext(TlsConstants.EXT_STATUS_REQUEST, data));
            TlsException ex =
                    assertThrows(
                            TlsException.class, () -> TlsMessageParser.clientHelloRequestsOcsp(ch));
            assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
        }
    }
}
