package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Расширение max_fragment_length (RFC 6066 §4) на стороне разбора. Неверная длина тела - ошибка
 * формата (decode_error), а недопустимый код при верной длине - illegal_parameter: так сервер
 * обязан ответить на запрос с кодом не из 1..4, а клиент - на ответ, который отличается от
 * запрошенного.
 */
@DisplayName("TlsMessageParser: max_fragment_length, коды alert")
class TlsMessageParserMaxFragmentLengthTest {

    private static final Set<Integer> MAX_FRAGMENT_LENGTH_SENT =
            Set.of(TlsConstants.EXT_MAX_FRAGMENT_LENGTH);

    private static byte[] clientHelloWithMaxFragment(byte[] extensionBody) throws Exception {
        return TlsMessageParserTest.buildClientHelloBody(
                0x0303,
                new byte[0],
                TlsMessageParserTest.csBytes(0xC103),
                new byte[] {0x00},
                TlsMessageParserTest.svExt(),
                TlsMessageParserTest.saExt(),
                TlsMessageParserTest.ksExt(TlsConstants.GRP_GC256A),
                TlsMessageParserTest.encodeExt(
                        TlsConstants.EXT_MAX_FRAGMENT_LENGTH, extensionBody));
    }

    private static byte[] encryptedExtensionsWithMaxFragment(byte[] extensionBody) {
        byte[] ext =
                TlsMessageParserTest.encodeExt(TlsConstants.EXT_MAX_FRAGMENT_LENGTH, extensionBody);
        byte[] body = new byte[2 + ext.length];
        body[0] = (byte) (ext.length >>> 8);
        body[1] = (byte) ext.length;
        System.arraycopy(ext, 0, body, 2, ext.length);
        return body;
    }

    private static int clientHelloAlert(byte[] extensionBody) throws Exception {
        byte[] body = clientHelloWithMaxFragment(extensionBody);
        return assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A),
                        "ClientHello с неверным max_fragment_length должен быть отвергнут")
                .getAlertCode();
    }

    private static int encryptedExtensionsAlert(byte[] extensionBody) {
        byte[] body = encryptedExtensionsWithMaxFragment(extensionBody);
        return assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseEncryptedExtensions(
                                        body, MAX_FRAGMENT_LENGTH_SENT),
                        "EncryptedExtensions с неверным max_fragment_length отвергаются")
                .getAlertCode();
    }

    // ---- ClientHello (сервер разбирает запрос клиента) ----

    @ParameterizedTest(name = "код {0} в ClientHello -> illegal_parameter")
    @ValueSource(ints = {0, 5, 255})
    @DisplayName("ClientHello: недопустимый код -> illegal_parameter")
    void clientHelloInvalidCode(int code) throws Exception {
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                clientHelloAlert(new byte[] {(byte) code}),
                "RFC 6066 §4: код не из 1..4 -> illegal_parameter");
    }

    @ParameterizedTest(name = "тело из {0} байт в ClientHello -> decode_error")
    @ValueSource(ints = {0, 2})
    @DisplayName("ClientHello: длина тела не 1 -> decode_error")
    void clientHelloWrongLength(int length) throws Exception {
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                clientHelloAlert(new byte[length]),
                "Неверная длина расширения - ошибка формата");
    }

    @ParameterizedTest(name = "код {0} в ClientHello принимается")
    @ValueSource(ints = {1, 2, 3, 4})
    @DisplayName("ClientHello: коды 1..4 принимаются")
    void clientHelloValidCode(int code) throws Exception {
        byte[] body = clientHelloWithMaxFragment(new byte[] {(byte) code});
        assertEquals(
                code,
                TlsMessageParser.parseClientHello(body, TlsConstants.GRP_GC256A).clientMaxFragLen);
    }

    // ---- EncryptedExtensions (клиент разбирает ответ сервера) ----

    @ParameterizedTest(name = "код {0} в EncryptedExtensions -> illegal_parameter")
    @ValueSource(ints = {0, 5, 255})
    @DisplayName("EncryptedExtensions: недопустимый код -> illegal_parameter")
    void encryptedExtensionsInvalidCode(int code) {
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                encryptedExtensionsAlert(new byte[] {(byte) code}),
                "Код вне 1..4 не может быть тем, что клиент запрашивал");
    }

    @ParameterizedTest(name = "тело из {0} байт в EncryptedExtensions -> decode_error")
    @ValueSource(ints = {0, 2})
    @DisplayName("EncryptedExtensions: длина тела не 1 -> decode_error")
    void encryptedExtensionsWrongLength(int length) {
        assertEquals(
                TlsConstants.ALERT_DECODE_ERROR,
                encryptedExtensionsAlert(new byte[length]),
                "Неверная длина расширения - ошибка формата");
    }

    @ParameterizedTest(name = "код {0} в EncryptedExtensions принимается")
    @ValueSource(ints = {1, 2, 3, 4})
    @DisplayName("EncryptedExtensions: коды 1..4 принимаются")
    void encryptedExtensionsValidCode(int code) throws Exception {
        byte[] body = encryptedExtensionsWithMaxFragment(new byte[] {(byte) code});
        assertEquals(
                code,
                TlsMessageParser.parseEncryptedExtensions(body, MAX_FRAGMENT_LENGTH_SENT)
                        .maxFragLen);
    }
}
