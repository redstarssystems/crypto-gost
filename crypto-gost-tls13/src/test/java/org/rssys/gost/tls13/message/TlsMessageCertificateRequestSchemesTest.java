package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.ClientCertificateRequest;

/**
 * Схемы подписи в CertificateRequest (RFC 8446 §4.2.3, §4.3.2): разбор хранит весь список, а
 * решение «подходит ли наша схема» принимает движок. Структурные нарушения это
 * {@code decode_error}, отсутствие расширения это {@code missing_extension}.
 */
@DisplayName("Парсер CertificateRequest: схемы подписи")
class TlsMessageCertificateRequestSchemesTest {

    private static byte[] body(byte[] extensions) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0);
        out.write(extensions.length >>> 8);
        out.write(extensions.length);
        out.writeBytes(extensions);
        return out.toByteArray();
    }

    /** Расширение signature_algorithms с произвольным телом. */
    private static byte[] signatureAlgorithmsExtension(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(TlsConstants.EXT_SIGNATURE_ALGORITHMS >>> 8);
        out.write(TlsConstants.EXT_SIGNATURE_ALGORITHMS);
        out.write(data.length >>> 8);
        out.write(data.length);
        out.writeBytes(data);
        return out.toByteArray();
    }

    private static byte[] list(int... schemes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((2 * schemes.length) >>> 8);
        out.write(2 * schemes.length);
        for (int scheme : schemes) {
            out.write(scheme >>> 8);
            out.write(scheme);
        }
        return out.toByteArray();
    }

    private static byte[] request(byte[] extensionData) {
        return body(signatureAlgorithmsExtension(extensionData));
    }

    @Test
    @DisplayName("весь список сохраняется в порядке сервера, включая неизвестные коды")
    void listIsKeptInServerOrder() throws Exception {
        int[] schemes = {0x0403, TlsConstants.SIG_GOST_TC26_A_256, 0xFFFF};

        ClientCertificateRequest info =
                TlsMessageParser.parseCertificateRequest(request(list(schemes)));

        assertArrayEquals(schemes, info.signatureSchemes());
    }

    @Test
    @DisplayName("только чужие схемы: не ошибка разбора (клиент отправит пустой Certificate)")
    void foreignSchemesAreNotAParserError() throws Exception {
        ClientCertificateRequest info =
                TlsMessageParser.parseCertificateRequest(request(list(0x0403, 0x0804)));

        assertArrayEquals(new int[] {0x0403, 0x0804}, info.signatureSchemes());
    }

    @Test
    @DisplayName("массив схем копируется: правка возвращённого массива запись не меняет")
    void schemesAreCopied() throws Exception {
        ClientCertificateRequest info =
                TlsMessageParser.parseCertificateRequest(
                        request(list(TlsConstants.SIG_GOST_TC26_A_256)));

        int[] first = info.signatureSchemes();
        first[0] = 0;

        assertNotSame(first, info.signatureSchemes());
        assertEquals(TlsConstants.SIG_GOST_TC26_A_256, info.signatureSchemes()[0]);
    }

    @Test
    @DisplayName("пустой, нечётный, усечённый и с хвостом список: decode_error")
    void malformedListIsDecodeError() {
        byte[][] bodies = {
            // пустой список (раньше handshake_failure)
            {0x00, 0x00},
            // нечётная длина
            {0x00, 0x03, 0x07, 0x09, 0x07},
            // длина больше фактической
            {0x00, 0x04, 0x07, 0x09},
            // мусор в хвосте
            {0x00, 0x02, 0x07, 0x09, 0x07},
            // расширение из одного байта (раньше handshake_failure)
            {0x07},
            // расширение нулевой длины
            {}
        };
        for (byte[] data : bodies) {
            TlsException error =
                    assertThrows(
                            TlsException.class,
                            () -> TlsMessageParser.parseCertificateRequest(request(data)));

            assertEquals(
                    TlsConstants.ALERT_DECODE_ERROR,
                    error.getAlertCode(),
                    "Тело длиной " + data.length + ": " + error.getMessage());
        }
    }

    /** Расширение signature_algorithms_cert с заданным списком. */
    private static byte[] certExtension(byte[] data) {
        byte[] ext = signatureAlgorithmsExtension(data);
        ext[0] = (byte) (TlsConstants.EXT_SIGNATURE_ALGORITHMS_CERT >>> 8);
        ext[1] = (byte) TlsConstants.EXT_SIGNATURE_ALGORITHMS_CERT;
        return ext;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(first);
        out.writeBytes(second);
        return out.toByteArray();
    }

    @Test
    @DisplayName("без signature_algorithms_cert схемы цепочки совпадают с signature_algorithms")
    void chainSchemesDefaultToSignatureAlgorithms() throws Exception {
        ClientCertificateRequest info =
                TlsMessageParser.parseCertificateRequest(
                        request(list(TlsConstants.SIG_GOST_TC26_A_256, 0x0403)));

        assertArrayEquals(info.signatureSchemes(), info.certificateSignatureSchemes());
    }

    @Test
    @DisplayName("signature_algorithms_cert задаёт схемы цепочки отдельно от CertificateVerify")
    void certExtensionGivesChainSchemes() throws Exception {
        byte[] extensions =
                concat(
                        signatureAlgorithmsExtension(list(TlsConstants.SIG_GOST_TC26_A_256)),
                        certExtension(list(TlsConstants.SIG_GOST_TC26_512_A)));

        ClientCertificateRequest info = TlsMessageParser.parseCertificateRequest(body(extensions));

        assertArrayEquals(new int[] {TlsConstants.SIG_GOST_TC26_A_256}, info.signatureSchemes());
        assertArrayEquals(
                new int[] {TlsConstants.SIG_GOST_TC26_512_A}, info.certificateSignatureSchemes());
    }

    @Test
    @DisplayName("битый signature_algorithms_cert: decode_error")
    void malformedCertExtensionIsDecodeError() {
        byte[] extensions =
                concat(
                        signatureAlgorithmsExtension(list(TlsConstants.SIG_GOST_TC26_A_256)),
                        certExtension(new byte[] {0x00, 0x00}));

        TlsException error =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parseCertificateRequest(body(extensions)));

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
    }

    @Test
    @DisplayName("повтор signature_algorithms или signature_algorithms_cert: illegal_parameter")
    void duplicateExtensionIsIllegalParameter() {
        byte[] sigAlgs = signatureAlgorithmsExtension(list(TlsConstants.SIG_GOST_TC26_A_256));
        byte[] cert = certExtension(list(TlsConstants.SIG_GOST_TC26_A_256));
        byte[][] bodies = {
            body(concat(sigAlgs, sigAlgs)), body(concat(concat(sigAlgs, cert), cert))
        };
        for (byte[] request : bodies) {
            TlsException error =
                    assertThrows(
                            TlsException.class,
                            () -> TlsMessageParser.parseCertificateRequest(request));

            assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, error.getAlertCode());
        }
    }

    @Test
    @DisplayName("нет signature_algorithms: missing_extension")
    void absentExtensionIsMissingExtension() {
        TlsException error =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseCertificateRequest(
                                        // только неизвестное расширение 0x4A4A из одного байта
                                        body(new byte[] {0x4A, 0x4A, 0x00, 0x01, 0x00})));

        assertEquals(TlsConstants.ALERT_MISSING_EXTENSION, error.getAlertCode());
    }
}
