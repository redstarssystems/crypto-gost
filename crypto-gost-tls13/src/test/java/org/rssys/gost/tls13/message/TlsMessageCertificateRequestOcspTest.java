package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.OIDFilter;

/** status_request в CertificateRequest: запрос staple клиента (RFC 8446 §4.4.2.1). */
@DisplayName("CertificateRequest: запрос OCSP-staple (status_request)")
class TlsMessageCertificateRequestOcspTest {

    private static final byte[] EMPTY_STATUS_REQUEST = {0x00, 0x05, 0x00, 0x00};

    @Test
    @DisplayName("Без запроса байты прежние; с запросом в конец добавляется 00 05 00 00")
    void wireVector() {
        byte[] plain = TlsMessageBuilder.buildCertificateRequest();
        byte[] withOcsp = TlsMessageBuilder.buildCertificateRequest(null, true);

        assertArrayEquals(plain, TlsMessageBuilder.buildCertificateRequest(null, false));
        assertEquals(plain.length + EMPTY_STATUS_REQUEST.length, withOcsp.length);
        assertArrayEquals(
                EMPTY_STATUS_REQUEST,
                Arrays.copyOfRange(withOcsp, withOcsp.length - 4, withOcsp.length),
                "пустое status_request должно стоять после signature_algorithms");
        int extLen = ((withOcsp[1] & 0xFF) << 8) | (withOcsp[2] & 0xFF);
        assertEquals(withOcsp.length - 3, extLen, "длина блока extensions должна включать запрос");
    }

    @Test
    @DisplayName("Парсер: ocspRequested выставляется только при status_request")
    void parserFlag() throws TlsException {
        assertFalse(
                TlsMessageParser.parseCertificateRequest(
                                TlsMessageBuilder.buildCertificateRequest())
                        .ocspRequested());
        assertTrue(
                TlsMessageParser.parseCertificateRequest(
                                TlsMessageBuilder.buildCertificateRequest(null, true))
                        .ocspRequested());
    }

    @Test
    @DisplayName("Запрос сочетается с oid_filters")
    void withOidFilters() throws TlsException {
        List<OIDFilter> filters =
                List.of(new OIDFilter(new byte[] {0x55, 0x1D, 0x0F}, new byte[0]));
        ClientCertificateRequest info =
                TlsMessageParser.parseCertificateRequest(
                        TlsMessageBuilder.buildCertificateRequest(filters, true));
        assertTrue(info.ocspRequested());
        assertEquals(1, info.oidFilters().size());
    }

    @Test
    @DisplayName("Непустое тело status_request -> decode_error")
    // Форма CertificateStatusRequest из ClientHello для CertificateRequest не определена.
    void nonEmptyBodyRejected() {
        byte[] ok = TlsMessageBuilder.buildCertificateRequest(null, true);
        // Заменяем пустое расширение на status_request с одним байтом тела.
        byte[] bad = Arrays.copyOf(ok, ok.length + 1);
        bad[ok.length - 1] = 0x01; // длина тела = 1
        bad[ok.length] = 0x01;
        int extLen = ((bad[1] & 0xFF) << 8) | (bad[2] & 0xFF);
        bad[2] = (byte) (extLen + 1);
        TlsException e =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parseCertificateRequest(bad));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, e.getAlertCode());
    }
}
