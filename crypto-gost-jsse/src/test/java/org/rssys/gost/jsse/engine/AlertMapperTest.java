package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

/**
 * Таблица отображения алертов повторяет JDK ({@code sun.security.ssl.Alert}): класс исключения
 * задаёт сам алерт, фаза соединения не учитывается.
 */
@DisplayName("AlertMapper: маппинг TLS-alert в SSLException по таблице JDK")
class AlertMapperTest {

    /** Алерты, которые JDK помечает как «только для рукопожатия»: {@code SSLHandshakeException}. */
    private static final Map<String, Byte> HANDSHAKE_ALERTS =
            Map.ofEntries(
                    Map.entry("handshake_failure", TlsConstants.ALERT_HANDSHAKE_FAILURE),
                    Map.entry("bad_certificate", TlsConstants.ALERT_BAD_CERTIFICATE),
                    Map.entry(
                            "unsupported_certificate", TlsConstants.ALERT_UNSUPPORTED_CERTIFICATE),
                    Map.entry("certificate_revoked", TlsConstants.ALERT_CERTIFICATE_REVOKED),
                    Map.entry("certificate_expired", TlsConstants.ALERT_CERTIFICATE_EXPIRED),
                    Map.entry("certificate_unknown", TlsConstants.ALERT_CERTIFICATE_UNKNOWN),
                    Map.entry("illegal_parameter", TlsConstants.ALERT_ILLEGAL_PARAMETER),
                    Map.entry("unknown_ca", TlsConstants.ALERT_UNKNOWN_CA),
                    Map.entry("access_denied", TlsConstants.ALERT_ACCESS_DENIED),
                    Map.entry("decode_error", TlsConstants.ALERT_DECODE_ERROR),
                    Map.entry("decrypt_error", TlsConstants.ALERT_DECRYPT_ERROR),
                    Map.entry("protocol_version", TlsConstants.ALERT_PROTOCOL_VERSION),
                    Map.entry("insufficient_security", TlsConstants.ALERT_INSUFFICIENT_SECURITY),
                    Map.entry("missing_extension", TlsConstants.ALERT_MISSING_EXTENSION),
                    Map.entry("unsupported_extension", TlsConstants.ALERT_UNSUPPORTED_EXTENSION),
                    Map.entry("unrecognized_name", TlsConstants.ALERT_UNRECOGNIZED_NAME),
                    Map.entry(
                            "bad_certificate_status_response",
                            TlsConstants.ALERT_BAD_CERTIFICATE_STATUS_RESPONSE),
                    Map.entry("unknown_psk_identity", TlsConstants.ALERT_UNKNOWN_PSK_IDENTITY),
                    Map.entry("certificate_required", TlsConstants.ALERT_CERTIFICATE_REQUIRED),
                    Map.entry(
                            "no_application_protocol", TlsConstants.ALERT_NO_APPLICATION_PROTOCOL));

    /** Алерты без признака «только для рукопожатия»: общий {@code SSLException}. */
    private static final Map<String, Byte> GENERIC_ALERTS =
            Map.of(
                    "bad_record_mac", TlsConstants.ALERT_BAD_RECORD_MAC,
                    "record_overflow", TlsConstants.ALERT_RECORD_OVERFLOW,
                    "internal_error", TlsConstants.ALERT_INTERNAL_ERROR,
                    "inappropriate_fallback", TlsConstants.ALERT_INAPPROPRIATE_FALLBACK,
                    "user_canceled", TlsConstants.ALERT_USER_CANCELED);

    @Test
    @DisplayName(
            "Алерты рукопожатия, в том числе сертификатные и decrypt_error -> SSLHandshakeException")
    void handshakeAlertsMapToHandshakeException() {
        HANDSHAKE_ALERTS.forEach(
                (name, code) -> {
                    SSLException ex = AlertMapper.toException(code, "msg " + name, null);
                    assertInstanceOf(
                            SSLHandshakeException.class,
                            ex,
                            name + " должен давать SSLHandshakeException");
                    assertTrue(
                            ex.getMessage().contains("msg " + name),
                            "сообщение alert должно сохраняться: " + name);
                });
    }

    @Test
    @DisplayName("bad_record_mac, record_overflow, internal_error и др. -> общий SSLException")
    void genericAlertsMapToPlainSslException() {
        GENERIC_ALERTS.forEach(
                (name, code) -> {
                    SSLException ex = AlertMapper.toException(code, "msg " + name, null);
                    assertEquals(
                            SSLException.class,
                            ex.getClass(),
                            name + " должен давать именно SSLException, без подкласса");
                });
    }

    @Test
    @DisplayName("unexpected_message даёт SSLProtocolException")
    void unexpectedMessageMapsToProtocolException() {
        SSLException ex =
                AlertMapper.toException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "unexpected", null);

        assertInstanceOf(
                SSLProtocolException.class,
                ex,
                "unexpected_message должен давать SSLProtocolException");
    }

    @Test
    @DisplayName("Неизвестный код -> SSLProtocolException, как unexpected_message в JDK")
    void unknownCodeMapsToProtocolException() {
        for (int code : new int[] {21, 30, 41, 60, 100, 111, 114, 255}) {
            SSLException ex = AlertMapper.toException((byte) code, "unknown " + code, null);
            assertInstanceOf(
                    SSLProtocolException.class,
                    ex,
                    "неизвестный код " + code + " должен давать SSLProtocolException");
        }
    }

    @Test
    @DisplayName("Сообщение по умолчанию содержит код алерта")
    void defaultMessageContainsAlertCode() {
        SSLException ex = AlertMapper.toException(TlsConstants.ALERT_DECRYPT_ERROR, null, null);

        assertTrue(ex.getMessage().contains("51"), "сообщение должно содержать код алерта");
    }

    @Test
    @DisplayName("Исходное исключение стека прикладывается как причина; без него причины нет")
    void causeIsAttached() {
        TlsException origin =
                new TlsException(
                        TlsConstants.ALERT_DECRYPT_ERROR, "PSK binder verification failed");

        SSLException withCause =
                AlertMapper.toException(origin.getAlertCode(), origin.getMessage(), origin);
        SSLException withoutCause =
                AlertMapper.toException(TlsConstants.ALERT_DECRYPT_ERROR, "от пира", null);

        assertSame(origin, withCause.getCause(), "по трассе должно быть видно исходное нарушение");
        assertNull(withoutCause.getCause(), "алерт от пира причины не имеет");
    }
}
