package org.rssys.gost.tls13;

/**
 * Имена TLS-alert по коду для журнала (RFC 8446 §6).
 *
 * <p>Запись должна быть понятна без RFC: {@code bad_certificate (42)}. Неизвестный код не
 * теряется - выводится как {@code unknown (0x2a)}. Таблица одна на tls13 и jsse, чтобы
 * {@code close_notify} и остальные коды не обрабатывались в разных местах по-разному.
 */
public final class TlsAlerts {

    private TlsAlerts() {}

    /**
     * IANA-имя alert по коду.
     *
     * @param code код alert (RFC 8446 §6)
     * @return имя, {@code unknown} для неизвестного кода
     */
    public static String name(byte code) {
        return switch (code & 0xFF) {
            case TlsConstants.CLOSE_NOTIFY -> "close_notify";
            case TlsConstants.ALERT_UNEXPECTED_MESSAGE -> "unexpected_message";
            case TlsConstants.ALERT_BAD_RECORD_MAC -> "bad_record_mac";
            case TlsConstants.ALERT_RECORD_OVERFLOW -> "record_overflow";
            case TlsConstants.ALERT_HANDSHAKE_FAILURE -> "handshake_failure";
            case TlsConstants.ALERT_BAD_CERTIFICATE -> "bad_certificate";
            case TlsConstants.ALERT_UNSUPPORTED_CERTIFICATE -> "unsupported_certificate";
            case TlsConstants.ALERT_CERTIFICATE_REVOKED -> "certificate_revoked";
            case TlsConstants.ALERT_CERTIFICATE_EXPIRED -> "certificate_expired";
            case TlsConstants.ALERT_CERTIFICATE_UNKNOWN -> "certificate_unknown";
            case TlsConstants.ALERT_ILLEGAL_PARAMETER -> "illegal_parameter";
            case TlsConstants.ALERT_UNKNOWN_CA -> "unknown_ca";
            case TlsConstants.ALERT_ACCESS_DENIED -> "access_denied";
            case TlsConstants.ALERT_DECODE_ERROR -> "decode_error";
            case TlsConstants.ALERT_DECRYPT_ERROR -> "decrypt_error";
            case TlsConstants.ALERT_PROTOCOL_VERSION -> "protocol_version";
            case TlsConstants.ALERT_INSUFFICIENT_SECURITY -> "insufficient_security";
            case TlsConstants.ALERT_INTERNAL_ERROR -> "internal_error";
            case TlsConstants.ALERT_INAPPROPRIATE_FALLBACK -> "inappropriate_fallback";
            case TlsConstants.ALERT_USER_CANCELED -> "user_canceled";
            case TlsConstants.ALERT_MISSING_EXTENSION -> "missing_extension";
            case TlsConstants.ALERT_UNSUPPORTED_EXTENSION -> "unsupported_extension";
            case TlsConstants.ALERT_UNRECOGNIZED_NAME -> "unrecognized_name";
            case TlsConstants.ALERT_BAD_CERTIFICATE_STATUS_RESPONSE ->
                    "bad_certificate_status_response";
            case TlsConstants.ALERT_UNKNOWN_PSK_IDENTITY -> "unknown_psk_identity";
            case TlsConstants.ALERT_CERTIFICATE_REQUIRED -> "certificate_required";
            case TlsConstants.ALERT_NO_APPLICATION_PROTOCOL -> "no_application_protocol";
            default -> "unknown";
        };
    }

    /**
     * Код и имя alert для журнала.
     *
     * @param code код alert
     * @return {@code bad_certificate (42)} или {@code unknown (0x2a)}
     */
    public static String forLog(int code) {
        int value = code & 0xFF;
        String name = name((byte) value);
        if ("unknown".equals(name)) {
            return name + " (0x" + String.format("%02x", value) + ")";
        }
        return name + " (" + value + ")";
    }
}
