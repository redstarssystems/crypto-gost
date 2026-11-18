package org.rssys.gost.jsse.engine;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Маппинг TLS-alert кода на соответствующий подкласс SSLException.
 * <p>
 * Таблица повторяет JDK ({@code sun.security.ssl.Alert#createSSLException}): класс исключения
 * определяется самим алертом, а не фазой соединения.
 * <ul>
 *   <li>{@code unexpected_message} и неизвестный код - {@link SSLProtocolException} (JDK подменяет
 *       неизвестный код на {@code unexpected_message});</li>
 *   <li>алерты, возможные только в рукопожатии (в том числе сертификатные, {@code decrypt_error},
 *       {@code protocol_version}), - {@link SSLHandshakeException}; JDK отказ по сертификату тоже
 *       отдаёт как {@code SSLHandshakeException}, а не {@code SSLPeerUnverifiedException};</li>
 *   <li>остальные ({@code bad_record_mac}, {@code record_overflow}, {@code internal_error},
 *       {@code inappropriate_fallback}, {@code user_canceled}) - {@link SSLException}.</li>
 * </ul>
 * Принцип: fail-closed - любое нарушение протокола даёт конкретное исключение. Ветка JDK
 * {@code cause instanceof IOException -> SSLException} не воспроизводится: класс исключения
 * определяется только кодом алерта. Исходное исключение стека прикладывается как причина, чтобы
 * по трассе было видно, где именно нарушен протокол (как и в JDK).
 */
public final class AlertMapper {

    private AlertMapper() {}

    /**
     * Преобразует TLS-alert в SSLException.
     *
     * @param alertCode  код alert-описания (например 40 = handshake_failure)
     * @param message    дополнительное сообщение (может быть null)
     * @param cause      исходное исключение стека (TlsException) или null, если алерт пришёл от пира
     * @return SSLException соответствующего типа с приложенной причиной
     */
    public static SSLException toException(byte alertCode, String message, Throwable cause) {
        SSLException exception = create(alertCode, message);
        if (cause != null) {
            exception.initCause(cause);
        }
        return exception;
    }

    private static SSLException create(byte alertCode, String message) {
        String msg = (message != null) ? message : "Received fatal alert: " + (alertCode & 0xFF);
        switch (alertCode) {
            case TlsConstants.ALERT_HANDSHAKE_FAILURE:
            case TlsConstants.ALERT_BAD_CERTIFICATE:
            case TlsConstants.ALERT_UNSUPPORTED_CERTIFICATE:
            case TlsConstants.ALERT_CERTIFICATE_REVOKED:
            case TlsConstants.ALERT_CERTIFICATE_EXPIRED:
            case TlsConstants.ALERT_CERTIFICATE_UNKNOWN:
            case TlsConstants.ALERT_ILLEGAL_PARAMETER:
            case TlsConstants.ALERT_UNKNOWN_CA:
            case TlsConstants.ALERT_ACCESS_DENIED:
            case TlsConstants.ALERT_DECODE_ERROR:
            case TlsConstants.ALERT_DECRYPT_ERROR:
            case TlsConstants.ALERT_PROTOCOL_VERSION:
            case TlsConstants.ALERT_INSUFFICIENT_SECURITY:
            case TlsConstants.ALERT_MISSING_EXTENSION:
            case TlsConstants.ALERT_UNSUPPORTED_EXTENSION:
            case TlsConstants.ALERT_UNRECOGNIZED_NAME:
            case TlsConstants.ALERT_BAD_CERTIFICATE_STATUS_RESPONSE:
            case TlsConstants.ALERT_UNKNOWN_PSK_IDENTITY:
            case TlsConstants.ALERT_CERTIFICATE_REQUIRED:
            case TlsConstants.ALERT_NO_APPLICATION_PROTOCOL:
                return new SSLHandshakeException(msg);
            case TlsConstants.ALERT_BAD_RECORD_MAC:
            case TlsConstants.ALERT_RECORD_OVERFLOW:
            case TlsConstants.ALERT_INTERNAL_ERROR:
            case TlsConstants.ALERT_INAPPROPRIATE_FALLBACK:
            case TlsConstants.ALERT_USER_CANCELED:
                return new SSLException(msg);
            case TlsConstants.ALERT_UNEXPECTED_MESSAGE:
            default:
                // Неизвестный код JDK подменяет на unexpected_message
                return new SSLProtocolException(msg);
        }
    }
}
