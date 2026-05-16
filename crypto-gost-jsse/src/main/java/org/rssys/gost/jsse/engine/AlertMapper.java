package org.rssys.gost.jsse.engine;

import org.rssys.gost.tls13.TlsConstants;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import java.io.EOFException;

/**
 * Маппинг TLS-alert кода на соответствующий подкласс SSLException.
 * Принцип: fail-closed — любое нарушение протокола даёт конкретное исключение.
 */
public final class AlertMapper {

    private AlertMapper() {}

    /**
     * Преобразует TLS-alert в SSLException.
     *
     * @param alertCode  код alert-описания (например 40 = handshake_failure)
     * @param message    дополнительное сообщение (может быть null)
     * @return SSLException соответствующего типа
     */
    public static SSLException toException(byte alertCode, String message) {
        String msg = (message != null) ? message : "Received fatal alert: " + (alertCode & 0xFF);
        switch (alertCode) {
            case TlsConstants.CLOSE_NOTIFY:
                return new SSLException("Peer closed connection (close_notify)");
            case TlsConstants.ALERT_HANDSHAKE_FAILURE:
                return new SSLHandshakeException(msg);
            case TlsConstants.ALERT_BAD_CERTIFICATE:
            case TlsConstants.ALERT_CERTIFICATE_EXPIRED:
                return new SSLPeerUnverifiedException(msg);
            case TlsConstants.ALERT_DECRYPT_ERROR:
            case TlsConstants.ALERT_UNEXPECTED_MESSAGE:
            case TlsConstants.ALERT_ILLEGAL_PARAMETER:
            case TlsConstants.ALERT_DECODE_ERROR:
            case TlsConstants.ALERT_RECORD_OVERFLOW:
            case TlsConstants.ALERT_MISSING_EXTENSION:
            case TlsConstants.ALERT_CERTIFICATE_REQUIRED:
            case TlsConstants.ALERT_NO_APPLICATION_PROTOCOL:
                return new SSLProtocolException(msg);
            case TlsConstants.ALERT_INTERNAL_ERROR:
            default:
                return new SSLException(msg);
        }
    }

    /**
     * Определяет, является ли alert fatal.
     * В TLS 1.3 все alert'ы кроме close_notify считаются fatal (RFC 8446 §6).
     */
    public static boolean isFatal(byte alertCode) {
        return alertCode != TlsConstants.CLOSE_NOTIFY;
    }
}
