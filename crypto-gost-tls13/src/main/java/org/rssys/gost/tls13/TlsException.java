package org.rssys.gost.tls13;

import java.io.IOException;

/**
 * TLS-исключение с кодом алерта (RFC 8446 §6).
 * <p>
 * Каждый {@code throw new TlsException(alertCode, message)} явно указывает,
 * какой fatal alert должна получить удалённая сторона. {@code sendAlert()}
 * читает код напрямую, без хрупкого строкового маппинга.
 */
public final class TlsException extends IOException {
    private final byte alertCode;

    /**
     * @param alertCode код fatal alert (RFC 8446 §6)
     * @param message   описание ошибки
     */
    public TlsException(byte alertCode, String message) {
        super(message);
        this.alertCode = alertCode;
    }

    /**
     * @param alertCode код fatal alert (RFC 8446 §6)
     * @param message   описание ошибки
     * @param cause     причина (например, IOException из транспорта)
     */
    public TlsException(byte alertCode, String message, Throwable cause) {
        super(message, cause);
        this.alertCode = alertCode;
    }

    /** @return код fatal alert (RFC 8446 §6.1), напр. ALERT_DECRYPT_ERROR (51) */
    public byte getAlertCode() {
        return alertCode;
    }
}
