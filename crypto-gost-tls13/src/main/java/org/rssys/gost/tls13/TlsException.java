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
    private final boolean fromPeer;

    /**
     * @param alertCode код fatal alert (RFC 8446 §6)
     * @param message   описание ошибки
     */
    public TlsException(byte alertCode, String message) {
        super(message);
        this.alertCode = alertCode;
        this.fromPeer = false;
    }

    /**
     * @param alertCode код fatal alert (RFC 8446 §6)
     * @param message   описание ошибки
     * @param cause     причина (например, IOException из транспорта)
     */
    public TlsException(byte alertCode, String message, Throwable cause) {
        super(message, cause);
        this.alertCode = alertCode;
        this.fromPeer = false;
    }

    private TlsException(byte alertCode, String message, boolean fromPeer) {
        super(message);
        this.alertCode = alertCode;
        this.fromPeer = fromPeer;
    }

    /**
     * Создаёт исключение для fatal alert, полученного от пира.
     * <p>
     * На такое исключение ответного alert отправлять нельзя (RFC 8446 §6): пир уже закрыл
     * соединение, а отражённый обратно код только вводил бы в заблуждение.
     *
     * @param alertCode код alert, присланный пиром
     * @param message   описание
     * @return исключение с признаком {@link #isFromPeer()}
     */
    public static TlsException fromPeer(byte alertCode, String message) {
        return new TlsException(alertCode, message, true);
    }

    /**
     * @return {@code true}, если это fatal alert, присланный пиром, а не нарушение, найденное
     *         локально; ответный alert на него не отправляется
     */
    public boolean isFromPeer() {
        return fromPeer;
    }

    /** @return код fatal alert (RFC 8446 §6.1), напр. ALERT_DECRYPT_ERROR (51) */
    public byte getAlertCode() {
        return alertCode;
    }
}
