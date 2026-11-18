package org.rssys.gost.jsse;

/**
 * Исключение, выбрасываемое методами {@link GostSsl} при ошибках
 * конфигурации TLS или неудаче проверки соединения.
 */
public final class GostSslException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Создаёт исключение с сообщением.
     *
     * @param message описание ошибки
     */
    public GostSslException(String message) {
        super(message);
    }

    /**
     * Создаёт исключение с сообщением и причиной.
     *
     * @param message описание ошибки
     * @param cause   исходное исключение
     */
    public GostSslException(String message, Throwable cause) {
        super(message, cause);
    }
}
