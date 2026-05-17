package org.rssys.gost.jsse;

/**
 * Исключение, выбрасываемое методами {@link GostSsl} при ошибках
 * конфигурации TLS или неудаче проверки соединения.
 */
public class GostSslException extends RuntimeException {
    public GostSslException(String message) {
        super(message);
    }

    public GostSslException(String message, Throwable cause) {
        super(message, cause);
    }
}
