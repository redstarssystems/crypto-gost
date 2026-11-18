package org.rssys.gost.util;

import java.io.IOException;

/**
 * Ошибка аутентификации при чтении через {@link java.io.InputStream}: поток повреждён, подменён
 * или усечён.
 *
 * <p>{@code InputStream.read} может бросать только {@link IOException}, поэтому
 * {@link AuthenticationException} (проверяемое исключение, не наследующее {@code IOException})
 * приходит из потока завёрнутой в это исключение. Отдельный тип нужен, чтобы вызывающий отличал
 * атаку или порчу данных от обычной ошибки ввода-вывода (обрыв сети, закрытый файл): первую нельзя
 * повторять, вторую можно. Исходная причина доступна через {@link #getCause()}.
 */
public class AuthenticationIOException extends IOException {

    /**
     * @param message описание нарушения целостности
     * @param cause   исходная ошибка аутентификации
     */
    public AuthenticationIOException(String message, AuthenticationException cause) {
        super(message, cause);
    }
}
