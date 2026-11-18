package org.rssys.gost.pkix.util;

import java.io.IOException;

/**
 * Общий срок операции (соединение, заголовки, тело, перенаправления) вышел.
 *
 * <p>Отдельный тип нужен вызывающему, чтобы отличать срок от обычной сетевой ошибки.
 */
public final class DeadlineExceededException extends IOException {

    private static final long serialVersionUID = 1L;

    public DeadlineExceededException(String message) {
        super(message);
    }

    public DeadlineExceededException(String message, Throwable cause) {
        super(message, cause);
    }
}
