package org.rssys.gost.tls13;

import java.io.EOFException;

/**
 * Пир штатно закрыл соединение, прислав {@code close_notify} (RFC 8446 §6.1).
 * <p>
 * Наследует {@link EOFException}, поэтому прежний контракт {@code read()} («{@code EOFException}
 * при закрытии пиром») сохраняется. Отдельный тип нужен, чтобы отличать закрытие пиром от обрыва
 * транспорта: обрыв тоже приходит как {@code EOFException}, но на него ответный {@code close_notify}
 * отправлять нельзя.
 */
public final class PeerClosedException extends EOFException {

    /** @param message описание */
    public PeerClosedException(String message) {
        super(message);
    }
}
