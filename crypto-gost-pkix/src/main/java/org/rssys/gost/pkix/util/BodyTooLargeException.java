package org.rssys.gost.pkix.util;

import java.io.IOException;

/**
 * Тело ответа больше предела: заявленный {@code Content-Length} или фактически полученное.
 *
 * <p>Наследник {@link IOException}: общий {@code catch (IOException)} проглотит его, поэтому
 * вызывающий, для которого размер значит отказ, а не «адрес недоступен», перехватывает его раньше.
 */
public final class BodyTooLargeException extends IOException {

    private static final long serialVersionUID = 1L;

    /** Размер неизвестен: предел превышен при чтении, заявленного размера не было. */
    public static final long UNKNOWN_SIZE = -1L;

    private final int limit;
    private final long actual;

    /**
     * @param limit  предел в байтах
     * @param actual заявленный размер или {@link #UNKNOWN_SIZE}
     */
    public BodyTooLargeException(int limit, long actual) {
        super("Response body exceeds " + limit + " bytes");
        this.limit = limit;
        this.actual = actual;
    }

    /** @return предел в байтах */
    public int limit() {
        return limit;
    }

    /** @return заявленный размер или {@link #UNKNOWN_SIZE} */
    public long actual() {
        return actual;
    }
}
