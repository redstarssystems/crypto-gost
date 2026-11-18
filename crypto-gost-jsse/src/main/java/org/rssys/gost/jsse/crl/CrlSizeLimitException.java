package org.rssys.gost.jsse.crl;

import java.io.IOException;

/**
 * Ответ с CRL больше допустимого размера.
 *
 * <p>Это не «адрес недоступен»: сервер ответил, но CRL использовать нельзя. Поэтому проверка
 * цепочки отказывает сразу, а не переходит к следующему адресу CDP и не пропускает проверку
 * отзыва при политике {@code IF_CDP_PRESENT}. Подкласс {@link IOException}, чтобы остальные
 * реализации {@link CrlFetcher}, не знающие об этом исключении, продолжали работать.</p>
 */
public final class CrlSizeLimitException extends IOException {

    private static final long serialVersionUID = 1L;

    /** Значение {@link #getActualBytes()}, когда размер ответа неизвестен (chunked). */
    public static final long UNKNOWN_SIZE = -1L;

    private final long maxBytes;
    private final long actualBytes;

    /**
     * @param message     описание (без содержимого CRL)
     * @param maxBytes    действующий предел в байтах
     * @param actualBytes размер ответа или {@link #UNKNOWN_SIZE}
     */
    public CrlSizeLimitException(String message, long maxBytes, long actualBytes) {
        super(message);
        this.maxBytes = maxBytes;
        this.actualBytes = actualBytes;
    }

    /** @return предел размера CRL в байтах */
    public long getMaxBytes() {
        return maxBytes;
    }

    /** @return размер ответа в байтах или {@link #UNKNOWN_SIZE}, если он неизвестен */
    public long getActualBytes() {
        return actualBytes;
    }
}
