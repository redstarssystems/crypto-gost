package org.rssys.gost.pkix.internal.net;

import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * Проверка валидатора условного запроса, пришедшего от недоверенного сервера.
 *
 * <p>{@code Last-Modified} запоминается и возвращается серверу в заголовке {@code If-Modified-Since}
 * строкой как есть (значение нельзя пересчитывать по своим часам). Раз строка идёт обратно в
 * заголовок запроса, принимается только короткая безопасная форма: иначе условного запроса нет
 * (безопасная деградация до полной загрузки). Внутренний тип, не часть публичного API библиотеки.
 */
public final class HttpValidators {

    /** Наибольшая длина валидатора: дата IMF-fixdate занимает 29 знаков, остальное - мусор. */
    public static final int MAX_LAST_MODIFIED_CHARS = 64;

    private static final char FIRST_PRINTABLE = 0x20;
    private static final char LAST_PRINTABLE = 0x7E;

    private HttpValidators() {}

    /**
     * Возвращает значение {@code Last-Modified}, если его можно сохранить и отправить серверу.
     *
     * <p>Допустимо: не пустое, не длиннее {@link #MAX_LAST_MODIFIED_CHARS}, только печатные ASCII
     * (в том числе нет CR и LF), без ведущих и хвостовых пробелов, разбирается как HTTP-date в формате
     * IMF-fixdate (RFC 9110 §5.6.7).
     *
     * @param lastModified значение заголовка или {@code null}
     * @return то же значение, если допустимо, иначе {@code null}
     */
    public static String acceptLastModified(String lastModified) {
        if (lastModified == null
                || lastModified.isEmpty()
                || lastModified.length() > MAX_LAST_MODIFIED_CHARS
                || lastModified.charAt(0) == ' '
                || lastModified.charAt(lastModified.length() - 1) == ' ') {
            return null;
        }
        for (int i = 0; i < lastModified.length(); i++) {
            char c = lastModified.charAt(i);
            if (c < FIRST_PRINTABLE || c > LAST_PRINTABLE) {
                return null;
            }
        }
        try {
            DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.ENGLISH).parse(lastModified);
        } catch (DateTimeParseException e) {
            return null;
        }
        return lastModified;
    }
}
