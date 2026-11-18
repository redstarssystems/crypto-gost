package org.rssys.gost.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * Безопасный вывод недоверенных данных в журнал и сообщения исключений.
 *
 * <p>Адрес приходит из сертификата (CDP, AIA), из настроек вызывающего или из заголовка
 * {@code Location}; тело ошибки и {@code Content-Type} - от удалённого сервера. Всё это
 * может содержать учётные данные ({@code user:pass@}), токены в параметрах запроса и управляющие
 * символы для подделки строк журнала. Очищенное значение предназначено только для вывода: запрос
 * всегда идёт на полный адрес.
 *
 * <p>Класс общий для всех модулей библиотеки и открыт приложению: недоверенный текст пишется в
 * журнал и в сообщения исключений только через него. Методы не бросают исключений на любом тексте,
 * включая {@code null}; исключение только для отрицательного предела длины.
 */
public final class SafeText {

    /** Заглушка вместо адреса, который не разбирается: исходная строка в вывод не попадает. */
    public static final String MALFORMED_URI = "<malformed URI>";

    /** Значение для {@code null}: такой текст в выводе отличим от пустой строки. */
    public static final String NULL_TEXT = "null";

    /** Наибольшая длина значения заголовка и тела ошибки в выводе по умолчанию. */
    public static final int MAX_HEADER_CHARS = 128;

    private static final char REPLACEMENT = '?';
    private static final char FIRST_PRINTABLE = 0x20;
    private static final char LAST_PRINTABLE = 0x7E;

    private SafeText() {}

    /**
     * Адрес в виде {@code схема://хост:порт/путь}: без учётных данных, параметров запроса и
     * фрагмента.
     *
     * @param uri адрес или {@code null}
     * @return очищенный адрес или {@link #MALFORMED_URI}, если адрес не разбирается
     */
    public static String uri(URI uri) {
        if (uri == null) {
            return MALFORMED_URI;
        }
        StringBuilder sb = new StringBuilder();
        String scheme = uri.getScheme();
        if (scheme != null) {
            sb.append(printableAscii(scheme)).append(':');
        }
        // getHost() у адреса без разбираемого хоста (opaque, registry-based) даёт null: так
        // исключается вывод authority целиком, где могут оказаться учётные данные
        String host = uri.getHost();
        if (host != null) {
            sb.append("//").append(printableAscii(host));
            if (uri.getPort() >= 0) {
                sb.append(':').append(uri.getPort());
            }
        } else if (uri.isOpaque() || uri.getRawAuthority() != null) {
            return MALFORMED_URI;
        } else if (scheme != null) {
            sb.append("//");
        }
        String path = uri.getRawPath();
        if (path != null) {
            sb.append(printableAscii(path));
        }
        return sb.toString();
    }

    /**
     * То же для строки: не разбирающаяся строка заменяется на {@link #MALFORMED_URI}.
     *
     * @param uri адрес или {@code null}
     * @return очищенный адрес или {@link #MALFORMED_URI}
     */
    public static String uri(String uri) {
        if (uri == null) {
            return MALFORMED_URI;
        }
        try {
            return uri(new URI(uri));
        } catch (URISyntaxException e) {
            return MALFORMED_URI;
        }
    }

    /**
     * Строка не длиннее {@link #MAX_HEADER_CHARS}, только печатные ASCII (0x20-0x7E).
     *
     * @param text недоверенный текст или {@code null}
     * @return безопасная для журнала строка, {@link #NULL_TEXT} для {@code null}
     */
    public static String printableAscii(String text) {
        return printableAscii(text, MAX_HEADER_CHARS);
    }

    /**
     * Строка не длиннее {@code maxLength}, только печатные ASCII (0x20-0x7E): остальное, включая
     * перевод строки, заменяется знаком вопроса.
     *
     * @param text недоверенный текст или {@code null}
     * @param maxLength наибольшая длина результата, не меньше нуля
     * @return безопасная для журнала строка, {@link #NULL_TEXT} для {@code null}
     * @throws IllegalArgumentException если {@code maxLength} отрицателен
     */
    public static String printableAscii(String text, int maxLength) {
        if (maxLength < 0) {
            throw new IllegalArgumentException("maxLength must not be negative: " + maxLength);
        }
        if (text == null) {
            return NULL_TEXT;
        }
        int length = Math.min(text.length(), maxLength);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(printable(text.charAt(i)));
        }
        return sb.toString();
    }

    /**
     * Тело ошибки как текст: UTF-8 с заменой, не длиннее {@link #MAX_HEADER_CHARS}, только
     * печатные ASCII (остальное, включая перевод строки, заменяется).
     *
     * @param data тело ответа или {@code null}
     * @return безопасная для журнала строка, {@link #NULL_TEXT} для {@code null}
     */
    public static String printableAscii(byte[] data) {
        if (data == null) {
            return NULL_TEXT;
        }
        return printableAscii(new String(data, StandardCharsets.UTF_8));
    }

    private static char printable(char c) {
        return c >= FIRST_PRINTABLE && c <= LAST_PRINTABLE ? c : REPLACEMENT;
    }
}
