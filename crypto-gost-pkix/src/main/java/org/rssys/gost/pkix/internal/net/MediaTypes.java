package org.rssys.gost.pkix.internal.net;

import java.util.Locale;

/** Сверка значения {@code Content-Type} с ожидаемым типом содержимого. */
final class MediaTypes {

    private static final char PARAMETERS_SEPARATOR = ';';

    private MediaTypes() {}

    /**
     * Совпадает ли тип содержимого с ожидаемым.
     *
     * <p>Параметры ({@code charset} и т. п.) отбрасываются, регистр не учитывается, сравнение на
     * точное равенство, а не подстроку: иначе {@code text/html; x=application/timestamp-reply}
     * прошёл бы проверку.
     *
     * @param headerValue значение заголовка или {@code null}, если заголовка нет
     * @param expected    ожидаемый тип без параметров
     */
    static boolean matches(String headerValue, String expected) {
        if (headerValue == null) {
            return false;
        }
        int end = headerValue.indexOf(PARAMETERS_SEPARATOR);
        String type = end < 0 ? headerValue : headerValue.substring(0, end);
        return type.trim().toLowerCase(Locale.ROOT).equals(expected.toLowerCase(Locale.ROOT));
    }
}
