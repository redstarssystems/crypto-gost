package org.rssys.gost.jsse.testkit;

/**
 * Проверка, что учётные данные и параметры запроса из адреса не попадают в журнал и сообщения
 * исключений.
 * <p>
 * Тестовые адреса содержат userinfo и query с уникальным маркером {@link #MARKER}. Искать
 * отдельные слова вроде «pass» нельзя: они встречаются в обычных сообщениях, и проверка
 * срабатывала бы на безобидном тексте или молчала при другом секрете.
 */
public final class LogSecrets {

    /** Уникальная подстрока, входящая во все секретные части тестовых адресов. */
    public static final String MARKER = "zq9k";

    private static final String USER_INFO = "user:" + MARKER + "-pw";

    private static final String QUERY = "token=" + MARKER + "-token";

    private LogSecrets() {}

    /**
     * Собирает адрес с секретными userinfo и query.
     *
     * @param scheme схема без «://»
     * @param hostAndPath узел и путь, например {@code crl.example.com/root.crl}
     */
    public static String uri(String scheme, String hostAndPath) {
        return scheme + "://" + USER_INFO + "@" + hostAndPath + "?" + QUERY;
    }

    /** Содержит ли текст секретную часть тестового адреса. */
    public static boolean leaks(String text) {
        return text != null && text.contains(MARKER);
    }
}
