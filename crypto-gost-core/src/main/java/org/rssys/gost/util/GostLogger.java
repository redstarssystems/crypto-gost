package org.rssys.gost.util;

/**
 * Обёртка {@link java.util.logging.Logger}, работающая на JDK и Android.
 *
 * <p>{@link java.lang.System.Logger} недоступен в Android compile classpath
 * после трансформации android.jar в AGP. Этот класс использует
 * {@link java.util.logging.Logger} — доступен на JDK (1.4+) и Android (API 1+).
 *
 * <p>Уровни:
 * <ul>
 *   <li>{@link Level#TRACE} -> java.util.logging.Level.FINEST
 *   <li>{@link Level#DEBUG} -> java.util.logging.Level.FINE
 *   <li>{@link Level#INFO}  -> java.util.logging.Level.INFO
 *   <li>{@link Level#WARNING} -> java.util.logging.Level.WARNING
 *   <li>{@link Level#ERROR} -> java.util.logging.Level.SEVERE
 * </ul>
 *
 * <p>Имя логгера - полное имя класса, который пишет в журнал: уровень настраивается и для
 * отдельного класса, и для пакета целиком. Недоверенный текст (адреса, заголовки, сообщения
 * исключений чужого кода) пишется только через {@link SafeText}; ключевой материал не пишется
 * никогда.
 */
public class GostLogger {

    private final java.util.logging.Logger impl;

    /** Метка контекста без скобок; {@code null} - записи без префикса. */
    private final String context;

    GostLogger(String name) {
        this(java.util.logging.Logger.getLogger(name), null);
    }

    private GostLogger(java.util.logging.Logger impl, String context) {
        this.impl = impl;
        this.context = context;
    }

    /**
     * Возвращает логгер с заданным именем.
     *
     * @param name имя логгера, по соглашению библиотеки - полное имя класса
     * @return обёртка над {@link java.util.logging.Logger} с этим именем
     */
    public static GostLogger getLogger(String name) {
        return new GostLogger(name);
    }

    /**
     * Возвращает логгер с тем же именем и префиксом контекста в сообщениях.
     *
     * <p>Префикс нужен, чтобы связать записи одного соединения: формат записи -
     * {@code [conn#17] текст}. Имя JUL-логгера не меняется, поэтому настройка уровня по классу
     * и пакету продолжает работать. Обёртка неизменяема: исходный экземпляр не меняется.
     *
     * @param token метка без скобок, например {@code conn#17}; {@code null} или пустая строка
     *     означают «без префикса» и возвращают этот же экземпляр
     * @return логгер с префиксом или этот же экземпляр
     * @throws IllegalArgumentException если метка содержит управляющий символ, {@code [} или
     *     {@code ]}: такие символы подделали бы строку журнала или границу префикса
     */
    public GostLogger withContext(String token) {
        if (token == null || token.isEmpty()) {
            return this;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c < 0x20 || c == 0x7F || c == '[' || c == ']') {
                throw new IllegalArgumentException(
                        "Context token must not contain control characters or brackets");
            }
        }
        return new GostLogger(impl, token);
    }

    private String withPrefix(String msg) {
        return context == null ? msg : "[" + context + "] " + msg;
    }

    /**
     * Пишет запись с параметрами в формате {@link java.text.MessageFormat} ({@code {0}}).
     *
     * @param level уровень записи
     * @param msg шаблон сообщения; апостроф в шаблоне с параметрами не используется или удваивается
     * @param params параметры шаблона
     */
    public void log(Level level, String msg, Object... params) {
        // Уровень маппится один раз; префикс строится только после проверки уровня:
        // при выключенном журнале строка префикса не создаётся
        java.util.logging.Level julLevel = toJul(level);
        if (impl.isLoggable(julLevel)) {
            impl.log(julLevel, withPrefix(msg), params);
        }
    }

    /**
     * Пишет запись вместе с исключением.
     *
     * @param level уровень записи
     * @param msg текст сообщения
     * @param thrown исключение, которое сопровождает запись
     */
    public void log(Level level, String msg, Throwable thrown) {
        // Поведение то же (JUL проверяет уровень сам), проверка нужна для единообразия
        // с перегрузкой с параметрами; префикс тоже строится только после неё
        java.util.logging.Level julLevel = toJul(level);
        if (impl.isLoggable(julLevel)) {
            impl.log(julLevel, withPrefix(msg), thrown);
        }
    }

    /**
     * Проверяет, будет ли запись этого уровня выведена. Нужна, чтобы не собирать строки для
     * записи, которую JUL всё равно отбросит.
     *
     * @param level уровень записи
     * @return true если запись этого уровня будет выведена
     */
    public boolean isLoggable(Level level) {
        return impl.isLoggable(toJul(level));
    }

    /** Уровни записей библиотеки; соответствие уровням JUL указано в описании класса. */
    public enum Level {
        TRACE,
        DEBUG,
        INFO,
        WARNING,
        ERROR
    }

    private static java.util.logging.Level toJul(Level level) {
        if (level == null) return java.util.logging.Level.INFO;
        return switch (level) {
            case TRACE -> java.util.logging.Level.FINEST;
            case DEBUG -> java.util.logging.Level.FINE;
            case INFO -> java.util.logging.Level.INFO;
            case WARNING -> java.util.logging.Level.WARNING;
            case ERROR -> java.util.logging.Level.SEVERE;
        };
    }
}
