package org.rssys.gost.pkix.util;

/**
 * Обёртка {@link java.util.logging.Logger}, работающая на JDK и Android.
 *
 * <p>{@link java.lang.System.Logger} недоступен в Android compile classpath
 * после трансформации android.jar в AGP. Этот класс использует
 * {@link java.util.logging.Logger} — доступен на JDK (1.4+) и Android (API 1+).
 *
 * <p>Уровни:
 * <ul>
 *   <li>{@link Level#TRACE} → java.util.logging.Level.FINEST
 *   <li>{@link Level#DEBUG} → java.util.logging.Level.FINE
 *   <li>{@link Level#INFO}  → java.util.logging.Level.INFO
 *   <li>{@link Level#WARNING} → java.util.logging.Level.WARNING
 *   <li>{@link Level#ERROR} → java.util.logging.Level.SEVERE
 * </ul>
 */
public class GostLogger {

    private final java.util.logging.Logger impl;

    /* Для тестов — подмена log-вызовов конкретного инстанса. Per-class, не глобальный. */
    volatile LogSink sink;

    GostLogger(String name) {
        impl = java.util.logging.Logger.getLogger(name);
    }

    public static GostLogger getLogger(String name) {
        return new GostLogger(name);
    }

    public void log(Level level, String msg, Object... params) {
        LogSink s = sink;
        if (s != null) {
            s.log(level, msg, params);
            return;
        }
        if (impl.isLoggable(toJul(level))) {
            impl.log(toJul(level), msg, params);
        }
    }

    public void log(Level level, String msg, Throwable thrown) {
        LogSink s = sink;
        if (s != null) {
            s.log(level, msg, thrown);
            return;
        }
        impl.log(toJul(level), msg, thrown);
    }

    public boolean isLoggable(Level level) {
        return impl.isLoggable(toJul(level));
    }

    /** Подменяет {@link LogSink} на этом инстансе. Возвращает предыдущий для restore. */
    public LogSink setInstanceSink(LogSink newSink) {
        LogSink prev = sink;
        sink = newSink;
        return prev;
    }

    public enum Level {
        TRACE,
        DEBUG,
        INFO,
        WARNING,
        ERROR
    }

    /** Для тестов: перехватывает сообщения лога. */
    public interface LogSink {
        void log(Level level, String msg, Object... params);

        void log(Level level, String msg, Throwable thrown);
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
