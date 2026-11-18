package org.rssys.gost.pkix;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Перехват записей журнала модуля в тесте. Обработчик стоит на родителе всех логгеров модуля,
 * поэтому видны записи любого класса. Закрытие возвращает логгер в прежнее состояние, чтобы не
 * влиять на соседние тесты. Один класс на все модули: tls13 и jsse берут его из тестового
 * артефакта pkix и называют свой родитель логгеров.
 */
public final class LogCapture implements AutoCloseable {

    /** Родитель логгеров модуля pkix. */
    public static final String PKIX = "org.rssys.gost.pkix";

    /** Родитель логгеров модуля tls13. */
    public static final String TLS13 = "org.rssys.gost.tls13";

    /** Родитель логгеров модуля jsse. */
    public static final String JSSE = "org.rssys.gost.jsse";

    private final SimpleFormatter formatter = new SimpleFormatter();

    // Клиент и сервер рукопожатия пишут из разных потоков, а JUL не сериализует publish;
    // чтение идёт по снимку списка
    private final List<LogRecord> records = new CopyOnWriteArrayList<>();

    // Сильная ссылка: JUL хранит логгеры слабо, без неё обработчик мог бы пропасть вместе с ним
    private final Logger logger;
    private final Level savedLevel;
    private final boolean savedUseParentHandlers;

    private final Handler handler =
            new Handler() {
                @Override
                public void publish(LogRecord record) {
                    records.add(record);
                }

                @Override
                public void flush() {}

                @Override
                public void close() {}
            };

    private LogCapture(String loggerName) {
        logger = Logger.getLogger(loggerName);
        savedLevel = logger.getLevel();
        savedUseParentHandlers = logger.getUseParentHandlers();
        handler.setLevel(Level.ALL);
        logger.addHandler(handler);
        // Консоль не засоряем
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.ALL);
    }

    /**
     * Начинает перехват. Использовать в try-with-resources.
     *
     * @param loggerName родитель логгеров модуля: {@link #PKIX}, {@link #TLS13} или {@link #JSSE}
     */
    public static LogCapture start(String loggerName) {
        return new LogCapture(loggerName);
    }

    /** Тексты записей ровно этого уровня JUL с подставленными аргументами. */
    public List<String> messages(Level level) {
        return records.stream()
                .filter(r -> r.getLevel().equals(level))
                .map(formatter::formatMessage)
                .toList();
    }

    /** Тексты записей указанного уровня JUL и выше с подставленными аргументами. */
    public List<String> messagesAtOrAbove(Level threshold) {
        return records.stream()
                .filter(r -> r.getLevel().intValue() >= threshold.intValue())
                .map(formatter::formatMessage)
                .toList();
    }

    /**
     * Тексты записей любого уровня с подставленными аргументами, в порядке записи. Нужны там, где
     * проверяется, что в журнал не попало ничего лишнего, независимо от уровня.
     */
    public List<String> allMessages() {
        return records.stream().map(formatter::formatMessage).toList();
    }

    /**
     * Тексты записей любого уровня от логгеров, имя которых оканчивается на заданный суффикс
     * (например, {@code GostSSLEngine}). Перехват стоит на родителе всех логгеров модуля, и без
     * фильтра утверждение «запись сделал этот класс» прошло бы за счёт соседнего.
     */
    public List<String> allMessages(String loggerNameSuffix) {
        return records.stream()
                .filter(r -> endsWith(r, loggerNameSuffix))
                .map(formatter::formatMessage)
                .toList();
    }

    /** Тексты записей ровно этого уровня JUL от логгеров с заданным суффиксом имени. */
    public List<String> messages(Level level, String loggerNameSuffix) {
        return records.stream()
                .filter(r -> r.getLevel().equals(level) && endsWith(r, loggerNameSuffix))
                .map(formatter::formatMessage)
                .toList();
    }

    /** Имена логгеров, от которых пришли записи (без повторов, в порядке появления). */
    public List<String> loggerNames() {
        return records.stream().map(LogRecord::getLoggerName).distinct().toList();
    }

    /** Исключения, приложенные к записям (для проверок, что записано исключение или нет). */
    public List<Throwable> thrown() {
        return records.stream().map(LogRecord::getThrown).filter(t -> t != null).toList();
    }

    private static boolean endsWith(LogRecord record, String loggerNameSuffix) {
        String name = record.getLoggerName();
        return name != null && name.endsWith(loggerNameSuffix);
    }

    /** Забывает записи, сделанные до сих пор (между этапами одного теста). */
    public void clear() {
        records.clear();
    }

    @Override
    public void close() {
        logger.removeHandler(handler);
        logger.setLevel(savedLevel);
        logger.setUseParentHandlers(savedUseParentHandlers);
    }
}
