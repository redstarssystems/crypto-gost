package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GostLogger: контекст записи")
class GostLoggerTest {

    private static final String LOGGER_NAME = "test.GostLoggerContextTest";

    private final Logger jul = Logger.getLogger(LOGGER_NAME);
    private final SimpleFormatter formatter = new SimpleFormatter();
    private final List<LogRecord> records = new ArrayList<>();

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

    private Level savedLevel;
    private boolean savedUseParentHandlers;

    @BeforeEach
    void attach() {
        savedLevel = jul.getLevel();
        savedUseParentHandlers = jul.getUseParentHandlers();
        jul.addHandler(handler);
        jul.setUseParentHandlers(false);
        jul.setLevel(Level.ALL);
    }

    @AfterEach
    void detach() {
        jul.removeHandler(handler);
        jul.setLevel(savedLevel);
        jul.setUseParentHandlers(savedUseParentHandlers);
    }

    @Test
    @DisplayName("withContext добавляет [conn#N] к сообщению и не меняет имя логгера")
    void contextAddsPrefix() {
        GostLogger base = GostLogger.getLogger(LOGGER_NAME);
        GostLogger contextual = base.withContext("conn#17");

        contextual.log(GostLogger.Level.DEBUG, "value={0}", 7);

        assertEquals(1, records.size(), "одна запись");
        LogRecord record = records.get(0);
        assertEquals(LOGGER_NAME, record.getLoggerName(), "имя JUL-логгера не меняется");
        assertEquals("[conn#17] value=7", formatter.formatMessage(record), "текст записи");
    }

    @Test
    @DisplayName("Исходный логгер не получает префикс: обёртка неизменяема")
    void baseLoggerStaysWithoutPrefix() {
        GostLogger base = GostLogger.getLogger(LOGGER_NAME);
        base.withContext("conn#1");

        base.log(GostLogger.Level.DEBUG, "plain");

        assertEquals("plain", formatter.formatMessage(records.get(0)), "без префикса");
    }

    @Test
    @DisplayName("null и пустая метка означают «без префикса» и возвращают тот же экземпляр")
    void nullAndEmptyContextAreNoops() {
        GostLogger base = GostLogger.getLogger(LOGGER_NAME);

        assertSame(base, base.withContext(null), "null");
        assertSame(base, base.withContext(""), "пустая строка");
    }

    @Test
    @DisplayName("Управляющие символы и скобки в метке отвергаются")
    void unsafeContextRejected() {
        GostLogger base = GostLogger.getLogger(LOGGER_NAME);

        assertThrows(IllegalArgumentException.class, () -> base.withContext("a\nb"), "CR/LF");
        assertThrows(IllegalArgumentException.class, () -> base.withContext("a\u007fb"), "DEL");
        assertThrows(IllegalArgumentException.class, () -> base.withContext("a[b"), "открывающая");
        assertThrows(IllegalArgumentException.class, () -> base.withContext("a]b"), "закрывающая");
    }
}
