package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.testkit.LogSecrets;
import org.rssys.gost.pkix.LogCapture;

@DisplayName("CrlCache: адрес из CDP в сообщениях без учётных данных и параметров")
class CrlCacheLoggingTest {

    private static final String SECRET_URI = LogSecrets.uri("http", "crl.example.com/root.crl");

    private LogCapture log;

    @BeforeEach
    void captureLogger() {
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    @Test
    @DisplayName("Загрузчик вернул null: текст исключения без секретов")
    void noDataMessageHasNoSecrets() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);

        IOException e =
                assertThrows(
                        IOException.class,
                        () ->
                                cache.get(
                                        new CrlCache.CrlKey(SECRET_URI, "aa"),
                                        () -> null,
                                        null,
                                        der -> null,
                                        java.time.Duration.ofMinutes(1)));

        assertTrue(e.getMessage().contains("crl.example.com/root.crl"), e.getMessage());
        assertFalse(LogSecrets.leaks(e.getMessage()), "секреты в сообщении: " + e.getMessage());
    }

    @Test
    @DisplayName("Вытеснение базовой линии откатов: адрес в журнале без секретов")
    void evictionLogHasNoSecrets() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        // Предел числа запомненных номеров превышается разными адресами с секретами
        for (int i = 0; i < CrlCache.MAX_LAST_KNOWN + 2; i++) {
            cache.rememberCrlNumber(
                    new CrlCache.CrlKey(
                            LogSecrets.uri("http", "crl" + i + ".example.com/r.crl"), "aa"),
                    java.math.BigInteger.ONE);
        }

        List<String> lines = log.allMessages("CrlCache");
        assertFalse(lines.isEmpty(), "ожидалось предупреждение о вытеснении");
        for (String line : lines) {
            assertFalse(LogSecrets.leaks(line), "секреты в журнале: " + line);
        }
    }

    @Test
    @DisplayName("Загрузчик сообщил причину: исключение несёт её перечислением")
    void noDataExceptionCarriesFailure() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);

        CrlCache.NoDataException e =
                assertThrows(
                        CrlCache.NoDataException.class,
                        () ->
                                cache.get(
                                        new CrlCache.CrlKey(SECRET_URI, "aa"),
                                        () -> null,
                                        null,
                                        der -> null,
                                        java.time.Duration.ofMinutes(1)));

        assertTrue(e.failure() == null, "загрузчик без причины: причина не придумывается");
    }
}
