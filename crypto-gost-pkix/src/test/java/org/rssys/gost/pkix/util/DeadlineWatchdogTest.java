package org.rssys.gost.pkix.util;

import static org.junit.jupiter.api.Assertions.*;

import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Проверка срабатывания и отмены {@link DeadlineWatchdog}.
 */
class DeadlineWatchdogTest {

    @Test
    @DisplayName("Дедлайн истекает -> hasFired() = true")
    void testDeadlineFires() throws Exception {
        HttpURLConnection conn =
                (HttpURLConnection) URI.create("http://192.0.2.1:9999/").toURL().openConnection();
        try (DeadlineWatchdog watchdog = new DeadlineWatchdog(conn, Duration.ofMillis(10))) {
            Thread.sleep(100);
            assertTrue(watchdog.hasFired(), "Watchdog должен был сработать после дедлайна");
        }
    }

    @Test
    @DisplayName("close() до дедлайна -> hasFired() = false")
    void testCancelBeforeDeadline() throws Exception {
        HttpURLConnection conn =
                (HttpURLConnection) URI.create("http://192.0.2.1:9999/").toURL().openConnection();
        DeadlineWatchdog watchdog = new DeadlineWatchdog(conn, Duration.ofSeconds(5));
        watchdog.close();
        assertFalse(watchdog.hasFired(), "Watchdog не должен был сработать после отмены");
    }
}
