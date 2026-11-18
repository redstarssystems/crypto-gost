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

    /** Соединение, чей disconnect() блокируется надолго: имитация чтения тела при keep-alive. */
    private static final class BlockingConnection extends HttpURLConnection {
        private final long blockMillis;

        BlockingConnection(long blockMillis) {
            super(null);
            this.blockMillis = blockMillis;
        }

        @Override
        public void disconnect() {
            try {
                Thread.sleep(blockMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() {}
    }

    @Test
    @DisplayName("Заблокированный disconnect() одного сторожа не сдвигает срок другого")
    void blockedDisconnectDoesNotDelayOtherWatchdogs() throws Exception {
        HttpURLConnection other =
                (HttpURLConnection) URI.create("http://192.0.2.1:9999/").toURL().openConnection();
        try (DeadlineWatchdog blocking =
                        new DeadlineWatchdog(new BlockingConnection(3_000), Duration.ofMillis(20));
                DeadlineWatchdog victim = new DeadlineWatchdog(other, Duration.ofMillis(300))) {
            long start = System.nanoTime();
            while (!victim.hasFired() && (System.nanoTime() - start) < 2_000_000_000L) {
                Thread.sleep(10);
            }
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;

            assertTrue(blocking.hasFired(), "первый сторож должен был сработать");
            assertTrue(
                    victim.hasFired() && elapsedMs < 1_500,
                    "срок чужого сторожа не должен ждать заблокированного disconnect(): прошло "
                            + elapsedMs
                            + " мс");
        }
    }
}
