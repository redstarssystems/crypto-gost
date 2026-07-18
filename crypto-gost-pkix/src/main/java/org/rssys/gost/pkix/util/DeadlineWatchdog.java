package org.rssys.gost.pkix.util;

import java.net.HttpURLConnection;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Обёртка над {@link HttpURLConnection}, добавляющая total-deadline таймаут.
 *
 * <p>У {@link HttpURLConnection} нет единого timeout на весь запрос —
 * {@code setReadTimeout()} таймаутит только межпакетную паузу. Атакующий
 * может держать соединение открытым, присылая по 1 байту раз в N секунд.
 * Этот хелпер добавляет {@link ScheduledExecutorService}, который
 * {@link HttpURLConnection#disconnect() принудительно рвёт} соединение
 * по истечении общего дедлайна.
 *
 * <p>Использование (try-with-resources гарантирует отмену watchdog):
 * <pre>{@code
 *   HttpURLConnection conn = ...;
 *   conn.setConnectTimeout(...);
 *   conn.setReadTimeout(...);
 *   try (DeadlineWatchdog ignored = new DeadlineWatchdog(conn, deadline)) {
 *       conn.connect();
 *       // ... чтение ответа ...
 *   }
 * }</pre>
 *
 * <p>Если запрос завершается ровно на границе дедлайна, возможна гонка:
 * {@link #close()} не успевает отменить уже запущенную задачу, и
 * {@code disconnect()} выполняется на уже обработанном соединении.
 * Это безопасно — {@link HttpURLConnection#disconnect()} на завершённом
 * соединении является no-op.
 */
public final class DeadlineWatchdog implements AutoCloseable {

    private static final ScheduledExecutorService POOL =
            Executors.newSingleThreadScheduledExecutor(
                    r -> {
                        Thread t = new Thread(r, "deadline-watchdog");
                        t.setDaemon(true);
                        return t;
                    });

    private final ScheduledFuture<?> task;
    private final AtomicBoolean fired = new AtomicBoolean();

    public DeadlineWatchdog(HttpURLConnection conn, Duration deadline) {
        this.task =
                POOL.schedule(
                        () -> {
                            fired.set(true);
                            try {
                                conn.disconnect();
                            } catch (Exception ignored) {
                                // disconnect() на уже закрытом соединении — no-op
                            }
                        },
                        deadline.toMillis(),
                        TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        task.cancel(false);
    }

    /** Для тестов — true, если дедлайн истёк и {@code disconnect()} был вызван. */
    boolean hasFired() {
        return fired.get();
    }
}
