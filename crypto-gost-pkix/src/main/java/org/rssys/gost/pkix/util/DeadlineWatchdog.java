package org.rssys.gost.pkix.util;

import java.net.HttpURLConnection;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Сторож срока на соединение и заголовки {@link HttpURLConnection}.
 *
 * <p>У {@link HttpURLConnection} нет единого срока на весь запрос: {@code setReadTimeout()}
 * ограничивает только паузу между пакетами. Сторож по истечении срока рвёт соединение
 * ({@link HttpURLConnection#disconnect()}) и этим прерывает ожидание соединения и заголовков.
 *
 * <p><b>Ограничение: тело ответа сторожем не прерывается.</b> {@code disconnect()} во время чтения
 * тела блокируется, пока читатель не дочитает поток, и тело нужно ограничивать иначе: сторож
 * закрывают ({@link #close()}) до {@code getInputStream()}, а срок тела проверяют между чтениями
 * (см. {@link BoundedBodyReader}). После срабатывания сторожа {@code getResponseCode()} может
 * вернуть 200 с неполными заголовками, поэтому проверяйте {@link #hasFired()}.
 *
 * <p>{@code disconnect()} выполняется не в общем потоке таймера, а в отдельном одноразовом
 * потоке-демоне: если вызов заблокируется, остальные сторожа продолжат срабатывать вовремя. Поток
 * живёт не дольше, чем читатель дочитывает поток (не более таймаута чтения после дедлайна), поэтому
 * под нагрузкой число таких потоков ограничено числом одновременных запросов. Обычный
 * {@code new Thread}, а не {@code Thread.ofPlatform()}: последнего нет на Android 14.
 *
 * <p>Использование (try-with-resources закрывает сторож до чтения тела):
 * <pre>{@code
 *   HttpURLConnection conn = ...;
 *   conn.setConnectTimeout(...);
 *   conn.setReadTimeout(...);
 *   int status;
 *   try (DeadlineWatchdog watchdog = new DeadlineWatchdog(conn, remaining)) {
 *       conn.connect();
 *       status = conn.getResponseCode();
 *       if (watchdog.hasFired()) throw new DeadlineExceededException("...");
 *   }
 *   // тело: BoundedBodyReader.readAll(conn.getInputStream(), max, deadline)
 * }</pre>
 *
 * <p>Если запрос завершается ровно на границе дедлайна, возможна гонка: {@link #close()} не
 * успевает отменить уже запущенную задачу, и {@code disconnect()} выполняется на уже
 * обработанном соединении. Это безопасно: {@link HttpURLConnection#disconnect()} на завершённом
 * соединении является no-op, а блокировка, если она случится, не задевает других.
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
                            // Флаг выставляется раньше всего: читатель по нему отличает обрыв
                            // заголовков от нормального ответа
                            fired.set(true);
                            disconnectInOwnThread(conn);
                        },
                        deadline.toMillis(),
                        TimeUnit.MILLISECONDS);
    }

    /**
     * Рвёт соединение в отдельном одноразовом потоке: блокировка {@code disconnect()} не должна
     * останавливать общий поток таймера и сроки чужих соединений.
     */
    private static void disconnectInOwnThread(HttpURLConnection conn) {
        Thread t =
                new Thread(
                        () -> {
                            try {
                                conn.disconnect();
                            } catch (Exception ignored) {
                                // disconnect() на уже закрытом соединении — no-op
                            }
                        },
                        "deadline-watchdog-disconnect");
        t.setDaemon(true);
        t.start();
    }

    @Override
    public void close() {
        task.cancel(false);
    }

    /**
     * @return {@code true}, если срок истёк и соединение рвётся. После этого ответ неполон
     *         (возможно, код 200 с обрезанными заголовками), и принимать его нельзя
     */
    public boolean hasFired() {
        return fired.get();
    }
}
