package org.rssys.gost.pkix.util;

import java.time.Duration;

/**
 * Общий срок на всю операцию (соединение, заголовки, тело, перенаправления), отсчитываемый от
 * момента создания по монотонным часам ({@link System#nanoTime()}).
 *
 * <p>Нужен потому, что таймауты {@code HttpURLConnection} и {@code HttpClient} ограничивают
 * отдельные фазы (соединение, одно чтение, ожидание заголовков), но не операцию целиком: сервер,
 * присылающий по байту в интервале меньше таймаута чтения, держал бы загрузку сколько угодно.
 * Срок один на все шаги, поэтому перенаправления не сбрасывают его заново.
 */
public final class Deadline {

    /** Наименьший допустимый срок: {@code HttpURLConnection} считает 0 мс «ждать вечно». */
    public static final Duration MIN_TIMEOUT = Duration.ofMillis(1);

    /**
     * Наибольший допустимый срок одной загрузки (10 минут). Заведомо помещается в {@code int}
     * миллисекунд (так срок передаётся в {@code HttpURLConnection}) и на порядок больше
     * разумного срока загрузки большого CRL на медленном канале; большее значение означало бы
     * ошибку настройки, а не осмысленный срок.
     */
    public static final Duration MAX_FETCH_TIMEOUT = Duration.ofMinutes(10);

    private final long endNanos;

    private Deadline(long endNanos) {
        this.endNanos = endNanos;
    }

    /**
     * Проверяет срок загрузки: от {@link #MIN_TIMEOUT} до {@link #MAX_FETCH_TIMEOUT}.
     *
     * @param timeout срок
     * @return тот же срок
     * @throws IllegalArgumentException если срок {@code null}, короче 1 мс или длиннее предела
     */
    public static Duration requireValidTimeout(Duration timeout) {
        if (timeout == null
                || timeout.compareTo(MIN_TIMEOUT) < 0
                || timeout.compareTo(MAX_FETCH_TIMEOUT) > 0) {
            throw new IllegalArgumentException(
                    "timeout must be within " + MIN_TIMEOUT + " .. " + MAX_FETCH_TIMEOUT);
        }
        return timeout;
    }

    /**
     * Срок, истекающий через {@code timeout} от текущего момента.
     *
     * @param timeout срок (проверяется {@link #requireValidTimeout})
     */
    public static Deadline after(Duration timeout) {
        requireValidTimeout(timeout);
        return new Deadline(System.nanoTime() + timeout.toNanos());
    }

    /** @return оставшееся время в наносекундах, не меньше нуля */
    public long remainingNanos() {
        return Math.max(0L, endNanos - System.nanoTime());
    }

    /** @return {@code true}, если срок вышел */
    public boolean isExpired() {
        return endNanos - System.nanoTime() <= 0L;
    }

    /**
     * Остаток в миллисекундах, округлённый вверх, не меньше 1 и не больше 10 минут: подходит для
     * {@code setConnectTimeout}/{@code setReadTimeout}, где 0 означает «ждать вечно».
     */
    public int remainingMillisAtLeastOne() {
        long nanos = remainingNanos();
        long millis = (nanos + 999_999L) / 1_000_000L;
        return (int) Math.max(1L, Math.min(millis, MAX_FETCH_TIMEOUT.toMillis()));
    }
}
