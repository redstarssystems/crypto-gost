package org.rssys.gost.crossval.util;

import java.time.Duration;
import java.time.Instant;

/**
 * Проверка, что процесс из метки жив и это тот же процесс, а не новый с повторно выданным PID.
 */
public interface ProcessProbe {

    /** Допуск при сравнении времени старта: ОС округляет его до тиков. */
    Duration START_TOLERANCE = Duration.ofSeconds(2);

    /** Реальная проверка через {@link ProcessHandle}. */
    ProcessProbe SYSTEM = ProcessProbe::checkSystemProcess;

    /**
     * @param pid       PID из метки
     * @param startedAt время старта из метки или {@code null}
     * @return {@code true}, если это тот же живой процесс
     */
    boolean isSameLiveProcess(long pid, Instant startedAt);

    private static boolean checkSystemProcess(long pid, Instant startedAt) {
        return ProcessHandle.of(pid)
                .filter(ProcessHandle::isAlive)
                .map(handle -> startsAt(handle, startedAt))
                .orElse(false);
    }

    private static boolean startsAt(ProcessHandle handle, Instant expected) {
        // Время старта неизвестно метке или ОС: считаем процесс тем же, чтобы не удалить корень
        // чужого прогона. Ошибка в эту сторону даёт лишний отказ, а не опасное удаление
        if (expected == null) {
            return true;
        }
        return handle.info()
                .startInstant()
                .map(
                        actual ->
                                Duration.between(expected, actual).abs().compareTo(START_TOLERANCE)
                                        <= 0)
                .orElse(true);
    }
}
