package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ProcessProbe: тот же живой процесс по PID и времени старта")
class ProcessProbeTest {

    private static final ProcessHandle SELF = ProcessHandle.current();

    @Test
    @DisplayName("Текущий процесс с верным временем старта - тот же")
    void sameProcessMatches() {
        Instant started = SELF.info().startInstant().orElseThrow();

        assertTrue(ProcessProbe.SYSTEM.isSameLiveProcess(SELF.pid(), started));
    }

    @Test
    @DisplayName("Тот же PID, но другое время старта (повторно выданный номер) - не тот процесс")
    void reusedPidIsNotTheSameProcess() {
        Instant started = SELF.info().startInstant().orElseThrow();

        assertFalse(
                ProcessProbe.SYSTEM.isSameLiveProcess(
                        SELF.pid(), started.minus(Duration.ofHours(1))),
                "расхождение времени старта в час означает другой процесс");
    }

    @Test
    @DisplayName(
            "Время старта не записано - процесс считается тем же, чтобы не удалить чужой корень")
    void unknownStartTimeIsTreatedAsSame() {
        assertTrue(ProcessProbe.SYSTEM.isSameLiveProcess(SELF.pid(), null));
    }

    @Test
    @DisplayName("Завершившийся процесс - не тот")
    void deadProcessIsNotAlive() throws Exception {
        Process finished = new ProcessBuilder("true").start();
        finished.waitFor();

        assertFalse(ProcessProbe.SYSTEM.isSameLiveProcess(finished.pid(), Instant.now()));
    }
}
