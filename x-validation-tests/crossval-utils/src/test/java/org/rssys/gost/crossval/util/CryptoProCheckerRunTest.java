package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CryptoProChecker.runWithConfirm: ввод терпим к закрытому каналу, есть таймаут")
class CryptoProCheckerRunTest {

    @Test
    @DisplayName("Процесс завершается, не читая stdin: не Stream closed, результат возвращается")
    void processThatNeverReadsStdinIsNotAnError() throws Exception {
        // Повторяем: запись в канал завершившегося процесса падает не всегда, а по гонке
        for (int attempt = 0; attempt < 30; attempt++) {
            CryptoProChecker.Result r =
                    CryptoProChecker.runWithConfirm("bash", "-c", "echo done; exit 3");

            assertEquals(3, r.exitCode(), "код возврата процесса");
            assertTrue(r.output().contains("done"), "вывод: " + r.output());
        }
    }

    @Test
    @DisplayName("Процесс читает подтверждения со stdin")
    void processReceivesConfirmations() throws Exception {
        CryptoProChecker.Result r =
                CryptoProChecker.runWithConfirm("bash", "-c", "read a; read b; echo \"$a$b\"");

        assertEquals(0, r.exitCode());
        assertTrue(r.output().contains("YY"), "вывод: " + r.output());
    }

    @Test
    @DisplayName("Зависший процесс убивается по таймауту и даёт TIMEOUT_EXIT_CODE")
    void hungProcessIsKilledByTimeout() throws Exception {
        long start = System.nanoTime();

        CryptoProChecker.Result r =
                CryptoProChecker.runWithConfirm(Duration.ofSeconds(1), "bash", "-c", "sleep 30");

        assertEquals(CryptoProChecker.TIMEOUT_EXIT_CODE, r.exitCode(), "процесс должен быть убит");
        assertTrue(
                Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(10)) < 0,
                "сборка не должна ждать зависший процесс");
    }
}
