package org.rssys.gost.pkix.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Deadline: общий срок и границы допустимых значений")
class DeadlineTest {

    @Test
    @DisplayName("Границы срока: 1 мс и предел принимаются, меньше и больше - нет")
    void timeoutBoundaries() {
        Duration min = Deadline.MIN_TIMEOUT;
        Duration max = Deadline.MAX_FETCH_TIMEOUT;

        assertSame(min, Deadline.requireValidTimeout(min), "ровно 1 мс допустимо");
        assertSame(max, Deadline.requireValidTimeout(max), "ровно предел допустим");
        assertThrows(
                IllegalArgumentException.class,
                () -> Deadline.requireValidTimeout(min.minusNanos(1)),
                "меньше 1 мс недопустимо: HttpURLConnection поймёт его как «ждать вечно»");
        assertThrows(
                IllegalArgumentException.class,
                () -> Deadline.requireValidTimeout(max.plusNanos(1)),
                "предел + 1 нс недопустим");
    }

    @Test
    @DisplayName("null, ноль, отрицательный и переполняющий int срок отвергаются")
    void invalidTimeouts() {
        for (Duration bad :
                new Duration[] {
                    null,
                    Duration.ZERO,
                    Duration.ofNanos(1),
                    Duration.ofMillis(-1),
                    Duration.ofDays(365),
                    Duration.ofMillis(Integer.MAX_VALUE).plusMillis(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> Deadline.requireValidTimeout(bad),
                    "срок " + bad + " должен отвергаться");
        }
    }

    @Test
    @DisplayName("Остаток уменьшается, срок истекает; остаток в мс не меньше 1")
    void remainingAndExpiry() throws Exception {
        Deadline d = Deadline.after(Duration.ofMillis(60));
        assertFalse(d.isExpired(), "только что созданный срок не истёк");
        assertTrue(d.remainingMillisAtLeastOne() >= 1);
        assertTrue(d.remainingNanos() <= Duration.ofMillis(60).toNanos());

        Thread.sleep(120);

        assertTrue(d.isExpired(), "срок должен истечь");
        assertEquals(0L, d.remainingNanos(), "остаток не бывает отрицательным");
        assertEquals(
                1, d.remainingMillisAtLeastOne(), "для таймаутов сокета остаток не меньше 1 мс");
    }
}
