package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CrlFetcher.limitProblem: согласование предела загрузчика с maxCrlSize")
class CrlFetcherLimitTest {

    private static CrlFetcher fetcherWithLimit(int limit) {
        return new CrlFetcher() {
            @Override
            public byte[] fetch(String crlUri) {
                return null;
            }

            @Override
            public int maxResponseSize() {
                return limit;
            }
        };
    }

    @Test
    @DisplayName("Предел меньше maxCrlSize -> ошибка с обоими числами")
    void smallerLimitIsProblem() {
        String problem = CrlFetcher.limitProblem(fetcherWithLimit(1000), 2000);
        assertNotNull(problem, "Загрузчик оборвал бы большой CRL раньше разбора");
        assertTrue(problem.contains("1000") && problem.contains("2000"), problem);
    }

    @Test
    @DisplayName("Предел равен или больше maxCrlSize -> без ошибки")
    void sufficientLimitIsAccepted() {
        assertNull(CrlFetcher.limitProblem(fetcherWithLimit(2000), 2000));
        assertNull(CrlFetcher.limitProblem(fetcherWithLimit(3000), 2000));
    }

    @Test
    @DisplayName("Лямбда и загрузчик без переопределения (предел неизвестен) не проверяются")
    void unknownLimitIsSkipped() {
        CrlFetcher lambda = uri -> null;
        assertNull(CrlFetcher.limitProblem(lambda, Integer.MAX_VALUE));
        assertNull(CrlFetcher.limitProblem(null, 1), "Загрузчик не задан");
    }

    @Test
    @DisplayName("Загрузчики библиотеки сообщают свой предел")
    void libraryFetchersReportLimit() {
        assertNotNull(
                CrlFetcher.limitProblem(new JdkHttpCrlFetcher(Duration.ofSeconds(1), 100), 200));
        assertNotNull(
                CrlFetcher.limitProblem(
                        new UrlConnectionCrlFetcher(Duration.ofSeconds(1), 100), 200));
        assertNull(CrlFetcher.limitProblem(new JdkHttpCrlFetcher(), 100));
    }
}
