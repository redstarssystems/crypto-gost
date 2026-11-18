package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.internal.net.SlowServers;

/**
 * Поведение {@link CrlFetcher#fetchConditional} по умолчанию и значение {@link CrlFetchResult}.
 * Сетевая часть условной загрузки (заголовок {@code If-Modified-Since}, ответ 304, ответ 200
 * вместо 304, безусловный запрос) проверяется в тестах транспорта pkix, перевод исходов в
 * {@link CrlFetchResult} в {@code CrlFetchSupportTest}.
 */
@DisplayName("CrlFetcher.fetchConditional: поведение по умолчанию и значение результата")
class CrlFetcherConditionalTest {

    @Test
    @DisplayName("Загрузчик, знающий только fetch, получает полную загрузку по умолчанию")
    void defaultImplementationIsFullFetch() throws Exception {
        CrlFetcher lambda = uri -> new byte[] {1, 2, 3};

        CrlFetchResult result = lambda.fetchConditional("http://crl.example/x.crl", "any");

        assertFalse(result.isNotModified());
        assertArrayEquals(new byte[] {1, 2, 3}, result.der());
        assertNull(result.lastModified());
    }

    @Test
    @DisplayName(
            "CrlFetchResult: недопустимый Last-Modified отбрасывается, «не изменился» без даты")
    void resultValueSemantics() {
        assertNull(CrlFetchResult.full(new byte[1], "garbage").lastModified());
        assertEquals(
                SlowServers.COND_LAST_MODIFIED,
                CrlFetchResult.full(new byte[1], SlowServers.COND_LAST_MODIFIED).lastModified());
        assertTrue(CrlFetchResult.notModified().isNotModified());
        assertNull(CrlFetchResult.notModified().lastModified(), "дата 304 не передаётся");
        assertFalse(CrlFetchResult.full(new byte[1]).toString().contains("[B@"));
    }
}
