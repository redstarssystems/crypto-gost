package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Собственная логика jsse в загрузке CRL: проверка адреса и схемы и перевод исходов транспорта в
 * {@link CrlFetchResult}. Сетевое поведение (срок, размер, перенаправления, SSRF) проверяется в
 * тестах транспорта pkix, поэтому здесь вместо HTTP подставлена заглушка.
 */
@DisplayName("CrlFetchSupport: проверка входа и перевод исходов транспорта")
class CrlFetchSupportTest {

    private static final int LIMIT = 4096;
    private static final byte[] BODY = {1, 2, 3};
    private static final String VALIDATOR = "Sun, 08 Nov 2026 03:08:46 GMT";

    private static final FetchTransport NEVER =
            request -> {
                throw new AssertionError("запрос не должен выполняться");
            };

    private static CrlFetchResult run(String uri, String validator, FetchTransport transport)
            throws IOException {
        return CrlFetchSupport.runConditional(
                uri, validator, Duration.ofSeconds(1), LIMIT, target -> false, transport);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"not a uri", "http://[bad"})
    @DisplayName("Пустой или неразбираемый адрес: данных нет, запрос не выполняется")
    void emptyAndMalformedUrisGiveNothingWithoutRequest(String uri) throws Exception {
        CrlFetchResult result = run(uri, null, NEVER);

        assertNull(result.der(), "данных быть не должно");
        assertFalse(result.isNotModified(), "это не ответ «не изменился»");
        assertEquals(FetchFailure.BAD_ADDRESS, result.failure(), "причина для журнала");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/hostname",
                "ldap://crl.example/c.crl",
                "ftp://crl.example/c.crl",
                "mailto:crl@example.test"
            })
    @DisplayName("Схема не http и не https: данных нет, запрос не выполняется")
    void unsupportedSchemesGiveNothingWithoutRequest(String uri) throws Exception {
        CrlFetchResult result = run(uri, null, NEVER);

        assertNull(result.der(), "данных быть не должно: " + uri);
        assertEquals(FetchFailure.UNSUPPORTED_SCHEME, result.failure(), "причина: " + uri);
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTTP://crl.example/c.crl", "HtTpS://crl.example/c.crl"})
    @DisplayName("Схема регистронезависима (RFC 3986 §3.1): адрес принимается")
    void schemeCaseDoesNotMatter(String uri) throws Exception {
        AtomicInteger requests = new AtomicInteger();

        CrlFetchResult result =
                run(
                        uri,
                        null,
                        request -> {
                            requests.incrementAndGet();
                            return FetchOutcome.success(BODY);
                        });

        assertEquals(1, requests.get(), "запрос должен быть выполнен");
        assertArrayEquals(BODY, result.der(), "тело ответа возвращается как есть");
    }

    @Test
    @DisplayName("Размер больше предела: CrlSizeLimitException с заявленным размером")
    void declaredOversizeIsTranslated() {
        CrlSizeLimitException e =
                assertThrows(
                        CrlSizeLimitException.class,
                        () ->
                                run(
                                        "http://crl.example/c.crl",
                                        null,
                                        request -> {
                                            throw new BodyTooLargeException(LIMIT, LIMIT + 1L);
                                        }),
                        "отказ по размеру не должен выглядеть как «адрес недоступен»");

        assertEquals(LIMIT, e.getMaxBytes(), "предел в исключении");
        assertEquals(LIMIT + 1L, e.getActualBytes(), "заявленный размер");
    }

    @Test
    @DisplayName("Размер неизвестен (chunked): размер в исключении неизвестен")
    void unknownOversizeIsTranslated() {
        CrlSizeLimitException e =
                assertThrows(
                        CrlSizeLimitException.class,
                        () ->
                                run(
                                        "http://crl.example/c.crl",
                                        null,
                                        request -> {
                                            throw new BodyTooLargeException(
                                                    LIMIT, BodyTooLargeException.UNKNOWN_SIZE);
                                        }));

        assertEquals(CrlSizeLimitException.UNKNOWN_SIZE, e.getActualBytes());
    }

    @Test
    @DisplayName("Ответ 304: результат «не изменился», тела и валидатора нет")
    void notModifiedIsTranslated() throws Exception {
        CrlFetchResult result =
                run("http://crl.example/c.crl", VALIDATOR, request -> FetchOutcome.unchanged());

        assertTrue(result.isNotModified());
        assertNull(result.der());
        assertNull(result.lastModified());
    }

    @Test
    @DisplayName("Ответ 200: тело и допустимый Last-Modified доходят до вызывающего")
    void fullResponseCarriesValidator() throws Exception {
        CrlFetchResult result =
                run(
                        "http://crl.example/c.crl",
                        null,
                        request -> FetchOutcome.success(BODY, VALIDATOR));

        assertArrayEquals(BODY, result.der());
        assertEquals(VALIDATOR, result.lastModified());
        assertFalse(result.isNotModified());
    }

    @Test
    @DisplayName("Отказ транспорта (не 200): данных нет, без исключения")
    void refusalMeansNoData() throws Exception {
        URI uri = URI.create("http://crl.example/c.crl");

        CrlFetchResult result =
                run(
                        uri.toString(),
                        null,
                        request ->
                                FetchOutcome.failure(
                                        FetchOutcome.Failure.NON_200, 500, uri, false));

        assertNull(result.der());
        assertFalse(result.isNotModified());
        assertEquals(FetchFailure.HTTP_STATUS, result.failure(), "причина для журнала");
    }

    @Test
    @DisplayName("Сетевая ошибка транспорта не проглатывается")
    void networkErrorPropagates() {
        IOException failure = new IOException("сеть недоступна");

        IOException thrown =
                assertThrows(
                        IOException.class,
                        () ->
                                run(
                                        "http://crl.example/c.crl",
                                        null,
                                        request -> {
                                            throw failure;
                                        }));

        assertSame(failure, thrown, "исключение должно дойти до вызывающего без замены");
    }
}
