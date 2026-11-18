package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.DeadlineExceededException;

/**
 * Контракт обоих CRL-загрузчиков: параметры проверяются при создании, общий срок соблюдается,
 * ответ больше предела даёт {@link CrlSizeLimitException} (а не обычную сетевую ошибку), прочие
 * ошибки - {@link IOException} или {@code null}, но не непроверяемое исключение.
 */
@DisplayName("CRL-загрузчики: проверка параметров, общий срок, размер, контракт исключений")
class CrlFetcherContractTest {

    enum Kind {
        JDK_HTTP(
                (t, m) -> new JdkHttpCrlFetcher(t, m, true),
                (t, m) -> new JdkHttpCrlFetcher(t, m),
                JdkHttpCrlFetcher::new),
        URL_CONNECTION(
                (t, m) -> new UrlConnectionCrlFetcher(t, m, true),
                (t, m) -> new UrlConnectionCrlFetcher(t, m),
                UrlConnectionCrlFetcher::new);

        final BiFunction<Duration, Integer, CrlFetcher> local;
        final BiFunction<Duration, Integer, CrlFetcher> publicCtor;
        final Supplier<CrlFetcher> defaultCtor;

        Kind(
                BiFunction<Duration, Integer, CrlFetcher> local,
                BiFunction<Duration, Integer, CrlFetcher> publicCtor,
                Supplier<CrlFetcher> defaultCtor) {
            this.local = local;
            this.publicCtor = publicCtor;
            this.defaultCtor = defaultCtor;
        }
    }

    private SlowServers servers;

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        servers.close();
    }

    private CrlFetcher fetcher(Kind kind) {
        return kind.local.apply(Duration.ofSeconds(1), 262_144);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Конструктор делегирует проверку срока и размера: по одному значению на границу, таблица в"
                    + " DeadlineTest")
    void constructorValidation(Kind kind) {
        for (Duration bad :
                new Duration[] {
                    null, Duration.ofNanos(500_000), Deadline.MAX_FETCH_TIMEOUT.plusNanos(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> kind.publicCtor.apply(bad, 1024),
                    kind + ": срок " + bad + " должен отвергаться");
        }
        for (int badSize : new int[] {0, -1}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> kind.publicCtor.apply(Duration.ofSeconds(5), badSize),
                    kind + ": предел размера " + badSize + " должен отвергаться");
        }
        assertDoesNotThrow(() -> kind.publicCtor.apply(Deadline.MIN_TIMEOUT, 1));
        assertDoesNotThrow(
                () -> kind.publicCtor.apply(Deadline.MAX_FETCH_TIMEOUT, Integer.MAX_VALUE));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Обычный ответ и предел размера сообщается наружу")
    void successAndLimit(Kind kind) throws Exception {
        CrlFetcher f = fetcher(kind);

        assertArrayEquals("OK".getBytes(), f.fetch(servers.base + "/ok"));
        assertEquals(262_144, f.maxResponseSize());
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Капля тела: DeadlineExceededException в пределах срока")
    void dripIsCutByDeadline(Kind kind) {
        long start = System.nanoTime();

        assertThrows(
                DeadlineExceededException.class,
                () -> fetcher(kind).fetch(servers.base + "/fastdrip"));

        long elapsed = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsed < 2_500, kind + ": fetch занял " + elapsed + " мс при сроке 1000 мс");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Слишком большой ответ (заявленный и фактический): CrlSizeLimitException с пределом")
    void sizeLimit(Kind kind) {
        for (String path : new String[] {"/declaredbig", "/chunkedbig"}) {
            CrlSizeLimitException e =
                    assertThrows(
                            CrlSizeLimitException.class,
                            () -> fetcher(kind).fetch(servers.base + path),
                            kind + " " + path);
            assertEquals(262_144, e.getMaxBytes(), "предел в исключении");
        }
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Недопустимые адреса и переходы: null или IOException, но не непроверяемое исключение")
    void edgeInputsNeverThrowUnchecked(Kind kind) {
        CrlFetcher f = fetcher(kind);
        String[] uris = {
            servers.base + "/rbad",
            servers.base + "/rfile",
            servers.base + "/rftp",
            servers.base + "/rnoloc",
            servers.base + "/error500drip",
            "http:///x",
            "http://",
            "http://[bad",
            "http://127.0.0.1:1/",
            "ftp://example.com/x",
            "file:///etc/hostname",
            "",
            "not a uri"
        };
        for (String uri : uris) {
            try {
                f.fetch(uri);
            } catch (IOException expected) {
                // допустимо: сетевая ошибка
            } catch (RuntimeException unexpected) {
                throw new AssertionError(
                        kind + " " + uri + ": непроверяемое исключение", unexpected);
            }
        }
        // Ответ 500 (тело не ждётся), пустой адрес и битое перенаправление дают именно null
        for (String uri :
                new String[] {
                    servers.base + "/rbad",
                    servers.base + "/rfile",
                    servers.base + "/error500drip",
                    ""
                }) {
            assertDoesNotThrow(
                    () -> assertNull(f.fetch(uri)), kind + " " + uri + ": ожидался null");
        }
        assertDoesNotThrow(() -> assertNull(f.fetch(null)));
        assertInstanceOf(
                IOException.class,
                assertThrows(
                        DeadlineExceededException.class,
                        () -> fetcher(kind).fetch(servers.base + "/stall")),
                "DeadlineExceededException должен быть IOException (контракт CrlFetcher)");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Конструктор без параметров: предел размера по умолчанию равен лимиту GostCrl")
    void defaultMaxResponseSize(Kind kind) {
        assertEquals(
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                kind.defaultCtor.get().maxResponseSize(),
                kind + ": предел по умолчанию");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Публичный конструктор блокирует не глобальный адрес: null, до сервера запрос не доходит")
    void publicConstructorBlocksNonGlobalAddress(Kind kind) throws Exception {
        // Заблокированный адрес для вызывающего равнозначен «зеркало недоступно»: данных нет.
        // Остальные загрузчики контракта создаются с отключённой проверкой, поэтому проводку
        // публичного конструктора проверяет только этот тест. Сервер живой и стоит на loopback:
        // без блокировки запрос до него дошёл бы и счётчик вырос; на адрес, где никто не слушает,
        // загрузчик вернул бы null и без блокировки, и тест ничего бы не охранял
        CrlFetcher f = kind.publicCtor.apply(Duration.ofSeconds(5), 1024);

        assertNull(
                f.fetch(servers.base + "/ok"), kind + ": заблокированный адрес должен давать null");
        assertEquals(
                0,
                servers.okRequests.get(),
                kind + ": заблокированный запрос не должен дойти до сервера");
    }

    private CrlFetcher blocking(Kind kind, Predicate<URI> blockedTarget) {
        return kind == Kind.JDK_HTTP
                ? new JdkHttpCrlFetcher(Duration.ofSeconds(1), 262_144, blockedTarget)
                : new UrlConnectionCrlFetcher(Duration.ofSeconds(1), 262_144, blockedTarget);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("SSRF на втором переходе: заблокированный адрес перехода даёт null без запроса")
    void blockedRedirectTargetGivesNull(Kind kind) throws Exception {
        // /r302 переводит на /ok; исходный адрес разрешён, переход блокируется
        CrlFetcher f = blocking(kind, uri -> "/ok".equals(uri.getPath()));

        assertNull(f.fetch(servers.base + "/r302"), kind + ": переход на заблокированный адрес");
        assertEquals(
                0, servers.okRequests.get(), kind + ": к заблокированному адресу ходить нельзя");
        assertArrayEquals(
                "OK".getBytes(),
                blocking(kind, uri -> false).fetch(servers.base + "/r302"),
                kind + ": без блокировки тот же переход выполняется");
    }
}
