package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.pkix.internal.net.SlowServers;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Оба транспорта TSP на общем движке загрузки: один набор сценариев, поведение должно совпадать
 * (на {@code HttpClient} и на {@code HttpURLConnection}).
 */
@DisplayName("Транспорты TSP: общий срок, перенаправления, ответ, контракт исключений")
class TspTransportsTest {

    enum Kind {
        JDK_HTTP((t, blocked) -> new JdkHttpTspTransport(t, blocked)),
        URL_CONNECTION((t, blocked) -> new UrlConnectionTspTransport(t, blocked));

        final BiFunction<Duration, Predicate<URI>, TspTransport> factory;

        Kind(BiFunction<Duration, Predicate<URI>, TspTransport> factory) {
            this.factory = factory;
        }
    }

    private static final byte[] REQUEST = {1, 2, 3};
    private static final Duration TIMEOUT = Duration.ofSeconds(1);
    // Срок 1 с плюс одно чтение и запас на медленный CI
    private static final long TOLERANCE_MILLIS = 2_500;
    // Тестовый сервер слушает loopback, поэтому блокировка отключается (кроме собственных тестов)
    private static final Predicate<URI> NOTHING_BLOCKED = uri -> false;

    private SlowServers servers;

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        servers.close();
    }

    private TspTransport transport(Kind kind) {
        return kind.factory.apply(Duration.ofSeconds(5), NOTHING_BLOCKED);
    }

    private String url(String path) {
        return servers.base + path;
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("200 с application/timestamp-reply с параметрами и в другом регистре: тело")
    void successWithTypeParametersAndCase(Kind kind) throws Exception {
        assertArrayEquals("TS".getBytes(), transport(kind).send(REQUEST, url("/type-ok")));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Запрос несёт Content-Type и Accept TSP")
    void requestHeaders(Kind kind) throws Exception {
        assertThrows(IOException.class, () -> transport(kind).send(REQUEST, url("/headers")));

        assertEquals("application/timestamp-query", servers.lastRequestType);
        assertEquals("application/timestamp-reply", servers.lastAccept);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Чужой Content-Type (нужный тип только в параметре): IOException")
    void wrongContentType(Kind kind) {
        IOException e =
                assertThrows(
                        IOException.class, () -> transport(kind).send(REQUEST, url("/type-wrong")));

        assertTrue(e.getMessage().startsWith("Unexpected Content-Type from TSA: 'text/html"));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Отказ сервера с большим телом: статус сохранён, тело усечено и очищено")
    void serverErrorKeepsStatusAndSanitizesBody(Kind kind) {
        IOException e =
                assertThrows(
                        IOException.class, () -> transport(kind).send(REQUEST, url("/err500big")));

        String message = e.getMessage();
        // Ответ 500 с text/plain сообщается кодом статуса, а не жалобой на Content-Type
        assertTrue(message.startsWith("TSA returned HTTP 500 for " + url("/err500big")), message);
        assertTrue(message.contains(": line1??INJECTED ??"), "очищенное тело: " + message);
        assertFalse(message.contains("\r") || message.contains("\n"), "перевод строки в сообщении");
        assertTrue(message.length() < 250, "тело усечено: " + message.length());
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Ответ 500 с телом, которое тянется дольше срока: сообщение с кодом, а не «timed out»")
    void slowErrorBodyReportsStatus(Kind kind) {
        TspTransport transport = kind.factory.apply(TIMEOUT, NOTHING_BLOCKED);
        long start = System.nanoTime();

        IOException e =
                assertThrows(
                        IOException.class, () -> transport.send(REQUEST, url("/error500drip")));

        assertTrue(e.getMessage().startsWith("TSA returned HTTP 500 for "), e.getMessage());
        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS,
                kind + ": тело отказа держало дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Размер ответа: ровно 1 МБ принимается, 1 МБ + 1 отвергается")
    void responseSizeLimit(Kind kind) throws Exception {
        TspTransport transport = transport(kind);

        assertEquals(
                1_048_576,
                transport.send(REQUEST, url("/tsp-size?n=1048576")).length,
                "ровно 1 МБ");
        IOException e =
                assertThrows(
                        IOException.class,
                        () -> transport.send(REQUEST, url("/tsp-size?n=1048577")));
        assertTrue(e.getMessage().startsWith("TSP response exceeds maximum size of 1048576"));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Капля тела (байт раз в 100 мс) обрывается по общему сроку")
    void slowDripIsCut(Kind kind) {
        TspTransport transport = kind.factory.apply(TIMEOUT, NOTHING_BLOCKED);
        long start = System.nanoTime();

        IOException e =
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/tsp-drip")));

        assertTrue(e.getMessage().startsWith("TSP request timed out"), e.getMessage());
        assertTrue(elapsedMillis(start) < TOLERANCE_MILLIS, kind + ": капля держала дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Остановка сервера после первого байта обрывается по сроку")
    void stalledBodyIsCut(Kind kind) {
        TspTransport transport = kind.factory.apply(TIMEOUT, NOTHING_BLOCKED);
        long start = System.nanoTime();

        assertThrows(IOException.class, () -> transport.send(REQUEST, url("/tsp-stall")));

        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS, kind + ": остановка держала дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Общий срок один на все переходы: два перехода по 600 мс не умещаются в 1 с")
    void deadlineIsSharedBetweenHops(Kind kind) {
        TspTransport transport = kind.factory.apply(TIMEOUT, NOTHING_BLOCKED);
        long start = System.nanoTime();

        assertThrows(IOException.class, () -> transport.send(REQUEST, url("/tspslow1")));

        assertTrue(elapsedMillis(start) < TOLERANCE_MILLIS, kind + ": срок обновлялся на переходе");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Пять запросов по 450 мс (каждый быстрее таймаута чтения) не умещаются в общий срок 2 с")
    void deadlineIsSharedWhenEachHopIsWithinReadTimeout(Kind kind) {
        TspTransport transport = kind.factory.apply(Duration.ofSeconds(2), NOTHING_BLOCKED);
        long start = System.nanoTime();

        assertThrows(IOException.class, () -> transport.send(REQUEST, url("/chain?n=4")));

        assertTrue(elapsedMillis(start) < 3_500, kind + ": срок не должен обновляться на переходе");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("POST следует за 307 и 308, тело запроса отправляется заново")
    void postFollowsTemporaryAndPermanentRedirects(Kind kind) throws Exception {
        assertArrayEquals(REQUEST, transport(kind).send(REQUEST, url("/r307tsp")), "после 307");
        assertArrayEquals(REQUEST, servers.lastEchoBody, "сервер получил тело повторно");
        assertArrayEquals(REQUEST, transport(kind).send(REQUEST, url("/r308tsp")), "после 308");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("POST не следует за 302 (раньше HttpClient превращал его в GET)")
    void postDoesNotFollow302(Kind kind) {
        IOException e =
                assertThrows(IOException.class, () -> transport(kind).send(REQUEST, url("/r302")));

        assertTrue(e.getMessage().startsWith("TSA returned HTTP 302"), e.getMessage());
        assertEquals(0, servers.okRequests.get(), "переход по 302 не должен выполняться");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Битый, отсутствующий, file: и ftp: Location: IOException, а не IllegalArgument")
    void invalidLocationIsIoException(Kind kind) {
        TspTransport transport = transport(kind);

        assertEquals(
                "Redirect with invalid Location header for " + url("/rbad"),
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/rbad")))
                        .getMessage());
        assertEquals(
                "Redirect without Location header for " + url("/rnoloc"),
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/rnoloc")))
                        .getMessage());
        assertEquals(
                "Unsupported redirect URL scheme: file",
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/rfile")))
                        .getMessage());
        assertEquals(
                "Unsupported redirect URL scheme: ftp",
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/rftp")))
                        .getMessage());
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Петля перенаправлений обрывается: Too many redirects")
    void redirectLoop(Kind kind) {
        IOException e =
                assertThrows(IOException.class, () -> transport(kind).send(REQUEST, url("/loop")));

        assertEquals("Too many redirects for " + url("/loop"), e.getMessage());
        assertEquals(5, servers.loopRequests.get(), "число запросов к серверу");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("SSRF на втором переходе: заблокированный Location не запрашивается")
    void blockedRedirectTarget(Kind kind) {
        TspTransport transport =
                kind.factory.apply(Duration.ofSeconds(5), uri -> "/tsp-echo".equals(uri.getPath()));

        IOException e =
                assertThrows(IOException.class, () -> transport.send(REQUEST, url("/r307tsp")));

        assertEquals("Redirect resolves to private address: " + url("/tsp-echo"), e.getMessage());
        assertEquals(null, servers.lastEchoBody, "заблокированный адрес не должен запрашиваться");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName(
            "Исходный адрес: loopback блокируется по умолчанию, схема file: и ftp: отвергается")
    void initialAddressChecks(Kind kind) throws Exception {
        TspTransport byDefault =
                kind == Kind.JDK_HTTP ? new JdkHttpTspTransport() : new UrlConnectionTspTransport();

        assertEquals(
                "TSP URL resolves to private address: " + url("/type-ok"),
                assertThrows(IOException.class, () -> byDefault.send(REQUEST, url("/type-ok")))
                        .getMessage());
        assertEquals(
                "Unsupported TSP URL scheme: file",
                assertThrows(IOException.class, () -> byDefault.send(REQUEST, "file:///etc/x"))
                        .getMessage());
        assertEquals(
                "Unsupported TSP URL scheme: ftp",
                assertThrows(IOException.class, () -> byDefault.send(REQUEST, "ftp://tsa.example/"))
                        .getMessage());
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Пустые и синтаксически неверные аргументы: IllegalArgumentException")
    void invalidArgumentsAreIllegalArgument(Kind kind) {
        TspTransport transport = transport(kind);

        for (String badUrl : new String[] {null, "", "  ", "http://[bad", "not a uri"}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> transport.send(REQUEST, badUrl),
                    kind + ": адрес «" + badUrl + "»");
        }
        assertThrows(IllegalArgumentException.class, () -> transport.send(null, url("/type-ok")));
        assertThrows(
                IllegalArgumentException.class, () -> transport.send(new byte[0], url("/type-ok")));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Адрес в сообщениях без учётных данных и параметров, запрос идёт на полный адрес")
    void addressIsSanitizedInMessagesButRequestedInFull(Kind kind) {
        String withSecrets =
                servers.base.replace("http://", "http://user:pass@") + "/query?token=secret";

        IOException e =
                assertThrows(IOException.class, () -> transport(kind).send(REQUEST, withSecrets));

        assertEquals("token=secret", servers.lastQuery, "сервер получил полный адрес");
        String text = e.getMessage();
        assertFalse(text.contains("pass") || text.contains("secret"), "секреты в тексте: " + text);
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    @DisplayName("Срок: границы проверяются при создании")
    void timeoutBounds(Kind kind) {
        for (Duration bad :
                new Duration[] {
                    null,
                    Duration.ZERO,
                    Duration.ofMillis(-1),
                    Duration.ofNanos(500_000),
                    Deadline.MAX_FETCH_TIMEOUT.plusNanos(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> kind.factory.apply(bad, NOTHING_BLOCKED),
                    kind + ": срок " + bad);
        }
        assertDoesNotThrow(() -> kind.factory.apply(Deadline.MIN_TIMEOUT, NOTHING_BLOCKED));
        assertDoesNotThrow(() -> kind.factory.apply(Deadline.MAX_FETCH_TIMEOUT, NOTHING_BLOCKED));
    }

    @Test
    @DisplayName("Публичные конструкторы со сроком проверяют его так же")
    void publicConstructorsValidateTimeout() {
        assertThrows(IllegalArgumentException.class, () -> new JdkHttpTspTransport(Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class, () -> new UrlConnectionTspTransport(Duration.ZERO));
        assertDoesNotThrow(() -> new JdkHttpTspTransport(Duration.ofSeconds(3)));
        assertDoesNotThrow(() -> new UrlConnectionTspTransport(Duration.ofSeconds(3)));
    }

    @Test
    @DisplayName("JdkHttpTspTransport отвергает клиента, который сам следует перенаправлениям")
    void clientThatFollowsRedirectsIsRejected() {
        for (HttpClient.Redirect policy :
                new HttpClient.Redirect[] {
                    HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS
                }) {
            HttpClient client = HttpClient.newBuilder().followRedirects(policy).build();
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new JdkHttpTspTransport(client),
                    "клиент с " + policy + " обошёл бы проверку адреса на переходах");
        }
        assertDoesNotThrow(
                () ->
                        new JdkHttpTspTransport(
                                HttpClient.newBuilder()
                                        .followRedirects(HttpClient.Redirect.NEVER)
                                        .build()));
    }
}
