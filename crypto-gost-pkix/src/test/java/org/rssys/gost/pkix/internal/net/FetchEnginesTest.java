package org.rssys.gost.pkix.internal.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.util.SafeText;

/**
 * Общий срок, предел размера и политика перенаправлений обоих движков загрузки (на
 * {@code HttpClient} и на {@code HttpURLConnection}). Один набор сценариев на оба движка: поведение
 * должно совпадать.
 */
@DisplayName("Движки загрузки: общий срок, предел размера, перенаправления")
class FetchEnginesTest {

    enum Engine {
        JDK_HTTP {
            @Override
            FetchOutcome run(FetchRequest r) throws IOException {
                return new JdkHttpFetch().execute(r);
            }
        },
        URL_CONNECTION {
            @Override
            FetchOutcome run(FetchRequest r) throws IOException {
                return UrlConnectionFetch.execute(r);
            }
        };

        abstract FetchOutcome run(FetchRequest request) throws IOException;
    }

    private static final Duration TIMEOUT = Duration.ofSeconds(1);
    private static final int MAX_SIZE = 262_144;
    // Допуск на медленный CI: срок 1 с плюс одно чтение и запас
    private static final long TOLERANCE_MILLIS = 2_500;

    private SlowServers servers;

    @BeforeEach
    void setUp() throws Exception {
        servers = new SlowServers();
    }

    @AfterEach
    void tearDown() {
        servers.close();
    }

    // Тестовый сервер слушает loopback, поэтому проверка SSRF отключается (кроме её собственных
    // тестов)
    private static final Predicate<URI> NOTHING_BLOCKED = uri -> false;

    private FetchRequest get(String path, Duration timeout) {
        return FetchRequest.crl(
                URI.create(servers.base + path), timeout, MAX_SIZE, NOTHING_BLOCKED);
    }

    private FetchRequest post(String path, byte[] body) {
        return FetchRequest.ocsp(
                URI.create(servers.base + path),
                body,
                Duration.ofSeconds(5),
                MAX_SIZE,
                NOTHING_BLOCKED);
    }

    private FetchRequest tsp(String path) {
        return FetchRequest.tsp(
                URI.create(servers.base + path),
                new byte[] {1},
                Duration.ofSeconds(5),
                MAX_SIZE,
                NOTHING_BLOCKED);
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    @org.junit.jupiter.api.Test
    @DisplayName("JdkHttpFetch отвергает клиента, который сам следует перенаправлениям")
    void clientThatFollowsRedirectsIsRejected() {
        for (java.net.http.HttpClient.Redirect policy :
                new java.net.http.HttpClient.Redirect[] {
                    java.net.http.HttpClient.Redirect.ALWAYS,
                    java.net.http.HttpClient.Redirect.NORMAL
                }) {
            java.net.http.HttpClient client =
                    java.net.http.HttpClient.newBuilder().followRedirects(policy).build();
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new JdkHttpFetch(client),
                    "клиент с " + policy + " обошёл бы SSRF-проверку на переходах");
        }
        new JdkHttpFetch(
                java.net.http.HttpClient.newBuilder()
                        .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                        .build());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Обычный ответ 200 возвращается целиком")
    void plainResponse(Engine engine) throws Exception {
        assertArrayEquals("OK".getBytes(), engine.run(get("/ok", Duration.ofSeconds(5))).body());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Медленная капля (байт раз в 300 мс) обрывается в пределах срока")
    void slowDripIsCut(Engine engine) {
        long start = System.nanoTime();

        assertThrows(DeadlineExceededException.class, () -> engine.run(get("/drip", TIMEOUT)));

        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS,
                engine + ": медленная капля удерживала загрузку дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName(
            "Быстрая капля (байт раз в 100 мс, таймаут чтения её не ловит) обрывается по общему сроку, соединение закрыто")
    void dripBodyIsCutByDeadline(Engine engine) throws Exception {
        long start = System.nanoTime();

        assertThrows(
                DeadlineExceededException.class,
                () -> engine.run(get("/fastdrip", TIMEOUT)),
                "капля тела должна оборваться по сроку, а не тянуться все 12 с");

        long elapsed = elapsedMillis(start);
        assertTrue(
                elapsed < TOLERANCE_MILLIS,
                engine + ": загрузка заняла " + elapsed + " мс при сроке " + TIMEOUT.toMillis());
        // После отмены фонового чтения быть не должно: сервер видит обрыв соединения клиентом
        long deadline = System.nanoTime() + 3_000_000_000L;
        while (!servers.clientDisconnected.get() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertTrue(
                servers.clientDisconnected.get(),
                engine + ": после срока соединение должно быть закрыто клиентом");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Остановка сервера после первого байта обрывается по сроку")
    void stalledBodyIsCutByDeadline(Engine engine) {
        long start = System.nanoTime();

        DeadlineExceededException e =
                assertThrows(
                        DeadlineExceededException.class, () -> engine.run(get("/stall", TIMEOUT)));
        if (engine == Engine.URL_CONNECTION) {
            // Остановку ловит таймаут чтения раньше общего срока: сообщение должно это различать
            assertTrue(
                    e.getMessage().contains("stalled"), "причина в сообщении: " + e.getMessage());
        }

        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS,
                engine + ": остановившийся сервер удерживал загрузку дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName(
            "Медленные заголовки обрываются по сроку: неполные заголовки не принимаются за ответ")
    void slowHeadersAreCutByDeadline(Engine engine) throws Exception {
        try (ServerSocket raw = SlowServers.slowHeaders()) {
            FetchRequest request =
                    FetchRequest.crl(
                            URI.create("http://127.0.0.1:" + raw.getLocalPort() + "/"),
                            TIMEOUT,
                            MAX_SIZE,
                            NOTHING_BLOCKED);
            long start = System.nanoTime();

            assertThrows(
                    IOException.class,
                    () -> engine.run(request),
                    "обрыв на заголовках должен быть ошибкой, а не пустым ответом 200");

            assertTrue(
                    elapsedMillis(start) < TOLERANCE_MILLIS,
                    engine + ": медленные заголовки удерживали загрузку дольше срока");
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName(
            "Заявленный Content-Length больше предела: BodyTooLargeException с заявленным размером")
    void declaredSizeOverLimit(Engine engine) {
        BodyTooLargeException e =
                assertThrows(
                        BodyTooLargeException.class,
                        () -> engine.run(get("/declaredbig", Duration.ofSeconds(5))));

        assertEquals(600_000L, e.actual(), "заявленный размер");
        assertEquals(MAX_SIZE, e.limit(), "предел");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Фактический размер больше предела при chunked: BodyTooLargeException")
    void actualSizeOverLimit(Engine engine) {
        BodyTooLargeException e =
                assertThrows(
                        BodyTooLargeException.class,
                        () -> engine.run(get("/chunkedbig", Duration.ofSeconds(5))));

        assertEquals(BodyTooLargeException.UNKNOWN_SIZE, e.actual(), "размер не заявлялся");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ не 200 с медленным телом: тело не читается, отказ NON_200 без ожидания")
    void nonOkBodyIsNotAwaited(Engine engine) throws Exception {
        long start = System.nanoTime();

        FetchOutcome outcome = engine.run(get("/error500drip", Duration.ofSeconds(5)));

        assertEquals(FetchOutcome.Failure.NON_200, outcome.failure());
        assertEquals(500, outcome.status());
        assertEquals(0, outcome.errorBody().length, "тело ошибки при пределе 0 не читается");

        assertTrue(
                elapsedMillis(start) < 2_000,
                engine + ": тело ответа 500 не должно ни читаться, ни накапливаться");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("GET следует за 302; POST за 302 не следует")
    void methodDependentRedirects(Engine engine) throws Exception {
        assertArrayEquals("OK".getBytes(), engine.run(get("/r302", Duration.ofSeconds(5))).body());
        FetchOutcome post = engine.run(post("/r302", new byte[] {1}));
        assertEquals(FetchOutcome.Failure.NON_200, post.failure(), "POST не следует за 302");
        assertEquals(302, post.status());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("POST следует за 307 и 308, тело запроса отправляется заново")
    void postFollowsTemporaryAndPermanentRedirects(Engine engine) throws Exception {
        byte[] body = {9, 8, 7};

        assertArrayEquals(body, engine.run(post("/r307", body)).body(), "после 307");
        assertArrayEquals(body, servers.lastEchoBody, "сервер получил тело повторно");
        assertArrayEquals(
                body, engine.run(post("/r308", body)).body(), "после 308 (относительный Location)");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Общий срок один на все переходы: два перехода по 600 мс не умещаются в 1 с")
    void deadlineIsSharedBetweenHops(Engine engine) {
        long start = System.nanoTime();

        assertThrows(DeadlineExceededException.class, () -> engine.run(get("/slow1", TIMEOUT)));

        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS,
                engine + ": срок не должен обновляться на каждом переходе");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Битый, отсутствующий, file: и ftp: Location: отказ с причиной, а не исключение")
    void invalidRedirectTargets(Engine engine) throws Exception {
        assertRedirectFailure(engine, "/rbad", FetchOutcome.Failure.BAD_LOCATION);
        assertRedirectFailure(engine, "/rnoloc", FetchOutcome.Failure.MISSING_LOCATION);
        assertRedirectFailure(engine, "/rfile", FetchOutcome.Failure.DISALLOWED_SCHEME);
        assertEquals(
                "file",
                engine.run(post("/rfile", new byte[] {1})).failedUri().getScheme(),
                engine + ": в исходе отвергнутый адрес перехода, а не адрес запроса");
        assertRedirectFailure(engine, "/rftp", FetchOutcome.Failure.DISALLOWED_SCHEME);
    }

    private void assertRedirectFailure(Engine engine, String path, FetchOutcome.Failure expected)
            throws Exception {
        FetchOutcome outcome = engine.run(post(path, new byte[] {1}));

        assertEquals(expected, outcome.failure(), engine + " " + path);
        assertEquals(307, outcome.status(), engine + " " + path + ": статус перенаправления");
        assertTrue(
                outcome.viaRedirect(),
                engine + " " + path + ": отказ относится к переходу, а не к исходному адресу");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Петля перенаправлений обрывается после 5 запросов")
    void redirectLoopIsBounded(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(get("/loop", Duration.ofSeconds(5)));

        assertEquals(FetchOutcome.Failure.TOO_MANY_REDIRECTS, outcome.failure());
        assertEquals(
                RedirectPolicy.MAX_REQUESTS,
                servers.loopRequests.get(),
                engine + ": число запросов к серверу");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("SSRF-проверка по умолчанию: loopback-адрес отвергается до обращения к серверу")
    void privateAddressIsBlockedBeforeAnyRequest(Engine engine) throws Exception {
        FetchRequest request =
                FetchRequest.crl(
                        URI.create(servers.base + "/loop"),
                        Duration.ofSeconds(5),
                        MAX_SIZE,
                        FetchRequest.BLOCK_PRIVATE_ADDRESSES);

        FetchOutcome outcome = engine.run(request);

        assertEquals(FetchOutcome.Failure.BLOCKED_TARGET, outcome.failure());
        assertEquals(false, outcome.viaRedirect(), "исходный адрес, а не переход");
        assertEquals(0, servers.loopRequests.get(), "к серверу не должно быть ни одного запроса");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("SSRF на втором переходе: заблокированный Location не запрашивается")
    void blockedTargetOnRedirectIsNotRequested(Engine engine) throws Exception {
        // /r302 переводит на /ok; исходный адрес разрешён, переход блокируется
        FetchRequest request =
                FetchRequest.crl(
                        URI.create(servers.base + "/r302"),
                        Duration.ofSeconds(5),
                        MAX_SIZE,
                        uri -> "/ok".equals(uri.getPath()));

        FetchOutcome outcome = engine.run(request);

        assertEquals(FetchOutcome.Failure.BLOCKED_TARGET, outcome.failure());
        assertTrue(outcome.viaRedirect(), "отказ получен на переходе");
        assertEquals(URI.create(servers.base + "/ok"), outcome.failedUri());
        assertEquals(0, servers.okRequests.get(), "заблокированный адрес не должен запрашиваться");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ не 200 с большим телом: статус сохранён, тело усечено до предела")
    void errorBodyIsTruncatedAndStatusKept(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(tsp("/err500big"));

        assertEquals(FetchOutcome.Failure.NON_200, outcome.failure());
        assertEquals(500, outcome.status());
        assertEquals(
                FetchRequest.TSP_ERROR_BODY_LIMIT,
                outcome.errorBody().length,
                engine + ": тело ошибки усекается, а не отвергается по размеру");
        // Тело от недоверенного сервера: управляющие символы в текст не попадают
        String text = SafeText.printableAscii(outcome.errorBody());
        assertTrue(text.startsWith("line1??INJECTED ??"), "текст: " + text);
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Тело отказа тянется дольше срока: код статуса сохраняется, тело - сколько успели")
    void slowErrorBodyKeepsStatus(Engine engine) throws Exception {
        FetchRequest request =
                FetchRequest.tsp(
                        URI.create(servers.base + "/error500drip"),
                        new byte[] {1},
                        TIMEOUT,
                        MAX_SIZE,
                        NOTHING_BLOCKED);
        long start = System.nanoTime();

        FetchOutcome outcome = engine.run(request);

        assertEquals(FetchOutcome.Failure.NON_200, outcome.failure());
        assertEquals(500, outcome.status(), engine + ": срок не должен скрывать код статуса");
        assertTrue(
                outcome.errorBody().length < FetchRequest.TSP_ERROR_BODY_LIMIT,
                engine + ": тело дочитано до предела за срок, хотя оно капает");
        assertTrue(
                elapsedMillis(start) < TOLERANCE_MILLIS,
                engine + ": медленное тело отказа держало загрузку дольше срока");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ 500 с типом text/plain даёт NON_200, а не жалобу на Content-Type")
    void statusIsCheckedBeforeContentType(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(tsp("/err500big"));

        assertEquals(FetchOutcome.Failure.NON_200, outcome.failure());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Content-Type с параметрами и в другом регистре принимается")
    void contentTypeWithParametersAndCase(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(tsp("/type-ok"));

        assertArrayEquals("TS".getBytes(), outcome.body());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Чужой Content-Type с нужным типом в параметре отвергается и передаётся в исходе")
    void wrongContentTypeIsRejected(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(tsp("/type-wrong"));

        assertEquals(FetchOutcome.Failure.UNEXPECTED_CONTENT_TYPE, outcome.failure());
        assertEquals(200, outcome.status());
        assertEquals("text/html; x=application/timestamp-reply", outcome.contentType());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Дополнительные заголовки запроса доходят до сервера")
    void requestHeadersAreSent(Engine engine) throws Exception {
        engine.run(tsp("/headers"));

        assertEquals("application/timestamp-reply", servers.lastAccept);
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Запрос идёт на полный адрес вместе с параметрами запроса")
    void fullUriWithQueryIsRequested(Engine engine) throws Exception {
        engine.run(get("/query?token=secret", Duration.ofSeconds(5)));

        assertEquals("token=secret", servers.lastQuery);
    }

    private FetchRequest conditional(String path, String ifModifiedSince) {
        return FetchRequest.crlConditional(
                URI.create(servers.base + path),
                Duration.ofSeconds(5),
                MAX_SIZE,
                NOTHING_BLOCKED,
                ifModifiedSince);
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Условный запрос: 304 на If-Modified-Since даёт «не изменилось» без тела")
    void conditionalNotModified(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(conditional("/cond", SlowServers.COND_LAST_MODIFIED));

        assertTrue(outcome.notModified(), engine + ": 304 на наш условный запрос");
        assertFalse(outcome.isSuccess());
        assertNull(outcome.lastModified(), "304 без Last-Modified валидатор не приносит");
        assertEquals(
                SlowServers.COND_LAST_MODIFIED, servers.lastIfModifiedSince, "строкой как есть");
        assertNull(servers.lastIfNoneMatch, "If-None-Match не посылается");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName(
            "304 с любой датой Last-Modified (позже, раньше, той же): «не изменилось», дата не читается")
    void lastModifiedOfNotModifiedResponseIsIgnored(Engine engine) throws Exception {
        for (String variant : new String[] {"new", "old", "same"}) {
            FetchOutcome outcome =
                    engine.run(conditional("/cond?" + variant, SlowServers.COND_LAST_MODIFIED));

            assertTrue(outcome.notModified(), engine + " " + variant);
            assertNull(
                    outcome.lastModified(), engine + " " + variant + ": 304 валидатор не приносит");
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("200 вместо 304: полная загрузка с Last-Modified ответа")
    void conditionalFullResponse(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(conditional("/cond", "Mon, 01 Jan 2024 00:00:00 GMT"));

        assertArrayEquals("COND".getBytes(), outcome.body());
        assertEquals(SlowServers.COND_LAST_MODIFIED, outcome.lastModified());
        assertFalse(outcome.notModified());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ 200 без Last-Modified: валидатора нет")
    void responseWithoutLastModified(Engine engine) throws Exception {
        FetchOutcome outcome =
                engine.run(conditional("/cond-nolm", SlowServers.COND_LAST_MODIFIED));

        assertArrayEquals("NOLM".getBytes(), outcome.body());
        assertNull(outcome.lastModified());
        assertEquals(
                SlowServers.COND_LAST_MODIFIED, servers.lastIfModifiedSince, "запрос был условным");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Недопустимый Last-Modified в ответе отбрасывается")
    void invalidResponseLastModified(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(conditional("/cond-badlm", null));

        assertArrayEquals("BADLM".getBytes(), outcome.body());
        assertNull(outcome.lastModified());
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Недопустимый валидатор в запросе не отправляется: запрос безусловный")
    void invalidRequestValidatorIsNotSent(Engine engine) throws Exception {
        for (String bad : new String[] {"yesterday", "", " " + SlowServers.COND_LAST_MODIFIED}) {
            servers.lastIfModifiedSince = "unset";

            engine.run(conditional("/cond", bad));

            assertNull(servers.lastIfModifiedSince, engine + ": «" + bad + "» не должен уходить");
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("304 на безусловный запрос - NON_200, а не «не изменилось»")
    void unconditional304IsNonOk(Engine engine) throws Exception {
        FetchOutcome outcome = engine.run(get("/always304", Duration.ofSeconds(5)));

        assertFalse(outcome.notModified(), engine + ": 304 без нашего условного запроса");
        assertEquals(FetchOutcome.Failure.NON_200, outcome.failure());
        assertEquals(304, outcome.status());
        assertNull(servers.lastIfModifiedSince);
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName(
            "Перенаправление: условный заголовок не уходит на второй запрос, валидатор не сохраняется")
    void conditionalIsNotForwardedAcrossRedirect(Engine engine) throws Exception {
        servers.lastIfModifiedSince = "unset";

        FetchOutcome outcome =
                engine.run(conditional("/cond-redirect", SlowServers.COND_LAST_MODIFIED));

        assertArrayEquals("COND".getBytes(), outcome.body(), "полная загрузка после перехода");
        assertNull(servers.lastIfModifiedSince, "второй запрос безусловный");
        assertNull(outcome.lastModified(), "ответ после перенаправления валидатор не даёт");
    }

    @org.junit.jupiter.api.Test
    @DisplayName("Фабрики запросов задают метод, схемы, тип ответа и предел тела ошибки")
    void factoriesSetProtocolParameters() {
        URI uri = URI.create("http://tsa.example/");
        Duration timeout = Duration.ofSeconds(3);

        FetchRequest ocsp = FetchRequest.ocsp(uri, new byte[] {1}, timeout, 10, NOTHING_BLOCKED);
        FetchRequest crl = FetchRequest.crl(uri, timeout, 10, NOTHING_BLOCKED);
        FetchRequest tsp = FetchRequest.tsp(uri, new byte[] {1}, timeout, 10, NOTHING_BLOCKED);

        assertEquals("POST", ocsp.method());
        assertEquals(Set.of("http"), ocsp.allowedSchemes());
        assertEquals(0, ocsp.errorBodyLimit());
        assertNull(ocsp.expectedMediaType());
        assertEquals("GET", crl.method());
        assertEquals(Set.of("http", "https"), crl.allowedSchemes());
        assertEquals(0, crl.errorBodyLimit());
        assertEquals("POST", tsp.method());
        assertEquals("application/timestamp-reply", tsp.expectedMediaType());
        assertEquals(FetchRequest.TSP_ERROR_BODY_LIMIT, tsp.errorBodyLimit());
    }

    // ---------------------------------------------------------------------------------------
    // Сценарии, которым нужны произвольные заголовки ответа: HttpServer их не отдаёт, поэтому
    // сервер сырой (сокет, ответ целиком задаёт тест)
    // ---------------------------------------------------------------------------------------

    private static final String[] BROKEN_CONTENT_LENGTHS = {
        "abc", "99999999999999999999", "", "-5"
    };
    private static final String BODY_16 = "0123456789ABCDEF";

    /** Сырой HTTP-сервер: на каждое соединение отдаёт один ответ, заданный функцией от пути. */
    private static final class RawServer implements AutoCloseable {
        private final ServerSocket socket;

        RawServer(Function<String, byte[]> responseByPath) throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread acceptor =
                    new Thread(
                            () -> {
                                while (!socket.isClosed()) {
                                    try (Socket client = socket.accept()) {
                                        BufferedReader in =
                                                new BufferedReader(
                                                        new InputStreamReader(
                                                                client.getInputStream(),
                                                                StandardCharsets.ISO_8859_1));
                                        String path = in.readLine().split(" ")[1];
                                        String line;
                                        while ((line = in.readLine()) != null && !line.isEmpty()) {
                                            // заголовки запроса не нужны
                                        }
                                        OutputStream out = client.getOutputStream();
                                        out.write(responseByPath.apply(path));
                                        out.flush();
                                    } catch (IOException | RuntimeException e) {
                                        // сервер закрыт или клиент оборвал соединение
                                    }
                                }
                            });
            acceptor.setDaemon(true);
            acceptor.start();
        }

        String base() {
            return "http://127.0.0.1:" + socket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private static byte[] rawResponse(String lengthHeader, byte[] body) {
        byte[] head =
                ("HTTP/1.1 200 OK\r\n" + lengthHeader + "Connection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1);
        byte[] all = Arrays.copyOf(head, head.length + body.length);
        System.arraycopy(body, 0, all, head.length, body.length);
        return all;
    }

    private static byte[] chunkedResponse(byte[] body) {
        byte[] head =
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .getBytes(StandardCharsets.ISO_8859_1);
        byte[] size =
                (Integer.toHexString(body.length) + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        byte[] tail = "\r\n0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        byte[] all = new byte[head.length + size.length + body.length + tail.length];
        System.arraycopy(head, 0, all, 0, head.length);
        System.arraycopy(size, 0, all, head.length, size.length);
        System.arraycopy(body, 0, all, head.length + size.length, body.length);
        System.arraycopy(tail, 0, all, head.length + size.length + body.length, tail.length);
        return all;
    }

    private FetchRequest rawGet(RawServer raw, String path) {
        return FetchRequest.crl(
                URI.create(raw.base() + path), Duration.ofSeconds(5), MAX_SIZE, NOTHING_BLOCKED);
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Ответ с Content-Length ровно по пределу принимается целиком")
    void bodyExactlyAtLimitIsAccepted(Engine engine) throws Exception {
        byte[] body = new byte[MAX_SIZE];
        try (RawServer raw =
                new RawServer(path -> rawResponse("Content-Length: " + MAX_SIZE + "\r\n", body))) {
            FetchOutcome outcome = engine.run(rawGet(raw, "/crl.crl"));

            assertEquals(MAX_SIZE, outcome.body().length, engine + ": тело ровно по пределу");
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Chunked-ответ ровно по пределу (заголовка длины нет) принимается целиком")
    void chunkedBodyExactlyAtLimitIsAccepted(Engine engine) throws Exception {
        byte[] body = new byte[MAX_SIZE];
        try (RawServer raw = new RawServer(path -> chunkedResponse(body))) {
            FetchOutcome outcome = engine.run(rawGet(raw, "/crl.crl"));

            assertEquals(MAX_SIZE, outcome.body().length, engine + ": тело ровно по пределу");
        }
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = "JDK_HTTP")
    @DisplayName("JdkHttpFetch: невалидный Content-Length даёт IOException, не лимит и не IAE")
    void jdkEngineRejectsBrokenContentLength(Engine engine) throws Exception {
        for (String broken : BROKEN_CONTENT_LENGTHS) {
            try (RawServer raw =
                    new RawServer(
                            path ->
                                    rawResponse(
                                            "Content-Length: " + broken + "\r\n",
                                            BODY_16.getBytes(StandardCharsets.ISO_8859_1)))) {
                IOException e =
                        assertThrows(
                                IOException.class,
                                () -> engine.run(rawGet(raw, "/crl.crl")),
                                "заголовок «" + broken + "» должен давать IOException");

                assertFalse(
                        e instanceof BodyTooLargeException,
                        "битый заголовок не превышение предела: «" + broken + "»");
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = "URL_CONNECTION")
    @DisplayName("UrlConnectionFetch: невалидный Content-Length значит «размер неизвестен»")
    void urlConnectionEngineTreatsBrokenContentLengthAsUnknown(Engine engine) throws Exception {
        for (String broken : BROKEN_CONTENT_LENGTHS) {
            try (RawServer raw =
                    new RawServer(
                            path ->
                                    rawResponse(
                                            "Content-Length: " + broken + "\r\n",
                                            BODY_16.getBytes(StandardCharsets.ISO_8859_1)))) {
                FetchOutcome outcome = engine.run(rawGet(raw, "/crl.crl"));

                assertArrayEquals(
                        BODY_16.getBytes(StandardCharsets.ISO_8859_1),
                        outcome.body(),
                        "заголовок «" + broken + "» не должен ломать загрузку");
            }
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Content-Length промежуточного перенаправления не учитывается, только финальный")
    void redirectContentLengthIsIgnored(Engine engine) throws Exception {
        byte[] redirect =
                ("HTTP/1.1 302 Found\r\nLocation: /final\r\n"
                                + "Content-Length: 5000\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1);
        byte[] fin =
                rawResponse(
                        "Content-Length: 16\r\n", BODY_16.getBytes(StandardCharsets.ISO_8859_1));
        try (RawServer raw = new RawServer(path -> "/redirect".equals(path) ? redirect : fin)) {
            FetchOutcome outcome =
                    engine.run(
                            FetchRequest.crl(
                                    URI.create(raw.base() + "/redirect"),
                                    Duration.ofSeconds(5),
                                    4096,
                                    NOTHING_BLOCKED));

            assertArrayEquals(
                    BODY_16.getBytes(StandardCharsets.ISO_8859_1),
                    outcome.body(),
                    engine + ": большой Content-Length у перенаправления не повод отказывать");
        }
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Порт вне диапазона в Location или в адресе: IOException, не IAE")
    void portOutOfRangeIsIoException(Engine engine) throws Exception {
        byte[] redirect =
                ("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:99999/\r\n"
                                + "Content-Length: 0\r\nConnection: close\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1);
        try (RawServer raw = new RawServer(path -> redirect)) {
            assertThrows(
                    IOException.class,
                    () -> engine.run(rawGet(raw, "/crl.crl")),
                    engine + ": порт 99999 в Location недоступный адрес");
        }
        assertThrows(
                IOException.class,
                () ->
                        engine.run(
                                FetchRequest.crl(
                                        URI.create("http://127.0.0.1:99999/crl.crl"),
                                        Duration.ofSeconds(5),
                                        MAX_SIZE,
                                        NOTHING_BLOCKED)),
                engine + ": порт 99999 в адресе недоступный адрес");
    }

    @ParameterizedTest
    @EnumSource(Engine.class)
    @DisplayName("Молчащий сервер (принял соединение, не отвечает): IOException по сроку")
    void silentServerIsCutByDeadline(Engine engine) throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            FetchRequest request =
                    FetchRequest.crl(
                            URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/crl.crl"),
                            TIMEOUT,
                            MAX_SIZE,
                            NOTHING_BLOCKED);
            long start = System.nanoTime();
            try {
                assertThrows(
                        IOException.class,
                        () -> engine.run(request),
                        engine + ": молчащий сервер должен давать IOException по сроку");

                assertTrue(
                        elapsedMillis(start) < TOLERANCE_MILLIS,
                        engine + ": молчащий сервер удерживал загрузку дольше срока");
                assertFalse(
                        Thread.currentThread().isInterrupted(),
                        engine + ": таймаут не должен оставлять флаг прерывания на потоке");
            } finally {
                Thread.interrupted(); // очистка флага, чтобы не влиять на следующие тесты
            }
        }
    }
}
