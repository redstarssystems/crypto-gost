package org.rssys.gost.pkix.internal.net;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Локальные серверы для проверки сроков загрузчиков: быстрые заголовки и медленное тело, остановка,
 * перенаправления, большие ответы. Каждый обработчик идёт в своём потоке, иначе медленный ответ
 * блокировал бы остальные запросы теста.
 */
public final class SlowServers implements AutoCloseable {

    private static final String TSP_REPLY = "application/timestamp-reply";

    /** Дата файла на «/cond». */
    public static final String COND_LAST_MODIFIED = "Sun, 08 Nov 2026 03:08:46 GMT";

    /** Более ранняя дата файла, которую 304 на «/cond?old» приносит с собой. */
    public static final String COND_PREVIOUS_MODIFIED = "Sun, 08 Nov 2026 03:00:00 GMT";

    /** Более поздняя дата файла, которую 304 на «/cond?new» приносит с собой. */
    public static final String COND_NEXT_MODIFIED = "Sun, 08 Nov 2026 03:13:54 GMT";

    private static final int CHAIN_STEP_MILLIS = 450;
    private static final int DRIP_STEP_MILLIS = 300;
    private static final int DRIP_BYTES = 40;
    // Быстрая капля: пауза меньше четверти срока (readTimeout), поэтому таймаут чтения её не ловит
    // и сработать должен именно общий срок
    private static final int FAST_DRIP_STEP_MILLIS = 100;
    private static final int FAST_DRIP_BYTES = 150;

    final HttpServer server;

    /** Адрес сервера вида {@code http://127.0.0.1:порт}. */
    public final String base;

    /** Сервер увидел обрыв соединения клиентом при записи (после отмены загрузки). */
    public final AtomicBoolean clientDisconnected = new AtomicBoolean();

    /** Число запросов на «/loop» (проверка предела перенаправлений). */
    public final AtomicInteger loopRequests = new AtomicInteger();

    /** Число запросов на «/ok»: проверка, что заблокированный переход до сервера не дошёл. */
    public final AtomicInteger okRequests = new AtomicInteger();

    /** Тело последнего запроса на «/echo». */
    public volatile byte[] lastEchoBody;

    /** Заголовок {@code Accept} последнего запроса на «/headers». */
    public volatile String lastAccept;

    /** Заголовок {@code Content-Type} последнего запроса на «/headers». */
    public volatile String lastRequestType;

    /** Тело файла на «/fresh». */
    public volatile byte[] freshBody = new byte[0];

    /** Дата файла на «/fresh» (HTTP-дата). */
    public volatile String freshModified = COND_LAST_MODIFIED;

    /** Следующий условный запрос на «/fresh» получит противоречивый ответ 304 с датой {@link #contradictDate}. */
    public final AtomicBoolean contradictNext = new AtomicBoolean();

    /** Дата, которую противоречивый 304 на «/fresh» приносит с собой. */
    public volatile String contradictDate = COND_NEXT_MODIFIED;

    /** Заголовок {@code If-Modified-Since} последнего запроса на «/cond», «/cond-nolm», «/always304». */
    public volatile String lastIfModifiedSince;

    /** Заголовок {@code If-None-Match} последнего запроса на «/cond». */
    public volatile String lastIfNoneMatch;

    /** Строка запроса (после «?») последнего запроса на «/query». */
    public volatile String lastQuery;

    public SlowServers() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        base = "http://127.0.0.1:" + server.getAddress().getPort();

        server.createContext(
                "/ok",
                ex -> {
                    okRequests.incrementAndGet();
                    respond(ex, 200, "OK".getBytes());
                });
        // Ответ 500 с большим телом, управляющими символами в начале и text/plain
        server.createContext(
                "/err500big",
                ex -> {
                    byte[] text = "line1\r\nINJECTED \u0001\u00e9".getBytes(StandardCharsets.UTF_8);
                    byte[] body = new byte[1000];
                    java.util.Arrays.fill(body, (byte) 'x');
                    System.arraycopy(text, 0, body, 0, text.length);
                    ex.getResponseHeaders().add("Content-Type", "text/plain");
                    respond(ex, 500, body);
                });
        // Тип содержимого с параметром и в другом регистре
        server.createContext(
                "/type-ok",
                ex -> {
                    ex.getResponseHeaders().add("Content-Type", "Application/Timestamp-Reply; x=1");
                    respond(ex, 200, "TS".getBytes());
                });
        // Тип чужой, нужный тип спрятан в параметре: подстрокой его принимать нельзя
        server.createContext(
                "/type-wrong",
                ex -> {
                    ex.getResponseHeaders()
                            .add("Content-Type", "text/html; x=application/timestamp-reply");
                    respond(ex, 200, "HTML".getBytes());
                });
        // Серверы TSP: ответы с типом application/timestamp-reply
        server.createContext(
                "/tsp-drip",
                ex -> {
                    ex.getResponseHeaders().add("Content-Type", TSP_REPLY);
                    drip(ex, 200, FAST_DRIP_STEP_MILLIS, FAST_DRIP_BYTES);
                });
        server.createContext(
                "/tsp-stall",
                ex -> {
                    ex.getResponseHeaders().add("Content-Type", TSP_REPLY);
                    stall(ex);
                });
        server.createContext(
                "/tsp-echo",
                ex -> {
                    ex.getResponseHeaders().add("Content-Type", TSP_REPLY);
                    byte[] in = ex.getRequestBody().readAllBytes();
                    lastEchoBody = in;
                    respond(ex, 200, in);
                });
        // Размер тела задаётся параметром n
        server.createContext(
                "/tsp-size",
                ex -> {
                    String query = ex.getRequestURI().getRawQuery();
                    byte[] body = new byte[Integer.parseInt(query.substring("n=".length()))];
                    ex.getResponseHeaders().add("Content-Type", TSP_REPLY);
                    respond(ex, 200, body);
                });
        server.createContext("/r307tsp", ex -> redirect(ex, 307, base + "/tsp-echo"));
        server.createContext("/r308tsp", ex -> redirect(ex, 308, "/tsp-echo"));
        // Цепочка из n+1 запросов, каждый отвечает через 450 мс (меньше четверти срока 2 с, так что
        // таймаут чтения HttpURLConnection не срабатывает): только общий срок отличает её от успеха
        server.createContext(
                "/chain",
                ex -> {
                    int left = Integer.parseInt(ex.getRequestURI().getRawQuery().substring(2));
                    try {
                        Thread.sleep(CHAIN_STEP_MILLIS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    if (left > 0) {
                        redirect(ex, 307, base + "/chain?n=" + (left - 1));
                    } else {
                        ex.getResponseHeaders().add("Content-Type", TSP_REPLY);
                        respond(ex, 200, "TS".getBytes());
                    }
                });
        server.createContext("/tspslow1", ex -> slowRedirect(ex, base + "/tspslow2"));
        server.createContext("/tspslow2", ex -> slowRedirect(ex, base + "/type-ok"));
        // Условные запросы. /cond: Last-Modified фиксирован, на совпадающий If-Modified-Since - 304
        // (с новым Last-Modified, если запрошено через ?new), иначе 200 с телом
        server.createContext(
                "/cond",
                ex -> {
                    lastIfModifiedSince = ex.getRequestHeaders().getFirst("If-Modified-Since");
                    lastIfNoneMatch = ex.getRequestHeaders().getFirst("If-None-Match");
                    String query = ex.getRequestURI().getRawQuery();
                    if (COND_LAST_MODIFIED.equals(lastIfModifiedSince)) {
                        // Как IIS: 304 без Last-Modified, если не запрошено новое значение
                        if ("new".equals(query)) {
                            ex.getResponseHeaders().add("Last-Modified", COND_NEXT_MODIFIED);
                        } else if ("old".equals(query)) {
                            ex.getResponseHeaders().add("Last-Modified", COND_PREVIOUS_MODIFIED);
                        } else if ("same".equals(query)) {
                            ex.getResponseHeaders().add("Last-Modified", COND_LAST_MODIFIED);
                        }
                        ex.getRequestBody().readAllBytes();
                        ex.sendResponseHeaders(304, -1);
                        ex.close();
                        return;
                    }
                    ex.getResponseHeaders().add("Last-Modified", COND_LAST_MODIFIED);
                    respond(ex, 200, "COND".getBytes());
                });
        // 200 без Last-Modified, условный заголовок игнорируется
        server.createContext(
                "/cond-nolm",
                ex -> {
                    lastIfModifiedSince = ex.getRequestHeaders().getFirst("If-Modified-Since");
                    respond(ex, 200, "NOLM".getBytes());
                });
        // Сервер всегда отвечает 304, даже на безусловный запрос
        server.createContext(
                "/always304",
                ex -> {
                    lastIfModifiedSince = ex.getRequestHeaders().getFirst("If-Modified-Since");
                    ex.getRequestBody().readAllBytes();
                    ex.sendResponseHeaders(304, -1);
                    ex.close();
                });
        // Перенаправление на /cond: условный запрос после перехода не должен уходить
        server.createContext("/cond-redirect", ex -> redirect(ex, 302, base + "/cond"));
        // Недопустимый Last-Modified в ответе
        server.createContext(
                "/cond-badlm",
                ex -> {
                    ex.getResponseHeaders().add("Last-Modified", "yesterday-ish");
                    respond(ex, 200, "BADLM".getBytes());
                });
        // Свежесть: /fresh отдаёт freshBody с датой freshModified и честно отвечает на
        // If-Modified-Since
        // (304, если файл не новее). Один раз по флагу contradictNext сервер врёт: отвечает 304,
        // но с датой contradictDate, которая новее отправленной (противоречит RFC 9110)
        server.createContext(
                "/fresh",
                ex -> {
                    String ims = ex.getRequestHeaders().getFirst("If-Modified-Since");
                    lastIfModifiedSince = ims;
                    ex.getRequestBody().readAllBytes();
                    if (ims != null && contradictNext.compareAndSet(true, false)) {
                        ex.getResponseHeaders().add("Last-Modified", contradictDate);
                        ex.sendResponseHeaders(304, -1);
                        ex.close();
                        return;
                    }
                    java.time.format.DateTimeFormatter f =
                            java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;
                    if (ims != null
                            && !java.time.ZonedDateTime.parse(freshModified, f)
                                    .isAfter(java.time.ZonedDateTime.parse(ims, f))) {
                        ex.sendResponseHeaders(304, -1);
                        ex.close();
                        return;
                    }
                    ex.getResponseHeaders().add("Last-Modified", freshModified);
                    respond(ex, 200, freshBody);
                });
        server.createContext(
                "/headers",
                ex -> {
                    lastAccept = ex.getRequestHeaders().getFirst("Accept");
                    lastRequestType = ex.getRequestHeaders().getFirst("Content-Type");
                    respond(ex, 200, "H".getBytes());
                });
        server.createContext(
                "/query",
                ex -> {
                    lastQuery = ex.getRequestURI().getRawQuery();
                    respond(ex, 200, "Q".getBytes());
                });
        // Капля: заголовки сразу, затем по байту раз в 300 мс (всего 12 с)
        server.createContext("/drip", ex -> drip(ex, 200));
        server.createContext("/error500drip", ex -> drip(ex, 500));
        server.createContext(
                "/fastdrip", ex -> drip(ex, 200, FAST_DRIP_STEP_MILLIS, FAST_DRIP_BYTES));
        // Остановка: заголовки и один байт, затем тишина на 10 с
        server.createContext("/stall", ex -> stall(ex));
        // Заявленный размер больше предела
        server.createContext(
                "/declaredbig",
                ex -> {
                    ex.getRequestBody().readAllBytes();
                    byte[] body = new byte[600_000];
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    } catch (IOException ignored) {
                        // клиент прервал приём
                    }
                });
        // Размер не заявлен (chunked), фактически больше предела
        server.createContext(
                "/chunkedbig",
                ex -> {
                    ex.getRequestBody().readAllBytes();
                    ex.sendResponseHeaders(200, 0);
                    try (OutputStream os = ex.getResponseBody()) {
                        byte[] chunk = new byte[50_000];
                        for (int i = 0; i < 12; i++) {
                            os.write(chunk);
                        }
                    } catch (IOException ignored) {
                        // клиент прервал приём
                    }
                });
        server.createContext("/r302", ex -> redirect(ex, 302, base + "/ok"));
        server.createContext("/r307", ex -> redirect(ex, 307, base + "/echo"));
        server.createContext("/r308", ex -> redirect(ex, 308, "/echo"));
        server.createContext("/rbad", ex -> redirect(ex, 307, "http://[bad"));
        server.createContext("/rfile", ex -> redirect(ex, 307, "file:///etc/hostname"));
        server.createContext("/rftp", ex -> redirect(ex, 307, "ftp://example.com/x"));
        server.createContext("/rnoloc", ex -> redirect(ex, 307, null));
        server.createContext(
                "/loop",
                ex -> {
                    loopRequests.incrementAndGet();
                    redirect(ex, 307, base + "/loop");
                });
        // Два перехода по 600 мс каждый: каждый укладывается в срок по отдельности, сумма - нет
        server.createContext("/slow1", ex -> slowRedirect(ex, base + "/slow2"));
        server.createContext("/slow2", ex -> slowRedirect(ex, base + "/ok"));
        server.createContext(
                "/echo",
                ex -> {
                    byte[] in = ex.getRequestBody().readAllBytes();
                    lastEchoBody = in;
                    respond(ex, 200, in.length == 0 ? "EMPTY".getBytes() : in);
                });
        server.start();
    }

    private static void stall(HttpExchange ex) throws IOException {
        ex.getRequestBody().readAllBytes();
        ex.sendResponseHeaders(200, 0);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(1);
            os.flush();
            Thread.sleep(10_000);
        } catch (IOException | InterruptedException ignored) {
            // клиент ушёл
        }
    }

    private void drip(HttpExchange ex, int status) throws IOException {
        drip(ex, status, DRIP_STEP_MILLIS, DRIP_BYTES);
    }

    private void drip(HttpExchange ex, int status, int stepMillis, int bytes) throws IOException {
        ex.getRequestBody().readAllBytes();
        ex.sendResponseHeaders(status, 0);
        try (OutputStream os = ex.getResponseBody()) {
            for (int i = 0; i < bytes; i++) {
                os.write(1);
                os.flush();
                Thread.sleep(stepMillis);
            }
        } catch (IOException e) {
            clientDisconnected.set(true);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void slowRedirect(HttpExchange ex, String to) throws IOException {
        ex.getRequestBody().readAllBytes();
        try {
            Thread.sleep(600);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        redirect(ex, 307, to);
    }

    private static void redirect(HttpExchange ex, int status, String location) throws IOException {
        ex.getRequestBody().readAllBytes();
        if (location != null) {
            ex.getResponseHeaders().add("Location", location);
        }
        ex.sendResponseHeaders(status, -1);
        ex.close();
    }

    private static void respond(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.getRequestBody().readAllBytes();
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    /**
     * Сырой сервер: «200 OK» и затем заголовок по байту раз в 100 мс (быстрее таймаута чтения),
     * конца заголовков нет.
     * {@code HttpURLConnection} в таком случае после обрыва сторожем возвращает 200 с неполными
     * заголовками.
     *
     * @return порт
     */
    static ServerSocket slowHeaders() throws IOException {
        ServerSocket raw = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
        Thread t =
                new Thread(
                        () -> {
                            try (Socket s = raw.accept()) {
                                s.getInputStream().read(new byte[8192]);
                                OutputStream os = s.getOutputStream();
                                os.write("HTTP/1.1 200 OK\r\n".getBytes());
                                os.flush();
                                for (int i = 0; i < FAST_DRIP_BYTES; i++) {
                                    os.write('X');
                                    os.flush();
                                    Thread.sleep(FAST_DRIP_STEP_MILLIS);
                                }
                            } catch (IOException | InterruptedException ignored) {
                                // клиент ушёл или тест закончился
                            }
                        });
        t.setDaemon(true);
        t.start();
        return raw;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
