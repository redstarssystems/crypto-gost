package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * HTTP-цикл UrlConnectionTspTransport с mock-сервером.
 */
class UrlConnectionTspTransportTest {

    private static final byte[] SENTINEL = "TSP_RESPONSE_OK".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REQUEST = "TSP_REQUEST".getBytes(StandardCharsets.UTF_8);

    private HttpServer server;
    private int port;

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private void startMock(byte[] responseBody, int statusCode, String contentType)
            throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext(
                "/",
                ex -> {
                    assertEquals("POST", ex.getRequestMethod());
                    assertEquals(
                            "application/timestamp-query",
                            ex.getRequestHeaders().getFirst("Content-Type"));

                    byte[] body = ex.getRequestBody().readAllBytes();
                    assertTrue(body.length > 0, "Тело TSP-запроса не должно быть пустым");

                    if (contentType != null) {
                        ex.getResponseHeaders().set("Content-Type", contentType);
                    }
                    ex.sendResponseHeaders(statusCode, responseBody.length);
                    ex.getResponseBody().write(responseBody);
                    ex.getResponseBody().close();
                });
        server.start();
        port = server.getAddress().getPort();
    }

    @Test
    @DisplayName("200 + application/timestamp-reply -> возвращает тело")
    void testSendSuccess() throws Exception {
        startMock(SENTINEL, 200, "application/timestamp-reply");
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport(true);
        byte[] result = transport.send(REQUEST, "http://localhost:" + port);
        assertArrayEquals(SENTINEL, result, "Transport должен вернуть тело ответа");
    }

    @Test
    @DisplayName("HTTP 500 -> IOException")
    void testSendServerError() throws Exception {
        startMock(SENTINEL, 500, "text/plain");
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport(true);
        assertThrows(
                java.io.IOException.class,
                () -> transport.send(REQUEST, "http://localhost:" + port));
    }

    @Test
    @DisplayName("200 + неверный Content-Type -> IOException")
    void testSendWrongContentType() throws Exception {
        startMock(SENTINEL, 200, "text/html");
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport(true);
        assertThrows(
                java.io.IOException.class,
                () -> transport.send(REQUEST, "http://localhost:" + port));
    }

    @Test
    @DisplayName("private IP -> IOException")
    void testPrivateIpBlocked() {
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport();
        assertThrows(java.io.IOException.class, () -> transport.send(REQUEST, "http://127.0.0.1/"));
    }

    @Test
    @DisplayName("file:// URI -> IOException")
    void testFileSchemeRejected() {
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport();
        assertThrows(java.io.IOException.class, () -> transport.send(REQUEST, "file:///etc/ocsp"));
    }

    @Test
    @DisplayName("Редирект -> успешный запрос")
    void testRedirect() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext(
                "/first",
                ex -> {
                    ex.getResponseHeaders().set("Location", "http://localhost:" + port + "/second");
                    ex.sendResponseHeaders(307, -1);
                    ex.getResponseBody().close();
                });
        server.createContext(
                "/second",
                ex -> {
                    assertEquals("POST", ex.getRequestMethod());
                    ex.getResponseHeaders().set("Content-Type", "application/timestamp-reply");
                    ex.sendResponseHeaders(200, SENTINEL.length);
                    ex.getResponseBody().write(SENTINEL);
                    ex.getResponseBody().close();
                });
        server.start();
        port = server.getAddress().getPort();

        UrlConnectionTspTransport transport = new UrlConnectionTspTransport(true);
        byte[] result = transport.send(REQUEST, "http://localhost:" + port + "/first");
        assertArrayEquals(SENTINEL, result, "Transport должен пройти редирект");
    }

    @Test
    @DisplayName("Превышение MAX_TSP_RESPONSE_SIZE -> IOException")
    void testResponseTooLarge() throws Exception {
        // Создаём ответ размером 2 МБ — превышает лимит
        byte[] largeResponse = new byte[2 * 1024 * 1024];
        startMock(largeResponse, 200, "application/timestamp-reply");
        UrlConnectionTspTransport transport = new UrlConnectionTspTransport(true);
        assertThrows(
                java.io.IOException.class,
                () -> transport.send(REQUEST, "http://localhost:" + port));
    }
}
