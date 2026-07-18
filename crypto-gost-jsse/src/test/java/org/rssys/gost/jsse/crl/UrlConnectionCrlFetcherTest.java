package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * HTTP-цикл UrlConnectionCrlFetcher с mock-сервером.
 */
@DisplayName("UrlConnectionCrlFetcher: HTTP получение CRL")
class UrlConnectionCrlFetcherTest {

    private static final byte[] SENTINEL =
            "CRL_RESPONSE_OK".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private HttpServer server;
    private int port;

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private void startMock(byte[] responseBody, int statusCode) throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext(
                "/",
                ex -> {
                    assertEquals("GET", ex.getRequestMethod(), "CRL fetch должен быть GET");
                    ex.sendResponseHeaders(statusCode, responseBody.length);
                    ex.getResponseBody().write(responseBody);
                    ex.getResponseBody().close();
                });
        server.start();
        port = server.getAddress().getPort();
    }

    @Test
    @DisplayName("200 + тело -> fetcher возвращает тело")
    void testFetchSuccess() throws Exception {
        startMock(SENTINEL, 200);
        UrlConnectionCrlFetcher fetcher =
                new UrlConnectionCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        byte[] result = fetcher.fetch("http://localhost:" + port + "/crl.crl");
        assertArrayEquals(SENTINEL, result, "Fetcher должен вернуть тело ответа");
    }

    @Test
    @DisplayName("HTTP 500 -> fetcher возвращает null")
    void testFetchServerError() throws Exception {
        startMock(SENTINEL, 500);
        UrlConnectionCrlFetcher fetcher =
                new UrlConnectionCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        assertNull(fetcher.fetch("http://localhost:" + port + "/crl.crl"));
    }

    @Test
    @DisplayName("private IP (127.0.0.1) блокируется -> null")
    void testPrivateIpBlocked() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch("http://127.0.0.1/crl.crl"));
    }

    @Test
    @DisplayName("localhost блокируется -> null")
    void testLocalhostBlocked() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch("http://localhost/crl.crl"));
    }

    @Test
    @DisplayName("file:// URI -> null (запрещённая схема)")
    void testFileScheme() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch("file:///etc/crl.crl"));
    }

    @Test
    @DisplayName("ldap:// URI -> null (запрещённая схема)")
    void testLdapScheme() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch("ldap://crl.example.com/crl"));
    }

    @Test
    @DisplayName("Ответ > maxResponseSize -> null")
    void testFetchOversizeResponse() throws Exception {
        byte[] largeResponse = new byte[6 * 1024 * 1024]; // 6 МБ > 5 МБ лимит
        startMock(largeResponse, 200);
        UrlConnectionCrlFetcher fetcher =
                new UrlConnectionCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        assertNull(fetcher.fetch("http://localhost:" + port + "/crl.crl"));
    }

    @Test
    @DisplayName("null URI -> null")
    void testFetchNullUri() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch(null));
    }

    @Test
    @DisplayName("пустой URI -> null")
    void testFetchEmptyUri() throws Exception {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher();
        assertNull(fetcher.fetch(""));
    }

    @Test
    @DisplayName("Редирект -> успешный запрос")
    void testRedirect() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext(
                "/first",
                ex -> {
                    ex.getResponseHeaders()
                            .set(
                                    "Location",
                                    "http://localhost:"
                                            + server.getAddress().getPort()
                                            + "/second");
                    ex.sendResponseHeaders(307, -1);
                    ex.getResponseBody().close();
                });
        server.start();
        port = server.getAddress().getPort();

        server.createContext(
                "/second",
                ex -> {
                    assertEquals("GET", ex.getRequestMethod());
                    ex.sendResponseHeaders(200, SENTINEL.length);
                    ex.getResponseBody().write(SENTINEL);
                    ex.getResponseBody().close();
                });

        UrlConnectionCrlFetcher fetcher =
                new UrlConnectionCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        byte[] result = fetcher.fetch("http://localhost:" + port + "/first");
        assertArrayEquals(SENTINEL, result, "Fetcher должен пройти редирект");
    }

    @Test
    @DisplayName("Таймаут -> IOException, флаг прерывания не выставляется")
    void testFetchTimeout() {
        UrlConnectionCrlFetcher fetcher = new UrlConnectionCrlFetcher(Duration.ofMillis(1), 1024);
        try {
            assertThrows(
                    java.io.IOException.class,
                    () -> fetcher.fetch("http://192.0.2.1:9999/crl.crl"));
            assertFalse(
                    Thread.currentThread().isInterrupted(),
                    "Таймаут не должен оставлять флаг прерывания на потоке");
        } finally {
            Thread.interrupted(); // защитная очистка для последующих тестов
        }
    }
}
