package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * HTTP-цикл JdkHttpCrlFetcher с mock-сервером.
 */
@DisplayName("JdkHttpCrlFetcher: HTTP получение CRL")
class JdkHttpCrlFetcherTest {

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
    @DisplayName("Успешный CRL-запрос: 200 + тело -> fetcher возвращает тело")
    void testFetchSuccess() throws Exception {
        startMock(SENTINEL, 200);
        JdkHttpCrlFetcher fetcher =
                new JdkHttpCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        byte[] result = fetcher.fetch("http://localhost:" + port + "/crl.crl");
        assertArrayEquals(SENTINEL, result, "Fetcher должен вернуть тело ответа");
    }

    @Test
    @DisplayName("HTTP 500 -> fetcher возвращает null")
    void testFetchServerError() throws Exception {
        startMock(SENTINEL, 500);
        JdkHttpCrlFetcher fetcher =
                new JdkHttpCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        assertNull(fetcher.fetch("http://localhost:" + port + "/crl.crl"));
    }

    @Test
    @DisplayName("private IP (127.0.0.1) блокируется -> null")
    void testPrivateIpBlocked() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch("http://127.0.0.1/crl.crl"));
    }

    @Test
    @DisplayName("localhost блокируется -> null")
    void testLocalhostBlocked() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch("http://localhost/crl.crl"));
    }

    @Test
    @DisplayName("file:// URI -> null (запрещённая схема)")
    void testFileScheme() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch("file:///etc/crl.crl"));
    }

    @Test
    @DisplayName("ldap:// URI -> null (запрещённая схема)")
    void testLdapScheme() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch("ldap://crl.example.com/crl"));
    }

    @Test
    @DisplayName("Ответ > maxResponseSize -> null")
    void testFetchOversizeResponse() throws Exception {
        byte[] largeResponse = new byte[6 * 1024 * 1024]; // 6MB > 5MB default
        startMock(largeResponse, 200);
        JdkHttpCrlFetcher fetcher =
                new JdkHttpCrlFetcher(Duration.ofSeconds(5), 5 * 1024 * 1024, true);
        assertNull(fetcher.fetch("http://localhost:" + port + "/crl.crl"));
    }

    @Test
    @DisplayName("null URI -> null")
    void testFetchNullUri() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch(null));
    }

    @Test
    @DisplayName("пустой URI -> null")
    void testFetchEmptyUri() throws Exception {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher();
        assertNull(fetcher.fetch(""));
    }

    @Test
    @DisplayName("Таймаут -> IOException")
    void testFetchTimeout() {
        JdkHttpCrlFetcher fetcher = new JdkHttpCrlFetcher(Duration.ofMillis(1), 1024);
        assertThrows(
                java.io.IOException.class, () -> fetcher.fetch("http://192.0.2.1:9999/crl.crl"));
    }
}
