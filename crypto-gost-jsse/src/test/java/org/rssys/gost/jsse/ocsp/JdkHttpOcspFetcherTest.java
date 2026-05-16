package org.rssys.gost.jsse.ocsp;
import org.rssys.gost.jsse.RssysGostJsseProvider;


import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import java.net.InetSocketAddress;
import java.security.Security;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP-цикл JdkHttpOcspFetcher с mock-сервером.
 */
class JdkHttpOcspFetcherTest {

    private static final byte[] SENTINEL = "OCSP_RESPONSE_OK".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static byte[] certDer;
    private static byte[] issuerDer;

    private HttpServer server;
    private int port;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, null, null, null, false, null);
        certDer = leaf.cert.getEncoded();
        issuerDer = root.cert.getEncoded();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private void startMock(byte[] responseBody, int statusCode) throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", ex -> {
            assertEquals("POST", ex.getRequestMethod());
            assertEquals("application/ocsp-request",
                    ex.getRequestHeaders().getFirst("Content-Type"));

            byte[] body = ex.getRequestBody().readAllBytes();
            assertTrue(body.length > 0, "OCSP request body should not be empty");

            ex.sendResponseHeaders(statusCode, responseBody.length);
            ex.getResponseBody().write(responseBody);
            ex.getResponseBody().close();
        });
        server.start();
        port = server.getAddress().getPort();
    }

    @Test
    @DisplayName("Успешный OCSP-запрос: 200 + тело → fetcher возвращает тело")
    void testFetchSuccess() throws Exception {
        startMock(SENTINEL, 200);
        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        byte[] result = fetcher.fetch(certDer, issuerDer, "http://localhost:" + port);
        assertArrayEquals(SENTINEL, result, "Fetcher should return sentinel body");
    }

    @Test
    @DisplayName("HTTP 500 → fetcher возвращает null")
    void testFetchServerError() throws Exception {
        startMock(SENTINEL, 500);
        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        assertNull(fetcher.fetch(certDer, issuerDer, "http://localhost:" + port));
    }

    @Test
    @DisplayName("HTTPS URI → null (запрещено, только HTTP)")
    void testFetchHttpsRejected() throws Exception {
        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher();
        assertNull(fetcher.fetch(certDer, issuerDer, "https://ocsp.example.com/"),
                "HTTPS URIs should be rejected");
    }

    @Test
    @DisplayName("Ответ > maxResponseSize → null")
    void testFetchOversizeResponse() throws Exception {
        byte[] largeResponse = new byte[70000];
        startMock(largeResponse, 200);
        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(5), 65536);
        assertNull(fetcher.fetch(certDer, issuerDer, "http://localhost:" + port));
    }

    @Test
    @DisplayName("Null аргументы → null")
    void testFetchNullArgs() {
        JdkHttpOcspFetcher fetcher = new JdkHttpOcspFetcher();
        assertNull(fetcher.fetch(null, issuerDer, "http://localhost/"));
        assertNull(fetcher.fetch(certDer, null, "http://localhost/"));
        assertNull(fetcher.fetch(certDer, issuerDer, null));
    }
}
