package org.rssys.gost.jsse.examples.undertow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/**
 * Большие тела запросов через Undertow: блокирующее чтение тела в рабочем потоке, тело много
 * больше записи TLS, после ответа соединение закрывается. Именно в таком сочетании хвост тела
 * разбирался как начало нового запроса (UT005014), поэтому сервер сверяет хеш всего тела.
 */
@DisplayName("Стресс-тест: Undertow, большие тела запросов с закрытием соединения, сверка хеша")
@Tag("stress")
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class UndertowLargeUploadTest {

    private static final int BODY_MB = Integer.getInteger("stress.bodyMb", 64);
    private static final int CLIENTS = Integer.getInteger("upload.largeClients", 8);
    private static final int REQUESTS_PER_CLIENT = Integer.getInteger("upload.requests", 2);
    private static final int BUF_SIZE = 64 * 1024;
    private static final int SOCKET_TIMEOUT_MS = 180_000;
    private static final long JOIN_TIMEOUT_MS = 300_000;
    private static final String HASH_HEADER = "X-Received-SHA256";
    // Контрольная сумма тела считается JDK, а не проверяемой библиотекой: сверка не должна
    // зависеть от кода, который она проверяет
    private static final String CHECKSUM_ALGORITHM = "SHA-256";

    private static Undertow server;
    private static int port;
    private static SSLContext clientCtx;

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ExamplesCertHelper helper = new ExamplesCertHelper();

        server =
                Undertow.builder()
                        .addHttpsListener(0, "0.0.0.0", helper.getSslContext())
                        .setHandler(hashingHandler())
                        .build();
        server.start();
        port = ((InetSocketAddress) server.getListenerInfo().get(0).getAddress()).getPort();

        clientCtx =
                SSLContext.getInstance(
                        GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        clientCtx.init(null, new TrustManager[] {helper.createTrustManager()}, null);
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop();
    }

    /**
     * Читает тело блокирующе в рабочем потоке (не в потоке ввода-вывода XNIO) и отвечает хешем
     * прочитанного. При недоборе тела отвечает 400, а не хешем части тела.
     */
    private static HttpHandler hashingHandler() {
        return exchange -> {
            if (exchange.isInIoThread()) {
                exchange.dispatch(hashingHandler());
                return;
            }
            exchange.startBlocking();
            try (InputStream in = exchange.getInputStream();
                    OutputStream out = exchange.getOutputStream()) {
                MessageDigest digest = MessageDigest.getInstance(CHECKSUM_ALGORITHM);
                long remaining = exchange.getRequestContentLength();
                byte[] buf = new byte[BUF_SIZE];
                while (remaining > 0) {
                    int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
                    if (n < 0) break;
                    digest.update(buf, 0, n);
                    remaining -= n;
                }
                byte[] hash = digest.digest();
                if (remaining > 0) {
                    exchange.setStatusCode(400);
                } else {
                    exchange.setStatusCode(200);
                    exchange.getResponseHeaders()
                            .put(new HttpString(HASH_HEADER), HexFormat.of().formatHex(hash));
                }
                exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, 0);
                out.flush();
            }
        };
    }

    @Test
    @DisplayName("Большие тела (размер через -Dstress.bodyMb): каждый запрос принят целиком")
    void largeBodyUpload() throws Exception {
        int bodySize = BODY_MB * 1024 * 1024;
        byte[] body = new byte[bodySize];
        for (int i = 0; i < bodySize; i++) {
            body[i] = (byte) i;
        }
        String expectedHash = sha256Hex(body);
        byte[] request = buildPost(body);

        System.out.printf(
                "[UPLOAD] %d МБ x %d клиентов x %d запросов (Connection: close)%n",
                BODY_MB, CLIENTS, REQUESTS_PER_CLIENT);

        AtomicLong done = new AtomicLong();
        AtomicLong errors = new AtomicLong();
        long t0 = System.nanoTime();

        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < CLIENTS; i++) {
            workers.add(
                    Thread.ofVirtual()
                            .name("upload-" + i)
                            .start(
                                    () -> {
                                        for (int r = 0; r < REQUESTS_PER_CLIENT; r++) {
                                            try {
                                                upload(request, expectedHash);
                                                done.incrementAndGet();
                                            } catch (Exception e) {
                                                errors.incrementAndGet();
                                                System.err.println("[UPLOAD_ERR] " + causeChain(e));
                                            }
                                        }
                                    }));
        }
        for (Thread t : workers) {
            t.join(JOIN_TIMEOUT_MS);
            assertFalse(
                    t.isAlive(), "клиент " + t.getName() + " не завершился за отведённое время");
        }

        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        long mbPerSec = elapsedMs > 0 ? done.get() * BODY_MB * 1000 / elapsedMs : 0;
        System.out.printf(
                "[UPLOAD] Итог: %d запросов, %d ошибок, ~%d МБ/с (%d мс)%n",
                done.get(), errors.get(), mbPerSec, elapsedMs);

        assertEquals(0, errors.get(), "ошибок быть не должно");
        assertEquals((long) CLIENTS * REQUESTS_PER_CLIENT, done.get(), "все запросы должны пройти");
    }

    /** Один запрос на новом соединении: статус 200 и хеш тела, совпадающий с отправленным. */
    private static void upload(byte[] request, String expectedHash) throws IOException {
        try (SSLSocket s =
                (SSLSocket) clientCtx.getSocketFactory().createSocket("localhost", port)) {
            s.setSoTimeout(SOCKET_TIMEOUT_MS);
            OutputStream out = s.getOutputStream();
            out.write(request);
            out.flush();

            String headers = readResponseHeaders(s.getInputStream());
            String statusLine = headers.substring(0, headers.indexOf("\r\n"));
            if (!statusLine.contains(" 200 ")) {
                throw new IOException("статус ответа не 200: " + statusLine);
            }
            String hash = headerValue(headers, HASH_HEADER);
            if (!expectedHash.equals(hash)) {
                throw new IOException("хеш тела не совпал: получен «" + hash + "»");
            }
        }
    }

    /** Читает заголовки ответа; тела у ответа нет (Content-Length: 0). */
    private static String readResponseHeaders(InputStream in) throws IOException {
        StringBuilder headers = new StringBuilder(512);
        while (true) {
            int b = in.read();
            if (b < 0) throw new IOException("соединение закрыто во время чтения заголовков");
            headers.append((char) b);
            int len = headers.length();
            if (len >= 4 && headers.lastIndexOf("\r\n\r\n") == len - 4) {
                return headers.toString();
            }
        }
    }

    private static String headerValue(String headers, String name) {
        String prefix = name.toLowerCase(Locale.ROOT) + ":";
        for (String line : headers.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return "";
    }

    private static byte[] buildPost(byte[] body) {
        String head =
                "POST /upload HTTP/1.1\r\n"
                        + "Host: localhost\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Length: "
                        + body.length
                        + "\r\n"
                        + "Connection: close\r\n\r\n";
        byte[] headBytes = head.getBytes(StandardCharsets.US_ASCII);
        byte[] request = new byte[headBytes.length + body.length];
        System.arraycopy(headBytes, 0, request, 0, headBytes.length);
        System.arraycopy(body, 0, request, headBytes.length, body.length);
        return request;
    }

    private static String sha256Hex(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance(CHECKSUM_ALGORITHM).digest(data));
    }

    // Цепочка причин в одну строку: по ней ошибки раскладываются по исходным исключениям
    private static String causeChain(Throwable e) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(t.getClass().getName()).append(": ").append(t.getMessage());
        }
        return sb.toString();
    }
}
