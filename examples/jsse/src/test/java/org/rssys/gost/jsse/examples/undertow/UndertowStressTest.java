package org.rssys.gost.jsse.examples.undertow;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import org.junit.jupiter.api.*;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.jsse.GostJsseConstants;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Стресс-тест Undertow + ГОСТ TLS 1.3: HTTP-профили под смешанной нагрузкой.
 * <p>
 * В отличие от JsseStressTest (raw echo), этот тест использует полноценный
 * HTTP-обмен (buildHttpPost / readHttpResponse) через реальный Undertow-сервер.
 * Цель — проверка JSSE-провайдера в интеграции с реальным HTTP-сервером.
 */
@DisplayName("Стресс-тест: Undertow под HTTP-нагрузкой")
@Tag("stress")
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class UndertowStressTest {

    private static final long TEST_DURATION_MIN = Long.getLong("stress.duration", 5);
    private static final int HEAP_WARN_PCT = 85;

    private static Undertow server;
    private static int port;
    private static GostSSLSessionContext srvCtx;

    private static SSLContext clientCtx;

    private static final AtomicLong[] profileRequests = new AtomicLong[5];
    private static final AtomicLong[] profileErrors = new AtomicLong[5];
    private static final AtomicLong bytesSent = new AtomicLong(0);
    static {
        for (int i = 0; i < 5; i++) {
            profileRequests[i] = new AtomicLong(0);
            profileErrors[i] = new AtomicLong(0);
        }
    }

    private static volatile boolean running;

    private static void readHttpResponse(InputStream in) throws IOException {
        StringBuilder headers = new StringBuilder(512);
        while (true) {
            int b = in.read();
            if (b < 0) throw new IOException("Соединение закрыто во время чтения HTTP-заголовков");
            headers.append((char) b);
            int len = headers.length();
            if (len >= 4 && headers.charAt(len - 4) == '\r'
                    && headers.charAt(len - 3) == '\n'
                    && headers.charAt(len - 2) == '\r'
                    && headers.charAt(len - 1) == '\n') break;
        }
        int contentLen = parseContentLength(headers.toString());
        if (contentLen <= 0) return;
        byte[] buf = new byte[8192];
        long total = 0;
        while (total < contentLen) {
            int want = (int) Math.min(buf.length, contentLen - total);
            int n = in.read(buf, 0, want);
            if (n < 0) throw new IOException("Connection closed: "
                    + total + " из " + contentLen + " байт тела");
            total += n;
        }
    }

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        ExamplesCertHelper helper = new ExamplesCertHelper();
        SSLContext serverCtx = helper.getSslContext();

        // Извлекаем GostSSLSessionContext из SSLContext для мониторинга
        srvCtx = (GostSSLSessionContext) serverCtx.getServerSessionContext();
        srvCtx.setSessionCacheSize(5000);

        server = Undertow.builder()
                .addHttpsListener(0, "0.0.0.0", serverCtx)
                .setHandler(new HttpHandler() {
                    @Override
                    public void handleRequest(HttpServerExchange exchange) throws Exception {
                        exchange.getRequestReceiver().receiveFullBytes((ex, bytes) -> {
                            ex.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/octet-stream");
                            ex.getResponseHeaders().put(Headers.CONTENT_LENGTH, bytes.length);
                            ex.getResponseSender().send(ByteBuffer.wrap(bytes));
                        });
                    }
                })
                .build();
        server.start();
        port = ((java.net.InetSocketAddress)
                server.getListenerInfo().get(0).getAddress()).getPort();

        clientCtx = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        clientCtx.init(null, new javax.net.ssl.TrustManager[]{helper.createTrustManager()}, null);
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop();
    }

    // ========================================================================
    // Основной тест
    // ========================================================================

    @Test
    @DisplayName("4 HTTP-профиля: короткие(30) + средние(20) + длинные(5) + обрывы(10) — 5 минут")
    void stressTest() throws Exception {
        running = true;
        List<Thread> workers = new ArrayList<>();

        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
        List<Long> heapSamples = new ArrayList<>();
        long gcCountStart = totalGcCount();
        String dumpFile = System.getProperty("user.dir")
                + "/build/reports/undertow-stress-dump-"
                + Instant.now().toString().replace(":", "-") + ".txt";

        monitor.scheduleAtFixedRate(() -> {
            if (!running) return;
            long used = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            long max = Runtime.getRuntime().maxMemory();
            int pct = (int) (used * 100 / max);
            heapSamples.add(used);

            int sessionCount = countIds(srvCtx);
            long gcNow = totalGcCount();

            System.out.printf("[JM] Heap: %dMB/%dMB (%d%%), Session ids: %d, "
                            + "GC: +%d, Reqs: [1=%d 2=%d 3=%d 4=%d], Err: [1=%d 2=%d 3=%d 4=%d]%n",
                    used / 1024 / 1024, max / 1024 / 1024, pct,
                    sessionCount, gcNow - gcCountStart,
                    profileRequests[1].get(), profileRequests[2].get(),
                    profileRequests[3].get(), profileRequests[4].get(),
                    profileErrors[1].get(), profileErrors[2].get(),
                    profileErrors[3].get(), profileErrors[4].get());

            if (heapSamples.size() >= 3) {
                long prev = heapSamples.get(heapSamples.size() - 3);
                if (used > prev * 1.5 && pct > HEAP_WARN_PCT) {
                    dumpThreads(dumpFile);
                }
            }
        }, 0, 30, TimeUnit.SECONDS);

        for (int i = 0; i < 30; i++)
            workers.add(Thread.ofVirtual().name("short-" + i).unstarted(this::profileShort));
        for (int i = 0; i < 20; i++)
            workers.add(Thread.ofVirtual().name("medium-" + i).unstarted(this::profileMedium));
        for (int i = 0; i < 5; i++)
            workers.add(Thread.ofVirtual().name("long-" + i).unstarted(this::profileLong));
        for (int i = 0; i < 10; i++)
            workers.add(Thread.ofVirtual().name("chaos-" + i).unstarted(this::profileChaos));

        for (Thread t : workers) t.start();
        Thread.sleep(TimeUnit.MINUTES.toMillis(TEST_DURATION_MIN));
        running = false;
        monitor.shutdown();
        for (Thread t : workers) t.join(10000);

        long reqs2 = profileRequests[2].get();
        assertTrue(reqs2 > 0,
                "Профиль 2: должен быть хотя бы один успешный запрос");
        long reqs3 = profileRequests[3].get();
        assertEquals(0, profileErrors[3].get(),
                "Профиль 3: ошибок быть не должно");
        long reqs1 = profileRequests[1].get();
        assertTrue(reqs1 > 0,
                "Профиль 1: должен быть хотя бы один запрос");
        long errs1 = profileErrors[1].get();
        long total1 = reqs1 + errs1;
        assertTrue(errs1 * 100 < total1,
                "Профиль 1: ошибок более 1% (" + errs1
                + " из " + total1 + ")");

        System.out.printf("[RESULT] Profile 1: %d req, %d err%n",
                profileRequests[1].get(), profileErrors[1].get());
        System.out.printf("[RESULT] Profile 2: %d req, %d err%n",
                profileRequests[2].get(), profileErrors[2].get());
        System.out.printf("[RESULT] Profile 3: %d req, %d err, %d KB sent%n",
                profileRequests[3].get(), profileErrors[3].get(),
                bytesSent.get() / 1024);
        System.out.printf("[RESULT] Profile 4: %d req, %d err (expected)%n",
                profileRequests[4].get(), profileErrors[4].get());
    }

    // ========================================================================
    // Профили нагрузки (HTTP)
    // ========================================================================

    private void profileShort() {
        int profileId = 1;
        byte[] httpReq = buildHttpPost("/echo", "application/octet-stream",
                generatePayload(1024), false);
        while (running) {
            SSLSocket s = null;
            try {
                s = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket("localhost", port);
                s.setSoTimeout(15000);
                OutputStream out = s.getOutputStream();
                out.write(httpReq);
                out.flush();
                readHttpResponse(s.getInputStream());
                profileRequests[profileId].incrementAndGet();
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
                System.err.println("[PROFILE1_ERR] " + e);
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileMedium() {
        int profileId = 2;
        while (running) {
            int sessionDuration = 5000 + CryptoRandom.INSTANCE.nextInt(25001);
            long deadline = System.currentTimeMillis() + sessionDuration;
            SSLSocket s = null;
            try {
                s = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket("localhost", port);
                s.setSoTimeout(15000);
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                while (running && System.currentTimeMillis() < deadline) {
                    byte[] body = generatePayload(1 + CryptoRandom.INSTANCE.nextInt(100));
                    byte[] req = buildHttpPost("/echo", "text/plain", body, false);
                    out.write(req);
                    out.flush();
                    readHttpResponse(in);
                    profileRequests[profileId].incrementAndGet();
                    Thread.sleep(100 + CryptoRandom.INSTANCE.nextInt(401));
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileLong() {
        int profileId = 3;
        byte[] chunk = generatePayload(16 * 1024);
        byte[] httpReq = buildHttpPost("/echo", "application/octet-stream", chunk, false);

        while (running) {
            SSLSocket s = null;
            try {
                s = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket("localhost", port);
                s.setSoTimeout(30000);
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                while (running) {
                    out.write(httpReq);
                    out.flush();
                    readHttpResponse(in);
                    profileRequests[profileId].incrementAndGet();
                    bytesSent.addAndGet(chunk.length);
                }
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileChaos() {
        int profileId = 4;
        while (running) {
            Socket raw = null;
            SSLSocket ssl = null;
            try {
                raw = new Socket("localhost", port);
                ssl = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket(raw, "localhost", port, true);
                ssl.setSoTimeout(5000);
                ssl.startHandshake();
                Thread.sleep(CryptoRandom.INSTANCE.nextInt(2001));
                profileRequests[profileId].incrementAndGet();
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                try { if (ssl != null) ssl.close(); } catch (Exception ignored) {}
                try { if (raw != null) raw.close(); } catch (Exception ignored) {}
            }
        }
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    private static byte[] buildHttpPost(String path, String contentType,
                                         byte[] body, boolean useChunked) {
        StringBuilder headers = new StringBuilder();
        headers.append("POST ").append(path).append(" HTTP/1.1\r\n");
        headers.append("Host: localhost\r\n");
        headers.append("Content-Type: ").append(contentType).append("\r\n");
        if (useChunked) {
            headers.append("Transfer-Encoding: chunked\r\n");
        } else {
            headers.append("Content-Length: ")
                    .append(body != null ? body.length : 0).append("\r\n");
        }
        headers.append("Connection: keep-alive\r\n");
        headers.append("\r\n");

        byte[] headerBytes = headers.toString().getBytes(StandardCharsets.US_ASCII);
        if (body == null || body.length == 0) return headerBytes;

        byte[] req = new byte[headerBytes.length + body.length];
        System.arraycopy(headerBytes, 0, req, 0, headerBytes.length);
        System.arraycopy(body, 0, req, headerBytes.length, body.length);
        return req;
    }

    private static int parseContentLength(String response) {
        for (String line : response.split("\r\n")) {
            if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                return Integer.parseInt(line.substring(15).trim());
            }
        }
        return -1;
    }

    private static byte[] generatePayload(int size) {
        byte[] data = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(data);
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (' ' + (data[i] & 0x5F));
        }
        return data;
    }

    private static int countIds(GostSSLSessionContext ctx) {
        Enumeration<byte[]> ids = ctx.getIds();
        int count = 0;
        while (ids.hasMoreElements()) {
            ids.nextElement();
            count++;
        }
        return count;
    }

    private static long totalGcCount() {
        long total = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            total += gc.getCollectionCount();
        }
        return total;
    }

    private static void log(String msg) {
        System.out.println("[LOG] " + msg);
    }

    private static void dumpThreads(String path) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(path, true))) {
            pw.println("=== Thread dump at " + Instant.now() + " ===");
            Thread.getAllStackTraces().forEach((t, stack) -> {
                pw.println(t.threadId() + " \"" + t.getName() + "\" [" + t.getState() + "]");
                for (StackTraceElement e : stack) {
                    pw.println("\tat " + e);
                }
                pw.println();
            });
        } catch (Exception ignored) {}
    }
}
