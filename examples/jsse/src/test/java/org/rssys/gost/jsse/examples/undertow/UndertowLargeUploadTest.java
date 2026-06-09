package org.rssys.gost.jsse.examples.undertow;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import org.junit.jupiter.api.*;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.tls13.TlsConstants;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Стресс-тест: Undertow с большими телами (handshake stress + throughput)")
@Tag("stress")
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class UndertowLargeUploadTest {

    private static final int DURATION_SEC = Integer.getInteger("upload.duration", 30);
    private static final int CLIENTS = Integer.getInteger("upload.clients", 10);
    private static final long MIN_BYTES = 100L * 1024 * 1024;
    private static final int PHASE1_BODY = 1024 * 1024;
    private static final int CHUNK_SIZE = 64 * 1024;
    private static final int BUF_SIZE = 65536;
    private static final int HEAP_WARN_PCT = 85;

    private static Undertow server;
    private static int port;
    private static SSLContext clientCtx;

    private static byte[] phase1Request;
    private static byte[] phase2Request;

    private static volatile boolean running;
    private static final AtomicLong phase1Reqs = new AtomicLong();
    private static final AtomicLong phase1Errs = new AtomicLong();
    private static final AtomicLong phase1Bytes = new AtomicLong();
    private static final AtomicLong phase2Reqs = new AtomicLong();
    private static final AtomicLong phase2Errs = new AtomicLong();
    private static final AtomicLong phase2Bytes = new AtomicLong();

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        ExamplesCertHelper helper = new ExamplesCertHelper();
        SSLContext serverCtx = helper.getSslContext();

        server = Undertow.builder()
                .addHttpsListener(0, "0.0.0.0", serverCtx)
                .setHandler(streamingHandler())
                .build();
        server.start();
        port = ((InetSocketAddress)
                server.getListenerInfo().get(0).getAddress()).getPort();

        clientCtx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        clientCtx.init(null, new TrustManager[]{helper.createTrustManager()}, null);

        byte[] body1 = new byte[PHASE1_BODY];
        byte[] body2 = new byte[CHUNK_SIZE];
        for (int i = 0; i < body1.length; i++) body1[i] = 0x41;
        for (int i = 0; i < body2.length; i++) body2[i] = 0x41;

        phase1Request = buildHttpPost("/handshake-stress", body1, true);
        phase2Request = buildHttpPost("/throughput", body2, false);
    }

    @AfterAll
    static void stopServer() {
        if (server != null) server.stop();
    }

    private static HttpHandler streamingHandler() {
        return exchange -> {
            if (exchange.isInIoThread()) {
                exchange.dispatch(streamingHandler());
                return;
            }
            exchange.startBlocking();
            try (InputStream in = exchange.getInputStream();
                 OutputStream out = exchange.getOutputStream()) {
                long contentLen = exchange.getRequestContentLength();
                byte[] buf = new byte[BUF_SIZE];
                while (contentLen > 0) {
                    int want = (int) Math.min(buf.length, contentLen);
                    int n = in.read(buf, 0, want);
                    if (n < 0) break;
                    contentLen -= n;
                }
                out.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        };
    }

    @Test
    @DisplayName("Фаза 1: handshake stress + Фаза 2: data throughput")
    void test() throws Exception {
        runPhase1();
        runPhase2();
    }

    private static void runPhase1() throws Exception {
        System.out.println("[PHASE1] handshake stress: " + CLIENTS + " clients x "
                + DURATION_SEC + "s, body=" + (PHASE1_BODY / 1024) + "KB, Connection: close");
        phase1Reqs.set(0);
        phase1Errs.set(0);
        phase1Bytes.set(0);
        running = true;

        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < CLIENTS; i++)
            workers.add(Thread.ofVirtual().name("p1-" + i)
                    .unstarted(UndertowLargeUploadTest::phase1Worker));
        workers.forEach(Thread::start);

        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
        final long gcStart = totalGcCount();
        final long t0 = System.currentTimeMillis();
        monitor.scheduleAtFixedRate(() -> reportPhase1(gcStart), 0, 5, TimeUnit.SECONDS);

        long deadline = t0 + DURATION_SEC * 1000L;
        while (System.currentTimeMillis() < deadline && phase1Bytes.get() < MIN_BYTES) {
            Thread.sleep(100);
        }
        running = false;
        monitor.shutdown();
        workers.forEach(t -> { try { t.join(5000); } catch (Exception ignored) {} });

        long elapsed = System.currentTimeMillis() - t0;
        long bytes = phase1Bytes.get();
        long mbPerSec = elapsed > 0 ? bytes / 1024 / 1024 * 1000 / elapsed : 0;
        System.out.printf("[PHASE1] Done: %d req, %d err, %d MB, ~%d MB/s (%dms)%n",
                phase1Reqs.get(), phase1Errs.get(), bytes / 1024 / 1024, mbPerSec, elapsed);

        assertEquals(0, phase1Errs.get(), "Фаза 1: ошибок быть не должно");
        assertTrue(bytes >= MIN_BYTES,
                "Фаза 1: передано " + bytes + " байт, минимум " + MIN_BYTES);
    }

    private static void phase1Worker() {
        while (running) {
            SSLSocket s = null;
            try {
                s = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket("localhost", port);
                s.setSoTimeout(30000);
                OutputStream out = s.getOutputStream();
                out.write(phase1Request);
                out.flush();
                readHttpResponse(s.getInputStream());
                phase1Reqs.incrementAndGet();
                phase1Bytes.addAndGet(PHASE1_BODY);
            } catch (Exception e) {
                phase1Errs.incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void runPhase2() throws Exception {
        System.out.println("[PHASE2] data throughput: " + CLIENTS + " clients x "
                + DURATION_SEC + "s, chunk=" + (CHUNK_SIZE / 1024) + "KB, keep-alive");
        phase2Reqs.set(0);
        phase2Errs.set(0);
        phase2Bytes.set(0);
        running = true;

        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < CLIENTS; i++)
            workers.add(Thread.ofVirtual().name("p2-" + i)
                    .unstarted(UndertowLargeUploadTest::phase2Worker));
        workers.forEach(Thread::start);

        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
        final long gcStart = totalGcCount();
        final long t0 = System.currentTimeMillis();
        monitor.scheduleAtFixedRate(() -> reportPhase2(gcStart), 0, 5, TimeUnit.SECONDS);

        long deadline = t0 + DURATION_SEC * 1000L;
        while (System.currentTimeMillis() < deadline && phase2Bytes.get() < MIN_BYTES) {
            Thread.sleep(100);
        }
        running = false;
        monitor.shutdown();
        workers.forEach(t -> { try { t.join(5000); } catch (Exception ignored) {} });

        long elapsed = System.currentTimeMillis() - t0;
        long bytes = phase2Bytes.get();
        long mbPerSec = elapsed > 0 ? bytes / 1024 / 1024 * 1000 / elapsed : 0;
        long approxRecs = bytes / TlsConstants.MAX_PLAINTEXT_LENGTH;
        System.out.printf("[PHASE2] Done: %d req, %d err, %d MB, ~%d MB/s (%dms), ~%d TLS records%n",
                phase2Reqs.get(), phase2Errs.get(), bytes / 1024 / 1024, mbPerSec, elapsed, approxRecs);

        assertEquals(0, phase2Errs.get(), "Фаза 2: ошибок быть не должно");
        assertTrue(bytes >= MIN_BYTES,
                "Фаза 2: передано " + bytes + " байт, минимум " + MIN_BYTES);
    }

    private static void phase2Worker() {
        while (running) {
            SSLSocket s = null;
            try {
                s = (SSLSocket) clientCtx.getSocketFactory()
                        .createSocket("localhost", port);
                s.setSoTimeout(30000);
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                while (running) {
                    out.write(phase2Request);
                    out.flush();
                    readHttpResponse(in);
                    phase2Reqs.incrementAndGet();
                    phase2Bytes.addAndGet(CHUNK_SIZE);
                }
            } catch (Exception e) {
                phase2Errs.incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void readHttpResponse(InputStream in) throws IOException {
        StringBuilder headers = new StringBuilder(512);
        while (true) {
            int b = in.read();
            if (b < 0) throw new IOException("Connection closed during headers");
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
                    + total + " of " + contentLen + " body bytes");
            total += n;
        }
    }

    private static byte[] buildHttpPost(String path, byte[] body, boolean closeAfter) {
        StringBuilder sb = new StringBuilder();
        sb.append("POST ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: localhost\r\n");
        sb.append("Content-Type: application/octet-stream\r\n");
        sb.append("Content-Length: ").append(body.length).append("\r\n");
        sb.append("Connection: ").append(closeAfter ? "close" : "keep-alive").append("\r\n");
        sb.append("\r\n");
        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.US_ASCII);
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

    private static void reportPhase1(long gcStart) {
        long used = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long max = Runtime.getRuntime().maxMemory();
        int pct = (int) (used * 100 / max);
        long gcNow = totalGcCount();
        System.out.printf("[P1] Heap: %dMB/%dMB (%d%%) GC: +%d Reqs: %d Err: %d Data: %dMB%n",
                used / 1024 / 1024, max / 1024 / 1024, pct,
                gcNow - gcStart,
                phase1Reqs.get(), phase1Errs.get(),
                phase1Bytes.get() / 1024 / 1024);
    }

    private static void reportPhase2(long gcStart) {
        long used = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        long max = Runtime.getRuntime().maxMemory();
        int pct = (int) (used * 100 / max);
        long gcNow = totalGcCount();
        System.out.printf("[P2] Heap: %dMB/%dMB (%d%%) GC: +%d Reqs: %d Err: %d Data: %dMB%n",
                used / 1024 / 1024, max / 1024 / 1024, pct,
                gcNow - gcStart,
                phase2Reqs.get(), phase2Errs.get(),
                phase2Bytes.get() / 1024 / 1024);
    }

    private static long totalGcCount() {
        long total = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            total += gc.getCollectionCount();
        }
        return total;
    }
}
