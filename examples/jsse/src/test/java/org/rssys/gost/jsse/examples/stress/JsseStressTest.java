package org.rssys.gost.jsse.examples.stress;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.util.CryptoRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.Socket;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Стресс-тест GostSSLServerSocket + ГОСТ TLS 1.3: длительная работа под смешанной нагрузкой.
 * <p>
 * Проверяет утечки памяти, зависания и корректность при долгой многопоточной работе.
 */
@DisplayName("Стресс-тест: GostSSLServerSocket под смешанной нагрузкой")
@Tag("stress")
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class JsseStressTest {

    // Константы
    private static final long TEST_DURATION_MIN = Long.getLong("stress.duration", 5);
    private static final int HEAP_WARN_PCT = 85;

    // Сервер
    private static GostSSLServerSocket serverSocket;
    private static Thread serverThread;
    private static GostSSLSessionContext srvCtx;
    private static volatile int port;

    // Клиентские поля — статические, т.к. инициализируются в @BeforeAll
    private static SSLContext clientCtx;

    // Счётчики для профилей (1-4)
    private static final AtomicLong[] profileRequests = new AtomicLong[5];
    private static final AtomicLong[] profileErrors = new AtomicLong[5];
    private static final AtomicLong bytesSent = new AtomicLong(0);
    static {
        for (int i = 0; i < 5; i++) {
            profileRequests[i] = new AtomicLong(0);
            profileErrors[i] = new AtomicLong(0);
        }
    }

    // Флаг работы теста
    private static volatile boolean running;

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        ExamplesCertHelper helper = new ExamplesCertHelper();
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        srvCtx = new GostSSLSessionContext(cs, cs.getHashLen());
        srvCtx.setSessionCacheSize(5000);
        serverSocket = new GostSSLServerSocket(0,
                helper.createKeyManager(), helper.createTrustManager(), srvCtx);
        port = serverSocket.getLocalPort();

        // Принимающий поток: на каждое подключение — виртуальный тред с echo-циклом
        serverThread = Thread.ofPlatform().name("gost-accept").start(() -> {
            while (true) {
                try {
                    Socket raw = serverSocket.accept();
                    if (raw == null) break;
                    Thread.ofVirtual().name("gost-srv-" + raw.getPort()).start(() -> {
                        try (SSLSocket ssl = (SSLSocket) raw;
                             InputStream in = ssl.getInputStream();
                             OutputStream out = ssl.getOutputStream()) {
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                out.write(buf, 0, n);
                                out.flush();
                            }
                        } catch (Exception ignored) {
                        }
                    });
                } catch (Exception e) {
                    if (!serverSocket.isBound()) break;
                }
            }
        });

        // Клиентский контекст
        clientCtx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        clientCtx.init(null, new javax.net.ssl.TrustManager[]{helper.createTrustManager()}, null);
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    // ========================================================================
    // Основной тест: 4 профиля нагрузки
    // ========================================================================

    @Test
    @DisplayName("4 профиля: короткие(50) + средние(20) + длинные(5) + обрывы(10) — 5 минут")
    void stressTest() throws Exception {
        running = true;
        List<Thread> workers = new ArrayList<>();

        // Мониторинг: heap, GC, PSK store, сессии
        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
        List<Long> heapSamples = new ArrayList<>();
        long gcCountStart = totalGcCount();
        String dumpFile = System.getProperty("user.dir")
                + "/build/reports/stress-dump-"
                + Instant.now().toString().replace(":", "-") + ".txt";

        monitor.scheduleAtFixedRate(() -> {
            if (!running) return;
            long used = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            long max = Runtime.getRuntime().maxMemory();
            int pct = (int) (used * 100 / max);
            heapSamples.add(used);

            // Считаем сессии через getIds() — это LRU-кэш под sessionCacheSize
            int sessionCount = countIds(srvCtx);
            int pskCount = 0; // IPskStore не имеет метода size() публичного
            long gcNow = totalGcCount();

            System.out.printf("[JM] Heap: %dMB/%dMB (%d%%), Session ids: %d, "
                            + "GC: +%d, Reqs: [1=%d 2=%d 3=%d 4=%d], Err: [1=%d 2=%d 3=%d 4=%d]%n",
                    used / 1024 / 1024, max / 1024 / 1024, pct,
                    sessionCount, gcNow - gcCountStart,
                    profileRequests[1].get(), profileRequests[2].get(),
                    profileRequests[3].get(), profileRequests[4].get(),
                    profileErrors[1].get(), profileErrors[2].get(),
                    profileErrors[3].get(), profileErrors[4].get());

            // Дамп потоков если heap растёт подозрительно
            if (heapSamples.size() >= 3) {
                long prev = heapSamples.get(heapSamples.size() - 3);
                if (used > prev * 1.5 && pct > HEAP_WARN_PCT) {
                    dumpThreads(dumpFile);
                }
            }
        }, 0, 30, TimeUnit.SECONDS);

        // Profile 1: 30 коротких сессий (fire-and-forget)
        for (int i = 0; i < 30; i++) {
            workers.add(Thread.ofVirtual().name("short-" + i).unstarted(this::profileShort));
        }
        // Profile 2: 20 средних сессий (request-response с паузами)
        for (int i = 0; i < 20; i++) {
            workers.add(Thread.ofVirtual().name("medium-" + i).unstarted(this::profileMedium));
        }
        // Profile 3: 5 длинных сессий (throughput)
        for (int i = 0; i < 5; i++) {
            workers.add(Thread.ofVirtual().name("long-" + i).unstarted(this::profileLong));
        }
        // Profile 4: 10 обрывов (chaos)
        for (int i = 0; i < 10; i++) {
            workers.add(Thread.ofVirtual().name("chaos-" + i).unstarted(this::profileChaos));
        }

        for (Thread t : workers) t.start();
        Thread.sleep(TimeUnit.MINUTES.toMillis(TEST_DURATION_MIN));
        running = false;
        monitor.shutdown();
        for (Thread t : workers) t.join(10000);

        // Проверки: каждый профиль должен сделать хотя бы один успешный обмен
        long reqs2 = profileRequests[2].get();
        assertTrue(reqs2 > 0,
                "Профиль 2: должен быть хотя бы один успешный запрос");
        long reqs3 = profileRequests[3].get();
        assertEquals(0, profileErrors[3].get(),
                "Профиль 3: ошибок быть не должно");
        long reqs1 = profileRequests[1].get();
        assertTrue(reqs1 > 0,
                "Профиль 1: должен быть хотя бы один запрос");
        assertTrue(profileErrors[1].get() * 100 < profileRequests[1].get(),
                "Профиль 1: ошибок более 1% (" + profileErrors[1].get()
                + " из " + profileRequests[1].get() + ")");

        System.out.printf("[RESULT] Profile 1: %d req, %d err%n",
                profileRequests[1].get(), profileErrors[1].get());
        System.out.printf("[RESULT] Profile 2: %d req, %d err%n",
                profileRequests[2].get(), profileErrors[2].get());
        System.out.printf("[RESULT] Profile 3: %d req, %d err, %d MB sent%n",
                profileRequests[3].get(), profileErrors[3].get(),
                bytesSent.get() / 1024 / 1024);
        System.out.printf("[RESULT] Profile 4: %d req, %d err (expected)%n",
                profileRequests[4].get(), profileErrors[4].get());
    }

    // ========================================================================
    // Профили
    // ========================================================================

    /** Profile 1: короткие сессии — fire-and-forget, reconnect без паузы */
    private void profileShort() {
        int profileId = 1;
        byte[] payload = generatePayload(1024);
        while (running) {
            try (SSLSocket s = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                s.setSoTimeout(15000);
                OutputStream out = s.getOutputStream();
                out.write(payload);
                out.flush();
                readEcho(s.getInputStream(), payload.length);
                profileRequests[profileId].incrementAndGet();
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            }
        }
    }

    /** Profile 2: средние сессии — одно соединение, многократные обмены */
    private void profileMedium() {
        int profileId = 2;
        while (running) {
            int sessionDuration = 5000 + CryptoRandom.INSTANCE.nextInt(25001);
            long deadline = System.currentTimeMillis() + sessionDuration;
            try (SSLSocket s = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                s.setSoTimeout(15000);
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                while (running && System.currentTimeMillis() < deadline) {
                    byte[] payload = generatePayload(1 + CryptoRandom.INSTANCE.nextInt(100));
                    out.write(payload);
                    out.flush();
                    readEcho(in, payload.length);
                    profileRequests[profileId].incrementAndGet();
                    Thread.sleep(100 + CryptoRandom.INSTANCE.nextInt(401));
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            }
        }
    }

    /** Profile 3: длинные сессии — непрерывные 16KB chunks */
    private void profileLong() {
        int profileId = 3;
        byte[] chunk = generatePayload(16 * 1024);

        while (running) {
            try (SSLSocket s = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                s.setSoTimeout(30000);
                OutputStream out = s.getOutputStream();
                InputStream in = s.getInputStream();

                while (running) {
                    out.write(chunk);
                    out.flush();
                    readEcho(in, chunk.length);
                    profileRequests[profileId].incrementAndGet();
                    bytesSent.addAndGet(chunk.length);
                }
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            }
        }
    }

    /** Profile 4: обрывы — hard close без close_notify через raw socket */
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
    // Max sessions subtest
    // ========================================================================

    @Test
    @DisplayName("Постепенное увеличение соединений до лимита heap")
    void maxConcurrentSessions() throws Exception {
        int step = 50;
        int maxSessions = 0;
        long maxMem = Runtime.getRuntime().maxMemory();
        List<SSLSocket> sockets = new CopyOnWriteArrayList<>();
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();

        for (int n = step; n <= 1000 && maxSessions >= n - step; n += step) {
            CountDownLatch latch = new CountDownLatch(step);
            for (int i = 0; i < step; i++) {
                pool.submit(() -> {
                    try {
                        SSLSocket s = (SSLSocket) clientCtx.getSocketFactory()
                                .createSocket("localhost", port);
                        s.startHandshake();
                        sockets.add(s);
                    } catch (Exception e) {
                        // not counted — нормально при достижении лимита
                    } finally {
                        latch.countDown();
                    }
                });
            }
            if (!latch.await(30, TimeUnit.SECONDS)) break;

            long heapNow = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            if (heapNow > maxMem * HEAP_WARN_PCT / 100.0) break;
            maxSessions = n;
        }

        assertTrue(maxSessions >= 50, "Должен выдержать минимум 50 сессий");
        log("Максимум одновременных сессий: ~" + maxSessions);
        for (SSLSocket s : sockets) {
            try { s.close(); } catch (Exception ignored) {}
        }
        pool.shutdown();
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    /** Читает ровно {@code len} байт из потока (эхо-ответ сервера). */
    private static void readEcho(InputStream in, int len) throws IOException {
        byte[] buf = new byte[8192];
        long total = 0;
        while (total < len) {
            int want = (int) Math.min(buf.length, len - total);
            int n = in.read(buf, 0, want);
            if (n < 0) throw new IOException("EOF: " + total + "/" + len + " bytes");
            total += n;
        }
    }

    private static byte[] generatePayload(int size) {
        byte[] data = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(data);
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
        } catch (Exception ignored) {
        }
    }
}
