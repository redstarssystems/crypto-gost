package org.rssys.gost.tls13.stress;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.TlsTransport;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;
import org.rssys.gost.util.CryptoRandom;

import java.io.EOFException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Стресс-тест: TlsSession + SocketTlsTransport под смешанной нагрузкой")
@Tag("stress")
@Timeout(value = 35, unit = TimeUnit.MINUTES)
class TlsSessionStressTest {

    private static final long TEST_DURATION_MIN = Long.getLong("stress.duration", 5);
    private static final int HEAP_WARN_PCT = 85;
    private static final int MAX_SESSIONS_LIMIT = Integer.getInteger("stress.maxSessions", 10000);
    private static final int SESSIONS_STEP = Integer.getInteger("stress.step", 50);

    private static ServerSocket serverSocket;
    private static Thread acceptThread;
    private static volatile int port;

    private static TlsServerConfig serverConfig;
    private static TlsClientConfig clientConfig;
    private static TlsTestHelper.CertBundle bundle;

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

    @BeforeAll
    static void setup() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());

        serverConfig = new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv);
        clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(bundle.cert.getPublicKey());

        serverSocket = new ServerSocket(0, 1024);
        port = serverSocket.getLocalPort();

        acceptThread = Thread.ofPlatform().name("tls13-accept").start(() -> {
            while (true) {
                try {
                    Socket raw = serverSocket.accept();
                    Thread.ofVirtual().name("tls13-srv-" + raw.getPort()).start(() -> {
                        try (TlsTransport t = new SocketTlsTransport(raw);
                             TlsSession s = TlsSession.createServer(serverConfig, t)) {
                            s.handshakeAsServer();
                            while (true) {
                                try {
                                    s.write(s.read());
                                } catch (EOFException e) {
                                    break;
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    });
                } catch (IOException e) {
                    if (serverSocket.isClosed()) break;
                }
            }
        });
    }

    @AfterAll
    static void teardown() throws Exception {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    @Test
    @DisplayName("4 профиля: короткие(30) + средние(20) + длинные(5) + обрывы(10)")
    void stressTest() throws Exception {
        running = true;
        List<Thread> workers = new ArrayList<>();

        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
        List<Long> heapSamples = new ArrayList<>();
        long gcCountStart = totalGcCount();
        String dumpFile = System.getProperty("user.dir")
                + "/build/reports/tls13-stress-dump-"
                + Instant.now().toString().replace(":", "-") + ".txt";

        monitor.scheduleAtFixedRate(() -> {
            if (!running) return;
            long used = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            long max = Runtime.getRuntime().maxMemory();
            int pct = (int) (used * 100 / max);
            heapSamples.add(used);

            long gcNow = totalGcCount();

            System.out.printf("[JM] Heap: %dMB/%dMB (%d%%), GC: +%d, "
                            + "Reqs: [1=%d 2=%d 3=%d 4=%d], Err: [1=%d 2=%d 3=%d 4=%d]%n",
                    used / 1024 / 1024, max / 1024 / 1024, pct,
                    gcNow - gcCountStart,
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
        }, 0, 10, TimeUnit.SECONDS);

        for (int i = 0; i < 30; i++) {
            workers.add(Thread.ofVirtual().name("short-" + i).unstarted(this::profileShort));
        }
        for (int i = 0; i < 20; i++) {
            workers.add(Thread.ofVirtual().name("medium-" + i).unstarted(this::profileMedium));
        }
        for (int i = 0; i < 5; i++) {
            workers.add(Thread.ofVirtual().name("long-" + i).unstarted(this::profileLong));
        }
        for (int i = 0; i < 10; i++) {
            workers.add(Thread.ofVirtual().name("chaos-" + i).unstarted(this::profileChaos));
        }

        for (Thread t : workers) t.start();
        Thread.sleep(TimeUnit.MINUTES.toMillis(TEST_DURATION_MIN));
        running = false;
        monitor.shutdown();
        for (Thread t : workers) t.join(10000);

        // Анализ формы floor: 6 окон по минимуму. Вердикт по окнам 4-5-6.
        if (heapSamples.size() >= 12) {
            int windowSize = heapSamples.size() / 6;
            long[] windowMins = new long[6];
            for (int w = 0; w < 6; w++) {
                long min = Long.MAX_VALUE;
                int start = w * windowSize;
                int end = (w == 5) ? heapSamples.size() : (w + 1) * windowSize;
                for (int i = start; i < end; i++) {
                    min = Math.min(min, heapSamples.get(i));
                }
                windowMins[w] = min;
            }

            long peakHeap = 0;
            for (long v : heapSamples) {
                peakHeap = Math.max(peakHeap, v);
            }

            System.out.printf("[HEAP] Начальный: %d MB, Пиковый: %d MB, Финальный: %d MB%n",
                    heapSamples.get(0) / 1024 / 1024, peakHeap / 1024 / 1024,
                    heapSamples.get(heapSamples.size() - 1) / 1024 / 1024);
            for (int w = 0; w < 6; w++) {
                System.out.printf("[HEAP] Окно %d: min %d MB%n",
                        w + 1, windowMins[w] / 1024 / 1024);
            }

            // Вердикт по окнам 4-5-6 (индексы 3,4,5): монотонный рост vs плато
            boolean monotonicGrowth = windowMins[3] < windowMins[4]
                    && windowMins[4] < windowMins[5];
            if (monotonicGrowth && windowMins[5] > windowMins[3] * 1.2) {
                System.out.println("[HEAP] Рост: окно 4 (" + (windowMins[3] / 1024 / 1024)
                        + " MB) → 6 (" + (windowMins[5] / 1024 / 1024)
                        + " MB) — возможна утечка, требуется длительный прогон (30+ мин)");
            } else {
                System.out.println("[HEAP] Вердикт: утечки нет, floor стабилен");
            }
        } else {
            System.out.println("[HEAP] Недостаточно данных для анализа тренда ("
                    + heapSamples.size() + " точек, нужно ≥12)");
        }

        assertTrue(profileRequests[2].get() > 0,
                "Профиль 2: должен быть хотя бы один успешный запрос");
        assertEquals(0, profileErrors[3].get(),
                "Профиль 3: ошибок быть не должно");
        assertTrue(profileRequests[1].get() > 0,
                "Профиль 1: должен быть хотя бы один запрос");
        long errs1 = profileErrors[1].get();
        long reqs1 = profileRequests[1].get();
        long total1 = reqs1 + errs1;
        assertTrue(errs1 * 100 < total1,
                "Профиль 1: ошибок более 1% (" + errs1
                + " из " + total1 + ")");

        System.out.printf("[RESULT] Profile 1: %d req, %d err%n",
                profileRequests[1].get(), profileErrors[1].get());
        System.out.printf("[RESULT] Profile 2: %d req, %d err%n",
                profileRequests[2].get(), profileErrors[2].get());
        System.out.printf("[RESULT] Profile 3: %d req, %d err, %d MB sent (не метрика throughput, см. TlsSessionStreamTest)%n",
                profileRequests[3].get(), profileErrors[3].get(),
                bytesSent.get() / 1024 / 1024);
        System.out.printf("[RESULT] Profile 4: %d req, %d err (expected)%n",
                profileRequests[4].get(), profileErrors[4].get());
        long totalReq = profileRequests[1].get() + profileRequests[2].get()
                + profileRequests[3].get() + profileRequests[4].get();
        long gcTotal = totalGcCount() - gcCountStart;
        System.out.printf("[RESULT] GC/req: %d / %d = %.4f (смешанный профиль — Profile 3 доминирует по трафику)%n",
                gcTotal, totalReq, (double) gcTotal / totalReq);
    }

    // ========================================================================
    // Профили
    // ========================================================================

    private void profileShort() {
        int profileId = 1;
        byte[] payload = generatePayload(1024);
        while (running) {
            Socket raw = null;
            TlsTransport t = null;
            TlsSession s = null;
            try {
                raw = new Socket("localhost", port);
                t = new SocketTlsTransport(raw);
                s = TlsSession.createClient(clientConfig, t);
                raw.setSoTimeout(15000);
                s.handshakeAsClient();
                s.write(payload);
                readEcho(s, payload.length);
                profileRequests[profileId].incrementAndGet();
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
                if (t != null) try { t.close(); } catch (Exception ignored) {}
                if (raw != null) try { raw.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileMedium() {
        int profileId = 2;
        while (running) {
            int sessionDuration = 5000 + CryptoRandom.INSTANCE.nextInt(25001);
            long deadline = System.currentTimeMillis() + sessionDuration;
            Socket raw = null;
            TlsTransport t = null;
            TlsSession s = null;
            try {
                raw = new Socket("localhost", port);
                t = new SocketTlsTransport(raw);
                s = TlsSession.createClient(clientConfig, t);
                raw.setSoTimeout(15000);
                s.handshakeAsClient();
                while (running && System.currentTimeMillis() < deadline) {
                    byte[] payload = generatePayload(1 + CryptoRandom.INSTANCE.nextInt(100));
                    s.write(payload);
                    readEcho(s, payload.length);
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
                if (t != null) try { t.close(); } catch (Exception ignored) {}
                if (raw != null) try { raw.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileLong() {
        int profileId = 3;
        byte[] chunk = generatePayload(16000);
        while (running) {
            Socket raw = null;
            TlsTransport t = null;
            TlsSession s = null;
            try {
                raw = new Socket("localhost", port);
                t = new SocketTlsTransport(raw);
                s = TlsSession.createClient(clientConfig, t);
                raw.setSoTimeout(30000);
                s.handshakeAsClient();
                while (running) {
                    s.write(chunk);
                    readEcho(s, chunk.length);
                    profileRequests[profileId].incrementAndGet();
                    bytesSent.addAndGet(chunk.length);
                }
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                if (s != null) try { s.close(); } catch (Exception ignored) {}
                if (t != null) try { t.close(); } catch (Exception ignored) {}
                if (raw != null) try { raw.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void profileChaos() {
        int profileId = 4;
        while (running) {
            Socket raw = null;
            TlsTransport t = null;
            TlsSession s = null;
            try {
                raw = new Socket("localhost", port);
                t = new SocketTlsTransport(raw);
                s = TlsSession.createClient(clientConfig, t);
                s.handshakeAsClient();
                Thread.sleep(CryptoRandom.INSTANCE.nextInt(2001));
                profileRequests[profileId].incrementAndGet();
            } catch (Exception e) {
                profileErrors[profileId].incrementAndGet();
            } finally {
                try { if (t != null) t.close(); } catch (Exception ignored) {}
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
        int maxSessions = 0;
        boolean stoppedByErrors = false;
        long maxMem = Runtime.getRuntime().maxMemory();
        long baselineHeap = Runtime.getRuntime().totalMemory()
                - Runtime.getRuntime().freeMemory();
        List<TlsSession> sessions = new CopyOnWriteArrayList<>();
        List<TlsTransport> transports = new CopyOnWriteArrayList<>();
        ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();

        for (int n = SESSIONS_STEP; n <= MAX_SESSIONS_LIMIT && maxSessions >= n - SESSIONS_STEP; n += SESSIONS_STEP) {
            CountDownLatch latch = new CountDownLatch(SESSIONS_STEP);
            AtomicInteger stepErrors = new AtomicInteger(0);
            for (int i = 0; i < SESSIONS_STEP; i++) {
                pool.submit(() -> {
                    try {
                        Socket raw = new Socket("localhost", port);
                        TlsTransport t = new SocketTlsTransport(raw);
                        TlsSession s = TlsSession.createClient(clientConfig, t);
                        s.handshakeAsClient();
                        s.write(generatePayload(1));
                        readEcho(s, 1);
                        sessions.add(s);
                        transports.add(t);
                    } catch (Exception e) {
                        // Нормально при достижении лимита heap
                        stepErrors.incrementAndGet();
                    } finally {
                        latch.countDown();
                    }
                });
            }
            if (!latch.await(30, TimeUnit.SECONDS)) break;

            long heapNow = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            if (heapNow > maxMem * HEAP_WARN_PCT / 100.0) break;

            // Ошибки при низком heap — проблема не в памяти, а в соединениях
            if (stepErrors.get() > 0 && heapNow < maxMem * 0.5) {
                System.err.println("[WARN] Step " + n + ": " + stepErrors.get()
                        + " errors at " + (heapNow / 1024 / 1024) + "MB heap"
                        + " — stopped by errors, not memory limit");
                stoppedByErrors = true;
                break;
            }

            maxSessions = n;
        }

        assertTrue(maxSessions >= 50, "Должен выдержать минимум 50 сессий");
        if (stoppedByErrors) {
            System.out.println("[LOG] Максимум одновременных сессий: ~" + maxSessions
                    + " (остановлено по ошибкам, не по памяти)");
        } else {
            System.out.println("[LOG] Максимум одновременных сессий: ~" + maxSessions
                    + " (черновая оценка, не для сайзинга)");
            long heapBefore = Runtime.getRuntime().totalMemory()
                    - Runtime.getRuntime().freeMemory();
            for (int gcTries = 0; gcTries < 5; gcTries++) {
                System.gc();
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                long heapAfter = Runtime.getRuntime().totalMemory()
                        - Runtime.getRuntime().freeMemory();
                long delta = Math.abs(heapAfter - heapBefore);
                if (delta * 100.0 / heapBefore < 2.0) {
                    heapBefore = heapAfter;
                    break;
                }
                heapBefore = heapAfter;
            }
            long memPerSession = (heapBefore - baselineHeap) / maxSessions;
            System.out.println("[SIZING] Память на сессию: ~" + (memPerSession / 1024) + " KB"
                    + " (черновая оценка, не для сайзинга)");
        }
        for (TlsSession s : sessions) {
            try { s.close(); } catch (Exception ignored) {}
        }
        for (TlsTransport t : transports) {
            try { t.close(); } catch (Exception ignored) {}
        }
        pool.shutdown();
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    private static void readEcho(TlsSession session, int len) throws IOException {
        byte[] data = session.read();
        if (data.length != len)
            throw new IOException("Echo mismatch: expected " + len + " got " + data.length);
    }

    private static byte[] generatePayload(int size) {
        byte[] data = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(data);
        return data;
    }

    private static long totalGcCount() {
        long total = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            total += gc.getCollectionCount();
        }
        return total;
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
