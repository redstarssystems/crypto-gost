package org.rssys.bench.crl;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import org.rssys.gost.jsse.crl.CrlBenchFetchers;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlCache.CrlKey;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Серия B, холодный путь: первое соединение и каждый {@code nextUpdate}, когда CRL надо скачать.
 *
 * <p>Потоки одновременно вызывают {@link CrlCache#get}: один скачивает CRL с локального сервера
 * (другая JVM), проверяет подпись и разбирает записи, остальные ждут и проверяют по готовому
 * объекту свой сертификат, как {@code GostX509TrustManager.checkCrl}. Каждый раунд начинается с
 * пустого кэша. Фазы отдельно не измеряются: загрузка идёт внутри {@code get}.</p>
 */
final class CellB {

    private static final int ROUNDS = 2;
    private static final int FETCH_TIMEOUT_SECONDS = 300;
    private static final long BUDGET_BYTES = 16L * 1024 * 1024 * 1024;

    private CellB() {}

    static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        String name = args[1];
        int threads = Integer.parseInt(args[2]);
        int port = Integer.parseInt(args[3]);
        try {
            run(dir, name, threads, port);
        } catch (OutOfMemoryError e) {
            CrlBench.result("outcome", "OOM", "threads", String.valueOf(threads), "ok", "0");
        } catch (Throwable e) {
            CrlBench.result(
                    "outcome", "ERROR", "detail", e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    private static void run(Path dir, String name, int threads, int port) throws Exception {
        GostCertificate ca = GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.CA_SUFFIX));
        GostCertificate leaf =
                GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.LEAF_SUFFIX));
        String uri = "http://127.0.0.1:" + port + "/crl";
        CrlFetcher fetcher =
                CrlBenchFetchers.allowLocal(
                        Duration.ofSeconds(FETCH_TIMEOUT_SECONDS), CrlBench.MAX_CRL_SIZE);
        CrlKey key = new CrlKey(uri, "00");
        CrlCache.Authenticator authenticator =
                der ->
                        CrlVerifier.authenticate(der, ca, CrlBench.LIMITS);

        long[] threadNanos = new long[ROUNDS];
        long[] roundNanos = new long[ROUNDS];
        boolean failed = false;
        int completed = 0;
        int lastOk = threads;
        int lastFetches = 0;
        for (int r = 0; r < ROUNDS && !failed; r++) {
            // Каждый раунд холодный: новый кэш, как первое соединение после запуска
            CrlCache cache = new CrlCache(BUDGET_BYTES, Duration.ZERO);
            AtomicInteger fetches = new AtomicInteger();
            CrlCache.Loader loader =
                    () -> {
                        fetches.incrementAndGet();
                        return fetcher.fetch(uri);
                    };
            CyclicBarrier start = new CyclicBarrier(threads + 1);
            AtomicInteger ok = new AtomicInteger();
            long[] threadT = new long[threads];
            Thread[] workers = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                int idx = t;
                workers[t] =
                        new Thread(
                                () -> {
                                    try {
                                        start.await();
                                        long a = System.nanoTime();
                                        CrlCache.Loaded loaded =
                                                cache.get(
                                                        key,
                                                        loader,
                                                        null,
                                                        authenticator,
                                                        Deadline.MAX_FETCH_TIMEOUT);
                                        loaded.crl()
                                                .verifyFor(
                                                        leaf, ca, null);
                                        threadT[idx] = System.nanoTime() - a;
                                        ok.incrementAndGet();
                                    } catch (Throwable e) {
                                        // часть потоков может получить OutOfMemoryError
                                    }
                                });
                workers[t].start();
            }
            start.await();
            long t0 = System.nanoTime();
            for (Thread w : workers) {
                w.join();
            }
            roundNanos[r] = System.nanoTime() - t0;
            threadNanos[r] = CrlBench.median(threadT);
            completed++;
            lastOk = ok.get();
            lastFetches = fetches.get();
            if (lastOk < threads) {
                failed = true;
            }
        }
        // Каждый раунд холодный; медиану времени берём по завершённым раундам
        long[] rounds = java.util.Arrays.copyOf(roundNanos, completed);
        CrlBench.result(
                "outcome", failed ? "OOM" : "OK",
                "threads", String.valueOf(threads),
                "ok", String.valueOf(lastOk),
                "medianMs", CrlBench.f1(CrlBench.ms(CrlBench.median(rounds))),
                "threadMs",
                        CrlBench.f1(
                                CrlBench.ms(
                                        CrlBench.median(
                                                java.util.Arrays.copyOf(threadNanos, completed)))),
                "fetches", String.valueOf(lastFetches));
    }
}
