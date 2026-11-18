package org.rssys.bench.crl;

import com.sun.management.ThreadMXBean;
import java.time.Duration;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlCache.CrlKey;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Серия C: кэш проверенных CRL, как в менеджере доверия после введения {@code VerifiedCrl}.
 *
 * <p>Потоки стартуют по барьеру и вызывают {@code CrlCache.get} с последующей проверкой своего
 * сертификата. Первый раунд холодный: один поток проверяет подпись и разбирает CRL, остальные
 * ждут. Остальные раунды горячие: подпись и разбор уже выполнены, остаётся проверка сертификата.
 * Бюджет кэша поднят, чтобы измерять удержание разобранного объекта, а не вытеснение.</p>
 */
final class CellC {

    private static final long SAMPLE_INTERVAL_MS = 10;
    private static final long BUDGET_BYTES = 16L * 1024 * 1024 * 1024;

    private CellC() {}

    static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        String name = args[1];
        int threads = Integer.parseInt(args[2]);
        int rounds = Integer.parseInt(args[3]);
        try {
            run(dir, name, threads, rounds);
        } catch (OutOfMemoryError e) {
            CrlBench.result("outcome", "OOM", "threads", String.valueOf(threads), "ok", "0");
        } catch (Throwable e) {
            CrlBench.result(
                    "outcome", "ERROR", "detail", e.getClass().getSimpleName() + ":" + e.getMessage());
        }
    }

    private static void run(Path dir, String name, int threads, int rounds) throws Exception {
        byte[] crlDer = CrlBench.read(dir, name, CrlBench.CRL_SUFFIX);
        GostCertificate ca = GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.CA_SUFFIX));
        GostCertificate leaf =
                GostCertificate.fromDer(CrlBench.read(dir, name, CrlBench.LEAF_SUFFIX));
        ThreadMXBean bean = (ThreadMXBean) ManagementFactory.getThreadMXBean();
        CrlCache cache = new CrlCache(BUDGET_BYTES, Duration.ZERO);
        CrlKey key = new CrlKey("bench://crl", "00");
        AtomicInteger loads = new AtomicInteger();
        CrlCache.Loader loader =
                () -> {
                    loads.incrementAndGet();
                    return crlDer;
                };
        CrlCache.Authenticator authenticator =
                der ->
                        CrlVerifier.authenticate(der, ca, CrlBench.LIMITS);

        AtomicLong peakUsed = new AtomicLong();
        Thread watcher = startWatcher(peakUsed);

        long[] roundNanos = new long[rounds];
        AtomicLong hotAlloc = new AtomicLong();
        AtomicInteger hotCalls = new AtomicInteger();
        int completed = 0;
        int lastRoundOk = threads;
        boolean failed = false;
        for (int r = 0; r < rounds && !failed; r++) {
            boolean hot = r > 0;
            CyclicBarrier start = new CyclicBarrier(threads + 1);
            AtomicInteger okThreads = new AtomicInteger();
            Thread[] workers = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                workers[t] =
                        new Thread(
                                () -> {
                                    try {
                                        start.await();
                                        long alloc0 =
                                                bean.getThreadAllocatedBytes(
                                                        Thread.currentThread().threadId());
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
                                        if (hot) {
                                            hotAlloc.addAndGet(
                                                    bean.getThreadAllocatedBytes(
                                                                    Thread.currentThread()
                                                                            .threadId())
                                                            - alloc0);
                                            hotCalls.incrementAndGet();
                                        }
                                        okThreads.incrementAndGet();
                                    } catch (Throwable e) {
                                        // OutOfMemoryError достаётся только части потоков;
                                        // число успешных считаем отдельно
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
            completed++;
            lastRoundOk = okThreads.get();
            if (lastRoundOk < threads) {
                failed = true;
            }
        }
        watcher.interrupt();

        long[] done = Arrays.copyOf(roundNanos, completed);
        long[] hotRounds = completed > 1 ? Arrays.copyOfRange(done, 1, completed) : done;
        CrlBench.result(
                "outcome", failed ? "OOM" : "OK",
                "threads", String.valueOf(threads),
                "ok", String.valueOf(lastRoundOk),
                "crlMb", CrlBench.f1(CrlBench.mb(crlDer.length)),
                "coldMs", CrlBench.f1(CrlBench.ms(done[0])),
                "medianMs", CrlBench.f1(CrlBench.ms(CrlBench.median(hotRounds))),
                "loads", String.valueOf(loads.get()),
                "allocPerCallMb",
                        hotCalls.get() == 0
                                ? "-"
                                : CrlBench.f1(CrlBench.mb(hotAlloc.get() / hotCalls.get())),
                "watcherPeakMb", CrlBench.f1(CrlBench.mb(peakUsed.get())));
    }

    /** Раз в 10 мс снимает занятую кучу: верхняя оценка пика, включает ещё не собранный мусор. */
    private static Thread startWatcher(AtomicLong peakUsed) {
        Thread watcher =
                new Thread(
                        () -> {
                            Runtime rt = Runtime.getRuntime();
                            while (!Thread.currentThread().isInterrupted()) {
                                long used = rt.totalMemory() - rt.freeMemory();
                                peakUsed.accumulateAndGet(used, Math::max);
                                try {
                                    Thread.sleep(SAMPLE_INTERVAL_MS);
                                } catch (InterruptedException e) {
                                    return;
                                }
                            }
                        });
        watcher.setDaemon(true);
        watcher.start();
        return watcher;
    }
}
