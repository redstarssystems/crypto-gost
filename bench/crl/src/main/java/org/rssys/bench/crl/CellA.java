package org.rssys.bench.crl;

import com.sun.management.ThreadMXBean;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Серия A, горячий путь: CRL уже лежит в кэше, на каждом рукопожатии заново выполняется
 * {@code CrlVerifier.verify} (хэш, подпись, строгий разбор записей).
 *
 * <p>Потоки стартуют по барьеру и проверяют общий массив DER, как параллельные рукопожатия.
 * Первый раунд холодный (JIT не прогрет), остальные прогретые.</p>
 */
final class CellA {

    private static final long SAMPLE_INTERVAL_MS = 10;

    private CellA() {}

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

        AtomicLong peakUsed = new AtomicLong();
        Thread watcher = startWatcher(peakUsed);

        long[] roundNanos = new long[rounds];
        AtomicLong allocBytes = new AtomicLong();
        AtomicInteger okCalls = new AtomicInteger();
        int completedRounds = 0;
        int lastRoundOk = threads;
        boolean failed = false;
        for (int r = 0; r < rounds && !failed; r++) {
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
                                        CrlVerifier.verify(
                                                crlDer,
                                                leaf,
                                                ca,
                                                null,
                                                CrlBench.LIMITS);
                                        allocBytes.addAndGet(
                                                bean.getThreadAllocatedBytes(
                                                                Thread.currentThread().threadId())
                                                        - alloc0);
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
            okCalls.addAndGet(okThreads.get());
            completedRounds++;
            lastRoundOk = okThreads.get();
            if (lastRoundOk < threads) {
                failed = true;
            }
        }
        watcher.interrupt();

        long[] done = java.util.Arrays.copyOf(roundNanos, completedRounds);
        StringBuilder roundsMs = new StringBuilder();
        for (int i = 0; i < done.length; i++) {
            if (i > 0) roundsMs.append(',');
            roundsMs.append(CrlBench.f1(CrlBench.ms(done[i])));
        }
        CrlBench.result(
                "outcome", failed ? "OOM" : "OK",
                "threads", String.valueOf(threads),
                "ok", String.valueOf(lastRoundOk),
                "crlMb", CrlBench.f1(CrlBench.mb(crlDer.length)),
                "roundsMs", roundsMs.toString(),
                "medianMs", CrlBench.f1(CrlBench.ms(CrlBench.median(done))),
                "allocPerCallMb",
                        okCalls.get() == 0
                                ? "-"
                                : CrlBench.f1(CrlBench.mb(allocBytes.get() / okCalls.get())),
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
