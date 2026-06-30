package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.testkit.GostTestCerts;
import org.rssys.gost.jsse.testkit.GostTestCerts.CertChain;

/**
 * Тесты thread-safety {@link GostX509KeyManager} под конкурентной нагрузкой.
 * <p>
 * После фикса бага (ArrayList -> {@link java.util.concurrent.CopyOnWriteArrayList})
 * все три теста должны проходить зелёными даже при параллельной записи и чтении.
 * CopyOnWriteArrayList оптимизирован для read-heavy сценария: addKeyEntry() копирует
 * массив (редко), а chooseServerAlias()/getCertificateChain() читают lock-free.
 */
@DisplayName("Потокобезопасность GostX509KeyManager")
@Tag("integration")
class GostX509KeyManagerConcurrencyTest {

    private static final int TIMEOUT_SEC = 30;

    @Test
    @DisplayName("50 параллельных chooseServerAlias (только чтение) — все успешны")
    void concurrentChooseServerAlias() throws Exception {
        GostX509KeyManager km = createKeyManagerWithBothTypes(5);
        int n = 50;
        CountDownLatch allDone = new CountDownLatch(n);
        CyclicBarrier start = new CyclicBarrier(n);
        AtomicInteger errorCount = new AtomicInteger(0);

        ExecutorService pool = Executors.newFixedThreadPool(n);
        for (int i = 0; i < n; i++) {
            pool.submit(
                    () -> {
                        try {
                            start.await(TIMEOUT_SEC, TimeUnit.SECONDS);
                            for (int j = 0; j < 100; j++) {
                                String alias =
                                        km.chooseEngineServerAlias(
                                                "ECGOST3410-2012-256", null, null);
                                if (alias == null) {
                                    errorCount.incrementAndGet();
                                }
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        } finally {
                            allDone.countDown();
                        }
                    });
        }

        assertTrue(
                allDone.await(TIMEOUT_SEC, TimeUnit.SECONDS),
                "Тест не завершился за " + TIMEOUT_SEC + " с");
        assertTrue(
                errorCount.get() == 0,
                "Ошибок не ожидается при чтении без записи, получено: " + errorCount.get());
    }

    @Test
    @DisplayName("20 запись + 20 чтение — без CME (CopyOnWriteArrayList)")
    void concurrentAddKeyEntryDuringRead() throws Exception {
        GostX509KeyManager km = createKeyManagerWithBothTypes(3);
        int nWriters = 20;
        int nReaders = 20;
        int total = nWriters + nReaders;
        CountDownLatch allDone = new CountDownLatch(total);
        CyclicBarrier start = new CyclicBarrier(total);
        AtomicInteger errorCount = new AtomicInteger(0);

        ExecutorService pool = Executors.newFixedThreadPool(total);

        for (int i = 0; i < nWriters; i++) {
            final int idx = i;
            pool.submit(
                    () -> {
                        try {
                            start.await(TIMEOUT_SEC, TimeUnit.SECONDS);
                            for (int j = 0; j < 50; j++) {
                                CertChain newCert = GostTestCerts.createServerCert();
                                km.addKeyEntry(
                                        "writer_" + idx + "_" + j, newCert.toJca(), newCert.key());
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        } finally {
                            allDone.countDown();
                        }
                    });
        }

        for (int i = 0; i < nReaders; i++) {
            pool.submit(
                    () -> {
                        try {
                            start.await(TIMEOUT_SEC, TimeUnit.SECONDS);
                            for (int j = 0; j < 100; j++) {
                                km.chooseEngineServerAlias("ECGOST3410-2012-256", null, null);
                                km.getCertificateChain("alias_0");
                                km.getPrivateKey("alias_0");
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        } finally {
                            allDone.countDown();
                        }
                    });
        }

        assertTrue(
                allDone.await(TIMEOUT_SEC, TimeUnit.SECONDS),
                "Тест не завершился за " + TIMEOUT_SEC + " с");
        assertTrue(
                errorCount.get() == 0,
                "Ошибок не ожидается (CopyOnWriteArrayList потокобезопасен), получено: "
                        + errorCount.get());
    }

    @Test
    @DisplayName("Смешанное чтение/запись — без CME (CopyOnWriteArrayList)")
    void mixedReadWriteConcurrency() throws Exception {
        GostX509KeyManager km = createKeyManagerWithBothTypes(3);
        int n = 30;
        CountDownLatch allDone = new CountDownLatch(n);
        CyclicBarrier start = new CyclicBarrier(n);
        AtomicInteger errorCount = new AtomicInteger(0);

        ExecutorService pool = Executors.newFixedThreadPool(n);
        for (int t = 0; t < n; t++) {
            final int threadIdx = t;
            pool.submit(
                    () -> {
                        try {
                            start.await(TIMEOUT_SEC, TimeUnit.SECONDS);
                            for (int j = 0; j < 100; j++) {
                                int op = (threadIdx + j) % 4;
                                switch (op) {
                                    case 0 -> {
                                        CertChain newCert = GostTestCerts.createServerCert();
                                        km.addKeyEntry(
                                                "mixed_" + threadIdx + "_" + j,
                                                newCert.toJca(),
                                                newCert.key());
                                    }
                                    case 1 ->
                                            km.chooseEngineServerAlias(
                                                    "ECGOST3410-2012-256", null, null);
                                    case 2 -> km.getCertificateChain("alias_0");
                                    case 3 -> km.getPrivateKey("alias_0");
                                }
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        } finally {
                            allDone.countDown();
                        }
                    });
        }

        assertTrue(
                allDone.await(TIMEOUT_SEC, TimeUnit.SECONDS),
                "Тест не завершился за " + TIMEOUT_SEC + " с");
        assertTrue(
                errorCount.get() == 0,
                "Ошибок не ожидается (CopyOnWriteArrayList потокобезопасен), получено: "
                        + errorCount.get());
    }

    /**
     * Создаёт GostX509KeyManager с {@code count} 256-битными алиасами.
     * <p>
     * GostTestCerts поддерживает только 256-битные ключи (Streebog256 в doHash),
     * поэтому все entry имеют hlen=32. В тестах используем keyType
     * ECGOST3410-2012-256, который соответствует filterAliases.
     */
    private static GostX509KeyManager createKeyManagerWithBothTypes(int count) throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        for (int i = 0; i < count; i++) {
            CertChain cc = GostTestCerts.createServerCert();
            km.addKeyEntry("alias_" + i, cc.toJca(), cc.key());
        }
        return km;
    }
}
