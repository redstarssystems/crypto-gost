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
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Пропускная способность TlsSession через реальный TCP — однопоточный write")
@Tag("stress")
@Timeout(value = 5, unit = TimeUnit.MINUTES)
class TlsSessionStreamTest {

    private static final int CHUNK_SIZE = 16383;
    private static final long WARMUP_MS = Long.getLong("stress.warmup", 5) * 1000L;
    private static final long MEASURE_MS = Long.getLong("stress.measure", 15) * 1000L;
    private static final int RUNS = Integer.getInteger("stress.iters", 5);
    private static final int SO_TIMEOUT_MS = (int) (MEASURE_MS + 15000);

    private static ServerSocket serverSocket;
    private static int port;
    private static TlsServerConfig serverConfig;
    private static TlsClientConfig clientConfig;

    @BeforeAll
    static void setup() throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        serverConfig = new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv);
        clientConfig = new TlsClientConfig(cs).withCaPublicKey(bundle.cert.getPublicKey());
        serverSocket = new ServerSocket(0);
        port = serverSocket.getLocalPort();
    }

    @AfterAll
    static void teardown() throws Exception {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    @Test
    @DisplayName("Непрерывная запись 16383-байтовых блоков без ожидания echo — 5 прогонов с медианой")
    void throughput() throws Exception {
        List<Double> validResults = new ArrayList<>();

        for (int iter = 0; iter < RUNS; iter++) {
            long[] measureStart = {Long.MIN_VALUE};
            AtomicLong measureBytes = new AtomicLong(0);
            AtomicLong lastByteNs = new AtomicLong(0);
            AtomicBoolean measuring = new AtomicBoolean(false);
            AtomicBoolean serverFailed = new AtomicBoolean(false);
            CountDownLatch accepted = new CountDownLatch(1);

            Thread srv = Thread.ofVirtual().name("stream-srv-" + iter).start(() -> {
                Socket raw = null;
                try {
                    accepted.countDown();
                    raw = serverSocket.accept();
                    raw.setSoTimeout(SO_TIMEOUT_MS);
                    try (TlsTransport t = new SocketTlsTransport(raw);
                         TlsSession s = TlsSession.createServer(serverConfig, t)) {
                        s.handshakeAsServer();
                        while (true) {
                            byte[] data = s.read();
                            if (measuring.get()) {
                                if (measureStart[0] == Long.MIN_VALUE)
                                    measureStart[0] = System.nanoTime();
                                measureBytes.addAndGet(data.length);
                                lastByteNs.set(System.nanoTime());
                            }
                        }
                    } catch (EOFException e) {
                        // нормальное завершение — close_notify получен
                    } catch (IOException e) {
                        // таймаут (soTimeout) или socket error — прогон бракуется
                    }
                } catch (IOException e) {
                    serverFailed.set(true);
                } finally {
                    if (raw != null) {
                        try { raw.close(); } catch (IOException ignored) { }
                    }
                }
            });

            assertTrue(accepted.await(10, TimeUnit.SECONDS),
                    "Сервер не принял соединение за 10 с");

            byte[] chunk = new byte[CHUNK_SIZE];
            CryptoRandom.INSTANCE.nextBytes(chunk);

            try (Socket raw = new Socket("localhost", port);
                 TlsTransport t = new SocketTlsTransport(raw);
                 TlsSession s = TlsSession.createClient(clientConfig, t)) {
                s.handshakeAsClient();

                long deadline = System.nanoTime() + WARMUP_MS * 1_000_000L;
                while (System.nanoTime() < deadline) {
                    s.write(chunk);
                }

                measuring.set(true);
                deadline = System.nanoTime() + MEASURE_MS * 1_000_000L;
                while (System.nanoTime() < deadline) {
                    s.write(chunk);
                }

                s.close();
            }

            srv.join(Duration.ofSeconds(12));

            if (serverFailed.get()) continue;
            if (srv.isAlive()) continue;

            long start = measureStart[0];
            long end = lastByteNs.get();
            long bytes = measureBytes.get();
            if (start == Long.MIN_VALUE || end == 0 || bytes == 0) continue;

            double sec = (end - start) / 1_000_000_000.0;
            if (sec < 5.0) continue;

            double mbps = bytes / (1024.0 * 1024.0 * sec);
            validResults.add(mbps);
        }

        assertFalse(validResults.isEmpty(), "Нет валидных прогонов");
        Collections.sort(validResults);
        int n = validResults.size();
        double median = (n % 2 == 0)
                ? (validResults.get(n / 2 - 1) + validResults.get(n / 2)) / 2.0
                : validResults.get(n / 2);
        double min = validResults.get(0);
        double max = validResults.get(n - 1);

        System.out.printf("[RESULT] Valid runs: %d (of %d)%n", validResults.size(), RUNS);
        System.out.printf("[RESULT] Min: %.1f MB/s, Max: %.1f MB/s, Median: %.1f MB/s%n", min, max, median);

        assertTrue(median > 0.0, "Медианный throughput = 0 — ошибка измерения");
    }
}
