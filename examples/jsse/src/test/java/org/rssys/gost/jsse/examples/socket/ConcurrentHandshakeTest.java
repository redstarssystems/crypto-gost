package org.rssys.gost.jsse.examples.socket;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.jsse.testkit.GostTestCerts;
import org.rssys.gost.jsse.testkit.GostTestCerts.CertChain;
import org.rssys.gost.tls13.TlsCiphersuite;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Тест 100 параллельных TLS handshake'ов к одному {@link GostSSLServerSocket}.
 * <p>
 * Цель: нагрузить shared state в момент массового завершения handshake —
 * {@link GostSSLSessionContext#putSession(GostSSLSession)} (synchronizedMap)
 * и {@link org.rssys.gost.tls13.psk.InMemoryPskStore#onTicketReceived(PskEntry)}
 * (ConcurrentHashMap). Гонка в synchronizedMap маловероятна при 10 клиентах,
 * но 100 одновременных handshake'ов создают реальное давление на блокировки.
 * <p>
 * Сервер принимает в пуле потоков, а не одном потоке: при одном server thread
 * accept() становится узким местом, и handshake'ы не выполняются одновременно.
 */
@DisplayName("100 параллельных handshake'ов к одному GostSSLServerSocket")
@Tag("integration")
class ConcurrentHandshakeTest {

    private static final int N = 100;
    private static final int TIMEOUT_SEC = 60;

    private GostSSLServerSocket serverSocket;
    private int port;
    private GostSSLSessionContext serverCtx;
    private GostSSLSessionContext clientCtx;
    private GostX509KeyManager clientKm;
    private GostX509TrustManager clientTm;
    private ExecutorService serverPool;
    private ExecutorService clientPool;
    private AtomicReference<String> firstError;

    @BeforeEach
    void setup() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        CertChain certs = GostTestCerts.createServerCert();

        // Серверные key/trust менеджеры
        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("server", certs.toJca(), certs.key());
        GostX509TrustManager serverTm = new GostX509TrustManager(certs.caKey(), false);

        // Клиентские менеджеры без сертификата (mTLS не требуется)
        clientKm = new GostX509KeyManager();
        clientTm = new GostX509TrustManager(certs.caKey(), false);

        // Раздельные session context'ы для сервера и клиентов
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverCtx = new GostSSLSessionContext(cs, cs.getHashLen());
        clientCtx = new GostSSLSessionContext(cs, cs.getHashLen());

        serverSocket = new GostSSLServerSocket(0, serverKm, serverTm, serverCtx);
        port = serverSocket.getLocalPort();

        firstError = new AtomicReference<>(null);
    }

    @AfterEach
    void teardown() {
        shutdownPool(serverPool);
        shutdownPool(clientPool);
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (Exception ignored) {
        }
    }

    @Test
    @DisplayName("100 параллельных handshake'ов — все успешны, NST сохранены")
    void concurrentHandshake100() throws Exception {
        // Серверный пул: N тредов, каждый блокирует accept().
        // accept() делегирует в ServerSocket.accept() (нативный, синхронизированный),
        // поэтому множественные accept() на одном сокете — безопасны.
        // Используем CountDownLatch до accept() — чтобы все треды были готовы
        // к параллельному приёму до того, как клиенты отправят startGun.
        CountDownLatch serverBlocked = new CountDownLatch(N);
        CountDownLatch allDone = new CountDownLatch(N);

        serverPool = Executors.newFixedThreadPool(N);
        for (int i = 0; i < N; i++) {
            serverPool.submit(() -> {
                try {
                    serverBlocked.countDown();
                    GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept();
                    accepted.startHandshake();
                    // Читаем PING от клиента
                    InputStream in = accepted.getInputStream();
                    OutputStream out = accepted.getOutputStream();
                    byte[] buf = new byte[1024];
                    int len = in.read(buf);
                    if (len > 0) {
                        out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                        out.flush();
                    }
                } catch (Exception e) {
                    firstError.compareAndSet(null,
                            "Server error: " + e.getClass().getSimpleName()
                                    + ": " + e.getMessage());
                }
            });
        }

        // Ждём пока все серверные треды заблокируются на accept()
        // Создаём клиентов после того как сервер готов
        assertTrue(serverBlocked.await(10, TimeUnit.SECONDS),
                "Все серверные треды должны войти в accept()");

        // Клиентский пул: N тредов, каждый создаёт GostSSLSocket
        clientPool = Executors.newFixedThreadPool(N);
        for (int i = 0; i < N; i++) {
            clientPool.submit(() -> {
                try {
                    GostSSLSocket client = new GostSSLSocket("localhost", port,
                            clientKm, clientTm, clientCtx);
                    client.setSoTimeout(15000);
                    // Handshake стартует автоматически при первом write
                    OutputStream out = client.getOutputStream();
                    out.write("PING\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();

                    InputStream in = client.getInputStream();
                    byte[] buf = new byte[1024];
                    int len = in.read(buf);
                    String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
                    if (!"PONG".equals(response)) {
                        firstError.compareAndSet(null,
                                "Unexpected response: " + response);
                    }
                    client.close();
                } catch (Exception e) {
                    firstError.compareAndSet(null,
                            "Client error: " + e.getClass().getSimpleName()
                                    + ": " + e.getMessage());
                } finally {
                    allDone.countDown();
                }
            });
        }

        // Ждём завершения всех клиентов
        assertTrue(allDone.await(TIMEOUT_SEC, TimeUnit.SECONDS),
                "Не все клиенты завершились за " + TIMEOUT_SEC + " с");

        // Верификация
        if (firstError.get() != null) {
            throw new AssertionError(firstError.get());
        }

        // Сервер выдал NST каждому клиенту — в serverCtx должны быть PSK
        assertTrue(serverCtx.getPskStore().size() > 0,
                "Сервер должен выдать NST после " + N + " handshake'ов");

        // Клиент получил NST — в clientCtx должны быть PSK
        assertTrue(clientCtx.getPskStore().size() > 0,
                "Клиент должен получить NST от сервера");
    }

    private static void shutdownPool(ExecutorService pool) {
        if (pool != null) {
            pool.shutdownNow();
            try {
                pool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }
    }
}
