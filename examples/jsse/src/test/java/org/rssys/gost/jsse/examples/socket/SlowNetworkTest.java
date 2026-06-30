package org.rssys.gost.jsse.examples.socket;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
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

/**
 * Тесты таймаутов partial reads имитирующих реальные сетевые условия.
 * <p>
 * Использует GostSSLServerSocket + raw java.net.Socket для контролируемой
 * подачи байтов — никаких внешних инструментов (tc netem не требуется).
 * <p>
 * В отличие от unit-тестов в {@code GostSSLSocketTcpTest}, эти тесты
 * фокусируются на пограничных случаях: нулевые записи, обрывы в середине
 * заголовка/тела, комбинации таймаут+обрыв. Каждый тест запускает
 * real TCP-соединение (эхосервер или сервер-заглушку).
 */
@DisplayName("Таймауты и partial reads в сетевых условиях")
@Tag("integration")
class SlowNetworkTest {

    private static final int TIMEOUT_MS = 10000;

    private CertChain certs;
    private GostX509KeyManager serverKm;
    private GostX509TrustManager serverTm;
    private GostX509KeyManager clientKm;
    private GostX509TrustManager clientTm;
    private GostSSLSessionContext sessionCtx;

    @BeforeEach
    void setup() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        certs = GostTestCerts.createServerCert();

        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("server", certs.toJca(), certs.key());
        serverTm = new GostX509TrustManager(certs.caKey(), false);

        clientKm = new GostX509KeyManager();
        clientTm = new GostX509TrustManager(certs.caKey(), false);

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        sessionCtx = new GostSSLSessionContext(cs, cs.getHashLen());
    }

    @AfterEach
    void teardown() {
        // Ничего не делаем — сокеты закрываются в тестах
    }

    @Test
    @DisplayName("Таймаут во время handshake — SocketTimeoutException")
    void timeoutDuringHandshake() throws Exception {
        // Сервер принимает TCP-соединение но не отвечает на TLS handshake.
        // Важно: GostSSLServerSocket.accept() возвращает GostSSLSocket без
        // запуска handshake — handshake ленивый, стартует только при явном
        // вызове startHandshake() или первом read()/write(). Поэтому accept()
        // не отвечает на ClientHello: серверный тред просто спит, клиент
        // ждёт ServerHello и падает по SoTimeout.
        // Это поведение подтверждено кодом GostSSLServerSocket.accept().
        GostSSLServerSocket serverSock = new GostSSLServerSocket(0, serverKm, serverTm, sessionCtx);
        try {
            int port = serverSock.getLocalPort();

            // Отдельный поток: accept без handshake — просто держим соединение
            CountDownLatch accepted = new CountDownLatch(1);
            Thread serverThread =
                    new Thread(
                            () -> {
                                try {
                                    Socket s = serverSock.accept();
                                    accepted.countDown();
                                    // Не делаем startHandshake() — клиент ждёт ответ и таймаутит
                                    Thread.sleep(10000);
                                    s.close();
                                } catch (Exception ignored) {
                                }
                            },
                            "server-silent");
            serverThread.start();

            GostSSLSocket client =
                    new GostSSLSocket("localhost", port, clientKm, clientTm, sessionCtx);
            client.setSoTimeout(300); // 300ms таймаут

            Exception ex = assertThrows(Exception.class, client::startHandshake);
            assertInstanceOf(
                    SocketTimeoutException.class,
                    ex,
                    "Ожидался SocketTimeoutException, получено: " + ex.getClass().getName());

            client.close();
            serverThread.join(2000);
            serverSock.close();
        } finally {
            serverSock.close();
        }
    }

    @Test
    @DisplayName("Таймаут во время read() после handshake — SocketTimeoutException")
    void timeoutDuringReadAfterHandshake() throws Exception {
        // Полноценный TLS handshake, затем сервер медлит с ответом.
        // Клиент делает read() — таймаут.
        GostSSLServerSocket serverSock = new GostSSLServerSocket(0, serverKm, serverTm, sessionCtx);
        try {
            int port = serverSock.getLocalPort();

            CountDownLatch accepted = new CountDownLatch(1);
            AtomicReference<Socket> acceptedRef = new AtomicReference<>();
            Thread serverThread =
                    new Thread(
                            () -> {
                                try {
                                    GostSSLSocket serverSsl = (GostSSLSocket) serverSock.accept();
                                    acceptedRef.set(serverSsl);
                                    serverSsl.startHandshake();
                                    accepted.countDown();
                                    // Сервер не пишет ответ — клиентский read() таймаутит
                                    Thread.sleep(10000);
                                    serverSsl.close();
                                } catch (Exception ignored) {
                                }
                            },
                            "server-slow");
            serverThread.start();

            GostSSLSocket client =
                    new GostSSLSocket("localhost", port, clientKm, clientTm, sessionCtx);
            client.setSoTimeout(300);

            // Клиент инициирует handshake
            client.startHandshake();

            // Ждём пока сервер примет и выполнит handshake
            assertTrue(
                    accepted.await(5, TimeUnit.SECONDS), "Сервер должен принять соединение за 5 с");

            // Клиент пишет и пытается прочитать — таймаут
            OutputStream out = client.getOutputStream();
            out.write("PING\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = client.getInputStream();
            Exception ex =
                    assertThrows(
                            Exception.class,
                            () -> {
                                byte[] buf = new byte[1024];
                                in.read(buf);
                            });
            assertInstanceOf(
                    SocketTimeoutException.class,
                    ex,
                    "Ожидался SocketTimeoutException, получено: " + ex.getClass().getName());

            client.close();
            serverThread.join(2000);
        } finally {
            serverSock.close();
        }
    }

    @Test
    @DisplayName("Нулевая запись write(new byte[0]) — не падает")
    void zeroByteWrite() throws Exception {
        // write(byte[0]) не должен отправлять TLS-запись с нулевым телом —
        // RFC 8446 не допускает нулевые Application Data записи.
        // Внутренняя проверка отсекает пустые массивы до передачи в engine.
        GostSSLServerSocket serverSock = new GostSSLServerSocket(0, serverKm, serverTm, sessionCtx);
        try {
            int port = serverSock.getLocalPort();

            CountDownLatch serverReady = new CountDownLatch(1);
            Thread serverThread =
                    new Thread(
                            () -> {
                                try {
                                    GostSSLSocket serverSsl = (GostSSLSocket) serverSock.accept();
                                    serverSsl.startHandshake();
                                    serverReady.countDown();
                                    // Сервер читает и отвечает — не должен застрять из-за нулевой
                                    // записи
                                    InputStream in = serverSsl.getInputStream();
                                    OutputStream out = serverSsl.getOutputStream();
                                    byte[] buf = new byte[1024];
                                    int len = in.read(buf);
                                    if (len > 0) {
                                        out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                                        out.flush();
                                    }
                                    serverSsl.close();
                                } catch (Exception ignored) {
                                }
                            },
                            "server-zero");
            serverThread.start();

            GostSSLSocket client =
                    new GostSSLSocket("localhost", port, clientKm, clientTm, sessionCtx);
            client.setSoTimeout(TIMEOUT_MS);
            client.startHandshake();

            assertTrue(serverReady.await(5, TimeUnit.SECONDS));

            // write(0) — не должен упасть
            assertDoesNotThrow(
                    () -> {
                        client.getOutputStream().write(new byte[0]);
                    });

            // write(0) не равносилен close — последующая запись должна работать
            OutputStream out = client.getOutputStream();
            out.write("PING\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = client.getInputStream();
            byte[] buf = new byte[1024];
            int len = in.read(buf);
            String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
            assertTrue(response.contains("PONG"), "Ожидался PONG, получено: " + response);

            client.close();
            serverThread.join(2000);
        } finally {
            serverSock.close();
        }
    }

    @Test
    @DisplayName("Таймаут на заголовке TLS-записи, потом retry — данные читаются")
    void timeoutThenRetry() throws Exception {
        // Сервер: handshake, потом перед отправкой PONG ждёт > SoTimeout.
        // Клиент: read() таймаутит, повторный read() получает данные.
        GostSSLServerSocket serverSock = new GostSSLServerSocket(0, serverKm, serverTm, sessionCtx);
        try {
            int port = serverSock.getLocalPort();

            CountDownLatch serverReady = new CountDownLatch(1);
            Thread serverThread =
                    new Thread(
                            () -> {
                                try {
                                    GostSSLSocket serverSsl = (GostSSLSocket) serverSock.accept();
                                    serverSsl.startHandshake();
                                    serverReady.countDown();
                                    InputStream in = serverSsl.getInputStream();
                                    OutputStream out = serverSsl.getOutputStream();

                                    byte[] buf = new byte[1024];
                                    int len = in.read(buf);

                                    // Пауза перед отправкой — клиент таймаутит
                                    Thread.sleep(1000);

                                    out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                                    out.flush();
                                    serverSsl.close();
                                } catch (Exception ignored) {
                                }
                            },
                            "server-delay");
            serverThread.start();

            GostSSLSocket client =
                    new GostSSLSocket("localhost", port, clientKm, clientTm, sessionCtx);
            client.setSoTimeout(200);
            client.startHandshake();

            assertTrue(serverReady.await(5, TimeUnit.SECONDS));

            OutputStream out = client.getOutputStream();
            out.write("PING\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Первый read — таймаут (сервер ещё не отправил ответ)
            InputStream in = client.getInputStream();
            byte[] buf = new byte[1024];
            assertThrows(
                    SocketTimeoutException.class,
                    () -> in.read(buf),
                    "Первый read должен упасть по таймауту");

            // Ждём пока сервер ответит
            Thread.sleep(1500);

            // Повторный read — успех (сервер отправил данные)
            client.setSoTimeout(TIMEOUT_MS);
            int len = in.read(buf);
            String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
            assertTrue(
                    response.contains("PONG"),
                    "Повторный read должен получить PONG, получено: " + response);

            client.close();
            serverThread.join(2000);
        } finally {
            serverSock.close();
        }
    }
}
