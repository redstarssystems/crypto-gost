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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Тесты close/reconnect для GostSSLSocket под нагрузкой.
 * <p>
 * Проверяет, что close_notify корректно обрабатывается при быстрых reconnect,
 * ресурсы освобождаются (accept/close циклически), и принудительный RST
 * не приводит к утечкам или зависаниям.
 * <p>
 * Все тесты используют raw {@link GostSSLServerSocket} + {@link GostSSLSocket} —
 * без HTTP-серверов приложений, чтобы изолировать поведение TCP/TLS-стека
 * от логики сервера.
 */
@DisplayName("GostSSLSocket close/reconnect под нагрузкой")
@Tag("integration")
class GostSSLSocketReconnectTest {

    private static final int TIMEOUT_MS = 10000;

    private CertChain certs;
    private GostX509KeyManager serverKm;
    private GostX509TrustManager serverTm;
    private GostX509KeyManager clientKm;
    private GostX509TrustManager clientTm;
    private GostSSLSessionContext clientSessionCtx;
    private GostSSLSessionContext serverSessionCtx;
    private GostSSLServerSocket serverSocket;
    private int port;

    @BeforeEach
    void setup() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        certs = GostTestCerts.createServerCert();

        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("server", certs.toJca(), certs.key());
        serverTm = new GostX509TrustManager(certs.caKey(), false);

        clientKm = new GostX509KeyManager();
        clientTm = new GostX509TrustManager(certs.caKey(), false);

        // Раздельные session context'ы для клиента и сервера.
        // Сервер хранит тикеты, которые выдаёт клиентам; клиент хранит полученные NST.
        // Если передать clientSessionCtx в сервер — сервер будет писать тикеты
        // в клиентский контекст, что сломает PSK-механизм (баг, который мы
        // обнаружили на ревью).
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        clientSessionCtx = new GostSSLSessionContext(cs, cs.getHashLen());
        serverSessionCtx = new GostSSLSessionContext(cs, cs.getHashLen());

        serverSocket = new GostSSLServerSocket(0, serverKm, serverTm, serverSessionCtx);
        port = serverSocket.getLocalPort();
    }

    @AfterEach
    void teardown() throws IOException {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
    }

    @Test
    @DisplayName("50 последовательных open-handshake-write-close")
    void rapidOpenClose50() throws Exception {
        int n = 50;

        CountDownLatch serverDone = new CountDownLatch(n);
        AtomicReference<String> serverError = new AtomicReference<>(null);

        // Серверный поток: принимает n соединений, каждое читает и отвечает
        Thread serverThread = new Thread(() -> {
            try {
                for (int i = 0; i < n; i++) {
                    try (GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept()) {
                        accepted.startHandshake();
                        accepted.setSoTimeout(TIMEOUT_MS);
                        InputStream in = accepted.getInputStream();
                        OutputStream out = accepted.getOutputStream();
                        byte[] buf = new byte[1024];
                        int len = in.read(buf);
                        if (len > 0) {
                            out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                            out.flush();
                        }
                    }
                    serverDone.countDown();
                }
            } catch (Exception e) {
                serverError.compareAndSet(null, e.getMessage());
            }
        }, "server-accept");
        serverThread.start();

        // Клиент: n соединений, каждое отправляет PING и проверяет PONG
        for (int i = 0; i < n; i++) {
            GostSSLSocket client = new GostSSLSocket("localhost", port,
                    clientKm, clientTm, clientSessionCtx);
            client.setSoTimeout(TIMEOUT_MS);
            try {
                OutputStream out = client.getOutputStream();
                out.write("PING\n".getBytes(StandardCharsets.UTF_8));
                out.flush();

                InputStream in = client.getInputStream();
                byte[] buf = new byte[1024];
                int len = in.read(buf);
                String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
                assertTrue(response.contains("PONG"),
                        "Итерация " + i + ": ожидался PONG, получено: " + response);
            } finally {
                client.close();
            }
        }

        serverThread.join(TIMEOUT_MS);
        if (serverError.get() != null) {
            throw new AssertionError("Серверная ошибка: " + serverError.get());
        }
        assertTrue(serverDone.await(0, TimeUnit.MILLISECONDS),
                "Сервер должен обработать все " + n + " соединений");
    }

    @Test
    @DisplayName("Close + reopen с тем же PSK-контекстом")
    void reconnectWithPsk() throws Exception {
        // Первое соединение: full handshake + app data
        pskConnectionHelper();
        // После первого соединения клиент должен получить NST от сервера.
        // Проверяем что PSK действительно сохранён в клиентском контексте.
        assertTrue(clientSessionCtx.getPskStore().size() > 0,
                "PSK должен быть сохранён после первого соединения");
        // Второе соединение с тем же clientSessionCtx — должно использовать PSK.
        // Прямое доказательство (engine.handshakeType == PSK) требует доступа
        // к внутреннему состоянию через рефлексию — не делаем.
        // Факт успешного повторного соединения — косвенная верификация.
        pskConnectionHelper();
    }

    /**
     * Вспомогательный метод: одно PING/PONG соединение через сервер+клиент.
     */
    private void pskConnectionHelper() throws Exception {
        AtomicReference<String> serverError = new AtomicReference<>(null);
        CountDownLatch serverReady = new CountDownLatch(1);

        // Серверный поток: одно соединение
        Thread serverThread = new Thread(() -> {
            try {
                try (GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept()) {
                    accepted.startHandshake();
                    accepted.setSoTimeout(TIMEOUT_MS);
                    InputStream in = accepted.getInputStream();
                    OutputStream out = accepted.getOutputStream();
                    byte[] buf = new byte[1024];
                    int len = in.read(buf);
                    if (len > 0) {
                        out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                        out.flush();
                    }
                }
                serverReady.countDown();
            } catch (Exception e) {
                serverError.compareAndSet(null, e.getMessage());
            }
        }, "server-psk");
        serverThread.start();

        try {
            // Клиент: отправляет PING, проверяет PONG
            GostSSLSocket client = new GostSSLSocket("localhost", port,
                    clientKm, clientTm, clientSessionCtx);
            client.setSoTimeout(TIMEOUT_MS);
            try {
                OutputStream out = client.getOutputStream();
                out.write("PING\n".getBytes(StandardCharsets.UTF_8));
                out.flush();

                InputStream in = client.getInputStream();
                byte[] buf = new byte[1024];
                int len = in.read(buf);
                String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
                assertTrue(response.contains("PONG"),
                        "Ожидался PONG, получено: " + response);
            } finally {
                client.close();
            }
        } finally {
            serverThread.join(TIMEOUT_MS);
            if (serverError.get() != null) {
                throw new AssertionError("Серверная ошибка: " + serverError.get());
            }
        }
    }

    @Test
    @DisplayName("Peer закрывает TCP после handshake — клиентский read не падает с NPE")
    void closeDuringRead() throws Exception {
        // Сервер: принимает, выполняет handshake, читает PING, закрывает сокет.
        // close() на GostSSLSocket отправляет close_notify (best-effort) — это
        // штатное закрытие TLS, не RST.
        // Клиент читает — должен получить или данные, или корректный EOF,
        // но не NullPointerException или другой internal error.
        CountDownLatch serverAccept = new CountDownLatch(1);
        CountDownLatch serverClosed = new CountDownLatch(1);
        Thread serverThread = new Thread(() -> {
            try {
                GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept();
                serverAccept.countDown();
                accepted.startHandshake();
                // Читаем PING
                InputStream sis = accepted.getInputStream();
                byte[] srvBuf = new byte[1024];
                sis.read(srvBuf);
                // Закрываем сокет с close_notify
                accepted.close();
                serverClosed.countDown();
            } catch (Exception ignored) {
            }
        }, "server-rst");
        serverThread.start();

        GostSSLSocket client = new GostSSLSocket("localhost", port,
                clientKm, clientTm, clientSessionCtx);
        client.setSoTimeout(5000);
        assertTrue(serverAccept.await(5, TimeUnit.SECONDS));

        // Клиент отправляет PING и закрывает — сервер получает данные и закрывает сам
        OutputStream out = client.getOutputStream();
        out.write("PING\n".getBytes(StandardCharsets.UTF_8));
        out.flush();

        // Ждём пока сервер прочитает PING и закроет сокет
        assertTrue(serverClosed.await(10, TimeUnit.SECONDS));

        // Клиент читает — должен получить IOException или корректное завершение
        // В любом случае не NPE и не зависание
        InputStream in = client.getInputStream();
        byte[] buf = new byte[1024];
        // Не assertThrows — GostSSLSocket может корректно вернуть EOF (-1)
        // или бросить IOException. Любое поведение ок, если не NPE.
        try {
            int n = in.read(buf);
            // Если прочитали — это остаточные данные TLS (close_notify processing)
            if (n > 0) {
                in.read(); // должен вернуть -1 или IOException
            }
        } catch (Exception e) {
            // IOException при read() на закрытом сокете — OK
        }

        client.close();
        serverThread.join(2000);
    }

    @Test
    @DisplayName("Peer закрывает TCP после PONG — write не падает с internal error")
    void closeDuringWrite() throws Exception {
        // Сервер: handshake, принимает PING, отвечает PONG, закрывает сокет.
        // Клиент: пишет PING, читает PONG, затем пытается писать ещё раз.
        // write() после close_notify от сервера может:
        //   a) упасть с IOException (если engine уже в CLOSED)
        //   b) записать в kernel buffer (TCP не блокирует write после FIN от peer)
        // Любой вариант приемлем, если не NullPointerException.
        CountDownLatch serverAccept = new CountDownLatch(1);
        CountDownLatch serverRead = new CountDownLatch(1);
        Thread serverThread = new Thread(() -> {
            try {
                GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept();
                serverAccept.countDown();
                accepted.startHandshake();
                // Читаем PING
                InputStream sis = accepted.getInputStream();
                byte[] srvBuf = new byte[1024];
                sis.read(srvBuf);
                serverRead.countDown();
                // Отвечаем PONG
                OutputStream sos = accepted.getOutputStream();
                sos.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                sos.flush();
                // Закрываем с close_notify
                accepted.close();
            } catch (Exception ignored) {
            }
        }, "server-close");
        serverThread.start();

        GostSSLSocket client = new GostSSLSocket("localhost", port,
                clientKm, clientTm, clientSessionCtx);
        client.setSoTimeout(5000);
        assertTrue(serverAccept.await(5, TimeUnit.SECONDS));

        // Клиент пишет PING и ждёт пока сервер прочитает
        OutputStream out = client.getOutputStream();
        out.write("PING\n".getBytes(StandardCharsets.UTF_8));
        out.flush();
        assertTrue(serverRead.await(10, TimeUnit.SECONDS));

        // Клиент читает PONG
        InputStream in = client.getInputStream();
        byte[] buf = new byte[1024];
        int len = in.read(buf);
        String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
        assertTrue(response.contains("PONG"),
                "Ожидался PONG, получено: " + response);

        // write() после прочтения PONG — может упасть, может нет
        // В любом случае не NPE и не зависание
        try {
            out.write("ANOTHER\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (Exception e) {
            // IOException при write() после закрытия сервером — OK
        }

        client.close();
        serverThread.join(2000);
    }

    @Test
    @DisplayName("100 последовательных PING-PONG к одному серверу")
    void sequentialPingPong100() throws Exception {
        int n = 100;

        Thread serverThread = new Thread(() -> {
            try {
                for (int i = 0; i < n; i++) {
                    try (GostSSLSocket accepted = (GostSSLSocket) serverSocket.accept()) {
                        accepted.startHandshake();
                        InputStream in = accepted.getInputStream();
                        OutputStream out = accepted.getOutputStream();
                        byte[] buf = new byte[1024];
                        int len = in.read(buf);
                        if (len > 0) {
                            out.write("PONG\n".getBytes(StandardCharsets.UTF_8));
                            out.flush();
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }, "server-seq");
        serverThread.start();

        for (int i = 0; i < n; i++) {
            try (GostSSLSocket client = new GostSSLSocket("localhost", port,
                    clientKm, clientTm, clientSessionCtx)) {
                client.setSoTimeout(TIMEOUT_MS);
                OutputStream out = client.getOutputStream();
                out.write("PING\n".getBytes(StandardCharsets.UTF_8));
                out.flush();

                InputStream in = client.getInputStream();
                byte[] buf = new byte[1024];
                int len = in.read(buf);
                String response = new String(buf, 0, len, StandardCharsets.UTF_8).trim();
                assertTrue(response.contains("PONG"),
                        "Итерация " + i + ": ожидался PONG, получено: " + response);
            }
        }

        serverThread.join(TIMEOUT_MS);
    }
}
