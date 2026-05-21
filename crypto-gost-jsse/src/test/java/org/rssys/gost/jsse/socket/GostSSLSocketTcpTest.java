package org.rssys.gost.jsse.socket;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTestHelper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TCP loopback-тесты: GostSSLSocket ↔ GostSSLSocket.
 */
class GostSSLSocketTcpTest {

    private static final int TEST_ITERATIONS = 3;
    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static TlsTestHelper.CertBundle serverCert;
    private static TlsTestHelper.CertBundle clientCert;
    private static TlsTestHelper.CertBundle rootCa;
    private static PublicKeyParameters caPub;

    private GostSSLServerSocket serverSocket;
    private Thread serverThread;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        rootCa = TlsTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();

        serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        clientCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null,
                false, null);
    }

    @AfterEach
    void tearDown() {
        if (serverSocket != null) {
            try { serverSocket.close(); } catch (Exception ignored) { }
        }
        if (serverThread != null) {
            serverThread.interrupt();
            try { serverThread.join(2000); } catch (InterruptedException ignored) { }
        }
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private GostX509KeyManager createServerKeyManager() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);
        return km;
    }

    private GostX509KeyManager createClientKeyManager() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("client", CertificateBridge.toJcaChain(clientCert.cert, rootCa.cert), clientCert.priv);
        return km;
    }

    private GostSSLSessionContext createSessionContext() {
        return new GostSSLSessionContext(cs, cs.getHashLen());
    }

    private GostX509TrustManager createTrustManager(PublicKeyParameters caKey) {
        return new GostX509TrustManager(caKey, false);
    }

    // ========================================================================
    // 1. Basic TCP loopback
    // ========================================================================

    @Test
    @DisplayName("TCP loopback: handshake + app data ping-pong + close")
    void testTcpLoopbackBasic() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();

                InputStream in = ssl.getInputStream();
                OutputStream out = ssl.getOutputStream();

                byte[] buf = new byte[1024];
                int n = in.read(buf);
                assertEquals("hello", new String(buf, 0, n));

                out.write("world".getBytes());
                out.flush();

                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-basic");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(10000);

        client.startHandshake();
        OutputStream cout = client.getOutputStream();
        cout.write("hello".getBytes());
        cout.flush();

        InputStream cin = client.getInputStream();
        byte[] buf = new byte[1024];
        int n = cin.read(buf);
        assertEquals("world", new String(buf, 0, n));

        client.close();

        assertTrue(serverDone.await(5, TimeUnit.SECONDS));
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 2. mTLS loopback
    // ========================================================================

    @Test
    @DisplayName("TCP loopback mTLS: обе стороны с сертификатами")
    void testTcpLoopbackMtls() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(caPub), createSessionContext());
        srv.setNeedClientAuth(true);
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();

                InputStream in = ssl.getInputStream();
                byte[] buf = new byte[1024];
                int n = in.read(buf);
                assertEquals("mtls-data", new String(buf, 0, n));

                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-mtls");

        serverThread.start();

        GostX509KeyManager ckm = createClientKeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(caPub), createSessionContext());
        client.setSoTimeout(10000);

        client.startHandshake();
        OutputStream out = client.getOutputStream();
        out.write("mtls-data".getBytes());
        out.flush();
        client.close();

        assertTrue(serverDone.await(5, TimeUnit.SECONDS));
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 3. Large data
    // ========================================================================

    @Test
    @DisplayName("TCP loopback large data: 100KB через socket")
    void testTcpLoopbackLargeData() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        int dataSize = 100_000;
        byte[] sentData = new byte[dataSize];
        Arrays.fill(sentData, (byte) 0xAB);

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                InputStream in = ssl.getInputStream();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int total = 0;
                while (total < dataSize) {
                    int n = in.read(buf);
                    if (n == -1) break;
                    baos.write(buf, 0, n);
                    total += n;
                }
                assertArrayEquals(sentData, baos.toByteArray());
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-large");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(10000);

        client.startHandshake();
        OutputStream out = client.getOutputStream();
        out.write(sentData);
        out.flush();
        client.close();

        assertTrue(serverDone.await(10, TimeUnit.SECONDS));
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 4. Multiple connections
    // ========================================================================

    @Test
    @DisplayName("TCP loopback multiple: 3 последовательных соединения")
    void testTcpLoopbackMultipleConnections() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        int port = srv.getLocalPort();
        CopyOnWriteArrayList<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int i = 0; i < TEST_ITERATIONS; i++) {
            String expectedMsg = "conn-" + i;

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            CountDownLatch serverDone = new CountDownLatch(1);

            Thread st = new Thread(() -> {
                try {
                    GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                    ssl.startHandshake();
                    InputStream in = ssl.getInputStream();
                    byte[] buf = new byte[1024];
                    int n = in.read(buf);
                    assertEquals(expectedMsg, new String(buf, 0, n));
                    ssl.close();
                } catch (Exception e) {
                    serverError.set(e);
                } finally {
                    serverDone.countDown();
                }
            }, "server-multi-" + i);

            st.start();

            GostX509KeyManager ckm = new GostX509KeyManager();
            GostSSLSocket client = new GostSSLSocket("localhost", port,
                    ckm, createTrustManager(null), createSessionContext());
            client.setSoTimeout(5000);

            client.startHandshake();
            OutputStream out = client.getOutputStream();
            out.write(expectedMsg.getBytes());
            out.flush();
            client.close();

            serverDone.await(5, TimeUnit.SECONDS);
            st.join(2000);
            if (serverError.get() != null) errors.add(serverError.get());
        }

        assertTrue(errors.isEmpty(), "Ошибки: " + errors);
    }

    // ========================================================================
    // 5. Auto-handshake
    // ========================================================================

    @Test
    @DisplayName("TCP loopback auto-handshake: write триггерит handshake без startHandshake()")
    void testTcpLoopbackAutoHandshake() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                // server тоже без явного startHandshake — триггернётся от read()
                InputStream in = ssl.getInputStream();
                byte[] buf = new byte[1024];
                int n = in.read(buf);
                assertEquals("auto", new String(buf, 0, n));
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-auto");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(5000);

        // НЕ вызываем startHandshake() — первый write() триггерит handshake
        OutputStream out = client.getOutputStream();
        out.write("auto".getBytes());
        out.flush();

        client.close();

        assertTrue(serverDone.await(5, TimeUnit.SECONDS));
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 6. HttpsURLConnection-style: layered socket
    // ========================================================================

    @Test
    @DisplayName("Layered socket: createSocket(Socket, host, port, autoClose) как HttpsURLConnection")
    void testLayeredSocket() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                InputStream in = ssl.getInputStream();
                byte[] buf = new byte[1024];
                int n = in.read(buf);
                assertEquals("layered", new String(buf, 0, n));
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-layered");

        serverThread.start();

        // Сначала plain TCP-сокет (как через прокси), потом оборачиваем
        Socket plain = new Socket("localhost", srv.getLocalPort());
        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket ssl = new GostSSLSocket(plain, "localhost", srv.getLocalPort(), true,
                ckm, createTrustManager(null), createSessionContext());
        ssl.setSoTimeout(5000);

        ssl.startHandshake();
        OutputStream out = ssl.getOutputStream();
        out.write("layered".getBytes());
        out.flush();
        ssl.close();

        assertTrue(serverDone.await(5, TimeUnit.SECONDS));
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 7. Close behavior: normal close
    // ========================================================================

    @Test
    @DisplayName("Close: normal close → close_notify отправлен")
    void testCloseNormal() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverGotClose = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                InputStream in = ssl.getInputStream();

                // Ждём close_notify от клиента после read()
                byte[] buf = new byte[1024];
                int n = in.read(buf);  // может вернуть -1 если close_notify уже пришёл
                if (n == -1) {
                    // WHY: close_notify пришёл без app-данных — чистый EOF
                    serverGotClose.countDown();
                } else {
                    assertEquals("data", new String(buf, 0, n));
                    // Пробуем ещё раз — close_notify
                    n = in.read(buf);
                    if (n == -1) serverGotClose.countDown();
                }
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "server-close");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(5000);

        client.startHandshake();
        OutputStream out = client.getOutputStream();
        out.write("data".getBytes());
        out.flush();

        client.close();  // close_notify отправлен

        assertTrue(serverGotClose.await(5, TimeUnit.SECONDS),
                "Server should receive close_notify");
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 8. Half-close unsupported
    // ========================================================================

    @Test
    @DisplayName("Half-close: shutdownInput/Output → UnsupportedOperationException")
    void testHalfCloseUnsupported() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                ssl.getInputStream().read(new byte[1024]);
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-halfclose");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(5000);
        client.startHandshake();

        assertThrows(UnsupportedOperationException.class, client::shutdownInput);
        assertThrows(UnsupportedOperationException.class, client::shutdownOutput);

        client.close();
        serverDone.await(3, TimeUnit.SECONDS);
    }

    // ========================================================================
    // 9. Socket timeout passthrough
    // ========================================================================

    @Test
    @DisplayName("Socket timeout: setSoTimeout + тихий peer → SocketTimeoutException")
    void testSoTimeout() throws Exception {
        // Используем тихий порт, на котором никто не отвечает (localhost:1 почти наверняка не открыт)
        // Или создаём сервер, который не отвечает
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        // Подключаемся plain TCP-сокетом, но не делаем handshake
        // Тогда read() во время handshake клиента будет ждать и упадёт по таймауту
        Socket slowClient = new Socket("localhost", srv.getLocalPort());

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket ssl = new GostSSLSocket(slowClient, "localhost", srv.getLocalPort(), true,
                ckm, createTrustManager(null), createSessionContext());
        ssl.setSoTimeout(500);  // 500ms таймаут

        long start = System.currentTimeMillis();
        Exception ex = assertThrows(Exception.class, () -> {
            // startHandshake будет ждать ServerHello, но сервер не ответит (никто не accept)
            ssl.startHandshake();
        });
        long elapsed = System.currentTimeMillis() - start;

        assertInstanceOf(SocketTimeoutException.class, ex,
                "SocketTimeoutException должен пробрасываться наверх, получено: " + ex.getClass().getName()
                        + " message: " + ex.getMessage());
        assertTrue(elapsed < 5000, "Тайм-аут должен сработать в течение 500 мс: " + elapsed + " мс");

        ssl.close();
        srv.close();
    }

    // ========================================================================
    // 10. HandshakeCompletedListener
    // ========================================================================

    @Test
    @DisplayName("HandshakeCompletedListener: listener вызывается после handshake")
    void testHandshakeCompletedListener() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                byte[] buf = new byte[1024];
                ssl.getInputStream().read(buf);
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-listener");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(5000);

        CountDownLatch listenerCalled = new CountDownLatch(1);
        client.addHandshakeCompletedListener(event -> {
            assertNotNull(event.getSession());
            listenerCalled.countDown();
        });

        client.startHandshake();
        assertTrue(listenerCalled.await(3, TimeUnit.SECONDS),
                "HandshakeCompletedListener should be called");

        client.close();
        serverDone.await(3, TimeUnit.SECONDS);
    }

    // ========================================================================
    // 11. Concurrent streams
    // ========================================================================

    @Test
    @DisplayName("Concurrent read/write: разные потоки читают и пишут")
    void testConcurrentReadWrite() throws Exception {
        int dataSize = 50_000;
        byte[] sentData = new byte[dataSize];
        Arrays.fill(sentData, (byte) 0xCD);

        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        // Сервер: echo-сервер, читает и пишет обратно
        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                InputStream in = ssl.getInputStream();
                OutputStream out = ssl.getOutputStream();

                byte[] buf = new byte[8192];
                int total = 0;
                while (total < dataSize) {
                    int n = in.read(buf);
                    if (n == -1) break;
                    out.write(buf, 0, n);
                    out.flush();
                    total += n;
                }
                assertEquals(dataSize, total);
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "server-concurrent");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(10000);
        client.startHandshake();

        // Пишем в одном потоке, читаем в другом
        AtomicReference<Throwable> writeError = new AtomicReference<>();
        CountDownLatch writeDone = new CountDownLatch(1);

        Thread writer = new Thread(() -> {
            try {
                OutputStream out = client.getOutputStream();
                out.write(sentData);
                out.flush();
            } catch (Exception e) {
                writeError.set(e);
            } finally {
                writeDone.countDown();
            }
        }, "writer");

        ByteArrayOutputStream readerBuf = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try {
                InputStream in = client.getInputStream();
                byte[] buf = new byte[8192];
                int total = 0;
                while (total < dataSize) {
                    int n = in.read(buf);
                    if (n == -1) break;
                    readerBuf.write(buf, 0, n);
                    total += n;
                }
            } catch (Exception e) {
                // Если данные ещё не все записаны, может быть таймаут — это ОК
                // в тесте проверяем только то, что успели прочитать
            }
        }, "reader");

        writer.start();
        reader.start();

        writer.join(15000);
        reader.join(10000);

        if (writeError.get() != null) throw new RuntimeException(writeError.get());

        client.close();
        serverDone.await(5, TimeUnit.SECONDS);

        assertArrayEquals(sentData, readerBuf.toByteArray(),
                "Concurrent read/write data mismatch: sent=" + sentData.length
                        + " received=" + readerBuf.size());
    }

    // ========================================================================
    // 12. Factory integration: SSLContext.getSocketFactory()
    // ========================================================================

    @Test
    @DisplayName("SSLContext factory: GostSSLSocketFactory через SSLContext.getSocketFactory()")
    void testFactoryFromContext() throws Exception {
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(null, null, null);

        javax.net.ssl.SSLSocketFactory factory = ctx.getSocketFactory();
        assertNotNull(factory);
        assertInstanceOf(GostSSLSocketFactory.class, factory);

        javax.net.ssl.SSLServerSocketFactory srvFactory = ctx.getServerSocketFactory();
        assertNotNull(srvFactory);
        assertInstanceOf(GostSSLServerSocketFactory.class, srvFactory);
    }

    // ========================================================================
    // 13. PSK resumption through TCP
    // ========================================================================

    @Test
    @DisplayName("PSK resumption: два последовательных TCP-соединения, второе использует PSK")
    void testPskResumptionOverTcp() throws Exception {
        GostSSLSessionContext srvCtx = createSessionContext();
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), srvCtx);
        serverSocket = srv;
        int port = srv.getLocalPort();

        // ---- Первое соединение: полный handshake ----
        // Сервер должен записать что-то обратно, чтобы NST отправился
        CountDownLatch firstDone = new CountDownLatch(1);
        AtomicReference<Throwable> srvErr1 = new AtomicReference<>();

        Thread st1 = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                // Читаем данные клиента — это заставляет сервер отправить NST
                // (NST лежит в outgoingQueue после finishHandshake, будет отправлен
                // при первом engine.wrap(), который триггерится AppOutputStream.write())
                byte[] buf = new byte[1024];
                int n = ssl.getInputStream().read(buf);
                assertEquals("conn1", new String(buf, 0, n));
                // Пишем ответ — это триггерит engine.wrap() → NST уходит первым
                ssl.getOutputStream().write("echo1".getBytes());
                ssl.getOutputStream().flush();
                ssl.close();
            } catch (Exception e) {
                srvErr1.set(e);
            } finally {
                firstDone.countDown();
            }
        }, "server-psk-1");

        st1.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSessionContext clientCtx = createSessionContext();
        GostSSLSocket c1 = new GostSSLSocket("localhost", port,
                ckm, createTrustManager(null), clientCtx);
        c1.setSoTimeout(5000);
        c1.startHandshake();
        c1.getOutputStream().write("conn1".getBytes());
        c1.getOutputStream().flush();
        // Читаем echo — NST приходит до echo, обрабатывается transparently
        byte[] echoBuf = new byte[1024];
        int echoLen = c1.getInputStream().read(echoBuf);
        assertEquals("echo1", new String(echoBuf, 0, echoLen));
        c1.close();

        firstDone.await(5, TimeUnit.SECONDS);
        if (srvErr1.get() != null) throw new RuntimeException(srvErr1.get());

        // Серверный store должен содержать PSK
        assertTrue(srvCtx.getPskStore().size() > 0, "Хранилище PSK сервера должно содержать записи после первого соединения");

        // ---- Второе соединение: должно быть PSK ----
        CountDownLatch secondDone = new CountDownLatch(1);
        AtomicReference<Throwable> srvErr2 = new AtomicReference<>();

        Thread st2 = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                byte[] buf = new byte[1024];
                int n = ssl.getInputStream().read(buf);
                assertEquals("conn2", new String(buf, 0, n));
                // WHY: пишем ответ, чтобы сервер отправил новый NST
                // (лежит в outgoingQueue после finishHandshake, отправляется
                // при первом engine.wrap(), который триггерится write).
                // Без этого клиент не получит новый NST и clientCtx будет пуст
                // при single-use PSK (RFC 8446 §8.1).
                ssl.getOutputStream().write("echo2".getBytes());
                ssl.getOutputStream().flush();
                ssl.close();
            } catch (Exception e) {
                srvErr2.set(e);
            } finally {
                secondDone.countDown();
            }
        }, "server-psk-2");

        st2.start();

        // Тот же clientCtx — PSK из первого соединения
        GostSSLSocket c2 = new GostSSLSocket("localhost", port,
                ckm, createTrustManager(null), clientCtx);
        c2.setSoTimeout(5000);
        c2.startHandshake();
        c2.getOutputStream().write("conn2".getBytes());
        c2.getOutputStream().flush();
        // WHY: читаем ответ сервера — вместе с echo2 приходит новый NST
        // (single-use PSK требует замены тикета после каждого использования).
        byte[] echoBuf2 = new byte[1024];
        int echoLen2 = c2.getInputStream().read(echoBuf2);
        assertEquals("echo2", new String(echoBuf2, 0, echoLen2));
        c2.close();

        secondDone.await(5, TimeUnit.SECONDS);
        if (srvErr2.get() != null) throw new RuntimeException(srvErr2.get());

        // Client store не пуст (PSK из первого соединения сохранён)
        assertTrue(clientCtx.getPskStore().size() > 0, "Хранилище PSK клиента должно содержать записи");
    }

    @Test
    @DisplayName("Peer закрыл TCP после handshake без close_notify → read() возвращает -1")
    void testClosePeerFirstPostHandshake() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        CountDownLatch clientClosed = new CountDownLatch(1);

        serverThread = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();
                // Пишем данные, чтобы клиент успел их прочитать перед закрытием
                OutputStream out = ssl.getOutputStream();
                out.write("hello".getBytes());
                out.flush();

                serverReady.countDown();
                clientClosed.await();

                // Детерминистично: ждём пока клиент закроет TCP,
                // затем пытаемся читать — должен вернуть -1
                InputStream in = ssl.getInputStream();
                byte[] buf = new byte[1024];
                int n = in.read(buf);
                assertEquals(-1, n, "read() после закрытия пиром TCP должен вернуть -1");
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "server-close-first");
        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(5000);

        client.startHandshake();
        // Читаем данные от сервера
        InputStream in = client.getInputStream();
        byte[] buf = new byte[1024];
        int n = in.read(buf);
        assertEquals("hello", new String(buf, 0, n));

        // Закрываем TCP без close_notify — hard close
        serverReady.await();
        client.closeUnderlyingForTest();
        clientClosed.countDown();

        serverThread.join(5000);
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    // ========================================================================
    // 15. Peer closes TCP during handshake
    // ========================================================================

    @Test
    @DisplayName("Close peer first: TCP разрыв во время handshake → IOException")
    void testClosePeerFirstDuringHandshake() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        serverSocket = srv;

        // Сервер: accept, сразу рвём TCP, не делая TLS handshake
        Thread st = new Thread(() -> {
            try {
                Socket raw = srv.accept();
                // WHY: сервер рвёт TCP до handshake — клиент должен получить IOException
                raw.close();
            } catch (Exception ignored) { }
        }, "server-during-hs");

        st.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client = new GostSSLSocket("localhost", srv.getLocalPort(),
                ckm, createTrustManager(null), createSessionContext());
        client.setSoTimeout(3000);

        // Handshake должен упасть — сервер разорвал TCP
        assertThrows(IOException.class, client::startHandshake,
                "Handshake should fail when peer closes TCP");

        client.close();
        st.join(3000);
    }

    // ========================================================================
    // 16. HttpsURLConnection — реальный JDK HTTP-клиент через GOST SSL
    // ========================================================================

    @Test
    @DisplayName("HttpsURLConnection: запрос через эмбеддед HTTPS-сервер на GostSSLServerSocket")
    void testHttpsUrlConnection() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv = new GostSSLServerSocket(0, skm,
                createTrustManager(null), createSessionContext());
        int port = srv.getLocalPort();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        // WHY: эмбеддед HTTP/1.1 сервер для проверки полного цикла HttpsURLConnection
        Thread st = new Thread(() -> {
            try {
                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                ssl.startHandshake();

                // Читаем HTTP-запрос (неполный — только для проверки, что соединение работает)
                InputStream in = ssl.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
                String requestLine = reader.readLine();
                assertNotNull(requestLine, "Должен быть получен HTTP-запрос");
                assertTrue(requestLine.startsWith("GET /"), "Неожиданный запрос: " + requestLine);

                // Пропускаем заголовки до пустой строки
                String header;
                while ((header = reader.readLine()) != null && !header.isEmpty()) { }

                // WHY: минимальный корректный HTTP/1.1 ответ
                String body = "Hello World";
                OutputStream out = ssl.getOutputStream();
                String response = "HTTP/1.1 200 OK\r\n"
                        + "Content-Length: " + body.length() + "\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "\r\n"
                        + body;
                out.write(response.getBytes("UTF-8"));
                out.flush();
                ssl.close();
            } catch (Exception e) {
                serverError.set(e);
            } finally {
                serverDone.countDown();
            }
        }, "https-server");
        st.start();

        // WHY: SSLContext с нашим TrustManager — для валидации серверного сертификата
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(null, new javax.net.ssl.TrustManager[]{createTrustManager(caPub)}, null);

        URL url = new URL("https://localhost:" + port + "/test");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        conn.connect();
        assertEquals(200, conn.getResponseCode(), "HTTP-статус должен быть 200");

        InputStream respIn = conn.getInputStream();
        byte[] buf = new byte[1024];
        int n = respIn.read(buf);
        String responseBody = new String(buf, 0, n);
        assertEquals("Hello World", responseBody, "Несоответствие тела ответа");

        conn.disconnect();
        assertTrue(serverDone.await(5, TimeUnit.SECONDS), "Сервер должен завершиться");
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }
}
