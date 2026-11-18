package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HttpsURLConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * TCP loopback-тесты: GostSSLSocket <-> GostSSLSocket.
 */
@DisplayName("GostSSLSocket: обмен данными по TCP")
class GostSSLSocketTcpTest {

    private static final int TEST_ITERATIONS = 3;
    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;
    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostCertificate caCert;

    private GostSSLServerSocket serverSocket;
    private Thread serverThread;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        rootCa = PkixCertTestHelper.createRootCA(params);
        caCert = rootCa.cert;

        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        clientCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    @AfterEach
    void tearDown() {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (Exception ignored) {
            }
        }
        if (serverThread != null) {
            serverThread.interrupt();
            try {
                serverThread.join(2000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private GostX509KeyManager createServerKeyManager() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        return km;
    }

    private GostX509KeyManager createClientKeyManager() throws Exception {
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCert.cert, rootCa.cert)),
                clientCert.priv);
        return km;
    }

    private GostSSLSessionContext createSessionContext() {
        return new GostSSLSessionContext(cs);
    }

    private GostX509TrustManager createTrustManager(GostCertificate caCert) {
        return caCert == null
                ? GostX509TrustManager.insecureTrustAll()
                : GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(caCert));
    }

    // ========================================================================
    // 1. Basic TCP loopback
    // ========================================================================

    /** Режим соединения: сертификат клиента и явное начало рукопожатия. */
    private enum LoopbackMode {
        PLAIN(false, true),
        MUTUAL_AUTH(true, true),
        AUTO_HANDSHAKE(false, false);

        final boolean clientCertificate;
        final boolean explicitHandshake;

        LoopbackMode(boolean clientCertificate, boolean explicitHandshake) {
            this.clientCertificate = clientCertificate;
            this.explicitHandshake = explicitHandshake;
        }
    }

    @ParameterizedTest
    @EnumSource(LoopbackMode.class)
    @DisplayName(
            "TCP loopback: обмен данными в обе стороны и закрытие; без и с сертификатом клиента,"
                    + " рукопожатие по startHandshake() и по первому write()")
    void testTcpLoopback(LoopbackMode mode) throws Exception {
        GostCertificate anchor = mode.clientCertificate ? caCert : null;
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(anchor), createSessionContext());
        if (mode.clientCertificate) {
            srv.setNeedClientAuth(true);
        }
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
                            try {
                                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                                if (mode.explicitHandshake) {
                                    ssl.startHandshake();
                                }
                                // без явного startHandshake() рукопожатие запускает read()
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
                        },
                        "server-" + mode);

        serverThread.start();

        GostX509KeyManager ckm =
                mode.clientCertificate ? createClientKeyManager() : new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(anchor),
                        createSessionContext());
        client.setSoTimeout(10000);

        if (mode.explicitHandshake) {
            client.startHandshake();
        }
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

    @Test
    @DisplayName("close() без close_notify пира закрывает inbound (зачистка ключей)")
    void testCloseWipesKeysBeforePeerCloseNotify() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        // Сервер держит соединение открытым до сигнала — так client.close()
        // гарантированно происходит ДО получения close_notify от пира.
        CountDownLatch clientClosed = new CountDownLatch(1);
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
                            try {
                                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                                ssl.startHandshake();
                                InputStream in = ssl.getInputStream();
                                byte[] buf = new byte[1024];
                                int n = in.read(buf);
                                assertEquals("hello", new String(buf, 0, n));
                                clientClosed.await(5, TimeUnit.SECONDS);
                                ssl.close();
                            } catch (Exception e) {
                                serverError.set(e);
                            } finally {
                                serverDone.countDown();
                            }
                        },
                        "server-p2-3");
        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
        client.setSoTimeout(10000);
        client.startHandshake();
        OutputStream cout = client.getOutputStream();
        cout.write("hello".getBytes());
        cout.flush();

        client.close();

        // closeInbound() отработал в close() -> destroyHandshakeEngine() зачистил ключи.
        assertTrue(
                client.engine().isInboundDone(),
                "inbound должен быть закрыт после close() даже без close_notify пира");

        clientClosed.countDown();
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
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        int dataSize = 100_000;
        byte[] sentData = new byte[dataSize];
        Arrays.fill(sentData, (byte) 0xAB);

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
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
                        },
                        "server-large");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
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
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        int port = srv.getLocalPort();
        CopyOnWriteArrayList<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int i = 0; i < TEST_ITERATIONS; i++) {
            String expectedMsg = "conn-" + i;

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            CountDownLatch serverDone = new CountDownLatch(1);

            Thread st =
                    new Thread(
                            () -> {
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
                            },
                            "server-multi-" + i);

            st.start();

            GostX509KeyManager ckm = new GostX509KeyManager();
            GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            port,
                            ckm,
                            createTrustManager(null),
                            createSessionContext());
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
    // 6. HttpsURLConnection-style: layered socket
    // ========================================================================

    @Test
    @DisplayName(
            "Многоуровневый сокет: createSocket(Socket, host, port, autoClose) как HttpsURLConnection")
    void testLayeredSocket() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
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
                        },
                        "server-layered");

        serverThread.start();

        // Сначала plain TCP-сокет (как через прокси), потом оборачиваем
        Socket plain = new Socket("localhost", srv.getLocalPort());
        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket ssl =
                new GostSSLSocket(
                        plain,
                        "localhost",
                        srv.getLocalPort(),
                        true,
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
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
    // 8. Half-close unsupported
    // ========================================================================

    @Test
    @DisplayName("Полузакрытие: shutdownInput/Output -> UnsupportedOperationException")
    void testHalfCloseUnsupported() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
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
                        },
                        "server-halfclose");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
        client.setSoTimeout(5000);
        client.startHandshake();

        assertThrows(UnsupportedOperationException.class, client::shutdownInput);
        assertThrows(UnsupportedOperationException.class, client::shutdownOutput);

        client.close();
        serverDone.await(3, TimeUnit.SECONDS);
    }

    // ========================================================================
    // 10. HandshakeCompletedListener
    // ========================================================================

    @Test
    @DisplayName("HandshakeCompletedListener: слушатель вызывается после рукопожатия")
    void testHandshakeCompletedListener() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
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
                        },
                        "server-listener");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
        client.setSoTimeout(5000);

        CountDownLatch listenerCalled = new CountDownLatch(1);
        client.addHandshakeCompletedListener(
                event -> {
                    assertNotNull(event.getSession());
                    listenerCalled.countDown();
                });

        client.startHandshake();
        assertTrue(
                listenerCalled.await(3, TimeUnit.SECONDS),
                "HandshakeCompletedListener должен быть вызван");

        client.close();
        serverDone.await(3, TimeUnit.SECONDS);
    }

    // ========================================================================
    // 11. Concurrent streams
    // ========================================================================

    @Test
    @DisplayName("Параллельное чтение/запись: разные потоки читают и пишут")
    void testConcurrentReadWrite() throws Exception {
        int dataSize = 50_000;
        byte[] sentData = new byte[dataSize];
        Arrays.fill(sentData, (byte) 0xCD);

        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        // Сервер: echo-сервер, читает и пишет обратно
        serverThread =
                new Thread(
                        () -> {
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
                        },
                        "server-concurrent");

        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
        client.setSoTimeout(10000);
        client.startHandshake();

        // Пишем в одном потоке, читаем в другом
        AtomicReference<Throwable> writeError = new AtomicReference<>();
        CountDownLatch writeDone = new CountDownLatch(1);

        Thread writer =
                new Thread(
                        () -> {
                            try {
                                OutputStream out = client.getOutputStream();
                                out.write(sentData);
                                out.flush();
                            } catch (Exception e) {
                                writeError.set(e);
                            } finally {
                                writeDone.countDown();
                            }
                        },
                        "writer");

        ByteArrayOutputStream readerBuf = new ByteArrayOutputStream();
        Thread reader =
                new Thread(
                        () -> {
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
                        },
                        "reader");

        writer.start();
        reader.start();

        writer.join(15000);
        reader.join(10000);

        if (writeError.get() != null) throw new RuntimeException(writeError.get());

        client.close();
        serverDone.await(5, TimeUnit.SECONDS);

        assertArrayEquals(
                sentData,
                readerBuf.toByteArray(),
                "Несовпадение данных при параллельном чтении/записи: отправлено="
                        + sentData.length
                        + " получено="
                        + readerBuf.size());
    }

    // ========================================================================
    // 12. Factory integration: SSLContext.getSocketFactory()
    // ========================================================================

    @Test
    @DisplayName("SSLContext factory: GostSSLSocketFactory через SSLContext.getSocketFactory()")
    void testFactoryFromContext() throws Exception {
        javax.net.ssl.SSLContext ctx =
                javax.net.ssl.SSLContext.getInstance(
                        GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
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
    @DisplayName("Peer закрыл TCP после рукопожатия без close_notify -> read() возвращает -1")
    void testClosePeerFirstPostHandshake() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        serverSocket = srv;

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        CountDownLatch clientClosed = new CountDownLatch(1);

        serverThread =
                new Thread(
                        () -> {
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
                                assertEquals(
                                        -1, n, "read() после закрытия пиром TCP должен вернуть -1");
                                ssl.close();
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "server-close-first");
        serverThread.start();

        GostX509KeyManager ckm = new GostX509KeyManager();
        GostSSLSocket client =
                new GostSSLSocket(
                        "localhost",
                        srv.getLocalPort(),
                        ckm,
                        createTrustManager(null),
                        createSessionContext());
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
    // 16. HttpsURLConnection — реальный JDK HTTP-клиент через GOST SSL
    // ========================================================================

    @Test
    @DisplayName("HttpsURLConnection: запрос через эмбеддед HTTPS-сервер на GostSSLServerSocket")
    void testHttpsUrlConnection() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), createSessionContext());
        int port = srv.getLocalPort();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        // эмбеддед HTTP/1.1 сервер для проверки полного цикла HttpsURLConnection
        Thread st =
                new Thread(
                        () -> {
                            try {
                                GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                                ssl.startHandshake();

                                // Читаем HTTP-запрос (неполный — только для проверки, что
                                // соединение работает)
                                InputStream in = ssl.getInputStream();
                                BufferedReader reader =
                                        new BufferedReader(new InputStreamReader(in, "UTF-8"));
                                String requestLine = reader.readLine();
                                assertNotNull(requestLine, "Должен быть получен HTTP-запрос");
                                assertTrue(
                                        requestLine.startsWith("GET /"),
                                        "Неожиданный запрос: " + requestLine);

                                // Пропускаем заголовки до пустой строки
                                String header;
                                while ((header = reader.readLine()) != null && !header.isEmpty()) {}

                                // минимальный корректный HTTP/1.1 ответ
                                String body = "Hello World";
                                OutputStream out = ssl.getOutputStream();
                                String response =
                                        "HTTP/1.1 200 OK\r\n"
                                                + "Content-Length: "
                                                + body.length()
                                                + "\r\n"
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
                        },
                        "https-server");
        st.start();

        // SSLContext с нашим TrustManager — для валидации серверного сертификата
        javax.net.ssl.SSLContext ctx =
                javax.net.ssl.SSLContext.getInstance(
                        GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        ctx.init(null, new javax.net.ssl.TrustManager[] {createTrustManager(caCert)}, null);

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

    // ========================================================================
    // wasResumed()
    // ========================================================================

    @Test
    @DisplayName(
            "wasResumed(): до рукопожатия исключение, второе соединение возобновлено на обеих сторонах")
    void testWasResumedOnSecondConnection() throws Exception {
        GostX509KeyManager skm = createServerKeyManager();
        GostSSLSessionContext serverSessions = createSessionContext();
        GostSSLSessionContext clientSessions = createSessionContext();
        GostSSLServerSocket srv =
                new GostSSLServerSocket(0, skm, createTrustManager(null), serverSessions);
        serverSocket = srv;

        List<Boolean> serverResumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        serverThread =
                new Thread(
                        () -> {
                            try {
                                for (int i = 0; i < 2; i++) {
                                    GostSSLSocket ssl = (GostSSLSocket) srv.accept();
                                    ssl.startHandshake();
                                    byte[] buf = new byte[16];
                                    ssl.getInputStream().read(buf);
                                    ssl.getOutputStream().write("world".getBytes());
                                    ssl.getOutputStream().flush();
                                    serverResumed.add(ssl.wasResumed());
                                    ssl.close();
                                }
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "server-resumption");
        serverThread.start();

        List<Boolean> clientResumed = new ArrayList<>();
        // Тикет привязан к экземпляру менеджера доверия: оба соединения используют один
        GostX509TrustManager clientTrust = createTrustManager(caCert);
        for (int i = 0; i < 2; i++) {
            GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            srv.getLocalPort(),
                            new GostX509KeyManager(),
                            clientTrust,
                            clientSessions);
            client.setSoTimeout(10000);
            assertThrows(
                    IllegalStateException.class,
                    client::wasResumed,
                    "итог неизвестен до завершения рукопожатия");
            client.startHandshake();
            client.getOutputStream().write("hello".getBytes());
            client.getOutputStream().flush();
            // чтение заодно принимает NewSessionTicket сервера
            client.getInputStream().read(new byte[16]);
            clientResumed.add(client.wasResumed());
            client.close();
            assertEquals(
                    clientResumed.get(i),
                    client.wasResumed(),
                    "значение не должно меняться после close()");
        }

        serverThread.join(5000);
        assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
        assertEquals(List.of(false, true), clientResumed, "клиент: полное, затем возобновление");
        assertEquals(List.of(false, true), serverResumed, "сервер: полное, затем возобновление");
    }
}
