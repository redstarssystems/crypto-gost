package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Приёмный предел max_fragment_length (RFC 6066 §4) на настоящем сокете: серверная сторона -
 * {@link GostSSLSocket}, полученный из {@link GostSSLServerSocket#accept()}, поверх TCP.
 *
 * <p>Нарушителем служит клиентский {@link GostSSLEngine} со снятой нарезкой по лимиту: AEAD не даёт
 * изменить запись на уровне сокета, поэтому запись больше лимита должен собрать сам отправитель.
 * Сокетный путь проверяется отдельно от движка: именно на нём приёмный лимит однажды терялся.
 */
@DisplayName("GostSSLSocket: приёмный лимит max_fragment_length")
class GostSSLSocketReceiveFragmentLimitTest {

    private static final int OVERSIZED_PAYLOAD = 2000;
    private static final int TIMEOUT_MS = 10_000;

    private static TlsCiphersuite suite;
    private static PkixCertTestHelper.CertBundle serverCert;

    private GostSSLServerSocket serverSocket;
    private Thread serverThread;
    private Socket clientSocket;

    /** Итог чтения на сервере: число прочитанных байт либо исключение. */
    private final AtomicReference<Object> serverReadOutcome = new AtomicReference<>();

    private final CountDownLatch serverReadDone = new CountDownLatch(1);

    @BeforeAll
    static void setUp() {
        Security.addProvider(new RssysGostJsseProvider());
        suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    @AfterEach
    void tearDown() throws Exception {
        if (clientSocket != null) {
            clientSocket.close();
        }
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.interrupt();
            serverThread.join(2000);
        }
    }

    /**
     * Запускает сервер: принимает соединение, проводит рукопожатие и один раз читает. С
     * {@code closeAfterRead} закрывает сокет после чтения, как обычное приложение; без него
     * сокет остаётся открытым, как у приложения, которое поймало исключение и не закрыло сокет.
     */
    private void startServer(boolean closeAfterRead) throws Exception {
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(serverCert.cert)), serverCert.priv);
        serverSocket =
                new GostSSLServerSocket(
                        0,
                        keyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        new GostSSLSessionContext(suite));
        serverThread =
                new Thread(
                        () -> {
                            GostSSLSocket accepted = null;
                            try {
                                accepted = (GostSSLSocket) serverSocket.accept();
                                accepted.startHandshake();
                                byte[] buf = new byte[4 * TlsConstants.MAX_PLAINTEXT_LENGTH];
                                serverReadOutcome.set(accepted.getInputStream().read(buf));
                            } catch (Exception e) {
                                serverReadOutcome.set(e);
                            } finally {
                                serverReadDone.countDown();
                                if (closeAfterRead && accepted != null) {
                                    try {
                                        accepted.close();
                                    } catch (Exception ignored) {
                                        // закрытие после сбоя best-effort
                                    }
                                }
                            }
                        },
                        "fragment-limit-server");
        serverThread.start();
    }

    /** Подключает клиентский движок с запросом 512 и проводит рукопожатие через сокет. */
    private GostSSLEngine connectViolator() throws Exception {
        clientSocket = new Socket("localhost", serverSocket.getLocalPort());
        clientSocket.setSoTimeout(TIMEOUT_MS);
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        serverSocket.getLocalPort(),
                        true);
        engine.setClientMaxFragLenRequest(TlsConstants.MAX_FRAG_LEN_512);
        handshake(engine);
        assertEquals(
                TlsConstants.MAX_FRAG_LEN_512,
                engine.getMaxFragmentLength(),
                "предусловие: лимит 512 согласован");
        return engine;
    }

    private void handshake(GostSSLEngine engine) throws Exception {
        InputStream in = clientSocket.getInputStream();
        OutputStream out = clientSocket.getOutputStream();
        ByteBuffer net = newNetBuffer();
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        engine.beginHandshake();
        for (int step = 0; step < 200; step++) {
            SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
            if (status == SSLEngineResult.HandshakeStatus.FINISHED
                    || status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                return;
            }
            switch (status) {
                case NEED_WRAP:
                    net.clear();
                    engine.wrap(ByteBuffer.allocate(0), net);
                    net.flip();
                    send(out, net);
                    break;
                case NEED_UNWRAP:
                    byte[] record = readRecord(in);
                    assertNotNull(record, "сервер закрыл соединение во время рукопожатия");
                    app.clear();
                    engine.unwrap(ByteBuffer.wrap(record), app);
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
                default:
                    break;
            }
        }
        throw new AssertionError("рукопожатие не завершено, status=" + engine.getHandshakeStatus());
    }

    private static ByteBuffer newNetBuffer() {
        return ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    }

    private static void send(OutputStream out, ByteBuffer net) throws IOException {
        if (net.hasRemaining()) {
            byte[] data = new byte[net.remaining()];
            net.get(data);
            out.write(data);
            out.flush();
        }
    }

    /** Читает из сокета одну TLS-запись целиком; null при закрытии соединения. */
    private static byte[] readRecord(InputStream in) throws IOException {
        byte[] header = in.readNBytes(TlsConstants.RECORD_HEADER_SIZE);
        if (header.length < TlsConstants.RECORD_HEADER_SIZE) {
            return null;
        }
        int bodyLen = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
        byte[] body = in.readNBytes(bodyLen);
        byte[] record = new byte[header.length + body.length];
        System.arraycopy(header, 0, record, 0, header.length);
        System.arraycopy(body, 0, record, header.length, body.length);
        return record;
    }

    /** Запись данных приложения, которую отправитель собрал без нарезки по лимиту. */
    private static byte[] oversizedRecord(GostSSLEngine sender) throws Exception {
        sender.disableSendFragmentLimitForTest();
        return wrapRecord(sender, new byte[OVERSIZED_PAYLOAD]);
    }

    private static byte[] wrapRecord(GostSSLEngine sender, byte[] payload) throws Exception {
        ByteBuffer net = newNetBuffer();
        sender.wrap(ByteBuffer.wrap(payload), net);
        net.flip();
        byte[] record = new byte[net.remaining()];
        net.get(record);
        return record;
    }

    /**
     * Читает записи сервера, пока движок с некорректной записью не закроется по fatal alert пира; возвращает
     * код этого alert. Тикеты и прочее post-handshake до alert проходят без ошибок.
     */
    private int alertReceivedByViolator(GostSSLEngine violator) throws Exception {
        InputStream in = clientSocket.getInputStream();
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        for (int i = 0; i < 20; i++) {
            byte[] record = readRecord(in);
            assertNotNull(record, "сервер закрыл соединение без fatal alert");
            app.clear();
            try {
                violator.unwrap(ByteBuffer.wrap(record), app);
            } catch (SSLException expected) {
                return violator.failureAlertCodeForTest();
            }
        }
        throw new AssertionError("fatal alert от сервера не получен");
    }

    private void assertServerRejectedRecord() throws Exception {
        assertTrue(serverReadDone.await(TIMEOUT_MS, TimeUnit.MILLISECONDS), "сервер не ответил");
        Object outcome = serverReadOutcome.get();
        assertTrue(
                outcome instanceof SSLException,
                "запись больше лимита должна дать SSLException на сервере, получено: " + outcome);
    }

    @Test
    @DisplayName("запись больше лимита после рукопожатия: SSLException на сервере, alert 22 пиру")
    void oversizedRecordAfterHandshake() throws Exception {
        startServer(true);
        GostSSLEngine violator = connectViolator();

        clientSocket.getOutputStream().write(oversizedRecord(violator));
        clientSocket.getOutputStream().flush();

        assertServerRejectedRecord();
        assertEquals(
                TlsConstants.ALERT_RECORD_OVERFLOW,
                alertReceivedByViolator(violator),
                "движок с некорректной записью должен получить record_overflow");
    }

    @Test
    @DisplayName("запись больше лимита после KeyUpdate: SSLException на сервере, alert 22 пиру")
    void oversizedRecordAfterKeyUpdate() throws Exception {
        startServer(true);
        GostSSLEngine violator = connectViolator();

        violator.initiateKeyUpdate(false);
        ByteBuffer net = newNetBuffer();
        violator.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        send(clientSocket.getOutputStream(), net);
        clientSocket.getOutputStream().write(oversizedRecord(violator));
        clientSocket.getOutputStream().flush();

        assertServerRejectedRecord();
        assertEquals(
                TlsConstants.ALERT_RECORD_OVERFLOW,
                alertReceivedByViolator(violator),
                "после KeyUpdate лимит на приём должен сохраняться");
    }

    @Test
    @DisplayName("alert уходит сразу, не при close(): приложение поймало SSLException и не закрыло")
    void alertIsSentWithoutClosingSocket() throws Exception {
        startServer(false);
        GostSSLEngine violator = connectViolator();

        clientSocket.getOutputStream().write(oversizedRecord(violator));
        clientSocket.getOutputStream().flush();

        assertServerRejectedRecord();
        assertEquals(
                TlsConstants.ALERT_RECORD_OVERFLOW,
                alertReceivedByViolator(violator),
                "fatal alert должен уйти пиру при сбое чтения, а не ждать close()");
    }

    @Test
    @DisplayName("запись ровно по лимиту принимается")
    void recordAtLimitIsAccepted() throws Exception {
        startServer(true);
        GostSSLEngine violator = connectViolator();
        int atLimit = TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512) - 1;

        clientSocket.getOutputStream().write(wrapRecord(violator, new byte[atLimit]));
        clientSocket.getOutputStream().flush();

        assertTrue(serverReadDone.await(TIMEOUT_MS, TimeUnit.MILLISECONDS), "сервер не ответил");
        assertEquals(
                atLimit,
                serverReadOutcome.get(),
                "запись по лимиту (" + atLimit + " байт) должна быть принята целиком");
    }
}
