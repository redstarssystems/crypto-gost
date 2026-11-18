package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.jsse.testkit.EngineSocketPeer;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Тайм-аут чтения ({@code setSoTimeout}) посреди TLS-записи: {@link GostSSLSocket} обязан
 * сохранить уже прочитанные байты, иначе следующее чтение приняло бы середину записи за заголовок.
 *
 * <p>Порядок событий задают защёлки: пир пишет часть записи, клиент получает тайм-аут, пир
 * дописывает остаток, клиент читает снова. Время в тесте не меряется.
 */
@DisplayName("GostSSLSocket: тайм-аут чтения посреди записи не теряет прочитанное")
class GostSSLSocketReadTimeoutTest {

    private static final byte[] PAYLOAD = "данные, записанные по частям".getBytes();
    private static final int SHORT_TIMEOUT_MS = 300;
    private static final int LONG_TIMEOUT_MS = 10_000;

    /** Сколько байт записи уходит до тайм-аута: середина тела. */
    private static final int MIDDLE_OF_BODY = -1;

    /** Три байта заголовка: тайм-аут посреди заголовка. */
    private static final int INSIDE_HEADER = 3;

    private static EngineServerPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        pki = EngineServerPki.create();
    }

    @ParameterizedTest(name = "отправлено до тайм-аута: {0}")
    @ValueSource(ints = {MIDDLE_OF_BODY, INSIDE_HEADER})
    @DisplayName("Пир пишет часть записи, клиент ловит тайм-аут, затем читает запись целиком")
    void timeoutInsideRecordKeepsReadBytes(int sentBeforeTimeout) throws Exception {
        CountDownLatch partSent = new CountDownLatch(1);
        CountDownLatch clientTimedOut = new CountDownLatch(1);
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> server =
                    CompletableFuture.runAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    socket.setSoTimeout(LONG_TIMEOUT_MS);
                                    GostSSLEngine engine =
                                            new GostSSLEngine(
                                                    pki.serverKm(),
                                                    GostX509TrustManager.insecureTrustAll(),
                                                    "localhost",
                                                    0,
                                                    false);
                                    EngineSocketPeer.handshake(engine, socket);
                                    byte[] wire = EngineSocketPeer.wrapData(engine, PAYLOAD);
                                    // Запись данных последняя в проводе: перед ней могут идти
                                    // тикеты, они уходят целиком
                                    int recordLength =
                                            TlsConstants.RECORD_HEADER_SIZE
                                                    + PAYLOAD.length
                                                    + 1
                                                    + TlsCiphersuite
                                                            .TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L
                                                            .getTagLen();
                                    int recordStart = wire.length - recordLength;
                                    int part =
                                            sentBeforeTimeout == MIDDLE_OF_BODY
                                                    ? TlsConstants.RECORD_HEADER_SIZE
                                                            + PAYLOAD.length / 2
                                                    : sentBeforeTimeout;
                                    OutputStream out = socket.getOutputStream();
                                    out.write(wire, 0, recordStart + part);
                                    out.flush();
                                    partSent.countDown();
                                    assertTrue(
                                            clientTimedOut.await(
                                                    LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS));
                                    out.write(
                                            Arrays.copyOfRange(
                                                    wire, recordStart + part, wire.length));
                                    out.flush();
                                    // Ждём закрытия клиентом, чтобы не оборвать соединение раньше
                                    socket.getInputStream().read();
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            try (GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(pki.rootCa().cert)),
                            new GostSSLSessionContext(
                                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L))) {
                client.setSoTimeout(LONG_TIMEOUT_MS);
                client.startHandshake();
                assertTrue(partSent.await(LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS));

                client.setSoTimeout(SHORT_TIMEOUT_MS);
                byte[] buffer = new byte[PAYLOAD.length];
                assertThrows(
                        SocketTimeoutException.class,
                        () -> client.getInputStream().read(buffer),
                        "запись не дописана: чтение упирается в тайм-аут");
                clientTimedOut.countDown();

                client.setSoTimeout(LONG_TIMEOUT_MS);
                byte[] received = client.getInputStream().readNBytes(PAYLOAD.length);
                assertArrayEquals(PAYLOAD, received, "после тайм-аута запись читается целиком");
            }
            server.get(LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    @Test
    @DisplayName(
            "Тайм-аут посреди рукопожатия: сокет открыт, повторный startHandshake продолжает его")
    void timeoutDuringHandshakeIsResumable() throws Exception {
        CountDownLatch clientTimedOut = new CountDownLatch(1);
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> server =
                    CompletableFuture.runAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    socket.setSoTimeout(LONG_TIMEOUT_MS);
                                    GostSSLEngine engine = serverEngine();
                                    // Полёт сервера уходит только после тайм-аута клиента
                                    EngineSocketPeer.handshake(
                                            engine,
                                            socket,
                                            FLIGHT_FRAMES,
                                            e -> awaitQuietly(clientTimedOut));
                                    socket.getOutputStream()
                                            .write(EngineSocketPeer.wrapData(engine, PAYLOAD));
                                    socket.getOutputStream().flush();
                                    socket.getInputStream().read();
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });
            try (GostSSLSocket client = client(listener)) {
                client.setSoTimeout(SHORT_TIMEOUT_MS);
                assertThrows(SocketTimeoutException.class, client::startHandshake);
                assertFalse(client.isClosed(), "тайм-аут не роковой: сокет открыт, как в JDK");
                clientTimedOut.countDown();

                client.setSoTimeout(LONG_TIMEOUT_MS);
                client.startHandshake();
                assertArrayEquals(
                        PAYLOAD,
                        client.getInputStream().readNBytes(PAYLOAD.length),
                        "рукопожатие продолжено, данные доходят");
            }
            server.get(LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    @Test
    @DisplayName("Обрыв соединения посреди рукопожатия: сокет закрыт")
    void connectionLossDuringHandshakeClosesSocket() throws Exception {
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> server =
                    CompletableFuture.runAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    // ClientHello прочитан, ответа нет: соединение закрывается
                                    socket.getInputStream().read(new byte[64]);
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });
            try (GostSSLSocket client = client(listener)) {
                client.setSoTimeout(LONG_TIMEOUT_MS);
                assertThrows(java.io.IOException.class, client::startHandshake);
                assertTrue(client.isClosed(), "после обрыва рукопожатия сокет закрыт");
            }
            server.get(LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    private static final int FLIGHT_FRAMES = 2;

    private static GostSSLEngine serverEngine() {
        return new GostSSLEngine(
                pki.serverKm(), GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    private static GostSSLSocket client(ServerSocket listener) throws Exception {
        return new GostSSLSocket(
                "localhost",
                listener.getLocalPort(),
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(pki.rootCa().cert)),
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(LONG_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
