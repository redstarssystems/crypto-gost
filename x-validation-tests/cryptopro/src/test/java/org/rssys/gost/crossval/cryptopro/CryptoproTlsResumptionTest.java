package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.HandshakeRecordCountingTransport;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Возобновление по PSK: сервер crypto-gost, клиент КриптоПро ({@code csptest -tlsc}, TLS 1.3).
 *
 * <p>Клиент делает три последовательных соединения с проверкой повторного использования сессии
 * ({@code -checkreuse -checksessionticket}); сервер crypto-gost обязан принять тикет на втором и
 * третьем. Кривая GC256A: {@code csptest} кладёт в {@code key_share} только её, поэтому
 * HelloRetryRequest нет ни в одном соединении. На остальных кривых каждое соединение идёт через
 * HelloRetryRequest; возобновление через него проверяет отдельный тест.
 */
@DisplayName("TLS 1.3: возобновление по PSK, сервер crypto-gost <- КриптоПро csptest -tlsc")
class CryptoproTlsResumptionTest {

    private static final int SUITE_KUZNYECHIK_L = 0xC103;
    private static final int SUITE_KUZNYECHIK_S = 0xC105;
    private static final String CSPTEST_PROTO_TLS13 = "7";
    private static final String CSPTEST_SUCCESS = "[ErrorCode: 0x00000000]";
    private static final String CLIENT_SAVED_FILE = "interop.txt";
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final int CONNECTIONS = 3;
    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(60);
    private static final long SERVER_JOIN_SECONDS = 15;
    private static final int ACCEPT_TIMEOUT_MS = 30_000;
    private static final int PEER_IO_TIMEOUT_MS = 10_000;

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
    }

    static Stream<Arguments> suites() {
        return Stream.of(
                Arguments.of("Kuznyechik MGM L", SUITE_KUZNYECHIK_L),
                Arguments.of("Kuznyechik MGM S", SUITE_KUZNYECHIK_S));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    @DisplayName("csptest -tlsc: второе и третье соединения возобновляются по тикету сервера")
    void serverResumesCryptoproClient(String suiteTitle, int suiteId) throws Exception {
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsServerConfig config =
                new TlsServerConfig(
                                TlsCiphersuite.byId(suiteId),
                                Collections.singletonList(bundle.cert),
                                bundle.priv)
                        .withSelectedNamedGroup(TlsConstants.GRP_GC256A);
        InMemoryPskStore store = new InMemoryPskStore(10);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener =
                new ServerSocket(0, CONNECTIONS, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Thread serverThread =
                    Thread.ofVirtual()
                            .start(
                                    () ->
                                            serve(
                                                    listener,
                                                    config,
                                                    store,
                                                    resumed,
                                                    new CopyOnWriteArrayList<>(),
                                                    serverError));

            TempDirUtils.withTempDir("cp-tls-resume-", dir -> {
                CryptoProChecker.Result client = runCsptestClient(dir, listener.getLocalPort());
                serverThread.join(SERVER_JOIN_SECONDS * 1000);
                String context = "csptest вывод:\n" + client.output()
                        + "\nошибка сервера: " + serverError.get() + "\nвозобновления: " + resumed;

                assertNull(serverError.get(), "сервер crypto-gost не должен получить ошибку. " + context);
                assertEquals(0, client.exitCode(), "csptest должен завершиться кодом 0. " + context);
                assertTrue(client.output().contains(CSPTEST_SUCCESS),
                        "csptest должен сообщить об успехе. " + context);
                assertEquals(List.of(false, true, true), resumed,
                        "сервер: первое соединение полное, второе и третье возобновлены. " + context);
                return null;
            });
        }
    }

    /**
     * Кривая GC256B: {@code csptest} кладёт в {@code key_share} только GC256A, поэтому каждое
     * соединение идёт через HelloRetryRequest, и тикет предъявляется во втором ClientHello.
     * Binder считается по RFC 8446 §4.2.11.2; КриптоПро проверяет его независимо.
     */
    @org.junit.jupiter.api.Test
    @DisplayName("csptest -tlsc + сервер crypto-gost на GC256B: возобновление через HRR")
    void serverResumesCryptoproClientThroughHrr() throws Exception {
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA());
        TlsServerConfig config =
                new TlsServerConfig(
                                TlsCiphersuite.byId(SUITE_KUZNYECHIK_L),
                                Collections.singletonList(bundle.cert),
                                bundle.priv)
                        .withSelectedNamedGroup(TlsConstants.GRP_GC256B);
        InMemoryPskStore store = new InMemoryPskStore(10);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        List<Integer> clientHellos = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener =
                new ServerSocket(0, CONNECTIONS, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Thread serverThread =
                    Thread.ofVirtual()
                            .start(
                                    () ->
                                            serve(
                                                    listener,
                                                    config,
                                                    store,
                                                    resumed,
                                                    clientHellos,
                                                    serverError));

            TempDirUtils.withTempDir("cp-tls-resume-hrr-", dir -> {
                CryptoProChecker.Result client = runCsptestClient(dir, listener.getLocalPort());
                serverThread.join(SERVER_JOIN_SECONDS * 1000);
                String context = "csptest вывод:\n" + client.output()
                        + "\nошибка сервера: " + serverError.get() + "\nвозобновления: " + resumed;

                assertNull(serverError.get(), "сервер crypto-gost не должен получить ошибку. " + context);
                assertEquals(0, client.exitCode(), "csptest должен завершиться кодом 0. " + context);
                assertTrue(client.output().contains(CSPTEST_SUCCESS),
                        "csptest должен сообщить об успехе. " + context);
                assertEquals(List.of(false, true, true), resumed,
                        "сервер: первое соединение полное, второе и третье возобновлены. " + context);
                assertEquals(List.of(2, 2, 2), clientHellos,
                        "все соединения шли через HRR: два ClientHello. " + context);
                return null;
            });
        }
    }

    private static CryptoProChecker.Result runCsptestClient(Path workDir, int port)
            throws Exception {
        return CryptoProChecker.runResult(
                workDir,
                CLIENT_TIMEOUT,
                CryptoProChecker.resolveCsptestBinary(),
                "-notime",
                "-tlsc",
                "-proto", CSPTEST_PROTO_TLS13,
                "-server", InetAddress.getLoopbackAddress().getHostAddress(),
                "-port", Integer.toString(port),
                // сертификат тестовый, цепочки к доверенному корню нет
                "-nocheck",
                "-checkproto",
                "-reconnects", Integer.toString(CONNECTIONS),
                "-checkreuse",
                "-checksessionticket",
                "-file", CLIENT_SAVED_FILE);
    }

    /** Принимает три соединения с общим хранилищем тикетов и записывает, возобновлено ли каждое. */
    private static void serve(
            ServerSocket listener,
            TlsServerConfig config,
            InMemoryPskStore store,
            List<Boolean> resumed,
            List<Integer> clientHellos,
            AtomicReference<Throwable> serverError) {
        try {
            for (int i = 0; i < CONNECTIONS; i++) {
                try (Socket socket = listener.accept();
                        SocketTlsTransport socketTransport = new SocketTlsTransport(socket);
                        HandshakeRecordCountingTransport transport =
                                new HandshakeRecordCountingTransport(socketTransport);
                        TlsSession session = TlsSession.createServer(config, transport)) {
                    socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
                    session.setPskStore(store);
                    session.handshakeAsServer();
                    session.read();
                    resumed.add(session.wasResumed());
                    clientHellos.add(transport.receivedPlainHandshakeRecords());
                    String response = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/plain\r\n"
                            + "Content-Length: " + RESPONSE_MARKER.length() + "\r\n"
                            + "Connection: close\r\n"
                            + "\r\n"
                            + RESPONSE_MARKER;
                    session.write(response.getBytes(StandardCharsets.UTF_8));
                    closeGracefully(session, socket);
                }
            }
        } catch (Throwable e) {
            serverError.set(e);
        }
    }

    /** Закрывает соединение первым, но без RST (как в {@code CryptoproTlsInteropTest}). */
    private static void closeGracefully(TlsSession session, Socket socket) throws IOException {
        session.close();
        socket.shutdownOutput();
        socket.getInputStream().readAllBytes();
    }
}
