package org.rssys.gost.crossval.jsse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.jsse.OpenSslJsseHelper.ServerPkiBundle;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Возобновление по PSK сервера jsse ({@link GostSSLEngine}) с клиентом КриптоПро
 * ({@code csptest -tlsc}, TLS 1.3).
 *
 * <p>Клиент делает три последовательных соединения с проверкой повторного использования сессии;
 * сервер jsse с общим контекстом сессий обязан принять тикет на втором и третьем. Кривая GC256A:
 * {@code csptest} кладёт в {@code key_share} только её, поэтому HelloRetryRequest нет.
 */
@DisplayName("jsse: возобновление по PSK сервера GostSSLEngine <- КриптоПро csptest -tlsc")
class CryptoproJsseServerResumptionCrossValidationTest {

    private static final String CSPTEST_PROTO_TLS13 = "7";
    private static final String CSPTEST_SUCCESS = "[ErrorCode: 0x00000000]";
    private static final String CLIENT_SAVED_FILE = "interop.txt";
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final int CONNECTIONS = 3;
    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(60);
    private static final long SERVER_JOIN_MS = 15_000;
    private static final int ACCEPT_TIMEOUT_MS = 30_000;
    private static final int PEER_IO_TIMEOUT_MS = 10_000;

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
        Security.addProvider(new RssysGostJsseProvider());
    }

    static Stream<Arguments> suites() {
        return Stream.of(
                Arguments.of("Kuznyechik MGM L", TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
                Arguments.of("Kuznyechik MGM S", TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    @DisplayName("csptest -tlsc: второе и третье соединения возобновляются по тикету сервера jsse")
    void serverResumesCryptoproClient(String title, TlsCiphersuite suite) throws Exception {
        runResumption(suite, ECParameters.tc26a256(), TlsConstants.GRP_GC256A);
    }

    /**
     * Сервер предпочитает GC256B, а {@code csptest} присылает key_share только для GC256A:
     * каждое соединение должно идти через HelloRetryRequest, тикет предъявляется во втором
     * ClientHello. Binder считается по RFC 8446 §4.2.11.2, КриптоПро проверяет его независимо.
     * <p>
     * Прохождение через HelloRetryRequest тест не измеряет, оно следует из поведения
     * {@code csptest}: если новая версия начнёт присылать key_share для нескольких групп, тест
     * останется зелёным, но перестанет проверять возобновление через HelloRetryRequest.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("suites")
    @DisplayName("csptest -tlsc: возобновление на сервере jsse с группой, не равной key_share клиента (HRR по ожиданию)")
    void serverResumesCryptoproClientThroughHrr(String title, TlsCiphersuite suite) throws Exception {
        runResumption(suite, ECParameters.cryptoProA(), TlsConstants.GRP_GC256B);
    }

    private void runResumption(TlsCiphersuite suite, ECParameters certCurve, int serverGroup)
            throws Exception {
        ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(certCurve);
        GostX509KeyManager keyManager =
                OpenSslJsseHelper.createKeyManager(pki.cert(), pki.caCert(), pki.priv());
        GostSSLSessionContext sessions = new GostSSLSessionContext(suite);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener =
                     new ServerSocket(0, CONNECTIONS, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            int port = listener.getLocalPort();
            Thread serverThread = Thread.ofVirtual().start(
                    () -> serve(listener, keyManager, sessions, port, serverGroup, resumed, serverError));

            TempDirUtils.withTempDir("cp-jsse-resume-", dir -> {
                CryptoProChecker.Result client = CryptoProChecker.runResult(
                        dir, CLIENT_TIMEOUT, CryptoProChecker.resolveCsptestBinary(),
                        "-notime", "-tlsc", "-proto", CSPTEST_PROTO_TLS13,
                        "-server", InetAddress.getLoopbackAddress().getHostAddress(),
                        "-port", Integer.toString(port),
                        // сертификат тестовый, цепочки к доверенному корню нет
                        "-nocheck", "-checkproto",
                        "-reconnects", Integer.toString(CONNECTIONS),
                        "-checkreuse", "-checksessionticket",
                        "-file", CLIENT_SAVED_FILE);
                serverThread.join(SERVER_JOIN_MS);
                String context = "csptest вывод:\n" + client.output()
                        + "\nошибка сервера: " + serverError.get() + "\nвозобновления: " + resumed;

                assertNull(serverError.get(), "сервер jsse не должен получить ошибку. " + context);
                assertEquals(0, client.exitCode(), "csptest должен завершиться кодом 0. " + context);
                assertTrue(client.output().contains(CSPTEST_SUCCESS),
                        "csptest должен сообщить об успехе. " + context);
                assertEquals(List.of(false, true, true), resumed,
                        "сервер jsse: первое соединение полное, второе и третье возобновлены. " + context);
                return null;
            });
        }
    }

    private static void serve(ServerSocket listener, GostX509KeyManager keyManager,
                              GostSSLSessionContext sessions, int port, int serverGroup,
                              List<Boolean> resumed, AtomicReference<Throwable> serverError) {
        try {
            GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
            for (int i = 0; i < CONNECTIONS; i++) {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
                    GostSSLEngine engine = GostSSLEngine.createForServer(
                            keyManager, trust, "localhost", port, sessions);
                    // csptest кладёт в key_share только GC256A: при той же группе сервера HRR
                    // нет, при другой каждое соединение идёт через HRR
                    engine.setClientNamedGroup(serverGroup);
                    engine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(engine, socket);
                    OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(engine, new byte[0], socket);
                    resumed.add(engine.wasResumed());

                    String response = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/plain\r\n"
                            + "Content-Length: " + RESPONSE_MARKER.length() + "\r\n"
                            + "Connection: close\r\n"
                            + "\r\n"
                            + RESPONSE_MARKER;
                    ByteBuffer net = ByteBuffer.allocate(
                            TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
                    engine.wrap(ByteBuffer.wrap(response.getBytes(StandardCharsets.UTF_8)), net);
                    net.flip();
                    byte[] data = new byte[net.remaining()];
                    net.get(data);
                    socket.getOutputStream().write(data);
                    socket.getOutputStream().flush();
                    socket.shutdownOutput();
                    socket.getInputStream().readAllBytes();
                }
            }
        } catch (Throwable e) {
            serverError.set(e);
        }
    }
}
