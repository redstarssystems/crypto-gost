package org.rssys.gost.crossval.jsse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.jsse.OpenSslJsseCrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.jsse.OpenSslJsseHelper.ServerPkiBundle;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Возобновление по PSK сервера jsse ({@link GostSSLEngine}) с клиентом OpenSSL ({@code s_client}).
 *
 * <p>Клиент OpenSSL возобновляет сессию через {@code -sess_out}/{@code -sess_in}; сервер jsse с
 * общим для двух соединений контекстом сессий обязан принять тикет на втором. В основном тесте группа
 * клиента совпадает с группой сервера ({@code -curves}), поэтому HelloRetryRequest нет; отдельный
 * тест проверяет возобновление через него.
 */
@DisplayName("jsse: возобновление по PSK сервера GostSSLEngine <- OpenSSL s_client")
class OpenSslJsseServerResumptionCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final long TIMEOUT_MS = 30_000;
    private static final int ACCEPT_TIMEOUT_MS = 30_000;
    private static final int PEER_IO_TIMEOUT_MS = 15_000;
    private static final long SERVER_JOIN_MS = 10_000;
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final String OPENSSL_REUSED = "Reused, TLSv1.3";
    private static final String CLIENT_HELLO_TRACE = "], ClientHello";
    private static final int CONNECTIONS = 2;

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslJsseHelper.assumeGostTls13();
        Security.addProvider(new RssysGostJsseProvider());
    }

    static Stream<Arguments> suitesAndCurves() {
        return Stream.of("GC256B", "GC256A")
                .flatMap(curve -> Stream.of(
                        Arguments.of(SUITE_L, curve),
                        Arguments.of(SUITE_S, curve)));
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("suitesAndCurves")
    @DisplayName("сервер GostSSLEngine + s_client: второе соединение возобновляется по тикету")
    void serverResumesOpenSslClient(String suiteName, String curveName) throws Exception {
        CurveSpec curve = OpenSslJsseCrossValidationTest.ALL_CURVES.stream()
                .filter(c -> c.ianaName().equals(curveName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve: " + curveName));
        TlsCiphersuite suite = suiteName.equals(SUITE_L)
                ? TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L
                : TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

        ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params());
        GostX509KeyManager keyManager =
                OpenSslJsseHelper.createKeyManager(pki.cert(), pki.caCert(), pki.priv());
        GostSSLSessionContext sessions = new GostSSLSessionContext(suite);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener = new ServerSocket(0, CONNECTIONS, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            int port = listener.getLocalPort();
            Thread serverThread = Thread.ofVirtual().start(
                    () -> serveTwice(listener, keyManager, sessions, port, resumed, serverError));

            TempDirUtils.withTempDir("jsse-resume-server-", tmpDir -> {
                Path session = tmpDir.resolve("session.pem");
                String first = OpenSslJsseHelper.runSClientWithHttpGet(
                        port, suiteName, curve.ianaName(), TIMEOUT_MS,
                        "-sess_out", session.toString());
                String second = OpenSslJsseHelper.runSClientWithHttpGet(
                        port, suiteName, curve.ianaName(), TIMEOUT_MS,
                        "-sess_in", session.toString());

                serverThread.join(SERVER_JOIN_MS);
                assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
                assertTrue(first.contains(RESPONSE_MARKER), "ответ первого соединения");
                assertTrue(second.contains(RESPONSE_MARKER), "ответ второго соединения");
                assertFalse(first.contains(OPENSSL_REUSED), "первое соединение s_client полное");
                assertTrue(second.contains(OPENSSL_REUSED),
                        "s_client должен сообщить о возобновлении сессии:\n" + second);
                assertEquals(List.of(false, true), resumed,
                        "сервер jsse: первое соединение полное, второе возобновлено");
                return null;
            });
        }
    }

    /**
     * s_client предлагает key_share только для GC256A, сервер jsse предпочитает GC256B (группа
     * по умолчанию): оба соединения идут через HelloRetryRequest, тикет предъявляется во втором
     * ClientHello. Binder считается по RFC 8446 §4.2.11.2, OpenSSL проверяет его независимо.
     */
    @ParameterizedTest(name = "{0}")
    @org.junit.jupiter.params.provider.ValueSource(strings = {SUITE_L, SUITE_S})
    @DisplayName("сервер GostSSLEngine + s_client: возобновление через HRR")
    void serverResumesOpenSslClientThroughHrr(String suiteName) throws Exception {
        CurveSpec curve = OpenSslJsseCrossValidationTest.ALL_CURVES.stream()
                .filter(c -> c.ianaName().equals("GC256B"))
                .findFirst()
                .orElseThrow();
        TlsCiphersuite suite = suiteName.equals(SUITE_L)
                ? TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L
                : TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

        ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params());
        GostX509KeyManager keyManager =
                OpenSslJsseHelper.createKeyManager(pki.cert(), pki.caCert(), pki.priv());
        GostSSLSessionContext sessions = new GostSSLSessionContext(suite);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener = new ServerSocket(0, CONNECTIONS, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            int port = listener.getLocalPort();
            Thread serverThread = Thread.ofVirtual().start(
                    () -> serveTwice(listener, keyManager, sessions, port, resumed, serverError));

            TempDirUtils.withTempDir("jsse-resume-hrr-server-", tmpDir -> {
                Path session = tmpDir.resolve("session.pem");
                // первой идёт GC256A: key_share только для неё, сервер запрашивает GC256B
                String groups = "GC256A:GC256B";
                String first = OpenSslJsseHelper.runSClientWithHttpGet(
                        port, suiteName, groups, TIMEOUT_MS,
                        "-msg", "-sess_out", session.toString());
                String second = OpenSslJsseHelper.runSClientWithHttpGet(
                        port, suiteName, groups, TIMEOUT_MS,
                        "-msg", "-sess_in", session.toString());

                serverThread.join(SERVER_JOIN_MS);
                assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
                assertTrue(first.contains(RESPONSE_MARKER), "ответ первого соединения");
                assertTrue(second.contains(RESPONSE_MARKER), "ответ второго соединения");
                // OpenSSL в трассе -msg показывает HRR как ServerHello, поэтому HRR узнаётся
                // по двум отправленным ClientHello
                assertEquals(2, countOccurrences(first, CLIENT_HELLO_TRACE),
                        "первое соединение должно идти через HRR:\n" + first);
                assertEquals(2, countOccurrences(second, CLIENT_HELLO_TRACE),
                        "второе соединение должно идти через HRR:\n" + second);
                assertTrue(second.contains(OPENSSL_REUSED),
                        "s_client должен сообщить о возобновлении сессии:\n" + second);
                assertEquals(List.of(false, true), resumed,
                        "сервер jsse: первое соединение полное, второе возобновлено");
                return null;
            });
        }
    }

    private static int countOccurrences(String text, String fragment) {
        int count = 0;
        for (int at = text.indexOf(fragment); at >= 0; at = text.indexOf(fragment, at + 1)) {
            count++;
        }
        return count;
    }

    private static void serveTwice(ServerSocket listener, GostX509KeyManager keyManager,
                                   GostSSLSessionContext sessions, int port,
                                   List<Boolean> resumed, AtomicReference<Throwable> serverError) {
        try {
            GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
            for (int i = 0; i < CONNECTIONS; i++) {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
                    GostSSLEngine engine = GostSSLEngine.createForServer(
                            keyManager, trust, "localhost", port, sessions);
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
                }
            }
        } catch (Throwable e) {
            serverError.set(e);
        }
    }
}
