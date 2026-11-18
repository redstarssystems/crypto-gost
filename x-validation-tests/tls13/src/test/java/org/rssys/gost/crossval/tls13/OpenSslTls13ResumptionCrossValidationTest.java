package org.rssys.gost.crossval.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.tls13.OpenSslTls13CrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.HandshakeRecordCountingTransport;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Возобновление по PSK между crypto-gost и OpenSSL (gostprov, TLS 1.3).
 *
 * <p>Клиент OpenSSL возобновляет сессию через {@code -sess_out}/{@code -sess_in}; сервер
 * OpenSSL выдаёт тикеты, а клиент crypto-gost предъявляет их при втором соединении. Второе
 * соединение должно возобновиться на обеих сторонах, а не оборваться или перейти на полное
 * рукопожатие: именно по ошибке в формате ClientHello с PSK внешний сервер рвал такое соединение
 * фатальным {@code decode_error}.
 */
@DisplayName("TLS 1.3: возобновление по PSK crypto-gost <-> OpenSSL")
class OpenSslTls13ResumptionCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final int SUITE_L_ID = 0xC103;
    private static final int SUITE_S_ID = 0xC105;
    private static final long TIMEOUT_MS = 30_000;
    private static final int ACCEPT_TIMEOUT_MS = 30_000;
    private static final int PEER_IO_TIMEOUT_MS = 15_000;
    private static final long SERVER_JOIN_MS = 10_000;
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final String OPENSSL_REUSED = "Reused, TLSv1.3";

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslTls13Helper.assumeGostTls13();
    }

    static Stream<Arguments> suitesAndCurves() {
        return Stream.of("GC256B", "GC256A")
                .flatMap(
                        curve ->
                                Stream.of(
                                        Arguments.of(SUITE_L, SUITE_L_ID, curve),
                                        Arguments.of(SUITE_S, SUITE_S_ID, curve)));
    }

    // ------------------------------------------------------------------------
    // Клиент crypto-gost -> s_server
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}, {2}")
    @MethodSource("suitesAndCurves")
    @DisplayName("клиент crypto-gost + s_server: второе соединение возобновляется по тикету без HRR")
    void clientResumesAgainstOpenSslServer(String suiteName, int suiteId, String curveName)
            throws Exception {
        CurveSpec curve = curve(curveName);
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir(
                "tls13-resume-client-",
                tmpDir -> {
                    OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
                    Process sServer =
                            OpenSslTls13Helper.startSServer(
                                    port,
                                    suiteName,
                                    curve.ianaName(),
                                    tmpDir.resolve("cert.pem").toString(),
                                    tmpDir.resolve("key.pem").toString(),
                                    "-sigalgs",
                                    curve.sigalgsName());
                    try {
                        assertTrue(
                                OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                                "s_server не запустился");
                        GostCertificate serverCert =
                                GostCertificate.fromPemOrDer(
                                        Files.readAllBytes(tmpDir.resolve("cert.pem")));
                        InMemoryPskStore store = new InMemoryPskStore(10);

                        // Стартовая группа клиента совпадает с кривой сервера: HRR не нужен
                        int group = groupOf(curveName);
                        ClientOutcome first =
                                connectAndRequest(port, suiteId, group, serverCert, store);
                        assertFalse(first.resumed(), "первое соединение полное: тикета ещё нет");
                        assertEquals(1, first.clientHellos(), "без HRR один ClientHello");
                        assertTrue(
                                store.size() > 0,
                                "тикеты s_server должны быть сохранены клиентом после первого"
                                        + " соединения");

                        ClientOutcome second =
                                connectAndRequest(port, suiteId, group, serverCert, store);
                        assertTrue(
                                second.resumed(),
                                "второе соединение должно возобновиться по тикету s_server");
                        assertEquals(1, second.clientHellos(), "без HRR один ClientHello");
                    } finally {
                        OpenSslTls13Helper.destroyProcess(sServer);
                    }
                    return null;
                });
    }

    /**
     * Итог одного соединения клиента crypto-gost.
     *
     * @param resumed      соединение возобновлено по PSK
     * @param clientHellos число отправленных ClientHello: 2 означает, что был HelloRetryRequest
     */
    private record ClientOutcome(boolean resumed, int clientHellos) {}

    /**
     * Одно соединение клиента crypto-gost.
     *
     * @param startGroup стартовая группа ECDHE или 0 (по умолчанию GC256B)
     */
    private static ClientOutcome connectAndRequest(
            int port,
            int suiteId,
            int startGroup,
            GostCertificate serverCert,
            InMemoryPskStore store)
            throws Exception {
        return connectAndRequest(port, suiteId, startGroup, serverCert, store, null);
    }

    /**
     * Одно соединение клиента crypto-gost с именем сервера для SNI.
     *
     * @param serverHostname имя для SNI или null, если SNI не нужен; сверка имени с сертификатом
     *                       отключена, но имя в SNI всё равно уходит
     */
    private static ClientOutcome connectAndRequest(
            int port,
            int suiteId,
            int startGroup,
            GostCertificate serverCert,
            InMemoryPskStore store,
            String serverHostname)
            throws Exception {
        TlsClientConfig clientConfig =
                new TlsClientConfig(
                                TlsCiphersuite.byId(suiteId), TrustAnchors.ofCertificate(serverCert))
                        .withoutHostnameVerification()
                        .withSelectedNamedGroup(startGroup);
        if (serverHostname != null) {
            clientConfig = clientConfig.withServerHostname(serverHostname);
        }
        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                SocketTlsTransport socketTransport = new SocketTlsTransport(socket);
                HandshakeRecordCountingTransport transport =
                        new HandshakeRecordCountingTransport(socketTransport);
                TlsSession client = TlsSession.createClient(clientConfig, transport)) {
            socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
            client.setPskStore(store);
            client.handshakeAsClient();
            client.write(
                    "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            // чтение ответа заодно обрабатывает NewSessionTicket сервера
            byte[] response = client.read();
            String text = new String(response, StandardCharsets.UTF_8);
            assertTrue(
                    text.contains("TLS") || text.contains("HTTP"),
                    "ответ s_server должен содержать данные соединения");
            return new ClientOutcome(client.wasResumed(), transport.sentPlainHandshakeRecords());
        }
    }

    @Test
    @DisplayName(
            "клиент crypto-gost + s_server: подтверждение SNI в EE принимается, в том числе при"
                    + " возобновлении")
    void clientAcceptsServerNameAcknowledgementOfOpenSsl() throws Exception {
        CurveSpec curve = curve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir(
                "tls13-resume-sni-",
                tmpDir -> {
                    OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
                    Process sServer =
                            OpenSslTls13Helper.startSServer(
                                    port,
                                    SUITE_L,
                                    curve.ianaName(),
                                    tmpDir.resolve("cert.pem").toString(),
                                    tmpDir.resolve("key.pem").toString(),
                                    "-sigalgs",
                                    curve.sigalgsName(),
                                    "-servername",
                                    "localhost",
                                    "-cert2",
                                    tmpDir.resolve("cert.pem").toString(),
                                    "-key2",
                                    tmpDir.resolve("key.pem").toString(),
                                    "-trace");
                    // Вывод s_server читается с самого запуска: trace нужен для проверки, что
                    // подтверждение SNI действительно было отправлено, а не пропущено сервером
                    StringBuffer serverOutput = new StringBuffer();
                    Thread collector =
                            new Thread(
                                    () -> {
                                        try (var reader =
                                                new java.io.BufferedReader(
                                                        new java.io.InputStreamReader(
                                                                sServer.getInputStream(),
                                                                StandardCharsets.UTF_8))) {
                                            String line;
                                            while ((line = reader.readLine()) != null) {
                                                serverOutput.append(line).append('\n');
                                            }
                                        } catch (java.io.IOException ignored) {
                                            // процесс остановлен тестом
                                        }
                                    });
                    collector.setDaemon(true);
                    collector.start();
                    try {
                        long deadline = System.currentTimeMillis() + 10_000;
                        while (!serverOutput.toString().contains("ACCEPT")
                                && System.currentTimeMillis() < deadline) {
                            Thread.sleep(50);
                        }
                        assertTrue(serverOutput.toString().contains("ACCEPT"), "s_server не запустился");
                        GostCertificate serverCert =
                                GostCertificate.fromPemOrDer(
                                        Files.readAllBytes(tmpDir.resolve("cert.pem")));
                        InMemoryPskStore store = new InMemoryPskStore(10);
                        int group = groupOf("GC256B");

                        ClientOutcome first =
                                connectAndRequest(
                                        port, SUITE_L_ID, group, serverCert, store, "localhost");
                        assertFalse(first.resumed(), "первое соединение полное");
                        ClientOutcome second =
                                connectAndRequest(
                                        port, SUITE_L_ID, group, serverCert, store, "localhost");
                        assertTrue(second.resumed(), "второе соединение возобновляется по тикету");
                        // Подтверждение SNI (пустой server_name в EE) обязано прийти в обоих
                        // рукопожатиях, иначе тест ничего не проверяет. OpenSSL шлёт его только при
                        // настроенном обработчике имени (-servername с -cert2). Считаем по длине EE:
                        // 6 байт = длина списка (2) + заголовок одного расширения с пустым телом (4);
                        // вывод s_server буферизуется, поэтому ждём нужного числа вхождений с
                        // крайним сроком, а не фиксированную паузу
                        java.util.regex.Pattern acknowledgedEe =
                                java.util.regex.Pattern.compile("EncryptedExtensions, Length=6\\b");
                        long traceDeadline = System.currentTimeMillis() + 5_000;
                        int acknowledgements = 0;
                        while (System.currentTimeMillis() < traceDeadline) {
                            acknowledgements = 0;
                            var matcher = acknowledgedEe.matcher(serverOutput.toString());
                            while (matcher.find()) {
                                acknowledgements++;
                            }
                            if (acknowledgements >= 2) {
                                break;
                            }
                            Thread.sleep(50);
                        }
                        assertEquals(
                                2,
                                acknowledgements,
                                "s_server должен подтвердить SNI в EE при полном и при"
                                        + " возобновлённом рукопожатии");
                    } finally {
                        OpenSslTls13Helper.destroyProcess(sServer);
                    }
                    return null;
                });
    }

    private static int groupOf(String curveName) {
        return switch (curveName) {
            case "GC256A" -> TlsConstants.GRP_GC256A;
            case "GC256B" -> TlsConstants.GRP_GC256B;
            default -> throw new IllegalArgumentException("Unknown curve: " + curveName);
        };
    }

    // ------------------------------------------------------------------------
    // Клиент s_client -> сервер crypto-gost
    // ------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}, {2}")
    @MethodSource("suitesAndCurves")
    @DisplayName("сервер crypto-gost + s_client: второе соединение возобновляется по тикету")
    void serverResumesOpenSslClient(String suiteName, int suiteId, String curveName)
            throws Exception {
        CurveSpec curve = curve(curveName);
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params());
        TlsServerConfig config =
                new TlsServerConfig(
                        TlsCiphersuite.byId(suiteId),
                        Collections.singletonList(bundle.cert),
                        bundle.priv);
        InMemoryPskStore store = new InMemoryPskStore(10);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        List<Integer> clientHellos = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Thread serverThread =
                    Thread.ofVirtual()
                            .start(
                                    () ->
                                            serveTwice(
                                                    listener,
                                                    config,
                                                    store,
                                                    resumed,
                                                    clientHellos,
                                                    serverError));

            TempDirUtils.withTempDir(
                    "tls13-resume-server-",
                    tmpDir -> {
                        Path session = tmpDir.resolve("session.pem");
                        String first =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port,
                                        suiteName,
                                        curve.ianaName(),
                                        TIMEOUT_MS,
                                        "-sess_out",
                                        session.toString());
                        String second =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port,
                                        suiteName,
                                        curve.ianaName(),
                                        TIMEOUT_MS,
                                        "-sess_in",
                                        session.toString());

                        serverThread.join(SERVER_JOIN_MS);
                        assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
                        assertTrue(first.contains(RESPONSE_MARKER), "ответ первого соединения");
                        assertTrue(second.contains(RESPONSE_MARKER), "ответ второго соединения");
                        assertFalse(
                                first.contains(OPENSSL_REUSED),
                                "первое соединение s_client полное");
                        assertTrue(
                                second.contains(OPENSSL_REUSED),
                                "s_client должен сообщить о возобновлении сессии:\n" + second);
                        assertEquals(
                                List.of(false, true),
                                resumed,
                                "сервер crypto-gost: первое полное, второе возобновлено");
                        return null;
                    });
        }
    }

    // ------------------------------------------------------------------------
    // Возобновление через HelloRetryRequest
    // ------------------------------------------------------------------------
    //
    // Клиент без настройки начинает с группы GC256B. На сервере с кривой GC256A каждое
    // соединение, и возобновление тоже, идёт через HelloRetryRequest: второй ClientHello несёт
    // binder, который считается по RFC 8446 §4.2.11.2 (один хэш от message_hash, HRR и усечённого
    // ClientHello). Сторона OpenSSL проверяет его независимо.

    @Test
    @DisplayName("клиент crypto-gost + s_server на GC256A: возобновление через HRR")
    void clientResumesThroughHrr() throws Exception {
        CurveSpec curve = curve("GC256A");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir(
                "tls13-resume-hrr-client-",
                tmpDir -> {
                    OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
                    Process sServer =
                            OpenSslTls13Helper.startSServer(
                                    port,
                                    SUITE_L,
                                    curve.ianaName(),
                                    tmpDir.resolve("cert.pem").toString(),
                                    tmpDir.resolve("key.pem").toString(),
                                    "-sigalgs",
                                    curve.sigalgsName());
                    try {
                        assertTrue(
                                OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                                "s_server не запустился");
                        GostCertificate serverCert =
                                GostCertificate.fromPemOrDer(
                                        Files.readAllBytes(tmpDir.resolve("cert.pem")));
                        InMemoryPskStore store = new InMemoryPskStore(10);

                        ClientOutcome first =
                                connectAndRequest(port, SUITE_L_ID, 0, serverCert, store);
                        assertFalse(first.resumed(), "первое соединение полное");
                        assertEquals(2, first.clientHellos(), "первое соединение шло через HRR");
                        assertTrue(store.size() > 0, "тикеты сохранены");

                        ClientOutcome second =
                                connectAndRequest(port, SUITE_L_ID, 0, serverCert, store);
                        assertTrue(
                                second.resumed(),
                                "второе соединение должно возобновиться по тикету через HRR");
                        assertEquals(2, second.clientHellos(), "второе соединение шло через HRR");
                    } finally {
                        OpenSslTls13Helper.destroyProcess(sServer);
                    }
                    return null;
                });
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: возобновление через HRR")
    void serverResumesThroughHrr() throws Exception {
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(curve("GC256A").params());
        TlsServerConfig config =
                new TlsServerConfig(
                                TlsCiphersuite.byId(SUITE_L_ID),
                                Collections.singletonList(bundle.cert),
                                bundle.priv)
                        .withSelectedNamedGroup(TlsConstants.GRP_GC256A);
        InMemoryPskStore store = new InMemoryPskStore(10);
        List<Boolean> resumed = new CopyOnWriteArrayList<>();
        List<Integer> clientHellos = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket listener = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            Thread serverThread =
                    Thread.ofVirtual()
                            .start(
                                    () ->
                                            serveTwice(
                                                    listener,
                                                    config,
                                                    store,
                                                    resumed,
                                                    clientHellos,
                                                    serverError));

            TempDirUtils.withTempDir(
                    "tls13-resume-hrr-server-",
                    tmpDir -> {
                        Path session = tmpDir.resolve("session.pem");
                        // s_client предлагает GC256B первой, сервер выбирает GC256A: HRR в обоих
                        String groups = "GC256B:GC256A";
                        String first =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port,
                                        SUITE_L,
                                        groups,
                                        TIMEOUT_MS,
                                        "-sess_out",
                                        session.toString());
                        String second =
                                OpenSslTls13Helper.runSClientWithHttpGet(
                                        port,
                                        SUITE_L,
                                        groups,
                                        TIMEOUT_MS,
                                        "-sess_in",
                                        session.toString());

                        serverThread.join(SERVER_JOIN_MS);
                        assertNull(serverError.get(), "ошибка сервера: " + serverError.get());
                        assertTrue(first.contains(RESPONSE_MARKER), "ответ первого соединения");
                        assertTrue(second.contains(RESPONSE_MARKER), "ответ второго соединения");
                        assertTrue(
                                second.contains(OPENSSL_REUSED),
                                "s_client должен сообщить о возобновлении сессии:\n" + second);
                        assertEquals(
                                List.of(false, true),
                                resumed,
                                "сервер crypto-gost: первое полное, второе возобновлено");
                        assertEquals(
                                List.of(2, 2),
                                clientHellos,
                                "оба соединения шли через HRR: два ClientHello");
                        return null;
                    });
        }
    }

    private static void serveTwice(
            ServerSocket listener,
            TlsServerConfig config,
            InMemoryPskStore store,
            List<Boolean> resumed,
            List<Integer> clientHellos,
            AtomicReference<Throwable> serverError) {
        try {
            for (int i = 0; i < 2; i++) {
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
                    session.write(RESPONSE_MARKER.getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Throwable e) {
            serverError.set(e);
        }
    }

    static CurveSpec curve(String ianaName) {
        return OpenSslTls13CrossValidationTest.ALL_CURVES.stream()
                .filter(c -> c.ianaName().equals(ianaName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve: " + ianaName));
    }
}
