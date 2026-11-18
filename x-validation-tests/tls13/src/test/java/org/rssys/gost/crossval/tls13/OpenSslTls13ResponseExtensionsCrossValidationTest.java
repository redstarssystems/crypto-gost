package org.rssys.gost.crossval.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.tls13.OpenSslTls13CrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.HandshakeRecordCountingTransport;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Ответные расширения реального сервера OpenSSL (gostprov, TLS 1.3): клиент crypto-gost со
 * строгим разбором EncryptedExtensions и NewSessionTicket не должен отвергать то, что сервер
 * присылает законно. Cookie в HelloRetryRequest и OCSP-ответ в CertificateEntry через s_server
 * получить не удалось (подробности в плане): эти ветки покрыты модульными тестами.
 *
 * <p>Отрицательные случаи (лишнее расширение не в том сообщении) через OpenSSL не воспроизвести,
 * они проверяются модульными тестами на собранных вручную сообщениях. Каждый тест здесь сверяет по
 * {@code -trace}, что нужное расширение действительно пришло: иначе проверка прошла бы вхолостую.
 */
@DisplayName("TLS 1.3: ответные расширения OpenSSL принимаются клиентом crypto-gost")
class OpenSslTls13ResponseExtensionsCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final int SUITE_L_ID = 0xC103;
    private static final int PEER_IO_TIMEOUT_MS = 15_000;
    private static final long TRACE_WAIT_MS = 5_000;

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslTls13Helper.assumeGostTls13();
    }

    /** Результат соединения: что видел клиент и что напечатал s_server. */
    private record Outcome(
            boolean resumed, String alpn, int clientHellos, StringBuffer serverTrace) {}

    /**
     * Число вхождений {@code needle} внутри блока сообщения trace: блок начинается строкой
     * {@code "    <Message>, Length="} и длится до следующей такой строки. Поиск по всему trace дал бы
     * ложное совпадение, если то же расширение встретится в другом сообщении.
     */
    private static int countInMessage(String trace, String message, String needle) {
        int count = 0;
        boolean inside = false;
        for (String line : trace.split("\n")) {
            Matcher header = Pattern.compile("^ {4}(\\w+), Length=").matcher(line);
            if (header.find()) {
                inside = header.group(1).equals(message);
            } else if (inside && line.contains(needle)) {
                count++;
            }
        }
        return count;
    }

    /** Ждёт, пока в блоке сообщения появится нужное число вхождений (вывод s_server буферизуется). */
    private static int awaitInMessage(
            TracedServer server, String message, String needle, int atLeast)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + TRACE_WAIT_MS;
        int count = 0;
        while (System.currentTimeMillis() < deadline) {
            count = countInMessage(server.output.toString(), message, needle);
            if (count >= atLeast) {
                return count;
            }
            Thread.sleep(50);
        }
        return count;
    }

    private static Outcome connect(
            int port,
            GostCertificate serverCert,
            InMemoryPskStore store,
            UnaryOperator<TlsClientConfig> configure,
            TracedServer server)
            throws Exception {
        TlsClientConfig config =
                configure.apply(
                        new TlsClientConfig(
                                        TlsCiphersuite.byId(SUITE_L_ID),
                                        TrustAnchors.ofCertificate(serverCert))
                                .withoutHostnameVerification());
        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                SocketTlsTransport socketTransport = new SocketTlsTransport(socket);
                HandshakeRecordCountingTransport transport =
                        new HandshakeRecordCountingTransport(socketTransport);
                TlsSession client = TlsSession.createClient(config, transport)) {
            socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
            if (store != null) {
                client.setPskStore(store);
            }
            client.handshakeAsClient();
            client.write(
                    "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            // чтение ответа заодно обрабатывает NewSessionTicket сервера
            byte[] response = client.read();
            assertTrue(response.length > 0, "ответ s_server должен содержать данные");
            return new Outcome(
                    client.wasResumed(),
                    client.getAlpnProtocol(),
                    transport.sentPlainHandshakeRecords(),
                    server.output);
        }
    }

    /** Запускает s_server на GC256B с дополнительными ключами и передаёт сценарию. */
    private interface Scenario {
        void run(int port, GostCertificate serverCert, TracedServer server, Path tmpDir)
                throws Exception;
    }

    private static void withServer(
            Function<Path, String[]> extraArgsForDir, Scenario scenario) throws Exception {
        CurveSpec curve =
                OpenSslTls13CrossValidationTest.ALL_CURVES.stream()
                        .filter(c -> c.ianaName().equals("GC256B"))
                        .findFirst()
                        .orElseThrow();
        int port = OpenSslTls13Helper.findFreePort();
        TempDirUtils.withTempDir(
                "tls13-response-ext-",
                tmpDir -> {
                    OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
                    String[] extraArgs = extraArgsForDir.apply(tmpDir);
                    String[] args = new String[extraArgs.length + 3];
                    args[0] = "-sigalgs";
                    args[1] = curve.sigalgsName();
                    args[2] = "-trace";
                    System.arraycopy(extraArgs, 0, args, 3, extraArgs.length);
                    try (TracedServer server =
                            new TracedServer(
                                    OpenSslTls13Helper.startSServer(
                                            port,
                                            SUITE_L,
                                            curve.ianaName(),
                                            tmpDir.resolve("cert.pem").toString(),
                                            tmpDir.resolve("key.pem").toString(),
                                            args))) {
                        assertTrue(server.awaitOutput("ACCEPT", 10_000), "s_server не запустился");
                        GostCertificate serverCert =
                                GostCertificate.fromPemOrDer(
                                        Files.readAllBytes(tmpDir.resolve("cert.pem")));
                        scenario.run(port, serverCert, server, tmpDir);
                    }
                    return null;
                });
    }

    @Test
    @DisplayName("ALPN: сервер выбирает h2 из списка клиента, не совпадающего с первым элементом")
    void alpnNegotiatedWithOpenSsl() throws Exception {
        withServer(
                dir -> new String[] {"-alpn", "h2"},
                (port, serverCert, server, tmpDir) -> {
                    // h2 не первый в списке клиента: проверяется согласование, а не совпадение
                    // первого элемента
                    Outcome outcome =
                            connect(
                                    port,
                                    serverCert,
                                    null,
                                    cfg -> cfg.withAlpnProtocols(List.of("http/1.1", "h2")),
                                    server);
                    assertEquals("h2", outcome.alpn(), "клиент должен получить протокол сервера");
                    String alpn = "extension_type=application_layer_protocol_negotiation";
                    assertTrue(
                            awaitInMessage(server, "ClientHello", alpn, 1) >= 1,
                            "по trace ALPN должен прийти в ClientHello");
                    assertTrue(
                            awaitInMessage(server, "EncryptedExtensions", alpn, 1) >= 1,
                            "по trace ALPN должен прийти в EncryptedExtensions");
                });
    }

    @Test
    @DisplayName("NewSessionTicket с early_data: тикет принят, второе соединение возобновляется")
    void ticketWithEarlyDataAccepted() throws Exception {
        withServer(
                dir -> new String[] {"-early_data", "-max_early_data", "16384"},
                (port, serverCert, server, tmpDir) -> {
                    InMemoryPskStore store = new InMemoryPskStore(10);
                    Outcome first = connect(port, serverCert, store, c -> c, server);
                    assertFalse(first.resumed(), "первое соединение полное");
                    assertTrue(store.size() > 0, "тикет с early_data должен быть сохранён");
                    Outcome second = connect(port, serverCert, store, c -> c, server);
                    assertTrue(second.resumed(), "второе соединение возобновляется по тикету");
                    // Расширение early_data именно в NewSessionTicket: тикет не отвергнут из-за него
                    assertTrue(
                            awaitInMessage(
                                            server,
                                            "NewSessionTicket",
                                            "extension_type=early_data",
                                            1)
                                    >= 1,
                            "по trace NewSessionTicket должен нести early_data");
                });
    }
}
