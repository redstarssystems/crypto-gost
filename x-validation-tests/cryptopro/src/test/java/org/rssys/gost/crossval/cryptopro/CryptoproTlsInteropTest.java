package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Интероп TLS 1.3: сервер crypto-gost принимает клиент КриптоПро ({@code csptest -tlsc}).
 *
 * <p>Тест доказывает не только handshake, но и обмен данными: сервер отдаёт маркер
 * {@link #RESPONSE_MARKER}, клиент сохраняет ответ в файл, и тест читает его оттуда. Код
 * возврата {@code csptest} один не годится: после успешного handshake он может быть 0 и при
 * неудавшемся запросе.
 *
 * <p>Направление «наш клиент -> сервер КриптоПро» (-tlss) не покрыто: оно требует сертификат в
 * хранилище. Magma не покрыта: в
 * {@code TlsCiphersuite} есть только Кузнечик.
 */
@DisplayName("TLS 1.3: сервер crypto-gost <- КриптоПро csptest -tlsc")
class CryptoproTlsInteropTest {

    private static final int SUITE_KUZNYECHIK_L = 0xC103;
    private static final int SUITE_KUZNYECHIK_S = 0xC105;

    /** TLS 1.3 в нумерации {@code csptest -proto}. */
    private static final String CSPTEST_PROTO_TLS13 = "7";

    private static final String CLIENT_SAVED_FILE = "interop.txt";
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final String CSPTEST_SUCCESS = "[ErrorCode: 0x00000000]";

    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(30);
    private static final long SERVER_JOIN_SECONDS = 10;
    private static final int ACCEPT_TIMEOUT_MS = 20_000;
    private static final int PEER_IO_TIMEOUT_MS = 10_000;

    /**
     * Кривые ECDHE. GC256A и GC512C имеют кофактор 4: секрет считается как {@code (h·d)·Q}
     * (RFC 9367 §6.1.1), без кофактора КриптоПро отвергает handshake.
     */
    private record Curve(String name, int groupId, ECParameters params) {}

    private static final Curve GC256A = new Curve("GC256A", TlsConstants.GRP_GC256A, ECParameters.tc26a256());
    private static final Curve GC256B = new Curve("GC256B", TlsConstants.GRP_GC256B, ECParameters.cryptoProA());
    private static final Curve GC256C = new Curve("GC256C", TlsConstants.GRP_GC256C, ECParameters.cryptoProB());
    private static final Curve GC256D = new Curve("GC256D", TlsConstants.GRP_GC256D, ECParameters.cryptoProC());
    private static final Curve GC512A = new Curve("GC512A", TlsConstants.GRP_GC512A, ECParameters.tc26a512());
    private static final Curve GC512B = new Curve("GC512B", TlsConstants.GRP_GC512B, ECParameters.tc26b512());
    private static final Curve GC512C = new Curve("GC512C", TlsConstants.GRP_GC512C, ECParameters.tc26c512());

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
    }

    static Stream<Arguments> suiteAndCurve() {
        // csptest кладёт в key_share только GC256A: для неё ECDHE идёт без HelloRetryRequest,
        // для остальных кривых сервер обязан ответить HRR на выбранную группу (RFC 8446 §4.1.4)
        return Stream.of(GC256A, GC256B, GC256C, GC256D, GC512A, GC512B, GC512C)
                .flatMap(curve -> Stream.of(
                        Arguments.of("Kuznyechik MGM L", SUITE_KUZNYECHIK_L, curve),
                        Arguments.of("Kuznyechik MGM S", SUITE_KUZNYECHIK_S, curve)));
    }

    @ParameterizedTest(name = "{0}, {2}")
    @MethodSource("suiteAndCurve")
    @DisplayName("csptest -tlsc: handshake (с HRR) и обмен данными с сервером crypto-gost")
    void serverServesCryptoproClient(String suiteTitle, int suiteId, Curve curve)
            throws Exception {
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params());
        TlsServerConfig config =
                new TlsServerConfig(
                                TlsCiphersuite.byId(suiteId),
                                Collections.singletonList(bundle.cert),
                                bundle.priv)
                        .withSelectedNamedGroup(curve.groupId());

        try (ServerSocket listener =
                new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            CompletableFuture<Throwable> server =
                    CompletableFuture.supplyAsync(
                            () -> serveSingleRequest(listener, config),
                            task -> Thread.ofVirtual().start(task));

            TempDirUtils.withTempDir("cp-tls-", dir -> {
                CryptoProChecker.Result client = runCsptestClient(dir, listener.getLocalPort());
                // ошибку сервера читаем до проверок клиента: при обрыве handshake именно она
                // называет причину, а клиент видит лишь закрытое соединение
                Throwable serverError = server.get(SERVER_JOIN_SECONDS, TimeUnit.SECONDS);
                String context = "csptest вывод:\n" + client.output()
                        + "\nошибка сервера: " + serverError;

                assertNull(serverError, "сервер crypto-gost не должен получить ошибку. " + context);
                assertEquals(0, client.exitCode(), "csptest должен завершиться кодом 0. " + context);
                assertTrue(client.output().contains(CSPTEST_SUCCESS),
                        "csptest должен сообщить об успехе. " + context);

                Path saved = dir.resolve(CLIENT_SAVED_FILE);
                assertTrue(Files.exists(saved),
                        "csptest должен сохранить ответ сервера в " + CLIENT_SAVED_FILE + ". " + context);
                assertTrue(Files.readString(saved, StandardCharsets.ISO_8859_1).contains(RESPONSE_MARKER),
                        "сохранённый ответ должен содержать " + RESPONSE_MARKER + ". " + context);
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
                "-file", CLIENT_SAVED_FILE);
    }

    /**
     * Закрывает соединение первым, но без RST. Клиент ответа с {@code Connection: close} читает
     * до закрытия сервером и ещё пишет в сокет (закрывающий alert). Если закрыть сокет сразу, на
     * непрочитанные данные уйдёт RST, и {@code csptest} получает SIGPIPE: результат зависит от
     * гонки. Поэтому: close_notify, затем FIN, затем вычитываем остаток до закрытия клиентом.
     */
    private static void closeGracefully(TlsSession session, Socket socket) throws IOException {
        session.close();
        socket.shutdownOutput();
        socket.getInputStream().readAllBytes();
    }

    /** Принимает одно соединение, отвечает маркером на запрос и возвращает ошибку или null. */
    private static Throwable serveSingleRequest(ServerSocket listener, TlsServerConfig config) {
        try (Socket socket = listener.accept();
                SocketTlsTransport transport = new SocketTlsTransport(socket);
                TlsSession session = TlsSession.createServer(config, transport)) {
            // зависший клиент не должен вешать тест: чтение оборвётся по таймауту
            socket.setSoTimeout(PEER_IO_TIMEOUT_MS);
            session.handshakeAsServer();
            session.read();
            String response = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/plain\r\n"
                    + "Content-Length: " + RESPONSE_MARKER.length() + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n"
                    + RESPONSE_MARKER;
            session.write(response.getBytes(StandardCharsets.UTF_8));
            closeGracefully(session, socket);
            return null;
        } catch (Exception e) {
            return e;
        }
    }
}
