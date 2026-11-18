package org.rssys.gost.crossval.http2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Внешний HTTP/2-клиент поверх внешнего ГОСТ TLS против сервера Netty: единственная проверка, где
 * кадры HTTP/2 разбирает не наш код и не Netty.
 *
 * <p>Цепочка: {@code curl --http2-prior-knowledge} (nghttp2) говорит по открытому каналу с
 * {@code socat}, который запускает {@code openssl s_client -alpn h2} (ГОСТ-сборка OpenSSL) и
 * соединяет его со входом и выходом. TLS-соединение идёт на сервер Netty с
 * {@code GostSslContext}. Успех обмена доказывает, что внешний клиент получил HTTP/2 поверх
 * ГОСТ TLS от нашего сервера; {@code curl -w %{http_version}} отдаёт версию протокола, а сервер
 * запоминает согласованный ALPN.
 *
 * <p>Обратное направление (клиент Netty против внешнего сервера HTTP/2) не покрыто: на машине
 * нет внешнего сервера HTTP/2 ({@code nghttpd}, {@code nginx}), а {@code s_server} HTTP/2 не
 * говорит.
 *
 * <p>{@code s_client} не проверяет сертификат сервера (нет {@code -CAfile} и
 * {@code -verify_return_error}): здесь проверяется HTTP/2 и ALPN, а проверка сертификатов
 * покрыта другими тестами кросс-валидации. Свободный порт для {@code socat} берётся через
 * {@code ServerSocket(0)} и освобождается до запуска: теоретически его мог бы занять другой
 * процесс, на 20 прогонах подряд этого не случилось.
 *
 * <p>{@code s_client} запускается с {@code -nocommands}: без него байты {@code Q}, {@code R},
 * {@code k} внутри двоичных кадров HTTP/2 он принял бы за команды (выход, повторное
 * рукопожатие, обновление ключа).
 */
@DisplayName("HTTP/2: curl (nghttp2) -> socat -> openssl s_client (ГОСТ TLS) -> сервер Netty")
class ExternalHttp2ChainTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String CURVE_NAME = "GC256B";
    private static final String SIGALGS = "gostr34102012_256b";
    private static final String PATH = "/ping";
    private static final long CURL_TIMEOUT_SECONDS = 20;
    private static final long SOCAT_LIFETIME_SECONDS = 25;
    private static final long CLEANUP_SECONDS = 3;

    @BeforeAll
    static void preconditions() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        assumeTrue(
                toolRuns("curl", "--version") && curlSupportsHttp2(),
                "нужен curl с поддержкой HTTP/2");
        assumeTrue(toolRuns("socat", "-V"), "нужен socat");
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeGostTls13();
    }

    @Test
    @DisplayName("curl --http2-prior-knowledge получает ответ сервера Netty по HTTP/2")
    void externalHttp2ClientTalksToNettyServer() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.cryptoProA());
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(bundle.cert)), bundle.priv);
        GostSslContext context =
                GostSslContextBuilder.forServer(keyManager).applicationProtocols("h2").build();

        try (NettyHttp2Server server = NettyHttp2Server.start(context, TlsConstants.GRP_GC256B)) {
            TempDirUtils.withTempDir(
                    "http2-chain-",
                    dir -> {
                        ChainResult result = runChain(dir, server.port());
                        String context1 =
                                "curl: "
                                        + result.curlOutput()
                                        + "\nsocat/s_client: "
                                        + result.tunnelLog();

                        assertEquals(
                                0,
                                result.curlExit(),
                                "curl должен завершиться кодом 0. " + context1);
                        assertEquals(
                                "2",
                                result.httpVersion(),
                                "curl должен сообщить HTTP/2. " + context1);
                        assertEquals(
                                "PONG " + PATH,
                                result.body(),
                                "тело ответа сервера Netty. " + context1);
                        assertEquals(
                                NettyHttp2Server.HTTP2,
                                server.negotiatedProtocol(),
                                "сервер Netty должен согласовать ALPN h2. " + context1);
                        return null;
                    });
        }
    }

    private record ChainResult(
            int curlExit, String curlOutput, String httpVersion, String body, String tunnelLog) {}

    private static ChainResult runChain(Path dir, int nettyPort) throws Exception {
        int tunnelPort = freePort();
        Path bodyFile = dir.resolve("body.txt");
        Process socat = startTunnel(tunnelPort, nettyPort);
        try {
            Process curl =
                    new ProcessBuilder(
                                    "curl",
                                    "-sS",
                                    // socat поднимается не мгновенно: повтор при отказе в
                                    // соединении
                                    "--retry",
                                    "10",
                                    "--retry-connrefused",
                                    "--retry-delay",
                                    "1",
                                    "--http2-prior-knowledge",
                                    "-m",
                                    Long.toString(CURL_TIMEOUT_SECONDS),
                                    "-o",
                                    bodyFile.toString(),
                                    "-w",
                                    "%{http_version}",
                                    "http://127.0.0.1:" + tunnelPort + PATH)
                            .redirectErrorStream(true)
                            .start();
            boolean finished = curl.waitFor(CURL_TIMEOUT_SECONDS + 5, TimeUnit.SECONDS);
            if (!finished) {
                curl.destroyForcibly();
            }
            String output =
                    new String(curl.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            String body =
                    Files.exists(bodyFile)
                            ? Files.readString(bodyFile, StandardCharsets.UTF_8)
                            : "";
            int exit = finished ? curl.exitValue() : -1;
            return new ChainResult(exit, output, finished ? output : "", body, drain(socat));
        } finally {
            destroy(socat);
        }
    }

    /** Туннель: socat принимает одно соединение curl и подключает его к s_client. */
    private static Process startTunnel(int tunnelPort, int nettyPort) throws Exception {
        // Окружение ГОСТ-сборки OpenSSL (LD_LIBRARY_PATH и др.) нужно только s_client: системный
        // socat, получив его, падает на несовместимых символах libssl. Поэтому оно передаётся
        // через env внутри команды, а не процессу socat
        List<String> sClient = new ArrayList<>(List.of("env"));
        OpenSslChecker.getOpenSslEnv().forEach((name, value) -> sClient.add(name + "=" + value));
        sClient.addAll(
                List.of(
                        OpenSslChecker.resolveOpenSslBinary(),
                        "s_client",
                        "-connect",
                        "127.0.0.1:" + nettyPort,
                        "-tls1_3",
                        "-ciphersuites",
                        SUITE_L,
                        "-curves",
                        CURVE_NAME,
                        "-sigalgs",
                        SIGALGS,
                        "-alpn",
                        "h2",
                        "-quiet",
                        "-nocommands"));
        sClient.addAll(List.of(OpenSslChecker.resolveTls13Flags()));
        List<String> socat =
                List.of(
                        "socat",
                        "-T",
                        Long.toString(SOCAT_LIFETIME_SECONDS),
                        "TCP-LISTEN:" + tunnelPort + ",bind=127.0.0.1,reuseaddr",
                        // кавычки нужны: двоеточие в адресе -connect socat иначе счёл бы
                        // разделителем
                        "EXEC:'" + String.join(" ", sClient) + "'");
        return new ProcessBuilder(socat).redirectErrorStream(true).start();
    }

    private static String drain(Process process) throws IOException {
        return process.isAlive()
                ? "(процесс ещё работает)"
                : new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void destroy(Process process) throws InterruptedException {
        // socat запускает s_client дочерним процессом: гасим всё дерево, иначе s_client мог бы
        // пережить тест
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        process.waitFor(CLEANUP_SECONDS, TimeUnit.SECONDS);
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static boolean toolRuns(String... command) {
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            process.getInputStream().readAllBytes();
            return process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean curlSupportsHttp2() throws Exception {
        Process process = new ProcessBuilder("curl", "--version").redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        process.waitFor(10, TimeUnit.SECONDS);
        return output.contains("HTTP2");
    }
}
