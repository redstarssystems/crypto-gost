package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Сервер Netty ({@code GostSslContext}) принимает клиент КриптоПро ({@code csptest -tlsc}) с
 * расширением ALPN. Ответ сервера читается из файла, который сохраняет {@code csptest}: код
 * возврата один успех обмена не доказывает.
 *
 * <p>Обработчик создаётся через {@code newHandler}: при ALPN {@code SslHandler.engine()} остаётся
 * {@code GostSSLEngine}, поэтому группа ECDHE задаётся прямо на движке.
 *
 * <p>Направление «клиент Netty -> csptest -tlss» не покрыто: оно требует сертификат в хранилище
 * КриптоПро.
 */
@DisplayName("Netty: сервер GostSslContext <- КриптоПро csptest -tlsc (ALPN)")
class CryptoproNettyAlpnInteropTest {

    /** TLS 1.3 в нумерации {@code csptest -proto}. */
    private static final String CSPTEST_PROTO_TLS13 = "7";

    /** Расширение ALPN в нумерации {@code csptest -tlsext}. */
    private static final String CSPTEST_EXT_ALPN = "1";

    private static final String ALPN_PROTOCOL = "h2";
    private static final String CLIENT_SAVED_FILE = "interop.txt";
    private static final String RESPONSE_MARKER = "INTEROP_OK";
    private static final String CSPTEST_SUCCESS = "[ErrorCode: 0x00000000]";

    private static final Duration CLIENT_TIMEOUT = Duration.ofSeconds(30);
    private static final long SERVER_JOIN_SECONDS = 10;
    private static final int ACCEPT_TIMEOUT_MS = 20_000;
    private static final int SOCKET_POLL_MS = 50;
    private static final long EXCHANGE_TIMEOUT_MS = 15_000;

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
    }

    /** Итог серверной стороны: протокол ALPN, наблюдавшийся после рукопожатия, и ошибка. */
    private record ServerResult(String negotiatedProtocol, Throwable error) {}

    @Test
    @DisplayName("csptest -tlsc -tlsext 1 -alpn h2: ALPN согласован, ответ доходит до клиента")
    void nettyServerNegotiatesAlpnWithCryptoproClient() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(bundle.cert)), bundle.priv);
        GostSslContext serverContext =
                GostSslContextBuilder.forServer(keyManager)
                        .applicationProtocols(ALPN_PROTOCOL, "http/1.1")
                        .build();

        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(ACCEPT_TIMEOUT_MS);
            CompletableFuture<ServerResult> server =
                    CompletableFuture.supplyAsync(
                            () -> serveSingleRequest(listener, serverContext),
                            task -> Thread.ofVirtual().start(task));

            TempDirUtils.withTempDir("cp-netty-alpn-", dir -> {
                CryptoProChecker.Result client = runCsptestClient(dir, listener.getLocalPort());
                // ошибку сервера читаем до проверок клиента: при обрыве рукопожатия именно она
                // называет причину
                ServerResult result = server.get(SERVER_JOIN_SECONDS, TimeUnit.SECONDS);
                String context = "csptest вывод:\n" + client.output()
                        + "\nошибка сервера: " + result.error();

                assertNull(result.error(), "сервер Netty не должен получить ошибку. " + context);
                assertEquals(ALPN_PROTOCOL, result.negotiatedProtocol(),
                        "сервер должен согласовать ALPN с КриптоПро. " + context);
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
                "-tlsext", CSPTEST_EXT_ALPN,
                "-alpn", ALPN_PROTOCOL,
                "-server", InetAddress.getLoopbackAddress().getHostAddress(),
                "-port", Integer.toString(port),
                // сертификат тестовый, цепочки к доверенному корню нет
                "-nocheck",
                "-checkproto",
                "-file", CLIENT_SAVED_FILE);
    }

    /** Принимает одно соединение, отвечает маркером на запрос и возвращает итог. */
    private static ServerResult serveSingleRequest(ServerSocket listener, GostSslContext context) {
        String negotiated = null;
        try (Socket socket = listener.accept()) {
            socket.setSoTimeout(SOCKET_POLL_MS);
            SslHandler handler = context.newHandler(UnpooledByteBufAllocator.DEFAULT);
            // csptest кладёт в key_share только GC256A: группа задаётся на движке, без
            // HelloRetryRequest. Доступ к движку возможен, потому что обработчик создан newHandler
            ((GostSSLEngine) handler.engine()).setClientNamedGroup(TlsConstants.GRP_GC256A);
            EmbeddedChannel channel = new EmbeddedChannel(handler);
            try {
                StringBuilder request = new StringBuilder();
                pumpUntil(channel, socket, request,
                        () -> handler.handshakeFuture().isDone() && request.length() > 0);
                handler.handshakeFuture().sync();
                negotiated = handler.applicationProtocol();

                String response = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "Content-Length: " + RESPONSE_MARKER.length() + "\r\n"
                        + "Connection: close\r\n"
                        + "\r\n"
                        + RESPONSE_MARKER;
                channel.writeOutbound(Unpooled.copiedBuffer(response, StandardCharsets.UTF_8));
                // close_notify, затем FIN, затем остаток до закрытия клиентом: без этого RST
                // на непрочитанные данные дал бы SIGPIPE у csptest
                channel.close();
                flushOutbound(channel, socket);
                socket.shutdownOutput();
                socket.getInputStream().readAllBytes();
                return new ServerResult(negotiated, null);
            } finally {
                closeQuietly(channel);
            }
        } catch (Exception e) {
            return new ServerResult(negotiated, e);
        }
    }

    private static void pumpUntil(EmbeddedChannel channel, Socket socket, StringBuilder received,
            BooleanSupplier done) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(EXCHANGE_TIMEOUT_MS);
        byte[] buffer = new byte[16_384];
        while (!done.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("Тайм-аут обмена с csptest");
            }
            flushOutbound(channel, socket);
            try {
                int n = socket.getInputStream().read(buffer);
                if (n < 0) {
                    throw new IOException("csptest закрыл соединение до запроса");
                }
                channel.writeInbound(Unpooled.copiedBuffer(buffer, 0, n));
                ByteBuf plain;
                while ((plain = channel.readInbound()) != null) {
                    received.append(plain.toString(StandardCharsets.ISO_8859_1));
                    plain.release();
                }
            } catch (SocketTimeoutException idle) {
                // данных пока нет: возвращаемся к проверке условия
            }
            channel.runPendingTasks();
        }
        flushOutbound(channel, socket);
    }

    private static void flushOutbound(EmbeddedChannel channel, Socket socket) throws IOException {
        ByteBuf out;
        while ((out = channel.readOutbound()) != null) {
            byte[] bytes = new byte[out.readableBytes()];
            out.readBytes(bytes);
            out.release();
            socket.getOutputStream().write(bytes);
        }
        socket.getOutputStream().flush();
    }

    private static void closeQuietly(EmbeddedChannel channel) {
        try {
            channel.finishAndReleaseAll();
        } catch (RuntimeException ignored) {
            // итог обмена уже зафиксирован
        }
    }
}
