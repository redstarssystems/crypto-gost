package org.rssys.gost.crossval.jsse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.jsse.OpenSslJsseCrossValidationTest.CurveSpec;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * Клиент Netty ({@code GostSslContext}) против внешнего сервера OpenSSL ({@code s_server}) с
 * ALPN. Проверяется то, что внутренние тесты доказать не могут: поведение ALPN при настоящей
 * внешней реализации.
 *
 * <p>Сетевой ввод-вывод ведётся вручную между {@code EmbeddedChannel} и сокетом: так проверяется
 * именно {@code SslHandler} Netty и {@code GostSSLEngine} под ним, без зависимости от цикла
 * событий транспорта.
 */
@DisplayName("Netty: клиент GostSslContext <-> OpenSSL s_server (ALPN)")
class OpenSslNettyCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String CURVE = "GC256B";
    private static final String HOST = "localhost";
    private static final String REQUEST = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    private static final String RESPONSE_STATUS = "HTTP/1.0 200 ok";
    private static final long ACCEPT_TIMEOUT_MS = 10_000;
    private static final long EXCHANGE_TIMEOUT_MS = 15_000;
    private static final int SOCKET_POLL_MS = 50;

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslJsseHelper.assumeGostTls13();
    }

    @Test
    @DisplayName("s_server -alpn h2,http/1.1: клиент Netty получает h2 и обменивается данными")
    void alpnNegotiatedWithOpenSslServer() throws Exception {
        ExchangeResult result = connect("h2", "h2,http/1.1");

        assertEquals("h2", result.negotiatedProtocol(), "ALPN должен согласоваться с OpenSSL");
        assertTrue(
                result.response().contains(RESPONSE_STATUS),
                "ответ s_server должен прийти через TLS: " + result.response());
    }

    @Test
    @DisplayName("s_server -alpn http/1.1 при клиенте h2: OpenSSL отвечает алертом 120")
    void alpnMismatchRejectedByOpenSslServer() {
        // RFC 7301 §3.2: при отсутствии общего протокола сервер завершает рукопожатие алертом
        // no_application_protocol. Клиент Netty обязан довести его как SSL-отказ, а не молча
        // продолжить без ALPN
        DecoderException failure =
                assertThrows(DecoderException.class, () -> connect("h2", "http/1.1"));

        assertInstanceOf(
                SSLHandshakeException.class,
                failure.getCause(),
                "отказ должен дойти как SSL-ошибка рукопожатия: " + failure);
        assertTrue(
                hasAlert120(failure),
                "клиент должен получить fatal alert 120 от OpenSSL: " + failure);
    }

    private static boolean hasAlert120(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null && message.contains("alert 120")) {
                return true;
            }
        }
        return false;
    }

    private record ExchangeResult(String negotiatedProtocol, String response) {}

    private static ExchangeResult connect(String clientAlpn, String serverAlpn) throws Exception {
        CurveSpec curve = OpenSslJsseCrossValidationTest.ALL_CURVES.stream()
                .filter(c -> c.ianaName().equals(CURVE))
                .findFirst()
                .orElseThrow();
        int port = OpenSslJsseHelper.findFreePort();
        // Сертификат s_server тестовый и выпущен не на localhost: проверка имени отключена
        // осознанно, как в других внешних тестах, где цепочка доверия не строится
        GostSslContext context =
                GostSslContextBuilder.forClient()
                        .trustManager(GostX509TrustManager.insecureTrustAll())
                        .withoutHostnameVerification()
                        .applicationProtocols(clientAlpn)
                        .build();

        return TempDirUtils.withTempDir("netty-openssl-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo(), curve.paramset());
            Process sServer = OpenSslJsseHelper.startSServer(port, SUITE_L, curve.ianaName(),
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName(),
                    "-alpn", serverAlpn);
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", ACCEPT_TIMEOUT_MS),
                        "s_server не запустился");
                SslHandler handler = context.newHandler(UnpooledByteBufAllocator.DEFAULT, HOST, port);
                try (SocketPump pump = new SocketPump(handler, port)) {
                    pump.pumpUntil(() -> handler.handshakeFuture().isDone());
                    handler.handshakeFuture().sync();
                    String protocol = handler.applicationProtocol();
                    pump.send(REQUEST);
                    pump.pumpUntil(() -> pump.received().contains(RESPONSE_STATUS));
                    return new ExchangeResult(protocol, pump.received());
                }
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
        });
    }

    /** Переносит байты между {@code EmbeddedChannel} с обработчиком и TCP-сокетом. */
    private static final class SocketPump implements AutoCloseable {
        private final Socket socket;
        private final EmbeddedChannel channel;
        private final StringBuilder received = new StringBuilder();
        private final byte[] buffer = new byte[16_384];

        SocketPump(SslHandler handler, int port) throws IOException {
            this.socket = new Socket(InetAddress.getLoopbackAddress(), port);
            this.socket.setSoTimeout(SOCKET_POLL_MS);
            this.channel = new EmbeddedChannel(handler);
        }

        String received() {
            return received.toString();
        }

        void send(String text) throws IOException {
            channel.writeOutbound(Unpooled.copiedBuffer(text, StandardCharsets.UTF_8));
            flushOutbound();
        }

        void pumpUntil(BooleanSupplier done) throws IOException {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(EXCHANGE_TIMEOUT_MS);
            while (!done.getAsBoolean()) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("Тайм-аут обмена с s_server");
                }
                flushOutbound();
                readFromSocket();
                channel.runPendingTasks();
            }
            flushOutbound();
        }

        private void flushOutbound() throws IOException {
            ByteBuf out;
            while ((out = channel.readOutbound()) != null) {
                byte[] bytes = new byte[out.readableBytes()];
                out.readBytes(bytes);
                out.release();
                socket.getOutputStream().write(bytes);
            }
            socket.getOutputStream().flush();
        }

        private void readFromSocket() throws IOException {
            try {
                int n = socket.getInputStream().read(buffer);
                if (n < 0) {
                    throw new IOException("s_server закрыл соединение");
                }
                channel.writeInbound(Unpooled.copiedBuffer(buffer, 0, n));
                ByteBuf plain;
                while ((plain = channel.readInbound()) != null) {
                    received.append(plain.toString(StandardCharsets.UTF_8));
                    plain.release();
                }
            } catch (SocketTimeoutException idle) {
                // данных пока нет: цикл вернётся к проверке условия
            }
        }

        @Override
        public void close() throws IOException {
            try {
                channel.finishAndReleaseAll();
            } catch (RuntimeException ignored) {
                // закрытие после проверок не должно затирать их результат
            } finally {
                socket.close();
            }
        }
    }
}
