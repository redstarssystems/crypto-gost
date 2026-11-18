package org.rssys.gost.jsse.examples.grpc;

import static org.junit.jupiter.api.Assertions.*;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.ClientAuth;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * gRPC поверх ГОСТ TLS: настоящий клиент и сервер {@code grpc-netty} с {@code GostSslContext},
 * унарный вызов и серверный поток. Для mTLS используется отдельный клиентский сертификат, как
 * в реальном развёртывании.
 */
@DisplayName("gRPC: нешейденный grpc-netty поверх GostSslContext")
class GrpcTest {

    private static final String ALPN_H2 = "h2";
    private static final String HOST = "localhost";

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;

    private Server server;
    private ManagedChannel channel;

    @BeforeAll
    static void createCertificates() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        serverCert = leaf(params, new String[] {HOST});
        clientCert = leaf(params, null);
    }

    private static PkixCertTestHelper.CertBundle leaf(ECParameters params, String[] dnsNames)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                rootCa.priv,
                rootCa.cert.getPublicKey(),
                rootCa.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                dnsNames,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static GostX509KeyManager keyManager(String alias, PkixCertTestHelper.CertBundle bundle)
            throws Exception {
        GostX509KeyManager keyManager = new GostX509KeyManager();
        keyManager.addKeyEntry(
                alias, CertificateBridge.toJca(List.of(bundle.cert, rootCa.cert)), bundle.priv);
        return keyManager;
    }

    private static GostX509TrustManager rootTrust() {
        return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));
    }

    private static GostSslContext plainServer() throws Exception {
        return GostSslContextBuilder.forServer(keyManager("default", serverCert))
                .applicationProtocols(ALPN_H2)
                .build();
    }

    private static GostSslContext mtlsServer() throws Exception {
        return GostSslContextBuilder.forServer(keyManager("default", serverCert))
                .trustManager(rootTrust())
                .clientAuth(ClientAuth.REQUIRE)
                .applicationProtocols(ALPN_H2)
                .build();
    }

    private static GostSslContext client() throws Exception {
        return GostSslContextBuilder.forClient()
                .trustManager(rootTrust())
                .applicationProtocols(ALPN_H2)
                .build();
    }

    private static GostSslContext clientWithCertificate() throws Exception {
        return GostSslContextBuilder.forClient()
                .trustManager(rootTrust())
                .keyManager(keyManager("client", clientCert))
                .applicationProtocols(ALPN_H2)
                .build();
    }

    @AfterEach
    void stop() throws InterruptedException {
        // Сервер мог запуститься, а создание канала упасть: останавливаем то, что есть
        if (channel != null) {
            channel.shutdownNow().awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        }
        if (server != null) {
            server.shutdownNow().awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    private void open(GostSslContext serverContext, GostSslContext clientContext) throws Exception {
        server = GrpcEchoServer.start(serverContext);
        channel = GrpcEchoServer.channel(clientContext, server.getPort());
    }

    @Test
    @DisplayName("Унарный вызов и серверный поток по gRPC")
    void unaryAndServerStreaming() throws Exception {
        open(plainServer(), client());

        byte[] reply = GrpcEchoServer.say(channel, "hello".getBytes(StandardCharsets.UTF_8));
        assertEquals("hello", new String(reply, StandardCharsets.UTF_8), "унарный вызов");

        Iterator<byte[]> stream =
                GrpcEchoServer.repeat(channel, "msg".getBytes(StandardCharsets.UTF_8));
        List<String> received = new ArrayList<>();
        while (stream.hasNext()) {
            received.add(new String(stream.next(), StandardCharsets.UTF_8));
        }
        assertEquals(List.of("msg#0", "msg#1", "msg#2"), received, "серверный поток");
    }

    @Test
    @DisplayName("mTLS с gRPC: обязательный клиентский сертификат, вызов проходит")
    void mutualTls() throws Exception {
        open(mtlsServer(), clientWithCertificate());

        byte[] reply = GrpcEchoServer.say(channel, "mtls".getBytes(StandardCharsets.UTF_8));

        assertEquals("mtls", new String(reply, StandardCharsets.UTF_8), "вызов с mTLS");
    }

    @Test
    @DisplayName("Клиент без сертификата при обязательном mTLS: UNAVAILABLE и алерт 116 в причине")
    void mutualTlsWithoutClientCertificateRejected() throws Exception {
        open(mtlsServer(), client());

        StatusRuntimeException failure =
                assertThrows(
                        StatusRuntimeException.class,
                        () ->
                                GrpcEchoServer.say(
                                        channel, "anonymous".getBytes(StandardCharsets.UTF_8)),
                        "сервер должен отказать клиенту без сертификата");

        // Только UNAVAILABLE с отказом рукопожатия: тайм-аут, неверный порт или ошибка имени
        // дали бы другой код или другую причину и не прошли бы эту проверку
        assertEquals(Status.Code.UNAVAILABLE, failure.getStatus().getCode(), "код статуса");
        SSLHandshakeException handshake = findHandshakeFailure(failure);
        assertNotNull(handshake, "в причине должен быть отказ рукопожатия: " + failure);
        assertTrue(
                handshake.getMessage().contains("alert " + TlsConstants.ALERT_CERTIFICATE_REQUIRED),
                "клиент должен получить certificate_required (116): " + handshake.getMessage());
    }

    @Test
    @DisplayName("Контекст без ALPN h2 gRPC отвергает при настройке канала")
    void contextWithoutAlpnRejectedByGrpc() throws Exception {
        GostSslContext withoutAlpn =
                GostSslContextBuilder.forClient().trustManager(rootTrust()).build();

        assertThrows(
                IllegalArgumentException.class,
                () -> GrpcEchoServer.channel(withoutAlpn, 1),
                "gRPC требует h2 в ALPN контекста");
    }

    private static SSLHandshakeException findHandshakeFailure(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof SSLHandshakeException handshake) {
                return handshake;
            }
        }
        return null;
    }
}
