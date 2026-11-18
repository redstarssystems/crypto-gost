package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;
import java.security.Security;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.EndpointIdentificationMode;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Проверка имени узла при работе через Netty: Netty при настройке engine передаёт
 * {@code endpointIdentificationAlgorithm = null} и не должен снимать проверку, выставленную при
 * создании engine.
 */
class GostSslContextEndpointIdentificationTest {

    private static final String WRONG_HOST = "wronghost.invalid";

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostSslContext serverCtx;
    private static GostX509TrustManager clientTrust;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        serverCtx = GostSslContextBuilder.forServer(serverKm).build();
        clientTrust =
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));
    }

    // ========================================================================
    // Builder: состояние клиентского контекста
    // ========================================================================

    @Test
    @DisplayName("Builder: по умолчанию клиентский контекст в строгом режиме проверки имени")
    void builderSetsStrictModeByDefault() throws Exception {
        GostSslContext ctx = clientBuilder().build();
        assertEquals(
                EndpointIdentificationMode.STRICT,
                clientSession(ctx).getEndpointIdentificationMode(),
                "по умолчанию строгий режим");
    }

    @Test
    @DisplayName("Builder с общим контекстом сессий: проверка имени сохраняется при SSLParameters")
    void sharedSessionContextKeepsHostnameVerification() throws Exception {
        GostSSLSessionContext shared =
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        GostSslContext ctx = clientBuilder().sessionContext(shared).build();

        // redirectToSharedState режим не переносит, builder выставляет его после перенаправления
        assertEquals(
                EndpointIdentificationMode.STRICT,
                clientSession(ctx).getEndpointIdentificationMode(),
                "строгий режим должен остаться на клиентском контексте");
        SSLEngine engine = ctx.context().createSSLEngine("localhost", 0);
        // Netty при настройке engine передаёт SSLParameters без алгоритма (null)
        engine.setSSLParameters(new SSLParameters());
        assertEquals(
                "HTTPS",
                engine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "новый SSLParameters не должен снимать проверку имени");
    }

    @Test
    @DisplayName("Builder: withoutHostnameVerification переводит контекст в режим DISABLED")
    void builderOptOutDisablesVerification() throws Exception {
        GostSslContext ctx = clientBuilder().withoutHostnameVerification().build();
        assertEquals(
                EndpointIdentificationMode.DISABLED,
                clientSession(ctx).getEndpointIdentificationMode(),
                "opt-out должен включать режим DISABLED");
        SSLEngine direct = ctx.context().createSSLEngine("localhost", 0);
        assertNull(
                direct.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "прямой createSSLEngine при opt-out не получает HTTPS");
    }

    @Test
    @DisplayName("Builder: серверный builder отвергает withoutHostnameVerification")
    void serverBuilderRejectsOptOut() {
        GostX509KeyManager km = new GostX509KeyManager();
        IllegalStateException e =
                assertThrows(
                        IllegalStateException.class,
                        () -> GostSslContextBuilder.forServer(km).withoutHostnameVerification());
        assertTrue(
                e.getMessage().contains("no effect on server side"),
                "ожидалась ошибка серверного opt-out: " + e.getMessage());
    }

    // ========================================================================
    // Реальное рукопожатие через Netty SslHandler
    // ========================================================================

    @Test
    @DisplayName("Netty: сертификат на другое имя отвергается по умолчанию")
    void wrongHostRejectedByDefault() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();
        Throwable cause = handshakeFailure(client, WRONG_HOST);
        assertInstanceOf(SSLException.class, cause, "ожидалась SSL-ошибка: " + cause);
    }

    @Test
    @DisplayName("Netty: совпадающее имя принимается")
    void matchingHostAccepted() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();
        assertNull(handshakeFailure(client, "localhost"), "рукопожатие должно пройти");
    }

    @Test
    @DisplayName("Netty: с withoutHostnameVerification() чужое имя принимается")
    void wrongHostAcceptedWithOptOut() throws Exception {
        GostSslContext client =
                GostSslContextBuilder.forClient()
                        .trustManager(clientTrust)
                        .withoutHostnameVerification()
                        .build();
        assertNull(handshakeFailure(client, WRONG_HOST), "при opt-out рукопожатие должно пройти");
    }

    @Test
    @DisplayName("Netty: клиентский handler без host отказывает до ClientHello")
    void handlerWithoutHostFailsClosed() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        Throwable cause = runHandshake(clientSsl, serverSsl);

        assertInstanceOf(SSLException.class, cause, "ожидалась SSL-ошибка: " + cause);
        assertTrue(
                cause.getMessage().contains("Peer host is required"),
                "отказ должен объяснять отсутствие host: " + cause.getMessage());
    }

    @Test
    @DisplayName("Netty: клиентский handler с blank host отказывает так же, как без host")
    void handlerWithBlankHostFailsClosed() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT, " ", 0);
        SslHandler serverSsl =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        Throwable cause = runHandshake(clientSsl, serverSsl);

        assertInstanceOf(SSLException.class, cause, "ожидалась SSL-ошибка: " + cause);
        assertTrue(
                cause.getMessage().contains("Peer host is required"),
                "отказ должен объяснять отсутствие host: " + cause.getMessage());
    }

    @Test
    @DisplayName("Netty: с withoutHostnameVerification() handler без host рукопожатие проходит")
    void handlerWithoutHostPassesWithOptOut() throws Exception {
        GostSslContext client =
                GostSslContextBuilder.forClient()
                        .trustManager(clientTrust)
                        .withoutHostnameVerification()
                        .build();
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        assertNull(runHandshake(clientSsl, serverSsl), "при opt-out host не нужен");
    }

    @Test
    @DisplayName("Netty: серверный handler без host рукопожатие проходит")
    void serverHandlerWithoutHostPasses() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);

        assertNull(
                runHandshake(clientSsl, serverSsl),
                "сервер имя клиента не сверяет, строгий режим на него не действует");
    }

    @Test
    @DisplayName("Netty: серверный движок не несёт алгоритм проверки имени, клиентский несёт HTTPS")
    void handlerEnginesCarryExpectedAlgorithm() throws Exception {
        GostSslContext client = GostSslContextBuilder.forClient().trustManager(clientTrust).build();

        SSLEngine serverEngine =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0).engine();
        SSLEngine clientEngine =
                client.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0).engine();

        assertInstanceOf(
                GostSSLEngine.class, serverEngine, "движок сервера не должен быть обёрнут");
        assertNull(
                serverEngine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "серверному движку проверка имени клиента не нужна");
        assertEquals(
                "HTTPS",
                clientEngine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "клиентский движок сверяет имя узла");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private GostSslContextBuilder clientBuilder() {
        return GostSslContextBuilder.forClient().trustManager(clientTrust);
    }

    private static GostSSLSessionContext clientSession(GostSslContext ctx) {
        return (GostSSLSessionContext) ctx.context().getClientSessionContext();
    }

    /** Возвращает причину отказа рукопожатия или null, если оно прошло. */
    private static Throwable handshakeFailure(GostSslContext client, String host) throws Exception {
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT, host, 0);
        SslHandler serverSsl =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        return runHandshake(clientSsl, serverSsl);
    }

    private static Throwable runHandshake(SslHandler clientSsl, SslHandler serverSsl)
            throws Exception {
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        try {
            while (!clientSsl.handshakeFuture().isDone() || !serverSsl.handshakeFuture().isDone()) {
                // Отказ клиента завершает его future; сервер при этом может ждать вечно.
                if (clientSsl.handshakeFuture().isDone()
                        && !clientSsl.handshakeFuture().isSuccess()) {
                    break;
                }
                if (System.nanoTime() > deadline) {
                    fail("Тайм-аут рукопожатия");
                }
                boolean progressed = false;
                try {
                    ByteBuf clientOut = clientCh.readOutbound();
                    if (clientOut != null) {
                        serverCh.writeInbound(clientOut.retain());
                        clientOut.release();
                        serverCh.runPendingTasks();
                        progressed = true;
                    }
                    ByteBuf serverOut = serverCh.readOutbound();
                    if (serverOut != null) {
                        clientCh.writeInbound(serverOut.retain());
                        serverOut.release();
                        clientCh.runPendingTasks();
                        progressed = true;
                    }
                    clientCh.runPendingTasks();
                    serverCh.runPendingTasks();
                } catch (Exception e) {
                    return unwrap(e);
                }
                if (!progressed) {
                    Thread.sleep(10);
                }
            }
            if (clientSsl.handshakeFuture().isDone() && !clientSsl.handshakeFuture().isSuccess()) {
                return unwrap(clientSsl.handshakeFuture().cause());
            }
            // Клиент завершает рукопожатие раньше сервера: ошибку сервера не маскируем успехом.
            if (serverSsl.handshakeFuture().isDone() && !serverSsl.handshakeFuture().isSuccess()) {
                return unwrap(serverSsl.handshakeFuture().cause());
            }
            return null;
        } finally {
            clientCh.finishAndReleaseAll();
            serverCh.finishAndReleaseAll();
        }
    }

    private static Throwable unwrap(Throwable t) {
        Throwable cause = t instanceof ExecutionException ? t.getCause() : t;
        return cause instanceof DecoderException && cause.getCause() != null
                ? cause.getCause()
                : cause;
    }
}
