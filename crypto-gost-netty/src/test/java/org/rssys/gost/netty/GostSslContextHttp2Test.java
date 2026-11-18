package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.netty.NettyTestSupport.Fixture;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Настоящий HTTP/2 поверх {@code GostSslContext}: сервер и клиент на {@code Http2FrameCodec} и
 * {@code Http2MultiplexHandler}, обмен кадрами по настоящему TCP. Проверяется не метка ALPN, а
 * запрос и ответ по потоку HTTP/2, в том числе с mTLS и клиентским OCSP-staple.
 */
@DisplayName("Netty: HTTP/2 поверх GostSslContext")
class GostSslContextHttp2Test {

    private static final String HOST = "localhost";
    private static final String PATH = "/ping";
    private static final String BODY_PREFIX = "PONG ";
    private static final String HTTP2 = "h2";
    private static final String HTTP11 = "http/1.1";
    private static final long TIMEOUT_SECONDS = 15;

    private static Fixture fixture;

    @BeforeAll
    static void setUp() throws Exception {
        fixture = new Fixture();
    }

    /** Итог запроса, увиденный клиентом, и протокол ALPN на обеих сторонах. */
    private record Exchange(
            String status,
            String body,
            String clientProtocol,
            String serverProtocol,
            int serverPeerCertificates) {}

    @Test
    @DisplayName("Запрос и ответ по потоку HTTP/2, ALPN h2 на обеих сторонах")
    void requestAndResponseOverHttp2() throws Exception {
        GostSslContext server =
                GostSslContextBuilder.forServer(fixture.serverKeyManager())
                        .applicationProtocols(HTTP2, HTTP11)
                        .build();
        GostSslContext client =
                GostSslContextBuilder.forClient()
                        .trustManager(fixture.rootTrust())
                        .applicationProtocols(HTTP2, HTTP11)
                        .build();

        Exchange exchange = exchange(server, client, null);

        assertEquals("200", exchange.status(), "статус ответа");
        assertEquals(BODY_PREFIX + PATH, exchange.body(), "тело ответа по потоку HTTP/2");
        assertEquals(HTTP2, exchange.clientProtocol(), "ALPN клиента");
        assertEquals(HTTP2, exchange.serverProtocol(), "ALPN сервера");
    }

    @Test
    @DisplayName("h2 + mTLS + обязательный клиентский staple: запрос проходит по HTTP/2")
    void http2WithMtlsAndClientStaple() throws Exception {
        GostSslContext server =
                GostSslContextBuilder.forServer(fixture.serverKeyManager())
                        .trustManager(fixture.rootTrust())
                        .clientAuth(ClientAuth.REQUIRE)
                        .clientOcspPolicy(ClientOcspPolicy.REQUIRE)
                        .applicationProtocols(HTTP2, HTTP11)
                        .build();
        GostSslContext client =
                GostSslContextBuilder.forClient()
                        .trustManager(fixture.rootTrust())
                        .keyManager(fixture.clientKeyManager())
                        .applicationProtocols(HTTP2, HTTP11)
                        .build();
        byte[] staple =
                GostOcspResponseBuilder.create(fixture.clientCert.cert.getSerialNumber())
                        .issuerDn(fixture.rootCa.subjectDn)
                        .thisUpdate(Instant.now())
                        .noNextUpdate()
                        .sign(fixture.rootCa.priv);

        Exchange exchange = exchange(server, client, staple);

        assertEquals("200", exchange.status(), "статус ответа");
        assertEquals(BODY_PREFIX + PATH, exchange.body(), "тело ответа по потоку HTTP/2");
        assertEquals(HTTP2, exchange.clientProtocol(), "ALPN клиента");
        assertTrue(
                exchange.serverPeerCertificates() > 0,
                "сервер должен видеть клиентский сертификат (mTLS при HTTP/2)");
    }

    // ========================================================================
    // Сервер и клиент
    // ========================================================================

    private static Exchange exchange(
            GostSslContext serverContext, GostSslContext clientContext, byte[] clientStaple)
            throws Exception {
        EventLoopGroup serverGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        EventLoopGroup clientGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        AtomicReference<SslHandler> serverTls = new AtomicReference<>();
        try {
            Channel serverChannel =
                    new ServerBootstrap()
                            .group(serverGroup)
                            .channel(NioServerSocketChannel.class)
                            .childHandler(
                                    new ChannelInitializer<SocketChannel>() {
                                        @Override
                                        protected void initChannel(SocketChannel ch) {
                                            SslHandler tls = serverContext.newHandler(ch.alloc());
                                            serverTls.set(tls);
                                            ch.pipeline().addLast(tls);
                                            ch.pipeline().addLast(new ServerNegotiation());
                                        }
                                    })
                            .bind(new InetSocketAddress(HOST, 0))
                            .sync()
                            .channel();
            int port = ((InetSocketAddress) serverChannel.localAddress()).getPort();

            CompletableFuture<ClientResponse> response = new CompletableFuture<>();
            AtomicReference<SslHandler> clientTls = new AtomicReference<>();
            Channel clientChannel =
                    new Bootstrap()
                            .group(clientGroup)
                            .channel(NioSocketChannel.class)
                            .handler(
                                    new ChannelInitializer<SocketChannel>() {
                                        @Override
                                        protected void initChannel(SocketChannel ch) {
                                            SslHandler tls =
                                                    clientContext.newHandler(
                                                            ch.alloc(), HOST, port);
                                            if (clientStaple != null) {
                                                // staple задаётся на движке до добавления
                                                // обработчика в канал: рукопожатие начинается при
                                                // добавлении
                                                ((GostSSLEngine) tls.engine())
                                                        .setOcspResponse(clientStaple);
                                            }
                                            clientTls.set(tls);
                                            ch.pipeline().addLast(tls);
                                            ch.pipeline().addLast(new ClientNegotiation(response));
                                        }
                                    })
                            .connect(new InetSocketAddress(HOST, port))
                            .sync()
                            .channel();
            try {
                ClientResponse result = response.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                SslHandler server = serverTls.get();
                int peers = 0;
                try {
                    peers = server.engine().getSession().getPeerCertificates().length;
                } catch (javax.net.ssl.SSLPeerUnverifiedException anonymous) {
                    // клиент без сертификата: у сервера нет пира
                }
                return new Exchange(
                        result.status(),
                        result.body(),
                        clientTls.get().applicationProtocol(),
                        server.applicationProtocol(),
                        peers);
            } finally {
                clientChannel.close().awaitUninterruptibly(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                serverChannel.close().awaitUninterruptibly(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
        } finally {
            shutdown(clientGroup);
            shutdown(serverGroup);
        }
    }

    private static void shutdown(EventLoopGroup group) {
        Future<?> done = group.shutdownGracefully(0, TIMEOUT_SECONDS, TimeUnit.SECONDS);
        done.awaitUninterruptibly(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private record ClientResponse(String status, String body) {}

    /** Серверная сторона: после ALPN настраивает конвейер HTTP/2. */
    private static final class ServerNegotiation extends ApplicationProtocolNegotiationHandler {
        ServerNegotiation() {
            super(HTTP11);
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
            if (!HTTP2.equals(protocol)) {
                ctx.close();
                return;
            }
            ctx.pipeline()
                    .addLast(
                            Http2FrameCodecBuilder.forServer().build(),
                            new Http2MultiplexHandler(
                                    new ChannelInitializer<Channel>() {
                                        @Override
                                        protected void initChannel(Channel stream) {
                                            stream.pipeline().addLast(new ServerStream());
                                        }
                                    }));
        }
    }

    /** Поток сервера: на запрос с путём отвечает {@code PONG <путь>}. */
    private static final class ServerStream extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof Http2HeadersFrame headers && headers.isEndStream()) {
                String body = BODY_PREFIX + headers.headers().path();
                ctx.write(
                        new DefaultHttp2HeadersFrame(
                                new DefaultHttp2Headers().status("200"), false));
                ctx.writeAndFlush(
                        new DefaultHttp2DataFrame(
                                Unpooled.copiedBuffer(body, StandardCharsets.UTF_8), true));
            } else {
                ReferenceCountUtil.release(msg);
            }
        }
    }

    /** Клиентская сторона: после ALPN настраивает конвейер и отправляет запрос. */
    private static final class ClientNegotiation extends ApplicationProtocolNegotiationHandler {
        private final CompletableFuture<ClientResponse> response;

        ClientNegotiation(CompletableFuture<ClientResponse> response) {
            super(HTTP11);
            this.response = response;
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
            if (!HTTP2.equals(protocol)) {
                response.completeExceptionally(
                        new IllegalStateException("ожидался h2, согласовано: " + protocol));
                ctx.close();
                return;
            }
            ctx.pipeline()
                    .addLast(
                            Http2FrameCodecBuilder.forClient().build(),
                            new Http2MultiplexHandler(new ChannelInboundHandlerAdapter()));
            Channel parent = ctx.channel();
            new Http2StreamChannelBootstrap(parent)
                    .handler(new ClientStream(response))
                    .open()
                    .addListener(
                            opened -> {
                                if (!opened.isSuccess()) {
                                    response.completeExceptionally(opened.cause());
                                    return;
                                }
                                Http2StreamChannel stream = (Http2StreamChannel) opened.getNow();
                                Http2Headers headers =
                                        new DefaultHttp2Headers()
                                                .method("GET")
                                                .path(PATH)
                                                .scheme("https")
                                                .authority(HOST);
                                stream.writeAndFlush(new DefaultHttp2HeadersFrame(headers, true));
                            });
        }

        @Override
        protected void handshakeFailure(ChannelHandlerContext ctx, Throwable cause) {
            response.completeExceptionally(cause);
            ctx.close();
        }
    }

    /** Поток клиента: собирает статус и тело ответа. */
    private static final class ClientStream extends ChannelInboundHandlerAdapter {
        private final CompletableFuture<ClientResponse> response;
        private String status;
        private final StringBuilder body = new StringBuilder();

        ClientStream(CompletableFuture<ClientResponse> response) {
            this.response = response;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            try {
                if (msg instanceof Http2HeadersFrame headers) {
                    status = String.valueOf(headers.headers().status());
                } else if (msg instanceof Http2DataFrame data) {
                    ByteBuf content = data.content();
                    body.append(content.toString(StandardCharsets.UTF_8));
                    if (data.isEndStream()) {
                        response.complete(new ClientResponse(status, body.toString()));
                    }
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            response.completeExceptionally(cause);
        }
    }
}
