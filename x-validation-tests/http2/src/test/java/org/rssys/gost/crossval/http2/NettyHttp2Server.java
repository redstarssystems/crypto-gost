package org.rssys.gost.crossval.http2;

import io.netty.bootstrap.ServerBootstrap;
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
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.util.ReferenceCountUtil;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.netty.GostSslContext;

/**
 * Сервер HTTP/2 на Netty поверх {@code GostSslContext}: на запрос отвечает {@code PONG <путь>}.
 * Запоминает протокол ALPN, согласованный при рукопожатии: сервер обслуживает только {@code h2},
 * поэтому успешный ответ уже доказывает согласование, а запомненное значение проверяется явно.
 */
final class NettyHttp2Server implements AutoCloseable {

    static final String HTTP2 = "h2";
    private static final String BODY_PREFIX = "PONG ";
    private static final long CLOSE_SECONDS = 5;

    private final EventLoopGroup group;
    private final Channel channel;
    private final AtomicReference<String> negotiated;

    private NettyHttp2Server(
            EventLoopGroup group, Channel channel, AtomicReference<String> negotiated) {
        this.group = group;
        this.channel = channel;
        this.negotiated = negotiated;
    }

    /**
     * Запускает сервер на свободном порту loopback.
     *
     * @param context серверный контекст с ALPN {@code h2}
     * @param namedGroup группа ECDHE, которую сервер предпочитает (под кривую сертификата)
     */
    static NettyHttp2Server start(GostSslContext context, int namedGroup)
            throws InterruptedException {
        AtomicReference<String> negotiated = new AtomicReference<>();
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        try {
            Channel channel =
                    new ServerBootstrap()
                            .group(group)
                            .channel(NioServerSocketChannel.class)
                            .childHandler(
                                    new ChannelInitializer<SocketChannel>() {
                                        @Override
                                        protected void initChannel(SocketChannel ch) {
                                            var tls = context.newHandler(ch.alloc());
                                            ((GostSSLEngine) tls.engine())
                                                    .setClientNamedGroup(namedGroup);
                                            ch.pipeline().addLast(tls);
                                            ch.pipeline().addLast(new Negotiation(negotiated));
                                        }
                                    })
                            .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                            .sync()
                            .channel();
            return new NettyHttp2Server(group, channel, negotiated);
        } catch (InterruptedException | RuntimeException e) {
            group.shutdownGracefully(0, CLOSE_SECONDS, TimeUnit.SECONDS);
            throw e;
        }
    }

    int port() {
        return ((InetSocketAddress) channel.localAddress()).getPort();
    }

    /** @return протокол ALPN, согласованный последним соединением, или null */
    String negotiatedProtocol() {
        return negotiated.get();
    }

    @Override
    public void close() {
        channel.close().awaitUninterruptibly(CLOSE_SECONDS, TimeUnit.SECONDS);
        group.shutdownGracefully(0, CLOSE_SECONDS, TimeUnit.SECONDS)
                .awaitUninterruptibly(CLOSE_SECONDS, TimeUnit.SECONDS);
    }

    private static final class Negotiation extends ApplicationProtocolNegotiationHandler {
        private final AtomicReference<String> negotiated;

        Negotiation(AtomicReference<String> negotiated) {
            super("http/1.1");
            this.negotiated = negotiated;
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
            negotiated.set(protocol);
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
                                            stream.pipeline().addLast(new Stream());
                                        }
                                    }));
        }
    }

    private static final class Stream extends ChannelInboundHandlerAdapter {
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
}
