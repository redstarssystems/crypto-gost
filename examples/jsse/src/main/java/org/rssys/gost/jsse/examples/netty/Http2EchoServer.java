package org.rssys.gost.jsse.examples.netty;

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
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.examples.Http2Clients;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * HTTP/2 поверх ГОСТ TLS на Netty: сервер на {@code Http2FrameCodec} и
 * {@code Http2MultiplexHandler}, ALPN выбирает {@code ApplicationProtocolNegotiationHandler}.
 * <p>
 * Что важно знать:
 * <ul>
 *   <li>серверный контекст создаётся с {@code applicationProtocols("h2", ...)}: без ALPN
 *       клиент HTTP/2 не согласует протокол;</li>
 *   <li>обработчик создаётся через {@code newHandler(...)}: при этом
 *       {@code handler.engine()} остаётся {@code GostSSLEngine}, и можно вызвать, например,
 *       {@code setOcspResponse}; путь {@code newEngine(...)} прячет движок в обёртку Netty;</li>
 *   <li>клиентский контекст проверяет имя узла, поэтому клиент обязан создавать обработчик с
 *       узлом: {@code newHandler(alloc, host, port)}.</li>
 * </ul>
 * Пример запускает сервер и обращается к нему клиентом OkHttp (независимая реализация HTTP/2).
 */
public final class Http2EchoServer implements AutoCloseable {

    private static final String HTTP11 = "http/1.1";
    private static final String HTTP2 = "h2";
    private static final String BODY_PREFIX = "PONG ";

    private final EventLoopGroup group;
    private final Channel channel;

    private Http2EchoServer(EventLoopGroup group, Channel channel) {
        this.group = group;
        this.channel = channel;
    }

    /**
     * Запускает сервер на свободном порту loopback.
     *
     * @param context серверный контекст с ALPN {@code h2}
     * @return запущенный сервер
     * @throws InterruptedException если ожидание привязки порта прервано
     */
    public static Http2EchoServer start(GostSslContext context) throws InterruptedException {
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
                                            ch.pipeline().addLast(context.newHandler(ch.alloc()));
                                            ch.pipeline().addLast(new Negotiation());
                                        }
                                    })
                            .bind(new InetSocketAddress("localhost", 0))
                            .sync()
                            .channel();
            return new Http2EchoServer(group, channel);
        } catch (InterruptedException | RuntimeException e) {
            group.shutdownGracefully(0, 5, TimeUnit.SECONDS);
            throw e;
        }
    }

    /** @return порт, на котором слушает сервер */
    public int port() {
        return ((InetSocketAddress) channel.localAddress()).getPort();
    }

    @Override
    public void close() {
        channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
        group.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
    }

    /** После ALPN настраивает конвейер HTTP/2; другой протокол сервер не обслуживает. */
    private static final class Negotiation extends ApplicationProtocolNegotiationHandler {
        Negotiation() {
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
                                            stream.pipeline().addLast(new StreamHandler());
                                        }
                                    }));
        }
    }

    /** Поток запроса: отвечает {@code PONG <путь>}. */
    private static final class StreamHandler extends ChannelInboundHandlerAdapter {
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

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();
        GostSslContext serverContext =
                GostSslContextBuilder.forServer(helper.createKeyManager())
                        .applicationProtocols(HTTP2, HTTP11)
                        .build();
        try (Http2EchoServer server = start(serverContext)) {
            OkHttpClient client = Http2Clients.okHttp(helper);
            Request request =
                    new Request.Builder()
                            .url("https://localhost:" + server.port() + "/ping")
                            .build();
            try (Response response = client.newCall(request).execute()) {
                System.out.println(
                        "protocol=" + response.protocol() + ", body=" + response.body().string());
                System.out.println(
                        response.protocol() == okhttp3.Protocol.HTTP_2 ? "SUCCESS" : "FAIL");
            }
        }
    }
}
