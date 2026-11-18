package org.rssys.gost.jsse.examples.netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;
import java.net.InetSocketAddress;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.examples.AbstractFinishedWithRequestTest;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/**
 * Netty: запрос, склеенный с Finished клиента, доставлен. Сервер — {@link SslHandler} поверх
 * движка из {@link SSLContext} с контекстом сессий, поэтому после Finished клиента билет стоит в
 * очереди.
 */
@DisplayName("Netty: запрос, склеенный с Finished клиента, доставлен")
class NettyFinishedWithRequestTest extends AbstractFinishedWithRequestTest {

    /** Предел тела запроса для агрегатора: запрос теста на порядки меньше. */
    private static final int MAX_CONTENT_LENGTH = 64 * 1024;

    private static ExamplesCertHelper helper;
    private static EventLoopGroup bossGroup;
    private static EventLoopGroup workerGroup;
    private static Channel serverChannel;
    private static int port;

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        helper = new ExamplesCertHelper();
        SSLContext serverContext = helper.getSslContext();
        bossGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        serverChannel =
                new ServerBootstrap()
                        .group(bossGroup, workerGroup)
                        .channel(NioServerSocketChannel.class)
                        .childHandler(
                                new ChannelInitializer<SocketChannel>() {
                                    @Override
                                    protected void initChannel(SocketChannel ch) {
                                        SSLEngine engine = serverContext.createSSLEngine();
                                        engine.setUseClientMode(false);
                                        ch.pipeline()
                                                .addLast(
                                                        new SslHandler(engine),
                                                        new HttpServerCodec(),
                                                        new HttpObjectAggregator(
                                                                MAX_CONTENT_LENGTH),
                                                        new EchoHandler());
                                    }
                                })
                        .bind("127.0.0.1", 0)
                        .sync()
                        .channel();
        port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    @AfterAll
    static void stopServer() throws InterruptedException {
        if (serverChannel != null) serverChannel.close().sync();
        if (bossGroup != null) bossGroup.shutdownGracefully().sync();
        if (workerGroup != null) workerGroup.shutdownGracefully().sync();
    }

    @Override
    protected int serverPort() {
        return port;
    }

    @Override
    protected ExamplesCertHelper certHelper() {
        return helper;
    }

    /** Отвечает телом запроса с длиной и закрывает соединение. */
    private static final class EchoHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            FullHttpResponse response =
                    new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1,
                            HttpResponseStatus.OK,
                            Unpooled.copiedBuffer(request.content()));
            response.headers()
                    .setInt(HttpHeaderNames.CONTENT_LENGTH, request.content().readableBytes());
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }
}
