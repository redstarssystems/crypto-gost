package org.rssys.gost.jsse.examples.netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * Демонстрация интеграции crypto-gost-jsse с Netty.
 * <p>
 * GostSslContextBuilder оборачивает JSSE-провайдер в Netty SslHandler.
 * В отличие от других примеров, клиент тоже через Netty Bootstrap —
 * GostSSLSocket не покрывает Netty pipeline (handler chain, ByteBuf allocator).
 */
public final class NettyEchoServer {

    private NettyEchoServer() {}

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();
        GostX509KeyManager km = helper.createKeyManager();
        GostX509TrustManager tm = helper.createTrustManager();

        // GostSslContextBuilder.build() сам регистрирует RssysGostJsseProvider
        GostSslContext serverCtx = GostSslContextBuilder.forServer(km).trustManager(tm).build();

        GostSslContext clientCtx = GostSslContextBuilder.forClient().trustManager(tm).build();

        // Boss = 1 thread (accept), worker = сколько даст NioEventLoopGroup
        // Клиент — отдельная группа, чтобы не конкурировать с worker'ами сервера
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        EventLoopGroup clientGroup = new NioEventLoopGroup(1);

        CountDownLatch serverReady = new CountDownLatch(1);
        AtomicReference<ChannelFuture> serverBindRef = new AtomicReference<>();

        try {
            ServerBootstrap sb = new ServerBootstrap();
            sb.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(
                            new ChannelInitializer<SocketChannel>() {
                                @Override
                                protected void initChannel(SocketChannel ch) {
                                    // SslHandler — первый в pipeline, ниже — бизнес-логика
                                    ch.pipeline()
                                            .addLast(
                                                    serverCtx.newHandler(ch.alloc()),
                                                    new ServerEchoHandler());
                                }
                            });

            // bind(0) — эфемерный порт: netty выделит свободный
            ChannelFuture bindFuture = sb.bind(0).sync();
            serverBindRef.set(bindFuture);
            int port = ((InetSocketAddress) bindFuture.channel().localAddress()).getPort();
            serverReady.countDown();

            CountDownLatch clientDone = new CountDownLatch(1);
            AtomicReference<String> clientResult = new AtomicReference<>("FAIL");

            Bootstrap cl = new Bootstrap();
            cl.group(clientGroup)
                    .channel(NioSocketChannel.class)
                    .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                    .handler(
                            new ChannelInitializer<SocketChannel>() {
                                @Override
                                protected void initChannel(SocketChannel ch) {
                                    ch.pipeline()
                                            .addLast(
                                                    clientCtx.newHandler(
                                                            ch.alloc(), "localhost", port),
                                                    new ClientEchoHandler(
                                                            clientDone, clientResult));
                                }
                            });

            cl.connect("localhost", port).sync();

            if (!clientDone.await(15, TimeUnit.SECONDS)) {
                System.out.println("FAIL (timeout)");
            } else {
                System.out.println(clientResult.get());
            }
        } finally {
            // shutdownGracefully(0, 1) — не ждать завершения таймеров, max 1s на close
            if (serverBindRef.get() != null) {
                serverBindRef.get().channel().close().sync();
            }
            bossGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS);
            workerGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS);
            clientGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS);
        }
    }

    private static final class ServerEchoHandler extends SimpleChannelInboundHandler<ByteBuf> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
            String text = msg.toString(CharsetUtil.UTF_8).trim();
            if ("PING".equals(text)) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("PONG\n", CharsetUtil.UTF_8));
            }
        }
    }

    private static final class ClientEchoHandler extends ChannelInboundHandlerAdapter {
        private final CountDownLatch done;
        private final AtomicReference<String> result;

        ClientEchoHandler(CountDownLatch done, AtomicReference<String> result) {
            this.done = done;
            this.result = result;
        }

        // Отправляем PING сразу после установки SSL-соединения
        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            ctx.writeAndFlush(Unpooled.copiedBuffer("PING\n", CharsetUtil.UTF_8));
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ByteBuf buf = (ByteBuf) msg;
            try {
                String text = buf.toString(CharsetUtil.UTF_8).trim();
                if ("PONG".equals(text)) {
                    result.set("SUCCESS");
                } else {
                    result.set("FAIL (unexpected: " + text + ")");
                }
            } finally {
                // ByteBuf нужно освободить — иначе memory leak в Netty
                ReferenceCountUtil.release(msg);
            }
            done.countDown();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            result.set("FAIL (" + cause.getMessage() + ")");
            done.countDown();
        }
    }
}
