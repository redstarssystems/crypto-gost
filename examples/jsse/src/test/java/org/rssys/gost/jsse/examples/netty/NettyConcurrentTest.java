package org.rssys.gost.jsse.examples.netty;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.examples.JsseCertHelper;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * Тест конкурентных TLS-соединений через Netty pipeline.
 * <p>
 * GostSSLEngine использует два отдельных лока (inbound/outbound), но race condition
 * в GostSSLSessionContext или KeyManager могут проявиться только под нагрузкой.
 * Этот тест запускает несколько клиентов одновременно к одному Netty-серверу —
 * каждый делает PING/PONG через защищённый канал.
 * Второй тест (rapidSequentialOpenClose) проверяет последовательные open-close
 * без параллельной нагрузки — это другой сценарий (reconnect, не concurrent).
 * <p>
 * Используем Netty, а не Jetty, потому что Netty предоставляет готовый асинхронный
 * Bootstrap для клиента — не писать собственный пул сокетов и не тащить HTTP-стек.
 */
@DisplayName("Конкурентные TLS-соединения через Netty")
@Tag("integration")
class NettyConcurrentTest {

    private static final int CLIENTS = 10;
    private static final int TIMEOUT_SEC = 30;

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static EventLoopGroup bossGroup;
    private static EventLoopGroup workerGroup;
    private static Channel serverChannel;
    private static int port;

    @BeforeAll
    static void startServer() throws Exception {
        JsseCertHelper helper = new JsseCertHelper();
        GostX509KeyManager km = helper.createKeyManager();
        GostX509TrustManager tm = helper.createTrustManager();

        serverCtx = GostSslContextBuilder.forServer(km).trustManager(tm).build();
        clientCtx = GostSslContextBuilder.forClient().trustManager(tm).build();

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();

        ServerBootstrap sb = new ServerBootstrap();
        sb.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(
                        new ChannelInitializer<SocketChannel>() {
                            @Override
                            protected void initChannel(SocketChannel ch) {
                                ch.pipeline()
                                        .addLast(
                                                serverCtx.newHandler(ch.alloc()),
                                                new ServerEchoHandler());
                            }
                        });

        serverChannel = sb.bind(0).sync().channel();
        port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    @AfterAll
    static void stopServer() throws InterruptedException {
        if (serverChannel != null) {
            serverChannel.close().sync();
        }
        bossGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS);
        workerGroup.shutdownGracefully(0, 1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("10 параллельных клиентов — все PING->PONG завершены успешно")
    void tenConcurrentClients() throws Exception {
        int n = CLIENTS;
        CountDownLatch allStart = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicReference<String> firstError = new AtomicReference<>(null);
        CountDownLatch allDone = new CountDownLatch(n);

        List<Thread> clients = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            final int clientId = i;
            Thread t =
                    new Thread(
                            () -> {
                                EventLoopGroup g = new NioEventLoopGroup(1);
                                try {
                                    allStart.await();

                                    CountDownLatch clientDone = new CountDownLatch(1);

                                    Bootstrap cl = new Bootstrap();
                                    cl.group(g)
                                            .channel(NioSocketChannel.class)
                                            .option(
                                                    io.netty.channel.ChannelOption
                                                            .CONNECT_TIMEOUT_MILLIS,
                                                    10000)
                                            .handler(
                                                    new ChannelInitializer<SocketChannel>() {
                                                        @Override
                                                        protected void initChannel(
                                                                SocketChannel ch) {
                                                            ch.pipeline()
                                                                    .addLast(
                                                                            clientCtx.newHandler(
                                                                                    ch.alloc(),
                                                                                    "localhost",
                                                                                    port),
                                                                            new ClientEchoHandler(
                                                                                    clientId,
                                                                                    successCount,
                                                                                    firstError,
                                                                                    clientDone));
                                                        }
                                                    });

                                    cl.connect("localhost", port).sync();
                                    clientDone.await(15, TimeUnit.SECONDS);
                                } catch (InterruptedException e) {
                                    firstError.compareAndSet(
                                            null, "Client " + clientId + " interrupted");
                                } catch (Exception e) {
                                    firstError.compareAndSet(
                                            null,
                                            "Client " + clientId + " error: " + e.getMessage());
                                } finally {
                                    g.shutdownGracefully(0, 0, TimeUnit.SECONDS);
                                    allDone.countDown();
                                }
                            },
                            "client-" + i);
            clients.add(t);
        }

        for (Thread t : clients) {
            t.start();
        }

        allStart.countDown();

        if (!allDone.await(TIMEOUT_SEC, TimeUnit.SECONDS)) {
            throw new AssertionError(
                    "Таймаут: не все клиенты завершились за " + TIMEOUT_SEC + " с");
        }

        if (firstError.get() != null) {
            throw new AssertionError(firstError.get());
        }
        assertEquals(n, successCount.get(), "Все " + n + " клиентов должны получить PONG");
    }

    @Test
    @DisplayName("20 последовательных open-close — ни один handshake не падает")
    void rapidSequentialOpenClose() throws Exception {
        int n = 20;
        for (int i = 0; i < n; i++) {
            final int clientIdx = i;
            EventLoopGroup g = new NioEventLoopGroup(1);
            try {
                CountDownLatch done = new CountDownLatch(1);
                AtomicReference<String> err = new AtomicReference<>(null);

                Bootstrap cl = new Bootstrap();
                cl.group(g)
                        .channel(NioSocketChannel.class)
                        .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                        .handler(
                                new ChannelInitializer<SocketChannel>() {
                                    @Override
                                    protected void initChannel(SocketChannel ch) {
                                        ch.pipeline()
                                                .addLast(
                                                        clientCtx.newHandler(
                                                                ch.alloc(), "localhost", port),
                                                        new ClientEchoHandler(
                                                                clientIdx,
                                                                new AtomicInteger(0),
                                                                err,
                                                                done));
                                    }
                                });

                cl.connect("localhost", port).sync();

                if (!done.await(10, TimeUnit.SECONDS)) {
                    throw new AssertionError("Client " + clientIdx + " timeout");
                }
                if (err.get() != null) {
                    throw new AssertionError("Client " + clientIdx + " failed: " + err.get());
                }
            } finally {
                g.shutdownGracefully(0, 0, TimeUnit.SECONDS);
            }
        }
    }

    /**
     * Серверный handler — echo PONG на PING.
     * <p>
     * Stateless: каждый экземпляр обслуживает одно соединение.
     * Протокол приложения — минимальный (PING->PONG), достаточный
     * для верификации TLS-соединения без HTTP-стека.
     */
    private static final class ServerEchoHandler extends SimpleChannelInboundHandler<ByteBuf> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
            String text = msg.toString(CharsetUtil.UTF_8).trim();
            if ("PING".equals(text)) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("PONG\n", CharsetUtil.UTF_8));
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            // "Engine is closed" и "Record authentication failed" — ожидаемы
            // при закрытии соединения до полной обработки буфера (close_notify
            // + остаточные данные в канале). Не глотаем неожиданные ошибки.
            if (cause instanceof DecoderException && cause.getCause() instanceof SSLException) {
                return;
            }
            ctx.fireExceptionCaught(cause);
        }
    }

    /**
     * Клиентский handler — отправляет PING при установке соединения,
     * проверяет PONG в ответе, закрывает соединение.
     * <p>
     * Использует AtomicReference для потокобезопасной передачи ошибки
     * в основной поток — каждый клиент работает в своём треде.
     */
    private static final class ClientEchoHandler extends ChannelInboundHandlerAdapter {
        private final int clientId;
        private final AtomicInteger successCounter;
        private final AtomicReference<String> errorRef;
        private final CountDownLatch done;

        ClientEchoHandler(
                int clientId,
                AtomicInteger successCounter,
                AtomicReference<String> errorRef,
                CountDownLatch done) {
            this.clientId = clientId;
            this.successCounter = successCounter;
            this.errorRef = errorRef;
            this.done = done;
        }

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
                    successCounter.incrementAndGet();
                } else {
                    errorRef.compareAndSet(
                            null, "Client " + clientId + " unexpected reply: " + text);
                }
                ctx.close();
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            done.countDown();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            errorRef.compareAndSet(
                    null, "Client " + clientId + " exception: " + cause.getMessage());
            ctx.close();
        }
    }
}
