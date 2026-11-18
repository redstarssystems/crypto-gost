package org.rssys.gost.jsse.examples.grpc;

import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerServiceDefinition;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.netty.GostSslContext;
import org.rssys.gost.netty.GostSslContextBuilder;

/**
 * gRPC поверх ГОСТ TLS: нешейденный {@code grpc-netty} и {@link GostSslContext}.
 * <p>
 * Что важно знать:
 * <ul>
 *   <li>{@code NettyServerBuilder.sslContext} и {@code NettyChannelBuilder.sslContext}
 *       принимают Netty {@code SslContext}, то есть {@code GostSslContext}, а не
 *       {@code javax.net.ssl.SSLContext};</li>
 *   <li>ALPN {@code h2} обязателен на обоих контекстах: {@code applicationProtocols("h2")},
 *       иначе gRPC отвергнет контекст ещё при настройке;</li>
 *   <li>gRPC сам создаёт движок через {@code newEngine(...)} и свой {@code SslHandler}:
 *       движок скрыт в обёртке Netty, поэтому {@code GostSSLEngine}, клиентский и серверный
 *       OCSP-staple через gRPC недоступны;</li>
 *   <li>клиентский контекст проверяет имя узла: адрес канала должен совпадать с SAN
 *       сертификата сервера;</li>
 *   <li>{@code grpc-netty-shaded} не подходит: у него свой перемещённый {@code SslContext}.</li>
 * </ul>
 * Методы описаны без protobuf: сообщения передаются как {@code byte[]}.
 */
public final class GrpcEchoServer {

    public static final String SERVICE = "echo.Echo";
    private static final String ALPN_H2 = "h2";
    private static final int STREAM_REPLIES = 3;

    private static final MethodDescriptor.Marshaller<byte[]> BYTES =
            new MethodDescriptor.Marshaller<>() {
                @Override
                public InputStream stream(byte[] value) {
                    return new ByteArrayInputStream(value);
                }

                @Override
                public byte[] parse(InputStream stream) {
                    try {
                        return stream.readAllBytes();
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
            };

    /** Унарный вызов: сервер возвращает полученные байты. */
    public static final MethodDescriptor<byte[], byte[]> ECHO =
            method("Say", MethodDescriptor.MethodType.UNARY);

    /** Серверный поток: сервер отвечает тремя сообщениями {@code <текст>#<номер>}. */
    public static final MethodDescriptor<byte[], byte[]> REPEAT =
            method("Repeat", MethodDescriptor.MethodType.SERVER_STREAMING);

    private GrpcEchoServer() {}

    private static MethodDescriptor<byte[], byte[]> method(
            String name, MethodDescriptor.MethodType type) {
        return MethodDescriptor.<byte[], byte[]>newBuilder()
                .setType(type)
                .setFullMethodName(MethodDescriptor.generateFullMethodName(SERVICE, name))
                .setRequestMarshaller(BYTES)
                .setResponseMarshaller(BYTES)
                .build();
    }

    /**
     * Запускает сервер gRPC на свободном порту.
     *
     * @param context серверный контекст с ALPN {@code h2}
     * @return запущенный сервер
     * @throws IOException если порт не удалось занять
     */
    public static Server start(GostSslContext context) throws IOException {
        ServerServiceDefinition service =
                ServerServiceDefinition.builder(SERVICE)
                        .addMethod(
                                ECHO,
                                ServerCalls.asyncUnaryCall(
                                        (request, observer) -> {
                                            observer.onNext(request);
                                            observer.onCompleted();
                                        }))
                        .addMethod(
                                REPEAT,
                                ServerCalls.asyncServerStreamingCall(
                                        (request, observer) -> {
                                            String text =
                                                    new String(request, StandardCharsets.UTF_8);
                                            for (int i = 0; i < STREAM_REPLIES; i++) {
                                                observer.onNext(
                                                        (text + "#" + i)
                                                                .getBytes(StandardCharsets.UTF_8));
                                            }
                                            observer.onCompleted();
                                        }))
                        .build();
        return NettyServerBuilder.forPort(0)
                .sslContext(context)
                .addService(service)
                .build()
                .start();
    }

    /**
     * Открывает клиентский канал на узел {@code localhost}.
     *
     * @param context клиентский контекст с ALPN {@code h2}
     * @param port порт сервера
     * @return канал
     */
    public static ManagedChannel channel(GostSslContext context, int port) {
        return NettyChannelBuilder.forAddress("localhost", port).sslContext(context).build();
    }

    /** Унарный вызов с тайм-аутом. */
    public static byte[] say(ManagedChannel channel, byte[] request) {
        return ClientCalls.blockingUnaryCall(
                channel,
                ECHO,
                CallOptions.DEFAULT.withDeadlineAfter(15, TimeUnit.SECONDS),
                request);
    }

    /** Вызов с потоком ответов сервера. */
    public static Iterator<byte[]> repeat(ManagedChannel channel, byte[] request) {
        return ClientCalls.blockingServerStreamingCall(
                channel,
                REPEAT,
                CallOptions.DEFAULT.withDeadlineAfter(15, TimeUnit.SECONDS),
                request);
    }

    /** Останавливает канал и сервер, дожидаясь завершения. */
    public static void shutdown(ManagedChannel channel, Server server) throws InterruptedException {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();
        GostSslContext serverContext =
                GostSslContextBuilder.forServer(helper.createKeyManager())
                        .applicationProtocols(ALPN_H2)
                        .build();
        GostSslContext clientContext =
                GostSslContextBuilder.forClient()
                        .trustManager(helper.createTrustManager())
                        .applicationProtocols(ALPN_H2)
                        .build();
        Server server = start(serverContext);
        ManagedChannel channel = channel(clientContext, server.getPort());
        try {
            byte[] reply = say(channel, "hello".getBytes(StandardCharsets.UTF_8));
            System.out.println("echo=" + new String(reply, StandardCharsets.UTF_8));
            Iterator<byte[]> stream = repeat(channel, "msg".getBytes(StandardCharsets.UTF_8));
            while (stream.hasNext()) {
                System.out.println("stream=" + new String(stream.next(), StandardCharsets.UTF_8));
            }
            System.out.println("SUCCESS");
        } finally {
            shutdown(channel, server);
        }
    }
}
