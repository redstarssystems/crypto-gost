package org.rssys.gost.jsse.examples.undertow;

import org.rssys.gost.jsse.examples.EchoSocketClient;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Демонстрация интеграции crypto-gost-jsse с Undertow 2.
 * <p>
 * Undertow — самый лаконичный вариант: addHttpsListener принимает
 * готовый SSLContext напрямую, без фабрик и обёрток.
 */
public final class UndertowEchoServer {

    private UndertowEchoServer() {}

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();

        Undertow server = Undertow.builder()
                .addHttpsListener(0, "0.0.0.0", helper.getSslContext())
                .setHandler(new HttpHandler() {
                    @Override
                    public void handleRequest(HttpServerExchange exchange) throws Exception {
                        // receiveFullBytes — Undertow требует явного чтения тела запроса
                        // (HTTP-парсер Undertow не материализует тело автоматически).
                        exchange.getRequestReceiver().receiveFullBytes((ex, bytes) -> {
                            String body = new String(bytes, StandardCharsets.UTF_8).trim();
                            if ("PING".equals(body)) {
                                ex.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                                ex.getResponseSender().send(ByteBuffer.wrap("PONG\n".getBytes(StandardCharsets.UTF_8)));
                            }
                        });
                    }
                })
                .build();

        server.start();
        int port = ((java.net.InetSocketAddress)
                server.getListenerInfo().get(0).getAddress()).getPort();
        try {
            EchoSocketClient.pingHttp("localhost", port, helper.getSslContext());
            System.out.println("SUCCESS");
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        } finally {
            server.stop();
        }
    }
}
