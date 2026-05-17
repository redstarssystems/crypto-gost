package org.rssys.gost.jsse.examples.jetty;

import org.rssys.gost.jsse.examples.EchoSocketClient;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.nio.charset.StandardCharsets;

/**
 * Демонстрация интеграции crypto-gost-jsse с Jetty 12.
 * <p>
 * Jetty 12 принимает готовый SSLContext через SslContextFactory.Server.
 * ALPN настраивается автоматически при наличии jetty-alpn-java-server на classpath.
 */
public final class JettyEchoServer {

    private JettyEchoServer() {}

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();

        SslContextFactory.Server scf = new SslContextFactory.Server();
        scf.setSslContext(helper.getSslContext());
        scf.setIncludeProtocols("TLSv1.3");

        Server server = new Server();
        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(scf, "http/1.1"),
                new HttpConnectionFactory(new HttpConfiguration()));
        connector.setPort(0);
        server.addConnector(connector);

        // Handler.Abstract — Jetty 12 core handler API.
        // blocking handler; Content.Source.asString() блокируется
        // в потоке пула Jetty.
        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response, Callback callback) {
                try {
                    String body = Content.Source.asString(
                            request, StandardCharsets.UTF_8).trim();
                    if ("PING".equals(body)) {
                        response.setStatus(200);
                        response.getHeaders().put(
                                org.eclipse.jetty.http.HttpHeader.CONTENT_TYPE, "text/plain");
                        // Content.Sink.write — утилита для отправки строки в blocking handler
                        Content.Sink.write(response, true, "PONG\n", callback);
                    } else {
                        callback.succeeded();
                    }
                    return true;
                } catch (Exception e) {
                    callback.failed(e);
                    return true;
                }
            }
        });

        server.start();
        int port = connector.getLocalPort();
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
