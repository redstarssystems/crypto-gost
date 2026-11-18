package org.rssys.gost.jsse.examples.jetty;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.ServiceLoader;
import javax.net.ssl.SSLContext;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.io.ssl.ALPNProcessor;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;
import org.rssys.gost.jsse.examples.Http2Clients;

/**
 * HTTP/2 в Jetty 12 поверх ГОСТ TLS: независимый клиент OkHttp и независимый сервер Jetty, TLS на
 * обеих сторонах библиотеки. Без {@link GostServerALPNProcessor} Jetty отвергает движок
 * библиотеки, поэтому тест проверяет и сам выбор процессора.
 */
@DisplayName("Jetty 12: HTTP/2 поверх ГОСТ TLS (OkHttp <-> Jetty)")
class JettyHttp2Test {

    private static ExamplesCertHelper helper;
    private static Server server;
    private static int port;

    @BeforeAll
    static void startServer() throws Exception {
        helper = new ExamplesCertHelper();
        SSLContext sslContext = helper.getSslContext();

        SslContextFactory.Server tls = new SslContextFactory.Server();
        tls.setSslContext(sslContext);
        tls.setIncludeProtocols(GostJsseConstants.PROTOCOL_TLS_1_3);

        server = new Server();
        HttpConfiguration configuration = new HttpConfiguration();
        ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory("h2", "http/1.1");
        alpn.setDefaultProtocol("http/1.1");
        ServerConnector connector =
                new ServerConnector(
                        server,
                        new SslConnectionFactory(tls, alpn.getProtocol()),
                        alpn,
                        new HTTP2ServerConnectionFactory(configuration),
                        new HttpConnectionFactory(configuration));
        connector.setPort(0);
        server.addConnector(connector);
        server.setHandler(
                new Handler.Abstract() {
                    @Override
                    public boolean handle(
                            org.eclipse.jetty.server.Request request,
                            org.eclipse.jetty.server.Response response,
                            Callback callback) {
                        response.setStatus(200);
                        Content.Sink.write(
                                response, true, "PONG " + request.getHttpURI().getPath(), callback);
                        return true;
                    }
                });
        server.start();
        port = connector.getLocalPort();
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    @DisplayName("OkHttp получает ответ Jetty по HTTP/2")
    void okHttpTalksHttp2ToJetty() throws IOException {
        OkHttpClient client = Http2Clients.okHttp(helper);
        Request request = new Request.Builder().url("https://localhost:" + port + "/ping").build();

        try (okhttp3.Response response = client.newCall(request).execute()) {
            assertEquals(Protocol.HTTP_2, response.protocol(), "должен быть согласован HTTP/2");
            assertEquals(200, response.code(), "код ответа");
            assertEquals("PONG /ping", response.body().string(), "тело ответа по потоку HTTP/2");
        }
    }

    @Test
    @DisplayName(
            "ServiceLoader находит наш процессор, он применяется к GostSSLEngine, а не к чужим")
    void ourProcessorIsDiscoveredAndAppliesToGostEngineOnly() throws Exception {
        boolean discovered =
                ServiceLoader.load(ALPNProcessor.Server.class).stream()
                        .anyMatch(provider -> provider.type() == GostServerALPNProcessor.class);
        assertTrue(discovered, "процессор должен регистрироваться через ServiceLoader");

        GostServerALPNProcessor processor = new GostServerALPNProcessor();
        GostSSLEngine gostEngine = (GostSSLEngine) helper.getSslContext().createSSLEngine();
        assertTrue(processor.appliesTo(gostEngine), "процессор должен применяться к GostSSLEngine");
        assertFalse(
                processor.appliesTo(
                        new javax.net.ssl.SSLEngine() {
                            @Override
                            public javax.net.ssl.SSLEngineResult wrap(
                                    java.nio.ByteBuffer[] s, int o, int l, java.nio.ByteBuffer d) {
                                return null;
                            }

                            @Override
                            public javax.net.ssl.SSLEngineResult unwrap(
                                    java.nio.ByteBuffer s, java.nio.ByteBuffer[] d, int o, int l) {
                                return null;
                            }

                            @Override
                            public Runnable getDelegatedTask() {
                                return null;
                            }

                            @Override
                            public void closeInbound() {}

                            @Override
                            public boolean isInboundDone() {
                                return false;
                            }

                            @Override
                            public void closeOutbound() {}

                            @Override
                            public boolean isOutboundDone() {
                                return false;
                            }

                            @Override
                            public String[] getSupportedCipherSuites() {
                                return new String[0];
                            }

                            @Override
                            public String[] getEnabledCipherSuites() {
                                return new String[0];
                            }

                            @Override
                            public void setEnabledCipherSuites(String[] s) {}

                            @Override
                            public String[] getSupportedProtocols() {
                                return new String[0];
                            }

                            @Override
                            public String[] getEnabledProtocols() {
                                return new String[0];
                            }

                            @Override
                            public void setEnabledProtocols(String[] p) {}

                            @Override
                            public javax.net.ssl.SSLSession getSession() {
                                return null;
                            }

                            @Override
                            public void beginHandshake() {}

                            @Override
                            public javax.net.ssl.SSLEngineResult.HandshakeStatus
                                    getHandshakeStatus() {
                                return null;
                            }

                            @Override
                            public void setUseClientMode(boolean m) {}

                            @Override
                            public boolean getUseClientMode() {
                                return false;
                            }

                            @Override
                            public void setNeedClientAuth(boolean n) {}

                            @Override
                            public boolean getNeedClientAuth() {
                                return false;
                            }

                            @Override
                            public void setWantClientAuth(boolean w) {}

                            @Override
                            public boolean getWantClientAuth() {
                                return false;
                            }

                            @Override
                            public void setEnableSessionCreation(boolean f) {}

                            @Override
                            public boolean getEnableSessionCreation() {
                                return false;
                            }
                        }),
                "процессор не должен применяться к чужому движку");
    }
}
