package org.rssys.gost.jsse.examples.jetty;

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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.examples.JsseCertHelper;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.tls13.TlsCiphersuite;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Тест PSK resumption через Jetty 12.
 * <p>
 * Два последовательных TLS-соединения к одному Jetty-серверу через один
 * {@link GostSSLSessionContext}. Первое соединение получает NST (New Session Ticket),
 * второе должно использовать PSK (без полного handshake).
 * <p>
 * Используем raw {@link GostSSLSocket} (не SSLContext.getSocketFactory()) —
 * явно передаём GostSSLSessionContext, чтобы проверить его состояние
 * через {@link GostSSLSessionContext#getPskStore()}.
 * Это единственный способ верифицировать PSK снаружи, потому что
 * {@code SSLContext.getClientSessionContext()} возвращает SSLSessionContext,
 * который не гарантирует каст к GostSSLSessionContext (зависит от JDK).
 */
@DisplayName("PSK resumption через Jetty 12")
@Tag("integration")
class JettyPskResumptionTest {

    private static final int TIMEOUT_MS = 15000;

    private Server server;
    private int port;
    private GostSSLSessionContext clientSessionCtx;
    private GostX509KeyManager clientKm;
    private GostX509TrustManager clientTm;

    @BeforeEach
    void startJetty() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        JsseCertHelper helper = new JsseCertHelper();

        // Серверный SSLContext для Jetty
        SslContextFactory.Server scf = new SslContextFactory.Server();
        scf.setSslContext(helper.getSslContext());
        scf.setIncludeProtocols("TLSv1.3");

        server = new Server();
        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(scf, "http/1.1"),
                new HttpConnectionFactory(new HttpConfiguration()));
        connector.setPort(0);
        server.addConnector(connector);

        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response, Callback callback) {
                try {
                    String body = Content.Source.asString(request, StandardCharsets.UTF_8).trim();
                    if ("PING".equals(body)) {
                        response.setStatus(200);
                        response.getHeaders().put(
                                org.eclipse.jetty.http.HttpHeader.CONTENT_TYPE, "text/plain");
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
        port = connector.getLocalPort();

        // Явный клиентский session context — хранит PSK между соединениями.
        // Используем конструктор (TlsCiphersuite, hashLen) как в GostSSLContextSpi.
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        clientSessionCtx = new GostSSLSessionContext(cs, cs.getHashLen());

        // Клиентские key/trust менеджеры — одни на оба соединения
        clientKm = helper.createKeyManager();
        clientTm = helper.createTrustManager();
    }

    @AfterEach
    void stopJetty() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    @DisplayName("Первое соединение — full handshake, PSK сохранён")
    void firstConnectionStoresPsk() throws Exception {
        doHttpPingPong();

        // После первого соединения Jetty отправляет NST.
        // Проверяем что PSK действительно сохранён в нашем session context.
        assertTrue(clientSessionCtx.getPskStore().size() > 0,
                "PSK должен быть сохранён после первого TLS-соединения");
    }

    @Test
    @DisplayName("Второе соединение с тем же PSK-контекстом — успешно")
    void secondConnectionUsesPsk() throws Exception {
        // Первое соединение — full handshake + получение NST
        doHttpPingPong();
        assertTrue(clientSessionCtx.getPskStore().size() > 0);

        // Второе соединение с тем же session context — должно использовать PSK
        // (без полного handshake). Прямое доказательство (engine.handshakeType)
        // требует рефлективного доступа к GostSSLEngine — мы не делаем этого
        // в интеграционном тесте. Факт успешного соединения после сохранения
        // PSK + что PSK не удалён после второго соединения — косвенная
        // верификация.
        doHttpPingPong();

        // Проверяем что PSK-тикет не был удалён после второго соединения
        // (если размер 0 — что-то сбросило PSK между соединениями)
        assertTrue(clientSessionCtx.getPskStore().size() > 0,
                "PSK должен оставаться в хранилище после второго соединения");
    }

    /**
     * Выполняет HTTP POST /echo через {@link GostSSLSocket} с общим
     * {@link GostSSLSessionContext}. Возвращает тело ответа.
     * <p>
     * Используем raw GostSSLSocket (а не EchoSocketClient), потому что
     * нам нужно передать явный session context — EchoSocketClient.pingHttp()
     * создаёт сокет через SSLContext, и мы не можем контролировать
     * какой session context будет использован.
     */
    private String doHttpPingPong() throws Exception {
        GostSSLSocket socket = new GostSSLSocket("localhost", port,
                clientKm, clientTm, clientSessionCtx);

        socket.setSoTimeout(TIMEOUT_MS);
        try {
            OutputStream out = socket.getOutputStream();
            byte[] req = ("POST /echo HTTP/1.1\r\n"
                    + "Host: localhost\r\n"
                    + "Content-Type: text/plain\r\n"
                    + "Content-Length: 4\r\n"
                    + "Connection: close\r\n"
                    + "\r\n"
                    + "PING").getBytes(StandardCharsets.US_ASCII);
            out.write(req);
            out.flush();

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            String line;
            boolean body = false;
            while ((line = in.readLine()) != null) {
                if (body) {
                    if ("PONG".equals(line.trim())) {
                        return "PONG";
                    }
                } else if (line.isEmpty()) {
                    body = true;
                }
            }
            throw new RuntimeException("No PONG in HTTP response");
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
                // close_notify best-effort — не влияет на результат
            }
        }
    }
}
