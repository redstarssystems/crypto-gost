package org.rssys.gost.jsse.examples.springboot;

import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.examples.EchoSocketClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Интеграционный тест: Spring Boot + ГОСТ TLS 1.3.
 * <p>
 * Проверяет полный HTTP-цикл через GostSSLSocket: TLS-хендшейк + POST /echo → PONG.
 */
@SpringBootTest(
        classes = GostSpringBootApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GostSpringBootIntegrationTest {

    @LocalServerPort
    private int port;

    @Test
    void gostTlsHttpExchange() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);

        String body = EchoSocketClient.pingHttp("localhost", port, ctx);
        assertEquals("PONG", body);
        assertTrue(body.contains("PONG"), "Expected PONG, got: " + body);
    }
}
