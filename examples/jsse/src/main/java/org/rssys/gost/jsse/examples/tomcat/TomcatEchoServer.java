package org.rssys.gost.jsse.examples.tomcat;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.examples.EchoSocketClient;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/**
 * Демонстрация интеграции crypto-gost-jsse с Tomcat 11 (Jakarta EE 10).
 * <p>
 * Tomcat 11 не предоставляет публичного API для прямой передачи
 * {@code javax.net.ssl.SSLContext} в Connector. Единственный поддерживаемый
 * способ — кастомный {@link SSLImplementation}, который возвращает
 * {@link SSLUtil}, оборачивающий наш SSLContext через
 * {@link SSLUtil#createSSLContext(javax.net.ssl.SSLContext, X509KeyManager, X509TrustManager)}.
 */
public final class TomcatEchoServer {

    private TomcatEchoServer() {}

    public static void main(String[] args) throws Exception {
        javax.net.ssl.SSLContext ctx = GostSSLUtil.getHelper().getSslContext();

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(0);

        Connector connector = new Connector("HTTP/1.1");
        connector.setPort(0);
        connector.setSecure(true);
        connector.setScheme("https");
        connector.setProperty("SSLEnabled", "true");
        connector.setProperty("sslImplementationName", GostSSLImplementation.class.getName());

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setSslProtocol(GostJsseConstants.PROTOCOL_TLS_1_3);

        SSLHostConfigCertificate cert =
                new SSLHostConfigCertificate(
                        sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        sslHostConfig.addCertificate(cert);

        connector.addSslHostConfig(sslHostConfig);
        tomcat.getService().addConnector(connector);

        org.apache.catalina.Context appCtx =
                tomcat.addContext("", System.getProperty("java.io.tmpdir"));
        Tomcat.addServlet(
                appCtx,
                "echo",
                new HttpServlet() {
                    @Override
                    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                            throws IOException {
                        String body =
                                new String(
                                                req.getInputStream().readAllBytes(),
                                                java.nio.charset.StandardCharsets.UTF_8)
                                        .trim();
                        resp.setStatus(200);
                        resp.setContentType("text/plain");
                        if ("PING".equals(body)) {
                            resp.getWriter().println("PONG");
                        }
                    }
                });
        appCtx.addServletMappingDecoded("/*", "echo");

        java.util.logging.Logger.getLogger("org.apache.catalina.loader")
                .setLevel(java.util.logging.Level.SEVERE);

        tomcat.start();
        int port = connector.getLocalPort();

        try {
            EchoSocketClient.pingHttp("localhost", port, ctx);
            System.out.println("SUCCESS");
        } catch (Exception e) {
            System.out.println("FAIL (" + e.getMessage() + ")");
        } finally {
            tomcat.stop();
        }
    }

    /**
     * Кастомный SSLImplementation для Tomcat 11.
     * <p>
     * {@link GostSSLUtil} создаёт {@code org.apache.tomcat.util.net.SSLContext}
     * через {@link SSLUtil#createSSLContext(javax.net.ssl.SSLContext, X509KeyManager, X509TrustManager)},
     * который оборачивает наш {@code javax.net.ssl.SSLContext} во внутренний формат Tomcat.
     * <p>
     * {@code getKeyManagers()} / {@code getTrustManagers()} возвращают
     * предварительно сконфигурированные менеджеры напрямую — не через
     * KeyStore/JSSE factory.
     */
    public static final class GostSSLImplementation extends SSLImplementation {
        @Override
        public SSLSupport getSSLSupport(SSLSession session, Map<String, List<String>> additional) {
            return null;
        }

        @Override
        public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
            return new GostSSLUtil();
        }
    }

    public static final class GostSSLUtil implements SSLUtil {
        // Все методы должны использовать ОДИН helper — иначе getKeyManagers()
        // и createSSLContext() получат РАЗНЫЕ сертификаты, и TLS упадёт.
        private static final ExamplesCertHelper HELPER;

        static {
            try {
                HELPER = new ExamplesCertHelper();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        /** Для TomcatEchoServer.main() — клиент и сервер используют один CA. */
        public static ExamplesCertHelper getHelper() {
            return HELPER;
        }

        @Override
        public org.apache.tomcat.util.net.SSLContext createSSLContext(
                List<String> negotiableProtocols) throws Exception {
            X509KeyManager km = HELPER.createKeyManager();
            X509TrustManager tm = HELPER.createTrustManager();
            // SSLUtil.createSSLContext — статический хелпер Tomcat, оборачивающий
            // javax SSLContext + key/trust managers в Tomcat-совместимый SSLContext
            return SSLUtil.createSSLContext(HELPER.getSslContext(), km, tm);
        }

        @Override
        public KeyManager[] getKeyManagers() throws Exception {
            return new KeyManager[] {HELPER.createKeyManager()};
        }

        @Override
        public TrustManager[] getTrustManagers() throws Exception {
            return new TrustManager[] {HELPER.createTrustManager()};
        }

        @Override
        public void configureSessionContext(SSLSessionContext sslSessionContext) {}

        @Override
        public String[] getEnabledProtocols() {
            return GostJsseConstants.SUPPORTED_PROTOCOLS.clone();
        }

        @Override
        public String[] getEnabledCiphers() {
            return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
        }
    }
}
