package org.rssys.gost.jsse.examples.tomcat;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.examples.AbstractFinishedWithRequestTest;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/**
 * Tomcat: запрос, склеенный с Finished клиента, доставлен. Пока билет сессии стоит в очереди, движок
 * оставляет запись данных во входном буфере; Tomcat после отправки билета дочитывает её сам.
 */
@DisplayName("Tomcat: запрос, склеенный с Finished клиента, доставлен")
class TomcatFinishedWithRequestTest extends AbstractFinishedWithRequestTest {

    private static Tomcat tomcat;
    private static Connector connector;
    private static Path baseDir;

    @BeforeAll
    static void startServer() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        Logger.getLogger("org.apache").setLevel(Level.WARNING);
        baseDir = Files.createTempDirectory("tomcat-finished-");

        tomcat = new Tomcat();
        tomcat.setBaseDir(baseDir.toString());
        tomcat.setPort(0);

        connector = new Connector("HTTP/1.1");
        connector.setPort(0);
        connector.setSecure(true);
        connector.setScheme("https");
        connector.setProperty("address", "127.0.0.1");
        connector.setProperty("SSLEnabled", "true");
        connector.setProperty(
                "sslImplementationName", TomcatEchoServer.GostSSLImplementation.class.getName());
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setSslProtocol(GostJsseConstants.PROTOCOL_TLS_1_3);
        sslHostConfig.addCertificate(
                new SSLHostConfigCertificate(
                        sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED));
        connector.addSslHostConfig(sslHostConfig);
        tomcat.getService().addConnector(connector);

        org.apache.catalina.Context context = tomcat.addContext("", baseDir.toString());
        Tomcat.addServlet(context, "echo", new EchoServlet());
        context.addServletMappingDecoded("/*", "echo");
        tomcat.start();
    }

    @AfterAll
    static void stopServer() throws LifecycleException, IOException {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
        if (baseDir != null) {
            try (var paths = Files.walk(baseDir)) {
                paths.sorted(java.util.Comparator.reverseOrder())
                        .forEach(path -> path.toFile().delete());
            }
        }
    }

    @Override
    protected int serverPort() {
        return connector.getLocalPort();
    }

    @Override
    protected ExamplesCertHelper certHelper() {
        // Сервер Tomcat создаёт контекст из того же помощника, иначе клиент не доверял бы корню
        return TomcatEchoServer.GostSSLUtil.getHelper();
    }

    /** Возвращает тело запроса с длиной, без поточной разбивки ответа. */
    private static final class EchoServlet extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response)
                throws IOException {
            byte[] body = request.getInputStream().readAllBytes();
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentLength(body.length);
            response.getOutputStream().write(body);
        }
    }
}
