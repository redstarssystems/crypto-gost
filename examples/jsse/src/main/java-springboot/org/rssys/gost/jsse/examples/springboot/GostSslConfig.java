package org.rssys.gost.jsse.examples.springboot;

import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.SSLImplementation;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SSLUtil;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.security.Security;
import java.util.List;
import java.util.Map;

/**
 * Конфигурация SSL для Spring Boot 3.4 с ГОСТ TLS 1.3.
 * <p>
 * Tomcat 11 использует поле {@code sslImplementationName}.
 * {@code connector.setProperty("sslImplementation", ...)} не работает —
 * Tomcat 11 ищет setSslImplementationName(), а IntrospectionUtils находит
 * его по имени свойства "sslImplementationName".
 */
@Configuration
public class GostSslConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> gostSslCustomizer() {
        return factory -> {
            factory.addConnectorCustomizers(connector -> {
                Security.addProvider(new RssysGostJsseProvider());
                connector.setSecure(true);
                connector.setScheme("https");
                connector.setProperty("SSLEnabled", "true");

                // Tomcat 11: setProperty("sslImplementationName", ...) через
                // IntrospectionUtils находит setSslImplementationName() на endpoint
                connector.setProperty("sslImplementationName",
                        GostSSLImplementation.class.getName());

                SSLHostConfig sslHostConfig = new SSLHostConfig();
                sslHostConfig.setHostName("_default_");
                sslHostConfig.setSslProtocol("TLSv1.3");

                SSLHostConfigCertificate cert = new SSLHostConfigCertificate(
                        sslHostConfig, Type.UNDEFINED);
                sslHostConfig.addCertificate(cert);
                connector.addSslHostConfig(sslHostConfig);
            });
            factory.setPort(8443);
        };
    }

    // ---- Кастомный SSLImplementation ----

    public static final class GostSSLImplementation extends SSLImplementation {
        @Override
        public SSLSupport getSSLSupport(SSLSession session,
                                        Map<String, List<String>> additional) {
            return null;
        }

        @Override
        public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
            return new GostSSLUtil();
        }
    }

    public static final class GostSSLUtil implements SSLUtil {
        // Все методы GostSSLUtil должны использовать ОДИН helper —
        // иначе getKeyManagers() и createSSLContext() получат РАЗНЫЕ
        // сертификаты, и TLS-хендшейк упадёт.
        private static final ExamplesCertHelper HELPER;
        static {
            try {
                HELPER = new ExamplesCertHelper();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public org.apache.tomcat.util.net.SSLContext createSSLContext(
                List<String> negotiableProtocols) throws Exception {
            X509KeyManager km = HELPER.createKeyManager();
            X509TrustManager tm = HELPER.createTrustManager();
            return SSLUtil.createSSLContext(HELPER.getSslContext(), km, tm);
        }

        @Override
        public KeyManager[] getKeyManagers() throws Exception {
            return new KeyManager[]{HELPER.createKeyManager()};
        }

        @Override
        public TrustManager[] getTrustManagers() throws Exception {
            return new TrustManager[]{HELPER.createTrustManager()};
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
