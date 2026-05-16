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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.examples.EchoSocketClient;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.TlsTestHelper.CertBundle;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Интеграционный тест mTLS: Jetty 12 + ГОСТ TLS 1.3.
 * <p>
 * Проверяет, что {@code GostSSLEngine} корректно обрабатывает взаимную аутентификацию
 * (mutual TLS) через Jetty pipeline: сервер запрашивает клиентский сертификат,
 * клиент с сертификатом получает HTTP 200, клиент без сертификата — rejected.
 * <p>
 * Использует {@link TlsTestHelper} для создания серверного и клиентского сертификатов,
 * подписанных одним CA — это приближает тест к реальному mTLS-сценарию, где
 * у сервера и клиента разные сертификаты (в отличие от {@code GostTestCerts},
 * который создаёт только серверный сертификат).
 */
@DisplayName("mTLS интеграция с Jetty 12")
@Tag("integration")
class JettyMtlsTest {

    private static ECParameters params;
    private static CertBundle rootCa;
    private static PublicKeyParameters caPub;
    private static CertBundle serverCert;
    private static CertBundle clientCert;

    private Server server;
    private int port;

    @BeforeAll
    static void createCertificates() throws Exception {
        params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();

        serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        clientCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, caPub, rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null,
                false, null);
    }

    @BeforeEach
    void startJetty() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("server", toJcaChain(serverCert), serverCert.priv);
        GostX509TrustManager serverTm = new GostX509TrustManager(caPub, false);
        SSLContext serverCtx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        serverCtx.init(new KeyManager[]{serverKm}, new TrustManager[]{serverTm}, null);

        SslContextFactory.Server scf = new SslContextFactory.Server();
        scf.setSslContext(serverCtx);
        scf.setNeedClientAuth(true);
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
    }

    @AfterEach
    void stopJetty() throws Exception {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    @DisplayName("Клиент с сертификатом — HTTP 200 PONG")
    void mtlsWithClientCert() throws Exception {
        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("client", toJcaChain(clientCert), clientCert.priv);
        GostX509TrustManager clientTm = new GostX509TrustManager(caPub, false);
        SSLContext clientCtx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        clientCtx.init(new KeyManager[]{clientKm}, new TrustManager[]{clientTm}, null);

        assertEquals("PONG", EchoSocketClient.pingHttp("localhost", port, clientCtx));
    }

    @Test
    @DisplayName("Клиент без сертификата — TLS handshake failure")
    void mtlsWithoutClientCert() throws Exception {
        GostX509TrustManager clientTm = new GostX509TrustManager(caPub, false);
        SSLContext clientCtx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        clientCtx.init(null, new TrustManager[]{clientTm}, null);

        assertThrows(Exception.class, () ->
                EchoSocketClient.pingHttp("localhost", port, clientCtx));
    }

    /**
     * Конвертирует CertBundle в цепочку JCA X509Certificate для GostX509KeyManager.
     * <p>
     * {@code CertificateBridge.toJca()} через DER-дамп преобразует
     * {@code TlsCertificate} в java.security.cert.X509Certificate — единственный
     * способ, которым GostX509KeyManager принимает сертификаты.
     */
    private static X509Certificate[] toJcaChain(CertBundle leaf, CertBundle... intermediates) throws Exception {
        X509Certificate[] result = new X509Certificate[1 + intermediates.length];
        result[0] = CertificateBridge.toJca(leaf.cert);
        for (int i = 0; i < intermediates.length; i++) {
            result[1 + i] = CertificateBridge.toJca(intermediates[i].cert);
        }
        return result;
    }
}
