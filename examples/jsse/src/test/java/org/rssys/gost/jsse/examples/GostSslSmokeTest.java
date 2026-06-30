package org.rssys.gost.jsse.examples;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.*;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.GostSslDev;
import org.rssys.gost.jsse.GostSslException;

/**
 * Smoke-тест {@link GostSsl}: все публичные методы через real TLS-соединение.
 */
@DisplayName("GostSsl: smoke-тест всех методов")
class GostSslSmokeTest {

    private static ExamplesCertHelper helper;
    private static byte[] caDer;
    private static byte[] certDer;
    private static byte[] keyDer;

    private static String caPem;
    private static String certPem;
    private static String keyPem;

    @BeforeAll
    static void setup() throws Exception {
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());
        helper = new ExamplesCertHelper();
        caDer = helper.getCaCertDer();
        certDer = helper.getCertDer();
        keyDer = helper.getKeyDer();

        caPem = pem(caDer, "CERTIFICATE");
        certPem = pem(certDer, "CERTIFICATE");
        keyPem = pem(keyDer, "PRIVATE KEY");
    }

    // ========================================================================
    // DER
    // ========================================================================

    @Test
    @DisplayName("GostSsl.clientContext(caDer) — клиент без сертификата")
    void clientContextNoCert() {
        assertNotNull(GostSsl.clientContext(caDer));
    }

    @Test
    @DisplayName("GostSsl.serverContext(certDer, keyDer, caDer) — сервер из DER")
    void serverContextDer() {
        assertNotNull(GostSsl.serverContext(certDer, keyDer, caDer));
    }

    @Test
    @DisplayName("GostSslDev.trustAllClientContextInsecure() — dev-контекст без проверки")
    void trustAllInsecure() {
        assertNotNull(GostSslDev.trustAllClientContextInsecure());
    }

    @Test
    @DisplayName("GostSsl.socket() + serverSocket() — полный handshake + echo")
    void socketHandshake() throws Exception {
        SSLContext srvCtx = GostSsl.serverContext(certDer, keyDer, caDer);
        SSLContext cliCtx = GostSsl.clientContext(caDer);

        SSLServerSocket ss = GostSsl.serverSocket(0, srvCtx);
        int port = ss.getLocalPort();

        AtomicReference<Exception> serverErr = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        Thread.ofVirtual()
                .start(
                        () -> {
                            try (SSLSocket accepted = (SSLSocket) ss.accept()) {
                                accepted.startHandshake();
                                InputStream in = accepted.getInputStream();
                                OutputStream out = accepted.getOutputStream();
                                byte[] buf = new byte[1024];
                                int n = in.read(buf);
                                out.write(buf, 0, n);
                                out.flush();
                            } catch (Exception e) {
                                serverErr.set(e);
                            } finally {
                                done.countDown();
                            }
                        });

        SSLSocket cli = GostSsl.socket("localhost", port, cliCtx);
        cli.getOutputStream().write("PING".getBytes());
        cli.getOutputStream().flush();
        byte[] resp = new byte[1024];
        int total = cli.getInputStream().read(resp);
        cli.close();
        ss.close();

        assertTrue(done.await(10, TimeUnit.SECONDS));
        assertNull(serverErr.get(), "Server error: " + serverErr.get());
        assertArrayEquals("PING".getBytes(), java.util.Arrays.copyOf(resp, total));
    }

    // ========================================================================
    // PEM
    // ========================================================================

    @Test
    @DisplayName("GostSsl.serverContext(certPem, keyPem, caPem) — сервер из PEM")
    void serverContextPem() {
        assertNotNull(GostSsl.serverContext(certPem, keyPem, caPem));
    }

    @Test
    @DisplayName("GostSsl.clientContext(certPem, keyPem, caPem) — клиент из PEM")
    void clientContextPem() {
        assertNotNull(GostSsl.clientContext(certPem, keyPem, caPem));
    }

    @Test
    @DisplayName("GostSsl.clientContext(caPem) — клиент только с CA из PEM")
    void clientContextCaPem() {
        assertNotNull(GostSsl.clientContext(caPem));
    }

    // ========================================================================
    // Builder
    // ========================================================================

    @Test
    @DisplayName("GostSsl.builder() — сервер через builder")
    void builderServer() {
        SSLContext ctx =
                GostSsl.builder()
                        .certificate(certDer, keyDer)
                        .trustCa(caDer)
                        .sessionCacheSize(5000)
                        .buildServerContext();
        assertNotNull(ctx);
    }

    @Test
    @DisplayName("GostSsl.builder() — клиент через builder")
    void builderClient() {
        SSLContext ctx =
                GostSsl.builder().certificate(certDer, keyDer).trustCa(caDer).buildClientContext();
        assertNotNull(ctx);
    }

    // ========================================================================
    // verify()
    // ========================================================================

    @Test
    @DisplayName("GostSsl.verifyServer() — односторонний TLS успешен")
    void verifyServerSuccess() {
        assertDoesNotThrow(() -> GostSsl.verifyServer(certPem, keyPem, caPem));
    }

    @Test
    @DisplayName("GostSsl.verifyServer() — неверный CA -> GostSslException")
    void verifyServerWrongCa() {
        // передаём серверный сертификат вместо CA —
        // он не является CA и не подписывал серверный cert,
        // поэтому verifyServer должен бросить GostSslException
        assertThrows(GostSslException.class, () -> GostSsl.verifyServer(certPem, keyPem, certPem));
    }

    // ========================================================================
    // Error handling
    // ========================================================================

    @Test
    @DisplayName("GostSsl.serverContext — неверный ключ")
    void invalidKey() {
        assertThrows(
                GostSslException.class,
                () -> GostSsl.serverContext(certDer, new byte[] {1, 2, 3}, caDer));
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static String pem(byte[] der, String type) {
        return "-----BEGIN "
                + type
                + "-----\n"
                + Base64.getEncoder().encodeToString(der)
                + "\n-----END "
                + type
                + "-----";
    }
}
