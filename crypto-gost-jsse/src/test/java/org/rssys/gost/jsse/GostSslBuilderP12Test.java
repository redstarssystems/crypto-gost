package org.rssys.gost.jsse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.TlsTestHelper.CertBundle;
import org.rssys.gost.tls13.cert.GostPkcs12Builder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostSslBuilder: roundtrip PFX через GostPkcs12Builder + GostSslBuilder.certificate(p12, pwd)")
class GostSslBuilderP12Test {

    private static ECParameters params;
    private static CertBundle serverBundle;
    private static CertBundle caBundle;
    private static byte[] pfxBytes;
    private static byte[] caPfxBytes;
    private static final char[] PASSWORD = "test-p12".toCharArray();

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();

        // 1. Генерируем CA
        caBundle = TlsTestHelper.createRootCA(params);

        // 2. Серверный сертификат, подписанный CA
        serverBundle = TlsTestHelper.createCertSignedBy(
                params, caBundle.priv, caBundle.cert.getPublicKey(), caBundle.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        // 3. PFX с ключом, leaf и CA
        pfxBytes = GostPkcs12Builder.newBuilder()
                .key(serverBundle.priv)
                .certificate(serverBundle.cert)
                .caCertificate(caBundle.cert)
                .password(PASSWORD)
                .iterations(100)
                .build();

        // 4. CA-only PFX (без приватного ключа — но GostPkcs12Builder кладёт ключ всегда;
        // создаём отдельный PFX для CA через builder с key=caKey, certificate=caCert)
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        caPfxBytes = GostPkcs12Builder.newBuilder()
                .key(caKp.getPrivate())
                .certificate(caBundle.cert)
                .password(PASSWORD)
                .iterations(100)
                .build();
    }

    @Test
    @DisplayName("GostSslBuilder.certificate(p12, pwd) создаёт SSLContext")
    void testCertificateP12CreatesContext() {
        SSLContext ctx = GostSsl.builder()
                .certificate(pfxBytes, PASSWORD)
                .trustCa(caPfxBytes, PASSWORD)
                .buildServerContext();
        assertNotNull(ctx, "SSLContext должен быть создан");
    }

    @Test
    @DisplayName("GostSslBuilder.certificate(p12, pwd) + trustCa(p12, pwd): loopback handshake")
    void testCertificateP12Loopback() throws Exception {
        SSLContext serverCtx = GostSsl.builder()
                .certificate(pfxBytes, PASSWORD)
                .trustCa(caPfxBytes, PASSWORD)
                .buildServerContext();

        SSLContext clientCtx = GostSsl.builder()
                .trustCa(caPfxBytes, PASSWORD)
                .buildClientContext();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket srv = (SSLServerSocket) serverCtx.getServerSocketFactory()
                .createServerSocket(0)) {
            int port = srv.getLocalPort();

            Thread serverThread = new Thread(() -> {
                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                    accepted.setSoTimeout(10_000);
                    accepted.startHandshake();

                    byte[] buf = new byte[1024];
                    int n = accepted.getInputStream().read(buf);
                    String msg = new String(buf, 0, n, StandardCharsets.UTF_8);
                    assertEquals("PING", msg, "сервер получил PING");

                    accepted.getOutputStream().write("PONG".getBytes(StandardCharsets.UTF_8));
                    accepted.getOutputStream().flush();
                } catch (Exception e) {
                    serverError.set(e);
                } finally {
                    serverDone.countDown();
                }
            }, "server-loopback");
            serverThread.start();

            try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                client.setSoTimeout(10_000);
                client.startHandshake();

                client.getOutputStream().write("PING".getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().flush();

                byte[] buf = new byte[1024];
                int n = client.getInputStream().read(buf);
                String response = new String(buf, 0, n, StandardCharsets.UTF_8);
                assertEquals("PONG", response, "клиент получил PONG");
            }

            assertTrue(serverDone.await(5, TimeUnit.SECONDS), "сервер завершился");
            assertNull(serverError.get(), "сервер без ошибок");
        }
    }

    @Test
    @DisplayName("trustCa(p12, pwd): все CA из цепочки PFX добавляются в trust store")
    void testTrustCaTwoCAsInPfx() throws Exception {
        ECParameters p = ECParameters.tc26a256();
        String nbf = "20240501120000Z";
        String naf = "21060101120000Z";

        CertBundle root = TlsTestHelper.createRootCA(p);

        CertBundle intermediate = TlsTestHelper.createCertSignedBy(
                p, root.priv, root.cert.getPublicKey(), root.subjectDn,
                nbf, naf, null, new byte[]{(byte) 0x04}, null,
                true, null);

        CertBundle server = TlsTestHelper.createCertSignedBy(
                p, intermediate.priv, intermediate.cert.getPublicKey(), intermediate.subjectDn,
                nbf, naf, new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);

        byte[] intermediatePfx = GostPkcs12Builder.newBuilder()
                .key(intermediate.priv)
                .certificate(intermediate.cert)
                .caCertificate(root.cert)
                .password(PASSWORD).iterations(100).build();

        byte[] serverPfx = GostPkcs12Builder.newBuilder()
                .key(server.priv)
                .certificate(server.cert)
                .caCertificate(intermediate.cert)
                .password(PASSWORD).iterations(100).build();

        SSLContext serverCtx = GostSsl.builder()
                .certificate(serverPfx, PASSWORD)
                .trustCa(intermediatePfx, PASSWORD)
                .buildServerContext();

        SSLContext clientCtx = GostSsl.builder()
                .trustCa(intermediatePfx, PASSWORD)
                .buildClientContext();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket srv = (SSLServerSocket) serverCtx.getServerSocketFactory()
                .createServerSocket(0)) {
            int port = srv.getLocalPort();

            Thread serverThread = new Thread(() -> {
                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                    accepted.setSoTimeout(10_000);
                    accepted.startHandshake();
                    assertEquals("PING", new String(accepted.getInputStream().readNBytes(4),
                            StandardCharsets.UTF_8), "сервер получил PING");
                    accepted.getOutputStream().write("PONG".getBytes(StandardCharsets.UTF_8));
                    accepted.getOutputStream().flush();
                } catch (Exception e) {
                    serverError.set(e);
                } finally {
                    serverDone.countDown();
                }
            }, "server-2ca");
            serverThread.start();

            try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
                client.setSoTimeout(10_000);
                client.startHandshake();
                client.getOutputStream().write("PING".getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().flush();
                assertEquals("PONG", new String(client.getInputStream().readNBytes(4),
                        StandardCharsets.UTF_8), "клиент получил PONG");
            }

            assertTrue(serverDone.await(5, TimeUnit.SECONDS), "сервер завершился");
            assertNull(serverError.get(), "сервер без ошибок");
        }
    }
}
