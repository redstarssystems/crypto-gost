package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.signature.ECParameters;

@DisplayName(
        "GostSslBuilder: обратимость PFX через GostPkcs12Builder + GostSslBuilder.certificate(p12, pwd)")
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
        caBundle = PkixCertTestHelper.createRootCA(params);

        // 2. Серверный сертификат, подписанный CA
        serverBundle =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        caBundle.priv,
                        caBundle.cert.getPublicKey(),
                        caBundle.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        // 3. PFX с ключом, leaf и CA
        pfxBytes =
                GostPkcs12Builder.create()
                        .key(serverBundle.priv)
                        .certificate(serverBundle.cert)
                        .caCertificate(caBundle.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();

        // 4. CA-only PFX: ключ должен соответствовать CA-сертификату
        caPfxBytes =
                GostPkcs12Builder.create()
                        .key(caBundle.priv)
                        .certificate(caBundle.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();
    }

    @Test
    @DisplayName("trustCaChain и trustCaBundle отклоняют PFX без MacData")
    void trustCaRejectsPfxWithoutMac() {
        byte[] withoutMac = stripMac(caPfxBytes);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSsl.builder().trustCaChain(withoutMac, PASSWORD),
                "PFX без MAC должен отклоняться в trustCaChain");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSsl.builder().trustCaBundle(withoutMac, PASSWORD),
                "PFX без MAC должен отклоняться в trustCaBundle");
    }

    @Test
    @DisplayName("trustCaBundle отклоняет контейнер с не-CA сертификатом")
    void trustCaBundleRejectsNonCaCertificate() {
        // pfxBytes содержит leaf сервера и CA: бандлом не является
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostSsl.builder().trustCaBundle(pfxBytes, PASSWORD),
                        "Смешанный контейнер не должен молча превращаться в цепочку ключа");
        assertTrue(
                e.getMessage().contains("trustCaChain"),
                "Сообщение должно указывать на trustCaChain");
    }

    @Test
    @DisplayName("trustCaChain берёт CA цепочки ключа из смешанного контейнера")
    void trustCaChainTakesKeyChainOfMixedContainer() throws Exception {
        SSLContext serverCtx =
                GostSsl.builder()
                        .certificate(pfxBytes, PASSWORD)
                        .trustCaChain(pfxBytes, PASSWORD)
                        .buildServerContext();
        SSLContext clientCtx =
                GostSsl.builder().trustCaChain(pfxBytes, PASSWORD).buildClientContext();

        assertDoesNotThrow(
                () -> handshake(serverCtx, clientCtx),
                "CA из цепочки смешанного контейнера должен быть якорем");
    }

    @Test
    @DisplayName("GostSslBuilder.certificate(p12, pwd) создаёт SSLContext")
    void testCertificateP12CreatesContext() {
        SSLContext ctx =
                GostSsl.builder()
                        .certificate(pfxBytes, PASSWORD)
                        .trustCaChain(caPfxBytes, PASSWORD)
                        .buildServerContext();
        assertNotNull(ctx, "SSLContext должен быть создан");
    }

    @Test
    @DisplayName(
            "GostSslBuilder.certificate(p12, pwd) + trustCaChain(p12, pwd): рукопожатие петлей")
    void testCertificateP12Loopback() throws Exception {
        SSLContext serverCtx =
                GostSsl.builder()
                        .certificate(pfxBytes, PASSWORD)
                        .trustCaChain(caPfxBytes, PASSWORD)
                        .buildServerContext();

        SSLContext clientCtx =
                GostSsl.builder().trustCaChain(caPfxBytes, PASSWORD).buildClientContext();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket srv =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
            int port = srv.getLocalPort();

            Thread serverThread =
                    new Thread(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                                    accepted.setSoTimeout(10_000);
                                    accepted.startHandshake();

                                    byte[] buf = new byte[1024];
                                    int n = accepted.getInputStream().read(buf);
                                    String msg = new String(buf, 0, n, StandardCharsets.UTF_8);
                                    assertEquals("PING", msg, "сервер получил PING");

                                    accepted.getOutputStream()
                                            .write("PONG".getBytes(StandardCharsets.UTF_8));
                                    accepted.getOutputStream().flush();
                                } catch (Exception e) {
                                    serverError.set(e);
                                } finally {
                                    serverDone.countDown();
                                }
                            },
                            "server-loopback");
            serverThread.start();

            try (SSLSocket client =
                    (SSLSocket) clientCtx.getSocketFactory().createSocket("localhost", port)) {
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
    @DisplayName("trustCaChain: все CA из цепочки ключа PFX добавляются в trust store")
    void testTrustCaTwoCAsInPfx() throws Exception {
        ECParameters p = ECParameters.tc26a256();
        String nbf = "20240501120000Z";
        String naf = "21060101120000Z";

        CertBundle root = PkixCertTestHelper.createRootCA(p);

        CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        p,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        nbf,
                        naf,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        null);

        CertBundle server =
                PkixCertTestHelper.createCertSignedBy(
                        p,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        nbf,
                        naf,
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        byte[] intermediatePfx =
                GostPkcs12Builder.create()
                        .key(intermediate.priv)
                        .certificate(intermediate.cert)
                        .caCertificate(root.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();

        byte[] serverPfx =
                GostPkcs12Builder.create()
                        .key(server.priv)
                        .certificate(server.cert)
                        .caCertificate(intermediate.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();

        SSLContext serverCtx =
                GostSsl.builder()
                        .certificate(serverPfx, PASSWORD)
                        .trustCaChain(intermediatePfx, PASSWORD)
                        .buildServerContext();

        SSLContext clientCtx =
                GostSsl.builder().trustCaChain(intermediatePfx, PASSWORD).buildClientContext();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket srv =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
            int port = srv.getLocalPort();

            Thread serverThread =
                    new Thread(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                                    accepted.setSoTimeout(10_000);
                                    accepted.startHandshake();
                                    assertEquals(
                                            "PING",
                                            new String(
                                                    accepted.getInputStream().readNBytes(4),
                                                    StandardCharsets.UTF_8),
                                            "сервер получил PING");
                                    accepted.getOutputStream()
                                            .write("PONG".getBytes(StandardCharsets.UTF_8));
                                    accepted.getOutputStream().flush();
                                } catch (Exception e) {
                                    serverError.set(e);
                                } finally {
                                    serverDone.countDown();
                                }
                            },
                            "server-2ca");
            serverThread.start();

            try (SSLSocket client =
                    (SSLSocket) clientCtx.getSocketFactory().createSocket("localhost", port)) {
                client.setSoTimeout(10_000);
                client.startHandshake();
                client.getOutputStream().write("PING".getBytes(StandardCharsets.UTF_8));
                client.getOutputStream().flush();
                assertEquals(
                        "PONG",
                        new String(client.getInputStream().readNBytes(4), StandardCharsets.UTF_8),
                        "клиент получил PONG");
            }

            assertTrue(serverDone.await(5, TimeUnit.SECONDS), "сервер завершился");
            assertNull(serverError.get(), "сервер без ошибок");
        }
    }

    @Test
    @DisplayName("trustCaBundle: независимый корень CA-бандла остаётся якорем доверия")
    void testTrustCaIndependentRootInCaOnlyBundle() throws Exception {
        ECParameters p = ECParameters.tc26a256();
        String nbf = "20240501120000Z";
        String naf = "21060101120000Z";

        CertBundle branchRoot = PkixCertTestHelper.createRootCA(p);
        CertBundle branchCa =
                PkixCertTestHelper.createCertSignedBy(
                        p,
                        branchRoot.priv,
                        branchRoot.cert.getPublicKey(),
                        branchRoot.subjectDn,
                        nbf,
                        naf,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        null);
        // Корень, не связанный с ключом бандла: строгая цепочка его отбрасывает,
        // но он должен остаться якорем, иначе trust-бандлы перестанут работать.
        CertBundle independentRoot = PkixCertTestHelper.createRootCA(p);
        CertBundle server =
                PkixCertTestHelper.createCertSignedBy(
                        p,
                        independentRoot.priv,
                        independentRoot.cert.getPublicKey(),
                        independentRoot.subjectDn,
                        nbf,
                        naf,
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        byte[] caBundlePfx =
                GostPkcs12Builder.create()
                        .key(branchCa.priv)
                        .certificate(branchCa.cert)
                        .caCertificate(independentRoot.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();
        byte[] serverPfx =
                GostPkcs12Builder.create()
                        .key(server.priv)
                        .certificate(server.cert)
                        .password(PASSWORD)
                        .iterations(1000)
                        .build();

        SSLContext serverCtx =
                GostSsl.builder()
                        .certificate(serverPfx, PASSWORD)
                        .trustCaBundle(caBundlePfx, PASSWORD)
                        .buildServerContext();
        SSLContext clientCtx =
                GostSsl.builder().trustCaBundle(caBundlePfx, PASSWORD).buildClientContext();

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverDone = new CountDownLatch(1);

        try (SSLServerSocket srv =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
            Thread serverThread =
                    new Thread(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                                    accepted.setSoTimeout(10_000);
                                    accepted.startHandshake();
                                } catch (Exception e) {
                                    serverError.set(e);
                                } finally {
                                    serverDone.countDown();
                                }
                            },
                            "server-independent-root");
            serverThread.start();

            try (SSLSocket client =
                    (SSLSocket)
                            clientCtx
                                    .getSocketFactory()
                                    .createSocket("localhost", srv.getLocalPort())) {
                client.setSoTimeout(10_000);
                assertDoesNotThrow(
                        client::startHandshake,
                        "сертификат сервера выпущен независимым корнем из CA-бандла");
            }

            assertTrue(serverDone.await(5, TimeUnit.SECONDS), "сервер завершился");
            assertNull(serverError.get(), "сервер без ошибок");
        }

        // trustCaChain берёт только цепочку ключа бандла: независимый корень якорем не становится
        SSLContext chainOnlyClientCtx =
                GostSsl.builder().trustCaChain(caBundlePfx, PASSWORD).buildClientContext();
        assertThrows(
                SSLException.class,
                () -> handshake(serverCtx, chainOnlyClientCtx),
                "trustCaChain не должен доверять независимому корню бандла");
    }

    /** Выполняет рукопожатие клиента с сервером на локальном порту; ошибка клиента пробрасывается. */
    private static void handshake(SSLContext serverCtx, SSLContext clientCtx) throws Exception {
        try (SSLServerSocket srv =
                (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
            Thread serverThread =
                    new Thread(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) srv.accept()) {
                                    accepted.setSoTimeout(10_000);
                                    accepted.startHandshake();
                                } catch (Exception ignored) {
                                    // ошибка сервера при отказе клиента ожидаема: проверяется
                                    // клиент
                                }
                            },
                            "server-handshake-helper");
            serverThread.start();
            try (SSLSocket client =
                    (SSLSocket)
                            clientCtx
                                    .getSocketFactory()
                                    .createSocket("localhost", srv.getLocalPort())) {
                client.setSoTimeout(10_000);
                client.startHandshake();
            } finally {
                serverThread.join(5_000);
            }
        }
    }

    private static byte[] stripMac(byte[] pfx) {
        byte[][] parts = org.rssys.gost.util.DerCodec.parseSequenceContents(pfx, 0);
        return org.rssys.gost.util.DerCodec.encodeSequence(parts[0], parts[1]);
    }
}
