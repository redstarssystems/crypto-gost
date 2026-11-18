package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
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
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Сервер без mTLS не проверяет клиентские сертификаты и не должен требовать trust store.
 * Проверяется и обратная сторона: если аутентификацию включают позже, рукопожатие обязано
 * отвергаться, а не приниматься без проверки.
 */
@DisplayName("GostSslBuilder: серверный контекст без trust store")
class GostSslBuilderServerTrustTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] KU_DIGITAL_SIGNATURE = new byte[] {(byte) 0x80};

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle server;
    private static PkixCertTestHelper.CertBundle client;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(PARAMS);
        server =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "250101000000Z",
                        "350101000000Z",
                        new String[] {"localhost"},
                        KU_DIGITAL_SIGNATURE,
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        client =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "250101000000Z",
                        "350101000000Z",
                        null,
                        KU_DIGITAL_SIGNATURE,
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);
    }

    private static byte[] keyDer(PkixCertTestHelper.CertBundle bundle) {
        return GostDerCodec.encodePrivateKey(bundle.priv);
    }

    private static GostSslBuilder serverBuilder() {
        return GostSsl.builder().certificate(server.cert.getEncoded(), keyDer(server));
    }

    private static SSLContext clientContext() {
        return GostSsl.builder()
                .certificate(client.cert.getEncoded(), keyDer(client))
                .trustCa(root.cert.getEncoded())
                .buildClientContext();
    }

    private static SSLContext trustingClientContext() {
        return GostSsl.builder().trustCa(root.cert.getEncoded()).buildClientContext();
    }

    private static Thread serveOnce(
            SSLServerSocket serverSocket, AtomicReference<Throwable> error, CountDownLatch done) {
        Thread thread =
                new Thread(
                        () -> {
                            try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                                socket.setSoTimeout(10_000);
                                socket.startHandshake();
                                byte[] buffer = new byte[64];
                                int read = socket.getInputStream().read(buffer);
                                socket.getOutputStream()
                                        .write(
                                                ("ECHO: "
                                                                + new String(
                                                                        buffer,
                                                                        0,
                                                                        read,
                                                                        StandardCharsets.UTF_8))
                                                        .getBytes(StandardCharsets.UTF_8));
                            } catch (Throwable failure) {
                                error.set(failure);
                            } finally {
                                done.countDown();
                            }
                        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static String call(int port, SSLContext context) throws Exception {
        try (SSLSocket socket = GostSsl.socket("localhost", port, context)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write("PING".getBytes(StandardCharsets.UTF_8));
            byte[] buffer = new byte[64];
            int read = socket.getInputStream().read(buffer);
            return new String(buffer, 0, read, StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("Сервер без якорей собирается и работает как односторонний TLS")
    void serverWithoutTrustAnchorsWorks() {
        assertTimeoutPreemptively(
                Duration.ofSeconds(20),
                () -> {
                    SSLContext serverContext = serverBuilder().buildServerContext();

                    try (SSLServerSocket socket = GostSsl.serverSocket(0, serverContext)) {
                        AtomicReference<Throwable> error = new AtomicReference<>();
                        CountDownLatch done = new CountDownLatch(1);
                        serveOnce(socket, error, done);

                        String answer = call(socket.getLocalPort(), trustingClientContext());
                        assertTrue(done.await(15, TimeUnit.SECONDS), "сервер завершил соединение");
                        assertEquals("ECHO: PING", answer, "сервер ответил");
                        assertNull(error.get(), "сервер не увидел ошибок");
                    }
                });
    }

    @Test
    @DisplayName("needClientAuth без якорей: ошибка на сборке")
    void needClientAuthWithoutAnchorsFailsAtBuild() {
        IllegalStateException error =
                assertThrows(
                        IllegalStateException.class,
                        () -> serverBuilder().needClientAuth(true).buildServerContext());
        assertTrue(
                error.getMessage().contains("requires trust anchors"),
                "текст ошибки про якоря: " + error.getMessage());
    }

    @Test
    @DisplayName("wantClientAuth без якорей: ошибка на сборке")
    void wantClientAuthWithoutAnchorsFailsAtBuild() {
        assertThrows(
                IllegalStateException.class,
                () -> serverBuilder().wantClientAuth(true).buildServerContext());
    }

    @Test
    @DisplayName("clientOcspPolicy без якорей: ошибка на сборке")
    void clientOcspPolicyWithoutAnchorsFailsAtBuild() {
        assertThrows(
                IllegalStateException.class,
                () ->
                        serverBuilder()
                                .clientOcspPolicy(ClientOcspPolicy.REQUIRE)
                                .buildServerContext());
    }

    @Test
    @DisplayName("crlPolicy без якорей: ошибка на сборке")
    void crlPolicyWithoutAnchorsFailsAtBuild() {
        assertThrows(
                IllegalStateException.class,
                () -> serverBuilder().crlPolicy(CrlPolicy.IF_CDP_PRESENT).buildServerContext());
    }

    @Test
    @DisplayName("Клиент без якорей по-прежнему не собирается")
    void clientWithoutAnchorsStillFails() {
        assertThrows(GostSslException.class, () -> GostSsl.builder().buildClientContext());
    }

    @Test
    @DisplayName("Аутентификация включена после сборки: клиент отвергается")
    void clientAuthEnabledAfterBuildRejectsClient() {
        assertTimeoutPreemptively(
                Duration.ofSeconds(20),
                () -> {
                    SSLContext serverContext = serverBuilder().buildServerContext();
                    ((GostSSLSessionContext) serverContext.getServerSessionContext())
                            .setNeedClientAuth(true);

                    try (SSLServerSocket socket = GostSsl.serverSocket(0, serverContext)) {
                        AtomicReference<Throwable> error = new AtomicReference<>();
                        CountDownLatch done = new CountDownLatch(1);
                        serveOnce(socket, error, done);

                        assertThrows(
                                SSLException.class,
                                () -> call(socket.getLocalPort(), clientContext()),
                                "клиент с сертификатом не должен пройти без якорей");
                        assertTrue(done.await(15, TimeUnit.SECONDS), "сервер завершил соединение");
                        assertTrue(
                                error.get() instanceof SSLException,
                                "сервер отверг сертификат клиента: " + error.get());
                    }
                });
    }

    @Test
    @DisplayName("needClientAuth на сокете после сборки: клиент отвергается")
    void clientAuthEnabledOnServerSocketRejectsClient() {
        assertTimeoutPreemptively(
                Duration.ofSeconds(20),
                () -> {
                    SSLContext serverContext = serverBuilder().buildServerContext();

                    try (SSLServerSocket socket = GostSsl.serverSocket(0, serverContext)) {
                        socket.setNeedClientAuth(true);
                        AtomicReference<Throwable> error = new AtomicReference<>();
                        CountDownLatch done = new CountDownLatch(1);
                        serveOnce(socket, error, done);

                        assertThrows(
                                SSLException.class,
                                () -> call(socket.getLocalPort(), clientContext()));
                        assertTrue(done.await(15, TimeUnit.SECONDS), "сервер завершил соединение");
                        assertTrue(
                                error.get() instanceof SSLException,
                                "сервер отверг сертификат клиента: " + error.get());
                    }
                });
    }

    @Test
    @DisplayName("mTLS с якорями работает как раньше")
    void mtlsWithAnchorsStillWorks() {
        assertTimeoutPreemptively(
                Duration.ofSeconds(20),
                () -> {
                    SSLContext serverContext =
                            serverBuilder()
                                    .trustCa(root.cert.getEncoded())
                                    .needClientAuth(true)
                                    .buildServerContext();

                    try (SSLServerSocket socket = GostSsl.serverSocket(0, serverContext)) {
                        AtomicReference<Throwable> error = new AtomicReference<>();
                        CountDownLatch done = new CountDownLatch(1);
                        serveOnce(socket, error, done);

                        String answer = call(socket.getLocalPort(), clientContext());
                        assertTrue(done.await(15, TimeUnit.SECONDS), "сервер завершил соединение");
                        assertEquals("ECHO: PING", answer, "mTLS-обмен прошёл");
                        assertNull(error.get(), "сервер не увидел ошибок");
                    }
                });
    }
}
