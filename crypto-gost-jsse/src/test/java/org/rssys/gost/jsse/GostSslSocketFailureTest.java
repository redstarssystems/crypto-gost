package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.testkit.GostTestCerts;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Неудачное рукопожатие в {@link GostSsl#socket}: вызывающий сокет не получает и закрыть сам не
 * может, поэтому закрывать его должен метод.
 */
@DisplayName("GostSsl.socket: сокет закрывается при неудачном рукопожатии")
class GostSslSocketFailureTest {

    private static SSLContext clientContext;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        clientContext = GostSsl.clientContext(root.cert.getEncoded());
    }

    @Test
    @DisplayName("Сервер отвечает не TLS и держит соединение: клиент закрывает своё при отказе")
    void socketIsClosedWhenHandshakeFails() throws Exception {
        try (ServerSocket plainServer =
                new ServerSocket(0, 1, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}))) {
            CompletableFuture<Integer> serverSideRead =
                    CompletableFuture.supplyAsync(() -> readUntilClientCloses(plainServer));

            assertThrows(
                    GostSslException.class,
                    () -> GostSsl.socket("127.0.0.1", plainServer.getLocalPort(), clientContext),
                    "сервер не TLS: рукопожатие должно завершиться отказом");

            assertEquals(
                    -1,
                    serverSideRead.get(5, TimeUnit.SECONDS),
                    "клиентский сокет должен быть закрыт: сервер видит конец потока");
        }
    }

    @Test
    @DisplayName("verifyServer: прерывание потока сохраняется флагом, а не теряется")
    void verifyServerKeepsInterruptFlag() throws Exception {
        GostTestCerts.CertChain server = GostTestCerts.createServerCert();
        String certPem = server.chain().get(0).toPem();
        String keyPem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[] {'\n'})
                                .encodeToString(GostDerCodec.encodePrivateKey(server.key()))
                        + "\n-----END PRIVATE KEY-----\n";
        String caPem = server.caCert().toPem();

        Thread.currentThread().interrupt();
        try {
            assertThrows(
                    GostSslException.class,
                    () -> GostSsl.verifyServer(certPem, keyPem, caPem),
                    "ожидание сервера прервано: проверка завершается отказом");
            assertTrue(
                    Thread.currentThread().isInterrupted(),
                    "флаг прерывания должен остаться установленным");
        } finally {
            Thread.interrupted();
        }
    }

    /** Принимает соединение, шлёт не-TLS данные и ждёт, пока клиент закроет своё соединение. */
    private static int readUntilClientCloses(ServerSocket server) {
        try (Socket accepted = server.accept()) {
            accepted.setSoTimeout(4000);
            OutputStream out = accepted.getOutputStream();
            out.write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28});
            out.flush();
            InputStream in = accepted.getInputStream();
            int value;
            do {
                value = in.read();
            } while (value != -1);
            return -1;
        } catch (java.net.SocketTimeoutException e) {
            return -2;
        } catch (java.io.IOException e) {
            // сброс соединения клиентом тоже означает, что клиент закрыл сокет
            return -1;
        }
    }
}
