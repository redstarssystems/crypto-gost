package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

/**
 * Отказ сервера клиентскому сертификату при mTLS. Сервер узнаёт об отказе уже после своего
 * Finished, и по RFC 8446 §4.4.4 его записи с этого места защищены ключами приложения: клиент,
 * отправивший свой Finished, читает ими же. Alert, защищённый ключами рукопожатия, клиент не
 * расшифровал бы и вместо причины увидел бы bad_record_mac.
 */
@DisplayName("TlsSession: alert при отказе сертификату клиента доходит с настоящим кодом")
class TlsSessionClientCertificateRejectionTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int TIMEOUT_SECONDS = 30;

    @Test
    @DisplayName("Сертификат клиента вне доверия сервера: клиент получает alert сервера")
    void clientSeesServerAlertCode() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle serverRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle foreignRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert = leaf(params, serverRoot);
        // Клиентский сертификат выпущен корнем, которому сервер не доверяет
        PkixCertTestHelper.CertBundle clientCert = leaf(params, foreignRoot);

        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Throwable> server =
                    CompletableFuture.supplyAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    TlsServerConfig config =
                                            new TlsServerConfig(
                                                            SUITE,
                                                            List.of(serverCert.cert),
                                                            serverCert.priv)
                                                    .needClientAuth(
                                                            TrustAnchors.ofCertificate(
                                                                    serverRoot.cert));
                                    TlsSession.createServer(config, new SocketTlsTransport(socket))
                                            .handshakeAsServer();
                                    return null;
                                } catch (Throwable e) {
                                    return e;
                                }
                            });

            Throwable clientFailure;
            try (Socket socket = new Socket("127.0.0.1", listener.getLocalPort())) {
                TlsClientConfig config =
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(serverRoot.cert))
                                .withoutHostnameVerification()
                                .withClientCertificateChain(clientCert.cert)
                                .withClientPrivateKey(clientCert.priv);
                TlsSession client = TlsSession.createClient(config, new SocketTlsTransport(socket));
                clientFailure = failureOf(client);
            }

            Throwable serverFailure = server.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            TlsException atServer = assertInstanceOf(TlsException.class, serverFailure);
            TlsException atClient = assertInstanceOf(TlsException.class, clientFailure);
            assertTrue(atClient.isFromPeer(), "клиент получил alert, а не нашёл ошибку записи сам");
            assertEquals(
                    atServer.getAlertCode(),
                    atClient.getAlertCode(),
                    "клиент видит тот же код, что отправил сервер, а не bad_record_mac");
        }
    }

    /** Рукопожатие клиента завершается; отказ сервера приходит при первом чтении. */
    private static Throwable failureOf(TlsSession client) {
        try {
            client.handshakeAsClient();
            client.read();
        } catch (Throwable e) {
            return e;
        }
        return null;
    }

    private static PkixCertTestHelper.CertBundle leaf(
            ECParameters params, PkixCertTestHelper.CertBundle root) throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        false,
                        null);
        assertNotNull(leaf.cert);
        return leaf;
    }
}
