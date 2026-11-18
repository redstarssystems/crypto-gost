package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Рукопожатие, в котором сообщение Certificate не помещается в одну TLS-запись.
 *
 * <p>Отправитель режет сообщение по размеру открытого текста записи, а цикл приёма рукопожатия
 * собирает его обратно из нескольких зашифрованных записей. Этот цикл отдельный от {@code read()}:
 * у него свои проверки типа записи, пустого фрагмента и alert, поэтому покрыт отдельно, в обе
 * стороны: сертификат сервера принимает клиент, сертификат клиента при mTLS принимает сервер.
 */
@DisplayName("TlsSession: Certificate длиннее одной записи в рукопожатии")
class TlsSessionLargeCertificateTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    private static final String NOT_BEFORE = "20240501120000Z";
    private static final String NOT_AFTER = "21060101120000Z";
    private static final int TIMEOUT_SECONDS = 20;

    // Число SAN-имён заметно меньше предела разбора (512), а размер сертификата заведомо больше
    // записи: ≈ 500 имён по ≈ 70 байт дают около 35 КБ
    private static final int SAN_COUNT = 500;
    private static final String SAN_PADDING = "a".repeat(48);

    private static final byte[] PING = {0x50, 0x49, 0x4E, 0x47};
    private static final byte[] PONG = {0x50, 0x4F, 0x4E, 0x47};

    @Test
    @DisplayName("Certificate сервера больше записи: клиент собирает его из нескольких записей")
    void clientAssemblesFragmentedServerCertificate() throws Exception {
        PkixCertTestHelper.CertBundle server =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(), NOT_BEFORE, NOT_AFTER, bigSanNames());
        assertCertificateExceedsOneRecord(server);

        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession =
                TlsSession.createServer(
                        new TlsServerConfig(
                                SUITE, Collections.singletonList(server.cert), server.priv),
                        pair.getServerTransport());
        TlsSession clientSession =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert))
                                .withServerHostname(HOST),
                        pair.getClientTransport());
        try {
            handshake(clientSession, serverSession);

            assertEquals(
                    1,
                    clientSession.getPeerCertificates().size(),
                    "Клиент получил цепочку из одного сертификата");
            assertArrayEquals(
                    server.cert.getEncoded(),
                    clientSession.getPeerCertificates().get(0).getEncoded(),
                    "Сертификат, собранный из записей, совпадает с отправленным");
            exchangeApplicationData(clientSession, serverSession);
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    @Test
    @DisplayName("Certificate клиента (mTLS) больше записи: сервер собирает его из нескольких")
    void serverAssemblesFragmentedClientCertificate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle server = signedByCa(params, ca, new String[] {HOST});
        PkixCertTestHelper.CertBundle client = signedByCa(params, ca, bigSanNames());
        assertCertificateExceedsOneRecord(client);

        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE, Collections.singletonList(server.cert), server.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(ca.cert)),
                        pair.getServerTransport());
        TlsSession clientSession =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(ca.cert))
                                .withServerHostname(HOST)
                                .withClientCertificateChain(client.cert)
                                .withClientPrivateKey(client.priv),
                        pair.getClientTransport());
        try {
            handshake(clientSession, serverSession);

            assertEquals(
                    1,
                    serverSession.getPeerCertificates().size(),
                    "Сервер получил цепочку клиента из одного сертификата");
            assertArrayEquals(
                    client.cert.getEncoded(),
                    serverSession.getPeerCertificates().get(0).getEncoded(),
                    "Сертификат клиента, собранный из записей, совпадает с отправленным");
            exchangeApplicationData(clientSession, serverSession);
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    private static PkixCertTestHelper.CertBundle signedByCa(
            ECParameters params, PkixCertTestHelper.CertBundle ca, String[] sanDnsNames)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                sanDnsNames,
                null,
                null,
                false,
                null);
    }

    /** Имена SAN: одно нужное для проверки имени хоста и много лишних, чтобы раздуть сертификат. */
    private static String[] bigSanNames() {
        String[] names = new String[SAN_COUNT + 1];
        names[0] = HOST;
        for (int i = 1; i <= SAN_COUNT; i++) {
            names[i] = "san-" + i + "-" + SAN_PADDING + ".example.com";
        }
        return names;
    }

    private static void assertCertificateExceedsOneRecord(PkixCertTestHelper.CertBundle bundle) {
        int size = bundle.cert.getEncoded().length;
        // Без этого условия тест молча превратился бы в проверку обычного рукопожатия
        assertTrue(
                size > TlsConstants.MAX_PLAINTEXT_LENGTH,
                "предусловие: сертификат (" + size + " байт) не помещается в одну запись");
    }

    private static void exchangeApplicationData(TlsSession client, TlsSession server)
            throws Exception {
        client.write(PING);
        assertArrayEquals(PING, server.read(), "Сервер прочитал данные клиента");
        server.write(PONG);
        assertArrayEquals(PONG, client.read(), "Клиент прочитал данные сервера");
    }

    private static void handshake(TlsSession client, TlsSession server) throws Exception {
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientDone =
                    exec.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverDone =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            exec.shutdownNow();
        }
    }
}
