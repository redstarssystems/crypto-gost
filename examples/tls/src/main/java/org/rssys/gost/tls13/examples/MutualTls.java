package org.rssys.gost.tls13.examples;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Взаимная аутентификация (mTLS).
 * <p>
 * Сервер отправляет CertificateRequest и проверяет клиентский сертификат по CA-якорю.
 * Клиент отправляет свой сертификат + CertificateVerify.
 * TlsServerConfig.needClientAuth(TrustAnchors) и TlsClientConfig.withClientCertificateChain().
 */
public final class MutualTls {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 1. Создаём корневой CA (bundle хранит сертификат + ключи)
        ExampleUtils.CertBundle caBundle = ExampleUtils.createRootCABundle();

        // 2. Сертификат сервера (подписан CA)
        ExampleUtils.CertBundle serverBundle = ExampleUtils.createServerCertBundle(caBundle);

        // 3. Сертификат клиента (подписан тем же CA)
        ExampleUtils.CertBundle clientBundle = ExampleUtils.createClientCertBundle(caBundle);

        // 4. Создаём пару транспортов
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
                InMemoryTlsTransport clientTp = pair.getClientTransport();
                TlsSession server =
                        TlsSession.createServer(
                                new TlsServerConfig(
                                                cs,
                                                Collections.singletonList(serverBundle.cert()),
                                                serverBundle.priv())
                                        .needClientAuth(
                                                TrustAnchors.ofCertificate(caBundle.cert())),
                                serverTp);
                TlsSession client =
                        TlsSession.createClient(
                                new TlsClientConfig(cs, TrustAnchors.ofCertificate(caBundle.cert()))
                                        .withServerHostname("localhost")
                                        .withClientCertificateChain(clientBundle.cert())
                                        .withClientPrivateKey(clientBundle.priv()),
                                clientTp)) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf =
                        exec.submit(
                                () -> {
                                    server.handshakeAsServer();
                                    return null;
                                });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                client.write("mTLS handshake done".getBytes(StandardCharsets.UTF_8));
                byte[] received = server.read();
                System.out.println(new String(received, StandardCharsets.UTF_8));
                System.out.println("SUCCESS");
            } finally {
                exec.shutdown();
                try {
                    exec.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }
}
