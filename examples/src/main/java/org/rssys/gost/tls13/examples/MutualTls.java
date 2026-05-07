package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;

/**
 * Взаимная аутентификация (mTLS).
 * <p>
 * Сервер отправляет CertificateRequest и проверяет клиентский сертификат через CA public key.
 * Клиент отправляет свой сертификат + CertificateVerify.
 * Демонстрирует TlsServerConfig.withCaPublicKey() и TlsClientConfig.withClientCertificate().
 */
public final class MutualTls {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 1. Генерируем корневой CA
        TlsCertificate ca = ExampleUtils.createRootCA();
        PrivateKeyParameters caPriv = null; // в примере CA ключ не нужен после подписания

        // 2. Сертификат сервера (подписан CA)
        KeyPair serverKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        TlsCertificate serverCert = ExampleUtils.createServerCert(ca, serverPriv, serverKp.getPublic());

        // 3. Сертификат клиента (подписан тем же CA)
        KeyPair clientKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters clientPriv = clientKp.getPrivate();
        TlsCertificate clientCert = ExampleUtils.createClientCert(ca, clientPriv, clientKp.getPublic());

        // 4. Создаём пару транспортов
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // 5. Сервер — требует клиентский сертификат (caPublicKey)
        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(pair.getServerTransport(), cs,
                        Collections.singletonList(serverCert), serverPriv)
                        .withCaPublicKey(ca.getPublicKey()));
        // 6. Клиент — отправляет свой сертификат
        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(pair.getClientTransport(), cs)
                        .withServerHostname("localhost")
                        .withCaPublicKey(ca.getPublicKey())
                        .withClientCertificate(clientCert)
                        .withClientPrivateKey(clientPriv));

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            client.write("mTLS handshake done".getBytes(StandardCharsets.UTF_8));
            byte[] received = server.read();
            System.out.println(new String(received, StandardCharsets.UTF_8));
            System.out.println("SUCCESS");
        } finally {
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            try { server.close(); } catch (Exception ignored) {}
            try { client.close(); } catch (Exception ignored) {}
        }
    }
}
