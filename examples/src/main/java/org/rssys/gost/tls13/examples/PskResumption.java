package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;

/**
 * PSK session resumption (аббревиатурный handshake).
 * <p>
 * Полный handshake -> сервер выдаёт NewSessionTicket -> клиент сохраняет PSK.
 * Второе соединение использует аббревиатурный handshake без Certificate/CertificateVerify.
 * Демонстрирует shared PskStore + setPskStore + естественный fallback при неизвестном тикете.
 */
public final class PskResumption {

    public static void main(String[] args) throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 1. Генерируем CA + сертификат сервера
        TlsCertificate ca = ExampleUtils.createRootCA();
        org.rssys.gost.api.KeyPair serverKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        TlsCertificate serverCert = ExampleUtils.createServerCert(ca, serverPriv, serverKp.getPublic());

        // 2. Shared PskStore — одно хранилище для сервера и клиента
        PskStore sharedStore = new PskStore(256); // макс. 256 PSK-тикетов

        // === Первое соединение: полный handshake + NewSessionTicket ===
        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();

        TlsSession server1 = TlsSession.createServer(
                new TlsServerConfig(pair1.getServerTransport(), cs,
                        Collections.singletonList(serverCert), serverPriv));
        server1.setPskStore(sharedStore);

        TlsSession client1 = TlsSession.createClient(
                new TlsClientConfig(pair1.getClientTransport(), cs));
        client1.setPskStore(sharedStore);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec.submit(() -> { server1.handshakeAsServer(); return null; });
            client1.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            // Клиент читает NewSessionTicket из post-handshake
            client1.read();
            client1.close();
            server1.close();
        } finally {
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }

        System.out.println("Full handshake done, PSK stored: " + sharedStore.size());

        // === Второе соединение: аббревиатурный handshake (PSK) ===
        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();

        TlsSession server2 = TlsSession.createServer(
                new TlsServerConfig(pair2.getServerTransport(), cs,
                        Collections.singletonList(serverCert), serverPriv));
        server2.setPskStore(sharedStore);

        TlsSession client2 = TlsSession.createClient(
                new TlsClientConfig(pair2.getClientTransport(), cs));
        client2.setPskStore(sharedStore);

        ExecutorService exec2 = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec2.submit(() -> { server2.handshakeAsServer(); return null; });
            client2.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            client2.write("Resumed via PSK".getBytes(StandardCharsets.UTF_8));
            byte[] received = server2.read();
            System.out.println(new String(received, StandardCharsets.UTF_8));
            System.out.println("SUCCESS");
        } finally {
            exec2.shutdown();
            try { exec2.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            try { server2.close(); } catch (Exception ignored) {}
            try { client2.close(); } catch (Exception ignored) {}
        }
    }
}
