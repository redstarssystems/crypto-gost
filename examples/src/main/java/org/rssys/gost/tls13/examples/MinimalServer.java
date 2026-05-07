package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
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
 * Минимальный сервер TLS 1.3 (с сертификатом, подписанным CA).
 * <p>
 * Демонстрирует:
 * <ul>
 *   <li>InMemoryTlsTransport (в production — SocketTlsTransport)</li>
 *   <li>TlsServerConfig с цепочкой сертификатов сервера</li>
 *   <li>Полный handshake TLS 1.3 со стороны сервера</li>
 *   <li>Чтение прикладных данных</li>
 * </ul>
 */
public final class MinimalServer {

    public static void main(String[] args) throws Exception {
        // 1. Генерируем корневой CA и сертификат сервера
        TlsCertificate ca = ExampleUtils.createRootCA();
        org.rssys.gost.api.KeyPair serverKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters serverPriv = serverKp.getPrivate();
        TlsCertificate serverCert = ExampleUtils.createServerCert(ca, serverPriv, serverKp.getPublic());

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 2. Создаём пару транспортов в памяти
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // 3. Создаём сессии сервера и клиента
        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(pair.getServerTransport(), cs,
                        Collections.singletonList(serverCert), serverPriv));
        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(pair.getClientTransport(), cs));

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            // 4. Клиентский handshake в отдельном потоке
            Future<Void> cf = exec.submit(() -> {
                client.handshakeAsClient();
                client.write("Hello from client!".getBytes(StandardCharsets.UTF_8));
                return null;
            });

            // 5. Серверный handshake в текущем потоке
            server.handshakeAsServer();
            cf.get(15, TimeUnit.SECONDS);

            // 6. Читаем прикладные данные
            byte[] received = server.read();
            System.out.println(new String(received, StandardCharsets.UTF_8));
            System.out.println("SUCCESS");
        } finally {
            // 7. Очистка
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            try { server.close(); } catch (Exception ignored) {}
            try { client.close(); } catch (Exception ignored) {}
        }
    }
}
