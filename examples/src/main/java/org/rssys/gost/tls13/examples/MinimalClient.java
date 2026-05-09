package org.rssys.gost.tls13.examples;

import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/**
 * Минимальный клиент TLS 1.3 (анонимный, без проверки CA).
 * <p>
 * Демонстрирует:
 * <ul>
 *   <li>InMemoryTlsTransport (в production — SocketTlsTransport)</li>
 *   <li>TlsClientConfig</li>
 *   <li>Полный handshake TLS 1.3 со стороны клиента</li>
 *   <li>Отправку прикладных данных</li>
 * </ul>
 */
public final class MinimalClient {

    public static void main(String[] args) throws Exception {
        // 1. Генерируем корневой CA и сертификат сервера
        TlsCertificate ca = ExampleUtils.createRootCA();
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        PrivateKeyParameters serverPriv = kp.getPrivate();
        TlsCertificate serverCert = ExampleUtils.createServerCert(ca, serverPriv, kp.getPublic());

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 2. Создаём пару транспортов в памяти
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        InMemoryTlsTransport serverTp = pair.getServerTransport();
        InMemoryTlsTransport clientTp = pair.getClientTransport();

        // 3. Создаём сессии сервера и клиента
        TlsSession server = TlsSession.createServer(
                serverTp, cs, serverCert, serverPriv);
        TlsSession client = TlsSession.createClient(
                clientTp, cs, null, null);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            // 4. Серверный handshake в отдельном потоке
            Future<Void> sf = exec.submit(() -> {
                server.handshakeAsServer();
                return null;
            });

            // 5. Клиентский handshake в текущем потоке
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            // 6. Отправляем прикладные данные
            client.write("Hello from client!".getBytes(StandardCharsets.UTF_8));
            byte[] received = server.read();
            System.out.println(new String(received, StandardCharsets.UTF_8));
            System.out.println("SUCCESS");
        } finally {
            // 7. Очистка
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            try { server.close(); } catch (Exception ignored) {}
            try { client.close(); } catch (Exception ignored) {}
            try { serverTp.close(); } catch (Exception ignored) {}
            try { clientTp.close(); } catch (Exception ignored) {}
        }
    }
}
