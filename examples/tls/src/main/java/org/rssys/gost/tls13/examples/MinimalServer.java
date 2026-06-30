package org.rssys.gost.tls13.examples;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.*;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

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
        ExampleUtils.CertBundle caBundle = ExampleUtils.createRootCABundle();
        ExampleUtils.CertBundle serverBundle = ExampleUtils.createServerCertBundle(caBundle);

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // 2. Создаём пару транспортов в памяти
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (InMemoryTlsTransport serverTp = pair.getServerTransport();
                InMemoryTlsTransport clientTp = pair.getClientTransport();
                TlsSession server =
                        TlsSession.createServer(
                                new TlsServerConfig(
                                        cs,
                                        Collections.singletonList(serverBundle.cert()),
                                        serverBundle.priv()),
                                serverTp);
                TlsSession client = TlsSession.createClient(new TlsClientConfig(cs), clientTp)) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                // 4. Клиентский handshake в отдельном потоке
                Future<Void> cf =
                        exec.submit(
                                () -> {
                                    client.handshakeAsClient();
                                    client.write(
                                            "Hello from client!".getBytes(StandardCharsets.UTF_8));
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
                try {
                    exec.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
            }
        }
    }
}
