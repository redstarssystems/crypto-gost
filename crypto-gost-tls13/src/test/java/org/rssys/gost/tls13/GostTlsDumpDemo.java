package org.rssys.gost.tls13;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HexFormat;

/**
 * Минимальный демо-тест для захвата трафика tcpdump/Wireshark.
 *
 * Запуск:
 *   1. sudo tcpdump -i lo -w /tmp/gost-tls.pcap port <PORT>  ← PORT печатается в stdout
 *   2. mvn test -pl crypto-gost-tls13 -Dtest=GostTlsDumpDemo
 *   3. Ctrl+C tcpdump
 *   4. wireshark /tmp/gost-tls.pcap   (или: tshark -r /tmp/gost-tls.pcap)
 *
 * Что увидите в Wireshark:
 *   - Content Type 22 (0x16) — Handshake: ClientHello, ServerHello, Certificate, Finished
 *   - Content Type 23 (0x17) — Application Data: зашифрованные байты "Hello from client!"
 *   - Record Layer Version: TLS 1.2 (0x0303) — стандарт для TLS 1.3 в wire format
 *
 * Wireshark НЕ сможет расшифровать Application Data — нет SSLKEYLOGFILE для ГОСТ.
 */
public class GostTlsDumpDemo {

    public static void main(String[] args) throws Exception {

        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        // Генерируем самоподписанный ГОСТ-сертификат
        TlsTestHelper.CertBundle bundle =
                TlsTestHelper.createCertWithKey(ECParameters.tc26a256());

        TlsServerConfig serverConfig = new TlsServerConfig(
                cs,
                Collections.singletonList(bundle.cert),
                bundle.priv);

        TlsClientConfig clientConfig = new TlsClientConfig(cs)
                .withCaPublicKey(bundle.cert.getPublicKey());

        // Сервер на случайном порту
        ServerSocket serverSocket = new ServerSocket(0);
        int port = serverSocket.getLocalPort();

        System.out.println("========================================");
        System.out.println("Запустите tcpdump:");
        System.out.println("  sudo tcpdump -i lo -w /tmp/gost-tls.pcap port " + port);
        System.out.println("Нажмите Enter когда tcpdump запущен...");
        System.out.println("========================================");
        System.in.read();

        // Серверный поток
        Thread serverThread = Thread.ofVirtual().name("demo-server").start(() -> {
            try {
                Socket raw = serverSocket.accept();
                System.out.println("[SERVER] Принято соединение от " + raw.getRemoteSocketAddress());

                try (var t = new SocketTlsTransport(raw);
                     var s = TlsSession.createServer(serverConfig, t)) {
                    s.handshakeAsServer();

                    byte[] received = s.read();
                    System.out.println("[SERVER] Получено: " + new String(received, StandardCharsets.UTF_8));
                    System.out.println("[SERVER] Hex: " + HexFormat.of().formatHex(received));

                    byte[] response = "Hello from server! Я зашифрован ГОСТ Кузнечик-МГМ.".getBytes(StandardCharsets.UTF_8);
                    s.write(response);
                    System.out.println("[SERVER] Отправлен ответ (" + response.length + " байт)");
                }

                System.out.println("[SERVER] Соединение закрыто (close_notify отправлен)");
            } catch (Exception e) {
                System.err.println("[SERVER] Ошибка: " + e.getMessage());
            }
        });

        // Небольшая пауза чтобы сервер успел вызвать accept()
        Thread.sleep(200);

        // Клиент
        System.out.println("\n[CLIENT] Подключаемся к localhost:" + port);
        try (Socket raw = new Socket("localhost", port);
             var t = new SocketTlsTransport(raw);
             var s = TlsSession.createClient(clientConfig, t)) {

            s.handshakeAsClient();
            System.out.println("[CLIENT] TLS handshake завершён (ГОСТ Р 34.10-2012 + Кузнечик-МГМ)");


            byte[] message = "Hello from client!".getBytes(StandardCharsets.UTF_8);
            System.out.println("[CLIENT] Отправляем: \"" + new String(message, StandardCharsets.UTF_8) + "\"");
            System.out.println("[CLIENT] Plaintext hex: " + HexFormat.of().formatHex(message));
            s.write(message);

            byte[] response = s.read();
            System.out.println("[CLIENT] Получен ответ: " + new String(response, StandardCharsets.UTF_8));
        }

        serverThread.join(3000);
        serverSocket.close();

        System.out.println("\n========================================");
        System.out.println("Готово. Остановите tcpdump (Ctrl+C) и откройте pcap:");
        System.out.println("  wireshark /tmp/gost-tls.pcap");
        System.out.println("  # или консольно:");
        System.out.println("  tshark -r /tmp/gost-tls.pcap -V");
        System.out.println();
        System.out.println("Что искать в Wireshark:");
        System.out.println("  Content Type: Handshake (22)    → ClientHello, ServerHello, Certificate");
        System.out.println("  Content Type: Application Data (23) → зашифрованные байты");
        System.out.println("  Plaintext 'Hello from client!' в pcap отсутствует → трафик зашифрован");
        System.out.println("========================================");
    }
}