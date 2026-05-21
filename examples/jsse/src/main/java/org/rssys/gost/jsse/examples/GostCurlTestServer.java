package org.rssys.gost.jsse.examples;

import io.undertow.Undertow;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/**
 * Тестовый HTTP-сервер для проверки gost-curl.
 * <p>
 * Генерирует CA + серверный сертификат (через {@link ExamplesCertHelper}),
 * стартует Undertow на случайном порту, выводит URL и путь к CA-сертификату.
 * Эхо-обработчик: возвращает тело запроса как тело ответа.
 * <p>
 * Запуск: {@code mvn install exec:java -pl examples/jsse -am -DskipTests
 * -Dexec.mainClass="...GostCurlTestServer"}
 * <p>
 * Проверка: {@code java -jar gost-curl.jar --ca <ca.pem> https://localhost:<port> -d "Привет"}
 */
public final class GostCurlTestServer {

    private GostCurlTestServer() {}

    public static void main(String[] args) throws Exception {
        ExamplesCertHelper helper = new ExamplesCertHelper();

        // Сохраняем CA-сертификат в PEM
        byte[] caDer = helper.getCaCertDer();
        String caPem = toPem(caDer, "CERTIFICATE");
        Path caPath = Files.createTempFile("gost-test-ca-", ".pem");
        Files.writeString(caPath, caPem);
        caPath.toFile().deleteOnExit();

        Undertow server = Undertow.builder()
                .addHttpsListener(0, "0.0.0.0", helper.getSslContext())
                .setHandler(GostCurlTestServer::handleRequest)
                .build();

        server.start();

        int port = ((InetSocketAddress) server.getListenerInfo().get(0).getAddress()).getPort();

        System.out.println("Server: https://localhost:" + port);
        System.out.println("CA cert: " + caPath.toAbsolutePath());
        System.out.println();
        System.out.println("Проверка:");
        System.out.println("  java -jar gost-curl.jar --ca " + caPath.toAbsolutePath()
                + " https://localhost:" + port + " -d \"Привет ГОСТ\"");
        System.out.println("  java -jar gost-curl.jar -k https://localhost:" + port
                + " -d \"Привет\" -v");
        System.out.println();
        System.out.println("Нажмите Ctrl+C для остановки.");

        // Бесконечное ожидание — сервер работает до Ctrl+C
        Thread.currentThread().join();
    }

    /**
     * Эхо-обработчик: возвращает тело запроса как тело ответа.
     * Позволяет проверить полный цикл: HTTP-запрос → TLS → ГОСТ-расшифровка → HTTP-ответ → TLS → ГОСТ-зашифровка.
     */
    private static void handleRequest(HttpServerExchange exchange) {
        exchange.getRequestReceiver().receiveFullBytes((ex, bytes) -> {
            ex.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
            ex.setStatusCode(200);
            ex.getResponseSender().send(ByteBuffer.wrap(bytes));
        });
    }

    /** DER → PEM с разбивкой Base64 по 64 символа. */
    private static String toPem(byte[] der, String label) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(label).append("-----\n");
        return sb.toString();
    }
}
