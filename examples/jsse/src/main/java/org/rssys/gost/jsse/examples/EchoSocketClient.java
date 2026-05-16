package org.rssys.gost.jsse.examples;

import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;

/**
 * Клиент для проверки JSSE-интеграции через SSLSocket API.
 * <p>
 * Использует {@code GostSSLSocketFactory}, полученный из SSLContext,
 * чтобы пройти полный путь: socket → handshake → защищённый I/O.
 * <p>
 * PING → PONG — протокол уровня приложения, достаточный для
 * верификации двустороннего TLS-соединения.
 */
public final class EchoSocketClient {

    private EchoSocketClient() {}

    /**
     * Прямое TLS-соединение: отправляет "PING", читает "PONG".
     * Работает с не-HTTP серверами (Netty EchoHandler).
     */
    public static String ping(String host, int port, javax.net.ssl.SSLContext ctx,
                              int timeoutMillis) throws Exception {
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
        socket.setSoTimeout(timeoutMillis);
        try {
            OutputStream out = socket.getOutputStream();
            PrintWriter pw = new PrintWriter(out, true, java.nio.charset.StandardCharsets.UTF_8);
            pw.println("PING");

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
            String response = in.readLine();
            if (!"PONG".equals(response)) {
                throw new RuntimeException("Unexpected response: " + response);
            }
            return response;
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    public static String ping(String host, int port, javax.net.ssl.SSLContext ctx) throws Exception {
        return ping(host, port, ctx, 10000);
    }

    /**
     * TLS через HTTP POST /echo. Шлёт "PING" как тело запроса,
     * извлекает "PONG" из тела ответа (пропуская HTTP-заголовки).
     * Работает с HTTP-серверами (Jetty, Undertow, Tomcat, Spring Boot).
     */
    public static String pingHttp(String host, int port, javax.net.ssl.SSLContext ctx,
                                  int timeoutMillis) throws Exception {
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
        socket.setSoTimeout(timeoutMillis);
        try {
            OutputStream out = socket.getOutputStream();
            byte[] req = ("POST /echo HTTP/1.1\r\n"
                    + "Host: " + host + "\r\n"
                    + "Content-Type: text/plain\r\n"
                    + "Content-Length: 4\r\n"
                    + "Connection: close\r\n"
                    + "\r\n"
                    + "PING").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.write(req);
            out.flush();

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.US_ASCII));
            String line;
            boolean body = false;
            while ((line = in.readLine()) != null) {
                if (body) {
                    if ("PONG".equals(line.trim())) return "PONG";
                } else if (line.isEmpty()) {
                    body = true;
                }
            }
            throw new RuntimeException("No PONG in HTTP response");
        } finally {
            try { socket.close(); } catch (Exception ignored) {}
        }
    }

    public static String pingHttp(String host, int port, javax.net.ssl.SSLContext ctx) throws Exception {
        return pingHttp(host, port, ctx, 10000);
    }
}
