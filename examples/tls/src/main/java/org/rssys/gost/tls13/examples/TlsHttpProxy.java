package org.rssys.gost.tls13.examples;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.Pkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Прокси-сервер для ГОСТ TLS termination.
 * Принимает ГОСТ TLS 1.3 соединение, читает HTTP-запрос,
 * проксирует plaintext HTTP на указанный бэкенд и возвращает ответ.
 * <p>
 * Пример запуска с тестовым сертификатом:
 * {@snippet :
 * make http-proxy PORT=4443 BACKEND_HOST=localhost BACKEND_PORT=8080
 * }
 * <p>
 * После запуска любой HTTP-клиент через ГОСТ TLS может обращаться
 * к бэкенду через этот прокси.
 */
public final class TlsHttpProxy {

    private TlsHttpProxy() {}

    public static void main(String[] args) throws Exception {
        int port = 4443;
        String p12Path = null;
        String password = "test";
        TlsCiphersuite suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
        String backendHost = "localhost";
        int backendPort = 8080;
        boolean mtls = false;
        String caPath = null;
        String caPassword = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
                case "--cert":
                    p12Path = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--cipher": {
                    String name = args[++i].toUpperCase();
                    if (name.equals("L")) {
                        suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
                    } else if (name.equals("S")) {
                        suite = TlsCiphersuite.byId(TlsConstants.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S);
                    } else {
                        System.err.println("Unknown cipher: " + name + " (use L or S)");
                        System.exit(1);
                    }
                    break;
                }
                case "--backend":
                    backendHost = args[++i];
                    backendPort = Integer.parseInt(args[++i]);
                    break;
                case "--mtls":
                    mtls = true;
                    break;
                case "--ca":
                    caPath = args[++i];
                    caPassword = i + 1 < args.length && !args[i + 1].startsWith("--")
                            ? args[++i] : "test";
                    break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    System.exit(1);
            }
        }

        if (p12Path == null) {
            System.err.println("Usage: TlsHttpProxy --cert <p12> [--port <port>] [--password <pwd>]"
                    + " [--cipher L|S] --backend <host> <port>"
                    + " [--mtls] [--ca <p12> <password>]");
            System.exit(1);
        }

        Pkcs12Loader.Result p12;
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            p12 = Pkcs12Loader.load(fis.readAllBytes(), password.toCharArray());
        }

        List<TlsCertificate> chain = p12.getCertificateChain();
        PrivateKeyParameters privKey = p12.getPrivateKey();
        TlsServerConfig config = new TlsServerConfig(suite, chain, privKey);

        if (mtls && caPath != null) {
            try (FileInputStream fis = new FileInputStream(caPath)) {
                Pkcs12Loader.Result caP12 = Pkcs12Loader.load(fis.readAllBytes(), caPassword.toCharArray());
                config.withCaPublicKey(caP12.getCertificateChain().get(0).getPublicKey());
            }
        }

        final TlsServerConfig cfg = config;
        final String fHost = backendHost;
        final int fPort = backendPort;

        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("=== GOST TLS HTTP Proxy ===");
            System.out.println("TLS port: " + port + " (0x" + Integer.toHexString(suite.getId()) + ")");
            System.out.println("Backend: " + backendHost + ":" + backendPort);
            System.out.println("mTLS: " + mtls);
            System.out.println("Waiting for connections...");
            System.out.println();

            while (true) {
                Socket s = ss.accept();
                final Socket socket = s;
                new Thread(() -> {
                    try {
                        handleConnection(socket, cfg, fHost, fPort);
                    } catch (Exception e) {
                        System.err.println("Connection error: " + e.getMessage());
                        try { socket.close(); } catch (IOException ignored) {}
                    }
                }).start();
            }
        }
    }

    private static void handleConnection(
            Socket socket,
            TlsServerConfig config,
            String backendHost,
            int backendPort) throws Exception {

        socket.setTcpNoDelay(true);
        socket.setSoTimeout(30_000); // таймаут на Keep-Alive простой

        try (SocketTlsTransport transport = new SocketTlsTransport(socket);
             TlsSession server = TlsSession.createServer(config, transport)) {

            server.handshakeAsServer();
            System.out.println("Handshake done: "
                    + ", peer=" + (server.getPeerCertificates() != null
                    ? server.getPeerCertificates().size() + " certs" : "none"));

            // Keep-Alive цикл: читаем запросы пока клиент шлёт
            while (true) {
                byte[] req;
                try {
                    req = server.read();
                } catch (Exception e) {
                    // close_notify или таймаут — нормальное завершение
                    break;
                }

                if (req.length == 0) break;

                String reqText = new String(req, StandardCharsets.UTF_8);
                System.out.println("Request: " + firstLine(reqText));

                try (Socket backend = new Socket(backendHost, backendPort)) {
                    backend.setTcpNoDelay(true);
                    backend.setSoTimeout(10_000);

                    OutputStream backendOut = backend.getOutputStream();
                    backendOut.write(req);
                    backendOut.flush();

                    byte[] resp = readHttpResponse(backend);
                    server.write(resp);
                    System.out.println("Response: " + resp.length + " bytes proxied");
                } catch (Exception e) {
                    System.err.println("Backend error: " + e.getMessage());
                    String errResp = "HTTP/1.1 502 Bad Gateway\r\n"
                            + "Content-Length: 0\r\n"
                            + "Connection: close\r\n\r\n";
                    server.write(errResp.getBytes(StandardCharsets.UTF_8));
                }

                // Если клиент хочет закрыть — выходим из Keep-Alive
                if (reqText.toLowerCase().contains("connection: close")) {
                    break;
                }
                // Переустанавливаем таймаут для следующей итерации
                socket.setSoTimeout(30_000);
            }
        }
    }

    private static String firstLine(String http) {
        int idx = http.indexOf("\r\n");
        return idx >= 0 ? http.substring(0, idx) : http;
    }

    /** Читает полный HTTP-ответ от бэкенда: заголовки + тело. */
    static byte[] readHttpResponse(Socket backend) throws IOException {
        InputStream in = backend.getInputStream();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        // 1. Читаем заголовки до \r\n\r\n
        byte[] headerBytes = readUntil(in, "\r\n\r\n");
        String headerText = new String(headerBytes, StandardCharsets.UTF_8);

        // 2. Заголовки в карту
        String contentLength = null;
        String transferEncoding = null;
        boolean connectionClose = true;
        for (String line : headerText.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon < 1) continue;
            String key = line.substring(0, colon).trim().toLowerCase();
            String val = line.substring(colon + 1).trim().toLowerCase();
            if ("content-length".equals(key)) contentLength = val;
            if ("transfer-encoding".equals(key)) transferEncoding = val;
            if ("connection".equals(key) && val.contains("keep-alive")) connectionClose = false;
        }

        // 3. Тело
        ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
        if (contentLength != null) {
            int len = Integer.parseInt(contentLength);
            byte[] body = new byte[len];
            readFully(in, body, 0, len);
            bodyBuf.write(body);
        } else if ("chunked".equals(transferEncoding)) {
            parseChunked(in, bodyBuf);
        } else {
            // Connection: close или неизвестно — читаем до EOF
            byte[] tmp = new byte[4096];
            int n;
            while ((n = in.read(tmp)) != -1) bodyBuf.write(tmp, 0, n);
        }

        // 4. Склеиваем заголовки + тело
        byte[] bodyBytes = bodyBuf.toByteArray();
        byte[] result = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, result, headerBytes.length, bodyBytes.length);
        return result;
    }

    /** Читает данные из стрима до появления искомой подстроки. */
    private static byte[] readUntil(InputStream in, String delimiter) throws IOException {
        byte[] delim = delimiter.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] ring = new byte[delim.length];
        int ringPos = 0;
        int matched = 0;

        while (true) {
            int b = in.read();
            if (b == -1) throw new IOException("Connection closed while reading headers");
            buf.write(b);

            if (b == delim[matched]) {
                matched++;
                if (matched == delim.length) return buf.toByteArray();
            } else {
                matched = 0;
            }
        }
    }

    /** Парсит Transfer-Encoding: chunked тело. */
    private static void parseChunked(InputStream in, ByteArrayOutputStream out) throws IOException {
        while (true) {
            String line = readLine(in);
            int chunkSize = Integer.parseInt(line.trim(), 16);
            if (chunkSize == 0) break;
            byte[] chunk = new byte[chunkSize];
            readFully(in, chunk, 0, chunkSize);
            out.write(chunk);
            readLine(in); // пропускаем trailing \r\n
        }
        // Пропускаем trailer (если есть) и финальный \r\n
        readLine(in);
    }

    /** Читает строку до \n (с \r или без). */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') buf.write(b);
        }
        return buf.toString(StandardCharsets.US_ASCII.name());
    }

    /** Читает ровно len байт в массив. */
    private static void readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        int end = off + len;
        while (off < end) {
            int read = in.read(buf, off, end - off);
            if (read == -1) throw new IOException("Connection closed by peer");
            off += read;
        }
    }
}
