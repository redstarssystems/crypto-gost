package org.rssys.gost.jsse.examples;

import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.GostSslBuilder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * JSSE-сервер, загружающий сертификаты из PFX-файлов.
 * <p>
 * Демонстрирует использование {@link GostSsl#builder()} с загрузкой
 * серверного и CA-сертификатов из PKCS12-контейнеров.
 * <p>
 * Пример запуска:
 * {@snippet :
 * java org.rssys.gost.jsse.examples.PfxServerExample \
 *     --cert /path/to/server.p12 --password changeit \
 *     --ca /path/to/ca.p12 --ca-password changeit \
 *     --port 4443
 * }
 * <p>
 * Если {@code --ca} не указан, сервер работает без проверки
 * клиентского сертификата.
 */
public final class PfxServerExample {

    private PfxServerExample() {}

    public static void main(String[] args) throws Exception {
        String certPath = null;
        String password = "changeit";
        String caPath = null;
        String caPassword = "changeit";
        int port = 4443;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--cert":
                    certPath = args[++i];
                    break;
                case "--password":
                    password = args[++i];
                    break;
                case "--ca":
                    caPath = args[++i];
                    break;
                case "--ca-password":
                    caPassword = args[++i];
                    break;
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    System.exit(1);
            }
        }

        if (certPath == null) {
            System.err.println("Usage: PfxServerExample --cert <server.p12> --password <pwd>"
                    + " [--ca <ca.p12>] [--ca-password <pwd>] [--port <n>]");
            System.exit(1);
        }

        byte[] serverPfx = Files.readAllBytes(Path.of(certPath));
        char[] pwd = password.toCharArray();

        GostSslBuilder builder = GostSsl.builder()
                .certificate(serverPfx, pwd);

        if (caPath != null) {
            byte[] caPfx = Files.readAllBytes(Path.of(caPath));
            builder.trustCa(caPfx, caPassword.toCharArray());
        } else {
            System.out.println("WARNING: no CA specified, trust-all mode");
            builder.trustAll();
        }

        SSLContext ctx = builder.buildServerContext();

        try (SSLServerSocket srv = (SSLServerSocket) ctx.getServerSocketFactory()
                .createServerSocket(port)) {
            System.out.println("Listening on port " + port);

            while (true) {
                try (SSLSocket socket = (SSLSocket) srv.accept()) {
                    socket.setSoTimeout(30_000);
                    socket.startHandshake();

                    InputStream in = socket.getInputStream();
                    OutputStream out = socket.getOutputStream();

                    byte[] buf = new byte[1024];
                    int n = in.read(buf);
                    String req = new String(buf, 0, n, StandardCharsets.UTF_8);

                    String resp = "PING".equals(req.trim()) ? "PONG" : "ECHO:" + req.trim();
                    out.write(resp.getBytes(StandardCharsets.UTF_8));
                    out.flush();

                    System.out.println(req.trim() + " -> " + resp);
                }
            }
        }
    }
}
