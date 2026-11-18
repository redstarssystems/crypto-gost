package org.rssys.bench.crl;

import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;

/**
 * Локальный HTTP-сервер, раздающий один CRL-файл.
 *
 * <p>Работает в отдельной JVM, чтобы его память не попала в измеряемую кучу. Файл отдаётся
 * потоком с диска, поэтому сервису хватает небольшой кучи даже при 16 одновременных ответах по
 * 200 МБ.</p>
 */
final class Server {

    private static final int COPY_BUFFER = 64 * 1024;
    private static final int POOL = 32;

    private Server() {}

    static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        int port = Integer.parseInt(args[1]);
        long length = Files.size(file);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 64);
        server.createContext(
                "/",
                ex -> {
                    ex.sendResponseHeaders(200, length);
                    try (InputStream in = Files.newInputStream(file);
                            OutputStream out = ex.getResponseBody()) {
                        byte[] buf = new byte[COPY_BUFFER];
                        int n;
                        while ((n = in.read(buf)) != -1) {
                            out.write(buf, 0, n);
                        }
                    }
                });
        server.setExecutor(Executors.newFixedThreadPool(POOL));
        server.start();
        System.out.println("READY");
        System.out.flush();
        Thread.currentThread().join();
    }
}
