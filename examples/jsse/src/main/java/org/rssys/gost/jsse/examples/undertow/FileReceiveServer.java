package org.rssys.gost.jsse.examples.undertow;

import io.undertow.Undertow;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.GostSslBuilder;
import org.rssys.gost.jsse.examples.ExamplesCertHelper;

/**
 * Многопоточный ГОСТ TLS 1.3 сервер приёма файлов на Undertow + виртуальных потоках Java 21.
 * <p>
 * Принимает POST-запросы произвольного размера, считает байты потоком
 * (без буферизации в памяти), отвечает {@code OK received=N bytes}
 * и дублирует статистику в текстовый лог.
 * <p>
 * При обрыве соединения (таймаут клиента, сетевая ошибка) в лог записывается
 * фактически полученное количество байт с пометкой {@code [aborted]}.
 * <p>
 * XNIO IO-потоки Undertow обрабатывают сетевой I/O; каждый HTTP-запрос
 * dispatched в {@link Executors#newVirtualThreadPerTaskExecutor()} —
 * блокирующее чтение тела не занимает платформенные потоки.
 * <p>
 * Запуск без сертификата (самоподписанный ГОСТ):
 * <pre>{@code
 * java org.rssys.gost.jsse.examples.undertow.FileReceiveServer --port 8443
 * }</pre>
 * Запуск с PFX:
 * <pre>{@code
 * java org.rssys.gost.jsse.examples.undertow.FileReceiveServer \
 *     --cert server.p12 --password changeit \
 *     --ca ca.p12 --ca-password changeit \
 *     --port 8443 --log upload.log
 * }</pre>
 * Отправка файла:
 * <pre>{@code
 * curl -k --tlsv1.3 -X POST --data-binary @bigfile.bin https://localhost:8443/
 * }</pre>
 *  * Раздача файла (GET):
 *  * <pre>{@code
 *  * java org.rssys.gost.jsse.examples.undertow.FileReceiveServer \
 *  *     --port 8443 --file /path/to/bigfile.bin
 *  * curl -k --tlsv1.3 https://localhost:8443/ -o received.bin
 *  * }</pre>
 */
public final class FileReceiveServer {

    private static final int BUF_SIZE = 65536;

    // Один executor на весь сервер — виртуальный поток под каждый запрос
    private static final Executor VIRTUAL = Executors.newVirtualThreadPerTaskExecutor();

    // ReentrantLock вместо synchronized: synchronized пиннит carrier thread
    // виртуального потока, что нейтрализует преимущества vthreads под нагрузкой
    private static final ReentrantLock LOG_LOCK = new ReentrantLock();

    // Путь к файлу для раздачи по GET (опционально)
    private static Path filePath;

    private FileReceiveServer() {}

    public static void main(String[] args) throws Exception {
        int port = 8443;
        String certPath = null;
        String password = "changeit";
        String caPath = null;
        String caPassword = "changeit";
        String logPath = "file-receive.log";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
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
                case "--log":
                    logPath = args[++i];
                    break;
                case "--file":
                    filePath = Path.of(args[++i]);
                    break;
                default:
                    System.err.println("Unknown flag: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        SSLContext sslCtx = buildSslContext(certPath, password, caPath, caPassword);
        PrintWriter log = new PrintWriter(new FileWriter(logPath, true), false);

        Undertow server =
                Undertow.builder()
                        .addHttpsListener(port, "0.0.0.0", sslCtx)
                        .setHandler(
                                exchange -> {
                                    if (exchange.isInIoThread()) {
                                        // dispatch из IO-потока в виртуальный поток Undertow API:
                                        // dispatch(Executor, HttpHandler)
                                        exchange.dispatch(VIRTUAL, ex -> handleRequest(ex, log));
                                        return;
                                    }
                                    handleRequest(exchange, log);
                                })
                        .build();

        Runtime.getRuntime()
                .addShutdownHook(
                        new Thread(
                                () -> {
                                    server.stop();
                                    log.close();
                                }));

        server.start();
        int actualPort =
                ((InetSocketAddress) server.getListenerInfo().get(0).getAddress()).getPort();
        System.out.println("FileReceiveServer listening on port " + actualPort);
        System.out.println("Log: " + logPath);
        System.out.println("Press Ctrl+C to stop.");
    }

    private static SSLContext buildSslContext(
            String certPath, String password, String caPath, String caPassword) throws Exception {
        if (certPath == null) {
            System.out.println("No --cert specified — generating self-signed GOST certificate");
            return new ExamplesCertHelper().getSslContext();
        }

        byte[] p12 = Files.readAllBytes(Path.of(certPath));
        GostSslBuilder builder = GostSsl.builder().certificate(p12, password.toCharArray());

        if (caPath != null) {
            byte[] caPfx = Files.readAllBytes(Path.of(caPath));
            builder.trustCa(caPfx, caPassword.toCharArray());
        } else {
            System.out.println("WARNING: no --ca specified — trust-all mode (development only)");
            builder.trustAll();
        }

        return builder.buildServerContext();
    }

    private static void handleRequest(HttpServerExchange exchange, PrintWriter log)
            throws Exception {
        String method = exchange.getRequestMethod().toString();
        switch (method) {
            case "GET" -> handleGetRequest(exchange, log);
            case "POST" -> handlePostRequest(exchange, log);
            default -> {
                exchange.setStatusCode(StatusCodes.METHOD_NOT_ALLOWED);
                exchange.getResponseHeaders()
                        .put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
                exchange.getResponseSender()
                        .send("Method not allowed: " + method + "\n", StandardCharsets.UTF_8);
            }
        }
    }

    private static void handlePostRequest(HttpServerExchange exchange, PrintWriter log)
            throws Exception {
        String remoteAddr = exchange.getSourceAddress().toString();
        // Имя файла передаётся клиентом в заголовке X-Filename; если заголовка нет — unknown
        String filename = exchange.getRequestHeaders().getFirst("X-Filename");
        if (filename == null || filename.isBlank()) {
            filename = "unknown";
        }
        exchange.startBlocking();

        long total = 0;
        boolean aborted = false;
        byte[] buf = new byte[BUF_SIZE];
        int n;
        try (InputStream in = exchange.getInputStream()) {
            while ((n = in.read(buf)) >= 0) {
                total += n;
            }
        } catch (Exception e) {
            // Клиент оборвал соединение (таймаут, сброс TCP) — фиксируем
            // сколько успели получить, чтобы запись в лог всё равно состоялась
            aborted = true;
        } finally {
            writeLine(log, remoteAddr, filename, total, aborted);
        }

        if (!aborted) {
            String resp = "OK received=" + total + " bytes\n";
            exchange.setStatusCode(200);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
            exchange.getResponseSender().send(resp, StandardCharsets.UTF_8);
        }
    }

    private static void handleGetRequest(HttpServerExchange exchange, PrintWriter log)
            throws Exception {
        if (filePath == null) {
            exchange.setStatusCode(StatusCodes.NOT_FOUND);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
            exchange.getResponseSender()
                    .send("No file configured for download\n", StandardCharsets.UTF_8);
            return;
        }
        if (!Files.exists(filePath) || !Files.isRegularFile(filePath)) {
            exchange.setStatusCode(StatusCodes.NOT_FOUND);
            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=utf-8");
            exchange.getResponseSender()
                    .send("File not found: " + filePath + "\n", StandardCharsets.UTF_8);
            return;
        }

        long fileSize = Files.size(filePath);
        String rangeHeader = exchange.getRequestHeaders().getFirst("Range");
        String remoteAddr = exchange.getSourceAddress().toString();

        exchange.startBlocking();
        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/octet-stream");
        exchange.getResponseHeaders().put(Headers.ACCEPT_RANGES, "bytes");

        boolean aborted = false;
        long start = 0;
        long end = fileSize - 1;

        if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
            String rangeValue = rangeHeader.substring(6).trim();
            int dashIdx = rangeValue.indexOf('-');
            if (dashIdx > 0) {
                // bytes=start-end
                try {
                    start = Long.parseLong(rangeValue.substring(0, dashIdx).trim());
                    if (dashIdx + 1 < rangeValue.length()) {
                        end = Long.parseLong(rangeValue.substring(dashIdx + 1).trim());
                    }
                    // end по умолчанию — конец файла (оставляем как есть: инициализировано
                    // fileSize-1)
                } catch (NumberFormatException e) {
                    // непарсящийся Range — игнорируем, отдаём 200
                    start = 0;
                    end = fileSize - 1;
                }
            } else if (dashIdx == 0) {
                // bytes=-suffix — последние N байт
                try {
                    long suffix = Long.parseLong(rangeValue.substring(1).trim());
                    start = Math.max(0, fileSize - suffix);
                    end = fileSize - 1;
                } catch (NumberFormatException e) {
                    start = 0;
                    end = fileSize - 1;
                }
            }

            // Валидация: если start > end или start >= fileSize — 416
            if (start > end || start >= fileSize) {
                exchange.setStatusCode(StatusCodes.REQUEST_RANGE_NOT_SATISFIABLE);
                exchange.getResponseHeaders().put(Headers.CONTENT_RANGE, "bytes */" + fileSize);
                exchange.getResponseSender()
                        .send("Range not satisfiable\n", StandardCharsets.UTF_8);
                // логируем факт 416
                writeLine(
                        log,
                        remoteAddr,
                        "RANGE_NOT_SATISFIABLE start="
                                + start
                                + " end="
                                + end
                                + " fileSize="
                                + fileSize,
                        0,
                        false);
                return;
            }

            // Корректировка end, если выходит за границы
            if (end >= fileSize) {
                end = fileSize - 1;
            }

            long contentLength = end - start + 1;
            long partialRemaining = contentLength;
            exchange.setStatusCode(StatusCodes.PARTIAL_CONTENT);
            exchange.getResponseHeaders()
                    .put(Headers.CONTENT_RANGE, "bytes " + start + "-" + end + "/" + fileSize);
            exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, contentLength);
            exchange.getResponseHeaders()
                    .put(
                            Headers.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + filePath.getFileName() + "\"");

            try (OutputStream os = exchange.getOutputStream();
                    var dstChannel = Channels.newChannel(os);
                    var fileChannel = FileChannel.open(filePath, StandardOpenOption.READ)) {
                fileChannel.position(start);
                while (partialRemaining > 0) {
                    long transferred =
                            fileChannel.transferTo(
                                    fileChannel.position(), partialRemaining, dstChannel);
                    if (transferred <= 0) break;
                    fileChannel.position(fileChannel.position() + transferred);
                    partialRemaining -= transferred;
                }
            } catch (IOException e) {
                aborted = true;
            } finally {
                writeLine(
                        log,
                        remoteAddr,
                        filePath.getFileName().toString(),
                        contentLength - Math.max(0, partialRemaining),
                        aborted);
            }
            return;
        }

        // Без Range — полный файл, 200 OK
        long fullRemaining = fileSize;
        exchange.setStatusCode(StatusCodes.OK);
        exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, fileSize);
        exchange.getResponseHeaders()
                .put(
                        Headers.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + filePath.getFileName() + "\"");

        try (OutputStream os = exchange.getOutputStream();
                var dstChannel = Channels.newChannel(os);
                var fileChannel = FileChannel.open(filePath, StandardOpenOption.READ)) {
            while (fullRemaining > 0) {
                long transferred =
                        fileChannel.transferTo(fileChannel.position(), fullRemaining, dstChannel);
                if (transferred <= 0) break;
                fileChannel.position(fileChannel.position() + transferred);
                fullRemaining -= transferred;
            }
        } catch (IOException e) {
            aborted = true;
        } finally {
            writeLine(
                    log,
                    remoteAddr,
                    filePath.getFileName().toString(),
                    fileSize - fullRemaining,
                    aborted);
        }
    }

    private static void writeLine(
            PrintWriter log, String addr, String filename, long bytes, boolean aborted) {
        String line =
                String.format(
                        "%s %s file=%s received=%d bytes%s",
                        LocalDateTime.now(), addr, filename, bytes, aborted ? " [aborted]" : "");
        LOG_LOCK.lock();
        try {
            log.println(line);
            log.flush();
        } finally {
            LOG_LOCK.unlock();
        }
        System.out.println(line);
    }

    private static void printUsage() {
        System.err.println(
                "Usage: FileReceiveServer [--port N] [--cert p12] [--password pwd]"
                        + " [--ca p12] [--ca-password pwd] [--log path] [--file path]");
    }
}
