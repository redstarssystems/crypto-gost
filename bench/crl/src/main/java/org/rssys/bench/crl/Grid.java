package org.rssys.bench.crl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ведущий процесс сетки: запускает каждую ячейку в новой JVM и собирает результаты.
 *
 * <p>Ячейки идут от большой кучи вниз и останавливаются после первого сбоя
 * ({@code OutOfMemoryError}, тайм-аут, деградация): с меньшей кучей будет только хуже, а худший
 * случай без остановки занял бы часы. Итог для сочетания - интервал: наименьшая куча, на которой
 * проверка прошла, и следующая ступень, на которой уже нет.</p>
 */
final class Grid {

    private static final int[] HEAPS_MB = {2048, 1024, 512, 256};
    private static final String[] SIZES = {"800k", "2m", "4m"};
    private static final int[] THREADS_A = {1, 4, 16};
    private static final int[] THREADS_B = {1, 16};
    private static final int[] THREADS_C = {1, 4, 16};
    private static final int ROUNDS_A = 3;
    private static final int ROUNDS_C = 5;
    private static final long CELL_TIMEOUT_SECONDS = 600;
    private static final long SERVER_START_TIMEOUT_SECONDS = 30;
    private static final int SERVER_HEAP_MB = 256;
    private static final double DEGRADATION_FACTOR = 10.0;
    private static final Pattern GC_AFTER =
            Pattern.compile("(\\d+)([KMG])->(\\d+)([KMG])\\(");

    private final Path dir;
    private final String jar;
    private final StringBuilder csv =
            new StringBuilder(
                    "series,jdk,size,threads,heapMb,status,ok,medianMs,gcLivePeakMb,details\n");
    private final List<String[]> summary = new ArrayList<>();

    private Grid(Path dir, String jar) {
        this.dir = dir;
        this.jar = jar;
    }

    static void main(String[] args) throws Exception {
        Grid grid = new Grid(Path.of(args[0]).toAbsolutePath(), args[1]);
        String java21 = args[2];
        String java25 = args[3];
        grid.header(java21, java25);
        for (String size : SIZES) {
            for (int threads : THREADS_A) {
                grid.ladder("A", java21, "21", size, threads);
            }
        }
        // Контрольные ячейки на JDK 25: самый тяжёлый размер при 1 и 16 проверках
        for (int threads : new int[] {1, 16}) {
            grid.ladder("A", java25, "25", "4m", threads);
        }
        for (String size : SIZES) {
            for (int threads : THREADS_B) {
                grid.ladder("B", java21, "21", size, threads);
            }
        }
        for (String size : SIZES) {
            for (int threads : THREADS_C) {
                grid.ladder("C", java21, "21", size, threads);
            }
        }
        for (String size : SIZES) {
            grid.stages(java21, size);
        }
        grid.finish();
    }

    private void header(String java21, String java25) throws Exception {
        System.out.println("== Условия замера ==");
        System.out.println("коммит: " + command(List.of("git", "-C", dir.toString(), "rev-parse", "--short", "HEAD")).strip());
        boolean dirty = !command(List.of("git", "-C", dir.toString(), "status", "--porcelain")).isBlank();
        System.out.println("незакоммиченные правки: " + (dirty ? "да" : "нет"));
        System.out.println("JDK 21: " + firstLine(command(List.of(java21, "-version"))));
        System.out.println("JDK 25: " + firstLine(command(List.of(java25, "-version"))));
        System.out.println("ядер: " + Runtime.getRuntime().availableProcessors());
        for (String line : Files.readAllLines(Path.of("/proc/meminfo"))) {
            if (line.startsWith("MemTotal") || line.startsWith("MemAvailable")) {
                System.out.println(line);
            }
        }
        System.out.println("сборщик: G1, -Xms равен -Xmx");
        System.out.println();
    }

    /** Одна «лестница»: фиксированные сочетание размера и числа проверок, куча уменьшается. */
    private void ladder(String series, String java, String jdk, String size, int threads)
            throws Exception {
        Process server = null;
        int port = 0;
        if (series.equals("B")) {
            port = freePort();
            server = startServer(java, size, port);
        }
        try {
            double baselineMs = -1;
            int lowestOk = -1;
            String firstFail = "-";
            boolean stop = false;
            for (int heap : HEAPS_MB) {
                if (stop) {
                    break;
                }
                Cell cell = runCell(series, java, jdk, size, threads, heap, port);
                String status = cell.status;
                if (status.equals("OK") && heap == HEAPS_MB[0]) {
                    baselineMs = cell.medianMs;
                } else if (status.equals("OK")
                        && baselineMs > 0
                        && cell.medianMs > baselineMs * DEGRADATION_FACTOR) {
                    // Деградация: вместо быстрого OutOfMemoryError JVM почти всё время собирает мусор
                    status = "DEGRADED";
                }
                csv.append(
                        String.join(
                                ",",
                                series,
                                jdk,
                                size,
                                String.valueOf(threads),
                                String.valueOf(heap),
                                status,
                                cell.ok,
                                CrlBench.f1(cell.medianMs),
                                cell.gcLivePeakMb,
                                cell.details.replace(',', ';')));
                csv.append('\n');
                System.out.printf(
                        "%s JDK%s %s x%d -Xmx%dm: %s (ok=%s, медиана=%s мс, живой пик=%s МБ)%n",
                        series, jdk, size, threads, heap, status, cell.ok,
                        CrlBench.f1(cell.medianMs), cell.gcLivePeakMb);
                if (status.equals("OK")) {
                    lowestOk = heap;
                } else {
                    firstFail = heap + " МБ: " + status;
                    stop = true;
                }
            }
            String interval;
            if (lowestOk < 0) {
                interval = "больше " + HEAPS_MB[0] + " МБ (" + firstFail + ")";
            } else if (firstFail.equals("-")) {
                interval = "не больше " + lowestOk + " МБ";
            } else {
                interval = "от " + lowestOk + " МБ (на " + firstFail + ")";
            }
            summary.add(new String[] {series, "JDK" + jdk, size, String.valueOf(threads), interval});
        } finally {
            if (server != null) {
                server.destroyForcibly();
            }
        }
    }

    private record Cell(
            String status, String ok, double medianMs, String gcLivePeakMb, String details) {}

    private Cell runCell(
            String series, String java, String jdk, String size, int threads, int heap, int port)
            throws Exception {
        String id = series + "-jdk" + jdk + "-" + size + "-x" + threads + "-" + heap + "m";
        Path gcLog = dir.resolve("gc-" + id + ".log");
        List<String> cmd = new ArrayList<>(List.of(java));
        cmd.add("-Xms" + heap + "m");
        cmd.add("-Xmx" + heap + "m");
        cmd.add("-XX:+UseG1GC");
        cmd.add("-XX:-HeapDumpOnOutOfMemoryError");
        cmd.add("-XX:ErrorFile=" + dir.resolve("hs_err_%p.log"));
        cmd.add("-Xlog:gc:file=" + gcLog);
        cmd.addAll(List.of("-cp", jar, CrlBench.class.getName()));
        if (series.equals("A")) {
            cmd.addAll(
                    List.of("cell-a", dir.toString(), size, String.valueOf(threads),
                            String.valueOf(ROUNDS_A)));
        } else if (series.equals("C")) {
            cmd.addAll(
                    List.of("cell-c", dir.toString(), size, String.valueOf(threads),
                            String.valueOf(ROUNDS_C)));
        } else {
            cmd.addAll(
                    List.of("cell-b", dir.toString(), size, String.valueOf(threads),
                            String.valueOf(port)));
        }
        Run run = execute(cmd, CELL_TIMEOUT_SECONDS);
        String gcPeak = gcLivePeak(gcLog);
        if (run.timedOut) {
            return new Cell("TIMEOUT", "0", 0, gcPeak, "тайм-аут " + CELL_TIMEOUT_SECONDS + " с");
        }
        Map<String, String> r = run.result;
        if (r == null) {
            boolean oom = run.tail.contains("OutOfMemoryError");
            return new Cell(oom ? "OOM" : "CRASH", "0", 0, gcPeak, oom ? "" : tailOf(run.tail));
        }
        String outcome = r.getOrDefault("outcome", "ERROR");
        double median = r.containsKey("medianMs") ? Double.parseDouble(r.get("medianMs")) : 0;
        StringBuilder details = new StringBuilder();
        for (String key : List.of("crlMb", "allocPerCallMb", "watcherPeakMb", "coldMs", "loads", "fetches", "threadMs", "detail")) {
            if (r.containsKey(key)) {
                details.append(key).append('=').append(r.get(key)).append(' ');
            }
        }
        return new Cell(outcome, r.getOrDefault("ok", "0") + "/" + threads, median, gcPeak, details.toString().strip());
    }

    private void stages(String java, String size) throws Exception {
        List<String> cmd =
                List.of(java, "-Xms2048m", "-Xmx2048m", "-XX:+UseG1GC", "-XX:-HeapDumpOnOutOfMemoryError",
                        "-cp", jar, CrlBench.class.getName(), "stages", dir.toString(), size);
        Run run = execute(cmd, CELL_TIMEOUT_SECONDS);
        String line = run.result == null ? "нет результата" : run.result.toString();
        System.out.println("stages " + size + ": " + line);
        csv.append("stages,21,").append(size).append(",1,2048,")
                .append(run.result == null ? "FAIL" : run.result.get("outcome")).append(",,,,")
                .append(line.replace(',', ';')).append('\n');
    }

    private void finish() throws IOException {
        Files.writeString(dir.resolve("results.csv"), csv.toString());
        StringBuilder adoc = new StringBuilder("[cols=\"1,1,1,1,3\",options=\"header\"]\n|===\n");
        adoc.append("|Серия |JDK |Записей |Проверок |Минимальная куча\n");
        for (String[] row : summary) {
            for (String cell : row) {
                adoc.append('|').append(cell).append(' ');
            }
            adoc.append('\n');
        }
        adoc.append("|===\n");
        Files.writeString(dir.resolve("summary.adoc"), adoc.toString());
        System.out.println();
        System.out.println(adoc);
    }

    // ---------------------------------------------------------------------------------------
    // Процессы
    // ---------------------------------------------------------------------------------------

    private record Run(boolean timedOut, Map<String, String> result, String tail) {}

    private static Run execute(List<String> cmd, long timeoutSeconds) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Map<String, String> result = new HashMap<>();
        boolean[] gotResult = {false};
        StringBuilder tail = new StringBuilder();
        Thread reader =
                new Thread(
                        () -> {
                            try (BufferedReader in =
                                    new BufferedReader(
                                            new InputStreamReader(
                                                    p.getInputStream(), StandardCharsets.UTF_8))) {
                                String line;
                                while ((line = in.readLine()) != null) {
                                    if (line.startsWith(CrlBench.RESULT_PREFIX)) {
                                        parseResult(line, result);
                                        gotResult[0] = true;
                                    } else {
                                        synchronized (tail) {
                                            tail.append(line).append('\n');
                                            if (tail.length() > 4000) {
                                                tail.delete(0, tail.length() - 4000);
                                            }
                                        }
                                    }
                                }
                            } catch (IOException e) {
                                // процесс убит по тайм-ауту
                            }
                        });
        reader.setDaemon(true);
        reader.start();
        boolean finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            p.destroyForcibly();
            p.waitFor();
        }
        reader.join(5000);
        synchronized (tail) {
            return new Run(!finished, gotResult[0] ? result : null, tail.toString());
        }
    }

    private static void parseResult(String line, Map<String, String> into) {
        for (String token : line.substring(CrlBench.RESULT_PREFIX.length()).split(" ")) {
            int eq = token.indexOf('=');
            if (eq > 0) {
                into.put(token.substring(0, eq), token.substring(eq + 1));
            }
        }
    }

    private Process startServer(String java, String size, int port) throws Exception {
        Path file = dir.resolve("crl-" + size + CrlBench.CRL_SUFFIX);
        Process p =
                new ProcessBuilder(
                                java, "-Xms" + SERVER_HEAP_MB + "m", "-Xmx" + SERVER_HEAP_MB + "m",
                                "-cp", jar, CrlBench.class.getName(), "serve", file.toString(),
                                String.valueOf(port))
                        .redirectErrorStream(true)
                        .start();
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(SERVER_START_TIMEOUT_SECONDS);
        while (System.nanoTime() < deadline) {
            if (in.ready() && "READY".equals(in.readLine())) {
                return p;
            }
            Thread.sleep(50);
        }
        p.destroyForcibly();
        throw new IllegalStateException("HTTP-сервер замера не запустился");
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static String command(List<String> cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }

    private static String firstLine(String s) {
        int nl = s.indexOf('\n');
        return nl < 0 ? s : s.substring(0, nl);
    }

    private static String tailOf(String tail) {
        String t = tail.strip();
        return t.length() > 200 ? t.substring(t.length() - 200) : t;
    }

    // ---------------------------------------------------------------------------------------
    // Журнал сборщика
    // ---------------------------------------------------------------------------------------

    /** Максимум занятой кучи после сборки (МБ) по журналу {@code -Xlog:gc}: живой пик. */
    private static String gcLivePeak(Path gcLog) {
        if (!Files.exists(gcLog)) {
            return "-";
        }
        double peak = -1;
        try {
            for (String line : Files.readAllLines(gcLog)) {
                Matcher m = GC_AFTER.matcher(line);
                if (m.find()) {
                    peak = Math.max(peak, toMb(Long.parseLong(m.group(3)), m.group(4)));
                }
            }
        } catch (IOException e) {
            return "-";
        }
        return peak < 0 ? "-" : CrlBench.f1(peak);
    }

    private static double toMb(long value, String unit) {
        return switch (unit) {
            case "K" -> value / 1024.0;
            case "G" -> value * 1024.0;
            default -> value;
        };
    }
}
