package org.rssys.gost.crossval.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * {@link RootStore} поверх {@code certmgr} КриптоПро для хранилища пользователя: {@code uRoot}
 * (тестовый корень) или {@code uMy} (сертификаты и CRL фикстур, которые нужно убрать после прогона).
 *
 * <p>Подтверждение подаётся как {@code Y} на stdin, без {@code -silent} (он даёт
 * {@code 0x80090022}). Каждая операция проверяет и код возврата, и {@code [ErrorCode: …]} из
 * вывода, под таймаутом: завис бы вызов, сборка не должна ждать бесконечно. Число сертификатов
 * считается по строкам-разделителям блоков ({@code 1-------}), а не по локализованным подписям.
 */
public final class CertmgrStore implements RootStore {

    /** Хранилище доверенных корней текущего пользователя. */
    public static final String ROOT_STORE = "uRoot";

    /** Личное хранилище текущего пользователя. */
    public static final String PERSONAL_STORE = "uMy";

    /** Таймаут одной операции {@code certmgr}. */
    public static final Duration TIMEOUT = Duration.ofSeconds(60);

    private final String store;

    /** Хранилище доверенных корней {@code uRoot}. */
    public CertmgrStore() {
        this(ROOT_STORE);
    }

    /**
     * @param store имя хранилища пользователя ({@code uRoot} или {@code uMy})
     */
    public CertmgrStore(String store) {
        this.store = store;
    }

    private static final String SUCCESS_CODE = "0x00000000";
    private static final String EMPTY_LIST_CODE = "0x8010002c";
    private static final String CONFIRM_INPUT = "Y\nY\nY\n";
    private static final Pattern ERROR_CODE = Pattern.compile("\\[ErrorCode: (0x[0-9A-Fa-f]+)]");
    private static final Pattern BLOCK_SEPARATOR = Pattern.compile("(?m)^\\s*\\d+-+\\s*$");

    @Override
    public int countByKeyId(byte[] keyId) throws IOException {
        Output out = run(CONFIRM_INPUT, "-list", "-store", store, "-keyid", hex(keyId));
        if (EMPTY_LIST_CODE.equalsIgnoreCase(out.errorCode())) {
            return 0;
        }
        out.requireSuccess("list");
        Matcher m = BLOCK_SEPARATOR.matcher(out.text());
        int count = 0;
        while (m.find()) {
            count++;
        }
        return count;
    }

    @Override
    public byte[] exportByKeyId(byte[] keyId) throws IOException {
        Path dir = Files.createTempDirectory("crossval-root-export-");
        try {
            Path file = dir.resolve("root.cer");
            run(
                            CONFIRM_INPUT,
                            "-export",
                            "-store",
                            store,
                            "-keyid",
                            hex(keyId),
                            "-dest",
                            file.toString())
                    .requireSuccess("export");
            return Files.readAllBytes(file);
        } finally {
            deleteTree(dir);
        }
    }

    @Override
    public void install(byte[] der) throws IOException {
        Path dir = Files.createTempDirectory("crossval-root-install-");
        try {
            Path file = dir.resolve("root.cer");
            Files.write(file, der);
            run(CONFIRM_INPUT, "-install", "-store", store, "-file", file.toString())
                    .requireSuccess("install");
        } finally {
            deleteTree(dir);
        }
    }

    @Override
    public void deleteByKeyId(byte[] keyId) throws IOException {
        run(CONFIRM_INPUT, "-delete", "-store", store, "-keyid", hex(keyId))
                .requireSuccess("delete");
    }

    /**
     * Снимок хранилища: счётчик каждой непустой строки вывода {@code certmgr -list} (сертификаты, без
     * CRL). Это мультимножество, а не множество: одинаковые строки не схлопываются. Строки
     * сравниваются как есть и нигде не печатаются: в хранилище лежат сертификаты пользователя, их
     * данные не должны попасть ни в журнал, ни в отчёт.
     */
    public java.util.Map<String, Integer> snapshot() throws IOException {
        Output out = run(CONFIRM_INPUT, "-list", "-store", store);
        if (!EMPTY_LIST_CODE.equalsIgnoreCase(out.errorCode())) {
            out.requireSuccess("list");
        }
        java.util.Map<String, Integer> lines = new java.util.HashMap<>();
        for (String line : out.text().split("\\R")) {
            String stripped = line.strip();
            if (!stripped.isEmpty() && !stripped.startsWith("[ErrorCode")) {
                lines.merge(stripped, 1, Integer::sum);
            }
        }
        return lines;
    }

    /**
     * @param authorityKeyId идентификатор ключа издателя CRL
     * @return число CRL этого издателя в хранилище
     */
    public int countCrlsByAuthorityKeyId(byte[] authorityKeyId) throws IOException {
        Output out =
                run(
                        CONFIRM_INPUT,
                        "-list",
                        "-crl",
                        "-store",
                        store,
                        "-authkeyid",
                        hex(authorityKeyId));
        if (EMPTY_LIST_CODE.equalsIgnoreCase(out.errorCode())) {
            return 0;
        }
        out.requireSuccess("list crl");
        Matcher m = BLOCK_SEPARATOR.matcher(out.text());
        int count = 0;
        while (m.find()) {
            count++;
        }
        return count;
    }

    /** Удаляет все CRL этого издателя из хранилища; вызывать, только если они были установлены. */
    public void deleteCrlsByAuthorityKeyId(byte[] authorityKeyId) throws IOException {
        run(CONFIRM_INPUT, "-delete", "-crl", "-store", store, "-authkeyid", hex(authorityKeyId))
                .requireSuccess("delete crl");
    }

    @Override
    public String describeByKeyId(byte[] keyId) throws IOException {
        return run(CONFIRM_INPUT, "-list", "-store", store, "-keyid", hex(keyId)).text();
    }

    /** Результат запуска {@code certmgr}. */
    private record Output(int exitCode, String errorCode, String text) {

        void requireSuccess(String operation) throws IOException {
            if (XSession.NO_X_ERROR_CODE.equalsIgnoreCase(errorCode)) {
                throw new IOException("certmgr " + operation + ": " + XSession.noAccessMessage());
            }
            if (exitCode != 0 || !SUCCESS_CODE.equalsIgnoreCase(errorCode)) {
                throw new IOException(
                        "certmgr "
                                + operation
                                + " failed: exit="
                                + exitCode
                                + ", ErrorCode="
                                + errorCode
                                + "\n"
                                + text);
            }
        }
    }

    private static Output run(String stdin, String... args) throws IOException {
        String[] command = new String[args.length + 1];
        command[0] = CryptoProChecker.resolveCertmgrBinary();
        System.arraycopy(args, 0, command, 1, args.length);
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        feed(process, stdin);
        // Вывод читаем отдельно: readAllBytes блокируется до закрытия потока и не дал бы
        // сработать таймауту
        CompletableFuture<String> text =
                CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                return new String(
                                        process.getInputStream().readAllBytes(),
                                        StandardCharsets.UTF_8);
                            } catch (IOException e) {
                                return "";
                            }
                        },
                        task -> Thread.ofVirtual().start(task));
        try {
            if (!process.waitFor(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new IOException(
                        "certmgr did not finish in "
                                + TIMEOUT
                                + ": the operation may be waiting for interactive confirmation");
            }
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for certmgr", e);
        }
        String output = text.join();
        return new Output(process.exitValue(), lastErrorCode(output), output);
    }

    /**
     * Подаёт ответы на запросы подтверждения. {@code certmgr} может завершиться, не читая stdin
     * (например, пустой {@code -list}); закрытый канал тогда не ошибка, итог определяют код
     * возврата и {@code ErrorCode}.
     */
    private static void feed(Process process, String stdin) {
        try (var in = process.getOutputStream()) {
            in.write(stdin.getBytes(StandardCharsets.UTF_8));
        } catch (IOException processAlreadyFinished) {
            // не читал stdin: подтверждение не требовалось
        }
    }

    private static String lastErrorCode(String output) {
        Matcher m = ERROR_CODE.matcher(output);
        String code = "";
        while (m.find()) {
            code = m.group(1);
        }
        return code;
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static void deleteTree(Path dir) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
