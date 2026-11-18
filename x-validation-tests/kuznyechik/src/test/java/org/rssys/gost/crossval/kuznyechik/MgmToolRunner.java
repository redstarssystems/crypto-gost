package org.rssys.gost.crossval.kuznyechik;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Собирает и запускает C-хелпер {@code mgm_tool.c}: эталонный Кузнечик-MGM на EVP API OpenSSL
 * с провайдером gostprov.
 * <p>
 * Утилита {@code openssl enc} AEAD-режимы не поддерживает, поэтому без хелпера MGM нечем сверить.
 * Хелпер собирается {@code gcc} один раз на прогон во временный каталог, который удаляет
 * {@link TempDirUtils#deleteRecursively}. Тест пропускается только при отсутствии предпосылок
 * (компилятор, заголовки, {@code libcrypto}, {@code gostprov.so}, возможность запускать файлы из
 * каталога временных файлов); если они есть, а сборка или запуск упали, это падение, а не пропуск.
 */
final class MgmToolRunner {

    /** Код выхода хелпера при отказе по тегу (прочие ненулевые коды - иные ошибки). */
    static final int EXIT_BAD_TAG = 2;

    private static final String SOURCE_RESOURCE = "/mgm_tool.c";
    private static final String EMPTY_ARGUMENT = "-";
    private static final long PROCESS_TIMEOUT_SECONDS = 60;

    private static Path workDir;
    private static Path executable;

    private MgmToolRunner() {}

    /** Результат запуска хелпера. */
    record Outcome(int exitCode, byte[] output, String diagnostics) {}

    /** Пропускает тест, если нет предпосылок сборки; иначе собирает хелпер (один раз). */
    static void prepare() throws Exception {
        if (executable != null) {
            return;
        }
        String root = OpenSslChecker.resolveOpenSslRoot();
        assumeTrue(!root.isEmpty(), "Корень OpenSSL не определён: нет заголовков для сборки");
        Path rootPath = Paths.get(root);
        assumeTrue(
                Files.exists(rootPath.resolve("include/openssl/evp.h")),
                "Нет заголовков OpenSSL в " + root);
        assumeTrue(
                Files.exists(rootPath.resolve("lib/ossl-modules/gostprov.so")),
                "Нет провайдера gostprov.so в " + root);
        assumeTrue(hasLibcrypto(rootPath.resolve("lib")), "Нет libcrypto в " + root);
        assumeTrue(commandWorks("gcc", "--version"), "Компилятор gcc недоступен");

        Path dir = Files.createTempDirectory("mgm-tool-");
        try {
            Path source = dir.resolve("mgm_tool.c");
            try (InputStream in = MgmToolRunner.class.getResourceAsStream(SOURCE_RESOURCE)) {
                if (in == null) {
                    fail("Не найден ресурс " + SOURCE_RESOURCE);
                }
                Files.write(source, in.readAllBytes());
            }
            Path binary = dir.resolve("mgm_tool");
            List<String> compile =
                    List.of(
                            "gcc",
                            "-Wall",
                            "-I" + rootPath.resolve("include"),
                            "-L" + rootPath.resolve("lib"),
                            "-Wl,-rpath," + rootPath.resolve("lib"),
                            source.toString(),
                            "-o",
                            binary.toString(),
                            "-lcrypto");
            Outcome built = execute(compile);
            if (built.exitCode() != 0) {
                fail("Сборка mgm_tool.c не удалась: " + built.diagnostics());
            }
            // Каталог временных файлов может быть смонтирован с noexec: это свойство окружения,
            // как и отсутствие gcc, а не дефект библиотеки, поэтому такой запуск пропускает тест.
            // Пробный запуск без аргументов штатно завершается кодом 1 (подсказка по
            // использованию).
            assumeTrue(canStart(binary), "Из каталога временных файлов нельзя запускать программы");
            workDir = dir;
            executable = binary;
        } catch (Throwable t) {
            TempDirUtils.deleteRecursively(dir);
            throw t;
        }
    }

    /** Удаляет собранный хелпер. */
    static void cleanup() {
        if (workDir != null) {
            TempDirUtils.deleteRecursively(workDir);
            workDir = null;
            executable = null;
        }
    }

    /** Шифрует через OpenSSL; результат {@code шифртекст || тег}. Любой отказ - падение теста. */
    static byte[] seal(byte[] key, byte[] icn, byte[] aad, byte[] plaintext) throws Exception {
        Outcome outcome = run("enc", key, icn, aad, plaintext);
        if (outcome.exitCode() != 0) {
            fail("OpenSSL не зашифровал: код " + outcome.exitCode() + " " + outcome.diagnostics());
        }
        return outcome.output();
    }

    /** Расшифровывает через OpenSSL; при отказе по тегу код {@link #EXIT_BAD_TAG}. */
    static Outcome open(byte[] key, byte[] icn, byte[] aad, byte[] sealed) throws Exception {
        return run("dec", key, icn, aad, sealed);
    }

    private static Outcome run(String mode, byte[] key, byte[] icn, byte[] aad, byte[] input)
            throws Exception {
        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        command.add(mode);
        command.add(hexArgument(key));
        command.add(hexArgument(icn));
        command.add(hexArgument(aad));
        command.add(hexArgument(input));
        Outcome raw = execute(command);
        byte[] decoded =
                raw.exitCode() == 0
                        ? CrossValUtils.fromHex(
                                new String(raw.output(), StandardCharsets.US_ASCII).trim())
                        : new byte[0];
        return new Outcome(raw.exitCode(), decoded, raw.diagnostics());
    }

    /** Пустой массив передаём маркером: пустой аргумент командной строки ненадёжен. */
    private static String hexArgument(byte[] data) {
        return data.length == 0 ? EMPTY_ARGUMENT : CrossValUtils.toHex(data);
    }

    /** Компоновщику нужна разделяемая libcrypto ({@code libcrypto.so} или {@code .so.N}). */
    private static boolean hasLibcrypto(Path libDir) throws IOException {
        if (!Files.isDirectory(libDir)) {
            return false;
        }
        try (var entries = Files.list(libDir)) {
            return entries.anyMatch(
                    entry -> entry.getFileName().toString().startsWith("libcrypto.so"));
        }
    }

    private static boolean commandWorks(String... command) {
        try {
            return execute(List.of(command)).exitCode() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    /** Запускается ли файл: ошибка старта (например, noexec) не то же, что код выхода. */
    private static boolean canStart(Path binary) {
        try {
            execute(List.of(binary.toString()));
            return true;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    /**
     * Запускает процесс с ограничением по времени. Оба потока вывода уходят в файлы, поэтому
     * ожидание завершения ограничено таймаутом: чтение из канала блокировалось бы до закрытия
     * потока и зависший процесс подвесил бы тест.
     */
    private static Outcome execute(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().putAll(OpenSslChecker.getOpenSslEnv());
        Path stdoutFile = Files.createTempFile("mgm-tool-stdout-", ".txt");
        Path stderrFile = Files.createTempFile("mgm-tool-stderr-", ".txt");
        try {
            builder.redirectOutput(stdoutFile.toFile());
            builder.redirectError(stderrFile.toFile());
            Process process = builder.start();
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                fail("Процесс не завершился за " + PROCESS_TIMEOUT_SECONDS + " с: " + command);
            }
            String diagnostics = Files.readString(stderrFile, StandardCharsets.UTF_8).trim();
            return new Outcome(process.exitValue(), Files.readAllBytes(stdoutFile), diagnostics);
        } finally {
            Files.deleteIfExists(stdoutFile);
            Files.deleteIfExists(stderrFile);
        }
    }
}
