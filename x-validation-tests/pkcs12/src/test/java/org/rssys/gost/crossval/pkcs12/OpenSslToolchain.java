package org.rssys.gost.crossval.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;

/**
 * Сборка OpenSSL для кросс-валидации PKCS#12.
 * <p>
 * На машине сборки две сборки OpenSSL с разными умениями (подробности в
 * {@code .opencode/plans/openssl-crossval-context.md}): системная с движком gost и эталонная
 * из {@code /opt/openssl-3.6.0-gost} с провайдером gostprov. Версия сборки входит в
 * {@link #toString()}, поэтому видна в имени запуска параметризованного теста и в отчёте.
 * Что именно умеет сборка, определяется пробами, а не номером версии.
 */
final class OpenSslToolchain {

    /** Результат запуска команды OpenSSL. */
    record Result(int exitCode, String output) {
        boolean ok() {
            return exitCode == 0;
        }
    }

    private static final Pattern SHORT_VERSION = Pattern.compile("OpenSSL\\s+\\S+");
    private static final long COMMAND_TIMEOUT_SECONDS = 60;

    /** Пароль эталонных PFX из RFC 9548 (A.2, A.3). */
    static final String RFC_PASSWORD = "Пароль для PFX";

    private final String name;
    private final String binary;
    private final List<String> engineFlags;
    private final List<String> providerFlags;
    private final Map<String, String> env;
    private final String version;
    // Проба идемпотентна: гонка двух потоков лишь повторит её, поэтому достаточно volatile
    private volatile Boolean canVerifyGostMac;
    private volatile Boolean canExportGostMac;

    private OpenSslToolchain(
            String name,
            String binary,
            List<String> engineFlags,
            List<String> providerFlags,
            Map<String, String> env,
            String version) {
        this.name = name;
        this.binary = binary;
        this.engineFlags = engineFlags;
        this.providerFlags = providerFlags;
        this.env = env;
        this.version = version;
    }

    /** Системная сборка с движком gost; {@code null}, если её нет или движок не работает. */
    static OpenSslToolchain system() {
        String binary = System.getProperty("openssl.system.binary", "/usr/bin/openssl");
        if (!Files.isExecutable(Path.of(binary))) {
            return null;
        }
        // Подкоманды kdf и dgst не принимают -engine, им нужен провайдер gostprov
        return create(
                "system",
                binary,
                List.of("-engine", "gost"),
                List.of("-provider", "gostprov", "-provider", "default"),
                Map.of());
    }

    /** Эталонная сборка из {@code openssl.binary} с флагами из {@code OpenSslChecker}; {@code null}, если недоступна. */
    static OpenSslToolchain reference() {
        String binary = OpenSslChecker.resolveOpenSslBinary();
        if (!Files.isExecutable(Path.of(binary))) {
            return null;
        }
        List<String> flags = List.of(OpenSslChecker.resolveEngineFlag());
        return create("reference", binary, flags, flags, OpenSslChecker.getOpenSslEnv());
    }

    /** Свойство: на этой машине обязаны быть сборки, умеющие ГОСТ MAC в PKCS#12 (его выставляет цель crossval). */
    static final String REQUIRE_GOST_MAC_PROPERTY = "crossval.openssl.requireGostMac";

    /** Сборки определяются один раз на весь прогон: пробы запускают процессы OpenSSL. */
    private static final class Holder {
        static final List<OpenSslToolchain> ALL = detect();
    }

    /** Все доступные сборки (без дублей по бинарнику). */
    static List<OpenSslToolchain> available() {
        return Holder.ALL;
    }

    /**
     * Требуется ли, чтобы нашлась сборка с проверкой ГОСТ MAC. На машине, где кросс-валидация
     * запускается целью crossval, исчезновение такой сборки (например, после обновления системы)
     * должно ломать прогон, а не молча переводить все проверки в пропуск.
     */
    static boolean gostMacRequired() {
        return Boolean.getBoolean(REQUIRE_GOST_MAC_PROPERTY);
    }

    private static List<OpenSslToolchain> detect() {
        List<OpenSslToolchain> result = new ArrayList<>();
        OpenSslToolchain system = system();
        if (system != null) {
            result.add(system);
        }
        OpenSslToolchain reference = reference();
        if (reference != null && (system == null || !system.binary.equals(reference.binary))) {
            result.add(reference);
        }
        return List.copyOf(result);
    }

    private static OpenSslToolchain create(
            String name,
            String binary,
            List<String> engineFlags,
            List<String> providerFlags,
            Map<String, String> env) {
        try {
            String fullVersion = OpenSslChecker.versionOf(binary, env);
            Matcher matcher = SHORT_VERSION.matcher(fullVersion);
            String shortVersion = matcher.find() ? matcher.group() : fullVersion;
            OpenSslToolchain toolchain =
                    new OpenSslToolchain(name, binary, engineFlags, providerFlags, env, shortVersion);
            // Сборка без работающего ГОСТ (движок или провайдер не загрузились) бесполезна для теста
            Path tmp = java.nio.file.Files.createTempDirectory("ossl-probe-");
            try {
                Result gen =
                        toolchain.run(
                                "genpkey",
                                "-algorithm",
                                "gost2012_256",
                                "-pkeyopt",
                                "paramset:A",
                                "-out",
                                tmp.resolve("k.pem").toString());
                return gen.ok() ? toolchain : null;
            } finally {
                TempDirUtils.deleteRecursively(tmp);
            }
        } catch (Exception e) {
            return null;
        }
    }

    String name() {
        return name;
    }

    /** Запускает подкоманду openssl с флагами движка или провайдера после её имени. */
    Result run(String subcommand, String... args) {
        List<String> cmd = new ArrayList<>();
        cmd.add(binary);
        cmd.add(subcommand);
        cmd.addAll(engineFlags);
        cmd.addAll(List.of(args));
        return execute(cmd);
    }

    /** Запускает подкоманду с флагами провайдера (для kdf и dgst, которые не принимают {@code -engine}). */
    Result runWithProvider(String subcommand, String... args) {
        List<String> cmd = new ArrayList<>();
        cmd.add(binary);
        cmd.add(subcommand);
        cmd.addAll(providerFlags);
        cmd.addAll(List.of(args));
        return execute(cmd);
    }

    /** Запускает подкоманду без флагов движка (например, {@code version}). */
    Result runPlain(String subcommand, String... args) {
        List<String> cmd = new ArrayList<>();
        cmd.add(binary);
        cmd.add(subcommand);
        cmd.addAll(List.of(args));
        return execute(cmd);
    }

    private Result execute(List<String> cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            pb.environment().putAll(env);
            Process process = pb.start();
            byte[] out;
            try (InputStream in = process.getInputStream()) {
                out = in.readAllBytes();
            }
            if (!process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Result(-1, "timeout: " + String.join(" ", maskSecrets(cmd)));
            }
            return new Result(
                    process.exitValue(), new String(out, StandardCharsets.UTF_8).trim());
        } catch (IOException e) {
            return new Result(-1, e.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(-1, "interrupted");
        }
    }

    /** Скрывает значения {@code hexpass:} и {@code hexkey:}: секреты не попадают в тексты ошибок. */
    private static List<String> maskSecrets(List<String> cmd) {
        List<String> masked = new ArrayList<>();
        for (String argument : cmd) {
            if (argument.startsWith("hexpass:") || argument.startsWith("hexkey:")) {
                masked.add(argument.substring(0, argument.indexOf(':') + 1) + "***");
            } else {
                masked.add(argument);
            }
        }
        return masked;
    }

    /**
     * Пароль передаётся через файл, а не аргументом команды: кириллица в аргументе зависит от
     * кодировки окружения JVM, в файле байты UTF-8 заданы однозначно.
     */
    static Path passwordFile(Path dir, String password) throws IOException {
        Path file = dir.resolve("pass-" + Integer.toHexString(password.hashCode()) + ".txt");
        Files.write(file, password.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    /** {@code pkcs12 -in pfx ...} с паролем из файла; MAC проверяется (без {@code -nomacver}). */
    Result pkcs12(Path pfx, Path passwordFile, String... extraArgs) {
        List<String> args = new ArrayList<>();
        args.add("-in");
        args.add(pfx.toString());
        args.add("-passin");
        args.add("file:" + passwordFile);
        args.addAll(List.of(extraArgs));
        return run("pkcs12", args.toArray(new String[0]));
    }

    /**
     * Умеет ли сборка проверять ГОСТ MAC в PKCS#12. Проба идёт на эталонном PFX из RFC 9548 A.2,
     * собранном независимо от нашей библиотеки: так результат не зависит от нашего кода.
     */
    boolean canVerifyGostMac() {
        if (canVerifyGostMac == null) {
            try {
                Path tmp = Files.createTempDirectory("ossl-mac-probe-");
                try {
                    Path pfx = tmp.resolve("a2.pfx");
                    Files.write(pfx, RfcPfx.a2());
                    Result result =
                            pkcs12(
                                    pfx,
                                    passwordFile(tmp, RFC_PASSWORD),
                                    "-nokeys",
                                    "-nocerts",
                                    "-noout");
                    canVerifyGostMac = result.ok();
                } finally {
                    TempDirUtils.deleteRecursively(tmp);
                }
            } catch (IOException e) {
                canVerifyGostMac = false;
            }
        }
        return canVerifyGostMac;
    }

    /**
     * Умеет ли сборка создавать PFX с ГОСТ MAC ({@code -macalg md_gost12_512}). Проба настоящая:
     * генерируется ключ, сертификат и выполняется экспорт.
     */
    boolean canExportGostMac() {
        if (canExportGostMac == null) {
            try {
                Path tmp = Files.createTempDirectory("ossl-export-probe-");
                try {
                    canExportGostMac = exportGostMacPfx(tmp, tmp.resolve("probe.pfx"), RFC_PASSWORD).ok();
                } finally {
                    TempDirUtils.deleteRecursively(tmp);
                }
            } catch (IOException e) {
                canExportGostMac = false;
            }
        }
        return canExportGostMac;
    }

    /**
     * Создаёт ключ, сертификат и PFX с ГОСТ MAC средствами самой сборки; возвращает результат
     * последнего шага (экспорта) или первого неудавшегося.
     */
    Result exportGostMacPfx(Path dir, Path pfxFile, String password) throws IOException {
        Path key = dir.resolve("key.pem");
        Path cert = dir.resolve("cert.pem");
        Result gen =
                run("genpkey", "-algorithm", "gost2012_256", "-pkeyopt", "paramset:A", "-out", key.toString());
        if (!gen.ok()) {
            return gen;
        }
        Result req =
                run(
                        "req", "-new", "-x509", "-key", key.toString(), "-out", cert.toString(),
                        "-subj", "/CN=crossval-openssl", "-days", "3", "-config", "/dev/null");
        if (!req.ok()) {
            return req;
        }
        return run(
                "pkcs12", "-export", "-inkey", key.toString(), "-in", cert.toString(),
                "-out", pfxFile.toString(), "-passout", "file:" + passwordFile(dir, password),
                "-keypbe", "kuznyechik-ctr-acpkm", "-certpbe", "NONE", "-macalg", "md_gost12_512");
    }

    @Override
    public String toString() {
        return name + " " + version;
    }
}
