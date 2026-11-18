package org.rssys.gost.crossval.util;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

/**
 * Файл-метка установленного на время прогона корня.
 *
 * <p>Пишется <b>до</b> установки (состояние {@link State#INSTALLING}), иначе падение между
 * установкой и записью оставило бы корень без следа. Хранит DER и идентификатор ключа корня, а
 * также PID и время старта процесса: по одному PID «процесс жив» ненадёжно из-за повторного
 * использования номеров.
 *
 * @param state     состояние установки
 * @param keyId     идентификатор ключа корня
 * @param der       DER установленного сертификата
 * @param pid       PID процесса, поставившего корень
 * @param startedAt время старта этого процесса ({@code null}, если ОС его не сообщает)
 * @param user      пользователь ОС: {@code uRoot} у каждого пользователя свой
 * @param createdAt время записи метки
 */
public record RootMark(
        State state,
        byte[] keyId,
        byte[] der,
        long pid,
        Instant startedAt,
        String user,
        Instant createdAt) {

    /**
     * Начало имени файла-метки; к нему через точку добавляются имя пользователя и идентификатор
     * ключа корня.
     */
    public static final String FILE_NAME = ".crossval-root-mark";

    /** Свойство, переопределяющее каталог меток. */
    public static final String DIRECTORY_PROPERTY = "crossval.cryptopro.rootMarkDir";

    /** Состояние установки корня. */
    public enum State {
        /** Метка записана, установка начата и могла не завершиться. */
        INSTALLING,
        /** Корень установлен и проверен. */
        INSTALLED
    }

    /**
     * Метка текущего процесса.
     *
     * @param state состояние
     * @param keyId идентификатор ключа корня
     * @param der   DER корня
     */
    public static RootMark ofCurrentProcess(State state, byte[] keyId, byte[] der) {
        ProcessHandle self = ProcessHandle.current();
        return new RootMark(
                state,
                keyId.clone(),
                der.clone(),
                self.pid(),
                self.info().startInstant().orElse(null),
                System.getProperty("user.name", ""),
                Instant.now());
    }

    /**
     * Каталог меток по умолчанию: {@code x-validation-tests}, вне {@code target/}, чтобы
     * {@code mvn clean} метки не уничтожил.
     */
    public static Path defaultDirectory() {
        String override = System.getProperty(DIRECTORY_PROPERTY);
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        Path workDir = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path p = workDir; p != null; p = p.getParent()) {
            Path name = p.getFileName();
            if (name != null && name.toString().equals("x-validation-tests")) {
                return p;
            }
        }
        Path nested = workDir.resolve("x-validation-tests");
        return Files.isDirectory(nested) ? nested : workDir;
    }

    /**
     * Путь метки корня: своя у каждого пользователя и у каждого корня. Метка на пользователя нужна
     * потому, что {@code uRoot} у каждого свой; метка на корень - чтобы два корня одной JVM (корень
     * фикстур и корень одноразового УЦ) не принимали метку друг друга за «собственный сбой» и не
     * затирали след.
     *
     * @param directory каталог меток
     * @param keyId     идентификатор ключа корня
     */
    public static Path pathFor(Path directory, byte[] keyId) {
        return directory.resolve(
                FILE_NAME + "." + userSuffix() + "." + HexFormat.of().formatHex(keyId));
    }

    /**
     * Имя пользователя для имени файла: у каждого пользователя свой {@code uRoot}, и метка одного не
     * должна затирать след упавшего прогона другого в общем клоне.
     */
    private static String userSuffix() {
        return System.getProperty("user.name", "unknown").replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    /** Путь метки корня в каталоге по умолчанию. */
    public static Path defaultPath(byte[] keyId) {
        return pathFor(defaultDirectory(), keyId);
    }

    /**
     * Все метки текущего пользователя в каталоге (по всем корням), по возрастанию имени.
     */
    public static List<Path> listMarks(Path directory) throws IOException {
        String prefix = FILE_NAME + "." + userSuffix() + ".";
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(f -> f.getFileName().toString().startsWith(prefix))
                    .filter(f -> !f.getFileName().toString().endsWith(".tmp"))
                    .sorted()
                    .toList();
        }
    }

    /**
     * Читает метку.
     *
     * @return метка или {@code null}, если файла нет
     */
    public static RootMark read(Path path) throws IOException {
        if (!Files.exists(path)) {
            return null;
        }
        Properties p = new Properties();
        try (Reader in = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            p.load(in);
        }
        String started = p.getProperty("startedAt", "");
        return new RootMark(
                State.valueOf(p.getProperty("state")),
                HexFormat.of().parseHex(p.getProperty("keyId")),
                Base64.getDecoder().decode(p.getProperty("der")),
                Long.parseLong(p.getProperty("pid")),
                started.isEmpty() ? null : Instant.parse(started),
                p.getProperty("user", ""),
                Instant.parse(p.getProperty("createdAt")));
    }

    /** Записывает метку атомарно: временный файл и переименование. */
    public void write(Path path) throws IOException {
        Properties p = new Properties();
        p.setProperty("state", state.name());
        p.setProperty("keyId", HexFormat.of().formatHex(keyId));
        p.setProperty("der", Base64.getEncoder().encodeToString(der));
        p.setProperty("pid", Long.toString(pid));
        p.setProperty("startedAt", startedAt == null ? "" : startedAt.toString());
        p.setProperty("user", user);
        p.setProperty("createdAt", createdAt.toString());
        Path dir = path.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, FILE_NAME, ".tmp");
        try (Writer out = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(out, "crossval trusted root mark");
        }
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** Удаляет метку, если она есть. */
    public static void delete(Path path) throws IOException {
        Files.deleteIfExists(path);
    }
}
