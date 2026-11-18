package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Проверка доступности утилит КриптоПро CSP (cryptcp, certmgr) и запуск их
 * с получением семантического exit-code.
 * <p>
 * В отличие от «слабых» текстовых проверок (совпадение подстроки в выводе),
 * {@code cryptcp} и {@code certmgr} пробрасывают внутренний {@code ErrorCode}
 * в код возврата процесса: {@code 0} — успех, {@code != 0} — ошибка (например,
 * {@code 249} = {@code 0x200001f9} на некорректной CAdES-подписи). Это позволяет
 * строить настоящие семантические assert'ы.
 * <p>
 * Флаги {@code -cadesbes/-cadest} требуют библиотеку {@code libcades} из пакета
 * {@code cprocsp-pki-cades-64} (КриптоПро ЭЦП SDK). При её отсутствии cryptcp
 * возвращает {@code 0x20000065} «Can't open file 'cades library'».
 */
public final class CryptoProChecker {

    /** Личное хранилище текущего пользователя — сюда ставим cert подписанта. */
    public static final String USER_STORE = "uMy";

    /**
     * Системное свойство, включающее тесты, которые создают контейнеры КриптоПро
     * ({@code -Dcrossval.cryptopro.containers=true}).
     */
    public static final String CONTAINERS_PROPERTY = "crossval.cryptopro.containers";

    /** Переменная окружения с тем же смыслом, что и {@link #CONTAINERS_PROPERTY}. */
    public static final String CONTAINERS_ENV = "CROSSVAL_CRYPTOPRO_CONTAINERS";

    /**
     * Системное свойство, разрешающее поставить тестовый корень в {@code uRoot} на время прогона
     * ({@code -Dcrossval.cryptopro.trustRoot=true}). Это единственный барьер: подтверждение
     * установки окном не блокирует, поэтому без свойства корень не ставится нигде.
     */
    public static final String TRUST_ROOT_PROPERTY = "crossval.cryptopro.trustRoot";

    /** Таймаут служебных операций {@code certmgr} над личным хранилищем. */
    private static final Duration CERTMGR_TIMEOUT = Duration.ofSeconds(60);

    private static final java.util.regex.Pattern ERROR_CODE =
            java.util.regex.Pattern.compile("\\[ErrorCode: (0x[0-9A-Fa-f]+)]");

    private static volatile String cachedCryptcpBinary;
    private static volatile String cachedCertmgrBinary;
    private static volatile String cachedCsptestBinary;
    private static volatile Boolean cachedCadesLibrary;

    private CryptoProChecker() {}

    /** Сбрасывает запомненные пути к утилитам: для тестов, подменяющих бинарники. */
    static void resetCachedBinaries() {
        cachedCryptcpBinary = null;
        cachedCertmgrBinary = null;
        cachedCsptestBinary = null;
        cachedCadesLibrary = null;
    }

    // ========================================================================
    // Пути к бинарникам
    // ========================================================================

    /**
     * Возвращает путь к {@code cryptcp}.
     * Сначала системное свойство {@code cryptcp.binary},
     * затем переменная окружения {@code CRYPTCP_BIN},
     * иначе — штатный путь {@code /opt/cprocsp/bin/amd64/cryptcp}.
     */
    public static String resolveCryptcpBinary() {
        if (cachedCryptcpBinary != null) return cachedCryptcpBinary;
        cachedCryptcpBinary =
                resolveBinary("cryptcp.binary", "CRYPTCP_BIN", "/opt/cprocsp/bin/amd64/cryptcp");
        return cachedCryptcpBinary;
    }

    /**
     * Возвращает путь к {@code certmgr}.
     * Сначала системное свойство {@code certmgr.binary},
     * затем переменная окружения {@code CERTMGR_BIN},
     * иначе — штатный путь {@code /opt/cprocsp/bin/amd64/certmgr}.
     */
    public static String resolveCertmgrBinary() {
        if (cachedCertmgrBinary != null) return cachedCertmgrBinary;
        cachedCertmgrBinary =
                resolveBinary("certmgr.binary", "CERTMGR_BIN", "/opt/cprocsp/bin/amd64/certmgr");
        return cachedCertmgrBinary;
    }

    /**
     * Возвращает путь к {@code csptest}.
     * Сначала системное свойство {@code csptest.binary},
     * затем переменная окружения {@code CSPTEST_BIN},
     * иначе — штатный путь {@code /opt/cprocsp/bin/amd64/csptest}.
     */
    public static String resolveCsptestBinary() {
        if (cachedCsptestBinary != null) return cachedCsptestBinary;
        cachedCsptestBinary =
                resolveBinary("csptest.binary", "CSPTEST_BIN", "/opt/cprocsp/bin/amd64/csptest");
        return cachedCsptestBinary;
    }

    private static String resolveBinary(String prop, String env, String fallback) {
        String override = System.getProperty(prop);
        if (override != null && !override.isEmpty()) return override;
        String fromEnv = System.getenv(env);
        if (fromEnv != null && !fromEnv.isEmpty()) return fromEnv;
        return fallback;
    }

    // ========================================================================
    // assume*: пропуск теста при недоступности
    // ========================================================================

    /**
     * Пропускает тест, если {@code cryptcp} недоступен
     * (не установлен КриптоПро CSP на этой машине).
     */
    public static void assumeCryptcpAvailable() {
        assumeTrue(cryptcpAvailable(), "cryptcp (КриптоПро CSP) недоступен — пропуск");
    }

    /**
     * Пропускает тест, если недоступна библиотека {@code libcades}
     * (флаги {@code -cadesbes/-cadest} не заработают без ЭЦП SDK).
     */
    public static void assumeCadesLibrary() {
        assumeCryptcpAvailable();
        assumeTrue(
                cadesLibraryAvailable(),
                "libcades (cprocsp-pki-cades-64) недоступна — пропуск CAdES-проверок");
    }

    /**
     * Пропускает тест, если {@code csptest} недоступен
     * (не установлен КриптоПро CSP на этой машине).
     */
    public static void assumeCsptestAvailable() {
        assumeTrue(csptestAvailable(), "csptest (КриптоПро CSP) недоступен — пропуск");
    }

    /**
     * Пропускает тест, если не включено создание контейнеров КриптоПро.
     * <p>
     * Генерация ключа в контейнере требует датчика случайных чисел КриптоПро. Если его
     * хранилище пусто или исчерпано, КриптоПро открывает графическое окно с просьбой
     * поводить мышью и ждёт человека; без него {@code csptest} упирается в таймаут. Поэтому
     * такие тесты выполняются только по явному запросу
     * ({@code -Dcrossval.cryptopro.containers=true} или
     * {@code CROSSVAL_CRYPTOPRO_CONTAINERS=true}), когда оператор рядом.
     */
    public static void assumeContainersEnabled() {
        assumeTrue(
                containersEnabled(),
                "создание контейнеров КриптоПро отключено (окно датчика случайных чисел):"
                        + " включите -D"
                        + CONTAINERS_PROPERTY
                        + "=true или "
                        + CONTAINERS_ENV
                        + "=true");
    }

    /**
     * @return true, если явно разрешено поставить тестовый корень в {@code uRoot} на время
     *         прогона ({@link #TRUST_ROOT_PROPERTY})
     */
    public static boolean trustRootEnabled() {
        return Boolean.getBoolean(TRUST_ROOT_PROPERTY);
    }

    /** @return true, если явно разрешено создание контейнеров КриптоПро */
    public static boolean containersEnabled() {
        String prop = System.getProperty(CONTAINERS_PROPERTY);
        if (prop != null && !prop.isEmpty()) {
            return Boolean.parseBoolean(prop);
        }
        return Boolean.parseBoolean(System.getenv(CONTAINERS_ENV));
    }

    /** Проверяет, что файл {@code csptest} существует и исполняем. */
    public static boolean csptestAvailable() {
        Path binary = Path.of(resolveCsptestBinary());
        return Files.isRegularFile(binary) && Files.isExecutable(binary);
    }

    /**
     * Проверяет, что {@code cryptcp} запускается и печатает баннер {@code CryptCP}.
     */
    public static boolean cryptcpAvailable() {
        try {
            ProcessBuilder pb = new ProcessBuilder(resolveCryptcpBinary());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getOutputStream().close();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return out.contains("CryptCP");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Проверяет наличие {@code libcades}: probe-запуск {@code cryptcp -verify -cadesbes}
     * на несуществующем файле. Отличаем ошибку загрузки cades library
     * ({@code 0x20000065}) от прочих ошибок по тексту вывода.
     * Результат кешируется.
     */
    public static boolean cadesLibraryAvailable() {
        if (cachedCadesLibrary != null) return cachedCadesLibrary;
        try {
            ProcessBuilder pb =
                    new ProcessBuilder(
                            resolveCryptcpBinary(),
                            "-verify",
                            "-cadesbes",
                            "-nochain",
                            "/nonexistent-crossval-probe.p7s",
                            "/dev/null");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getOutputStream().close();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            // Если cades library не загрузилась — в выводе код 0x20000065.
            cachedCadesLibrary =
                    !out.contains("0x20000065") && !out.toLowerCase().contains("cades library");
        } catch (Exception e) {
            cachedCadesLibrary = false;
        }
        return cachedCadesLibrary;
    }

    // ========================================================================
    // Управление хранилищем сертификатов
    // ========================================================================

    /**
     * Устанавливает DER-сертификат в личное хранилище {@link #USER_STORE}.
     * Без этого {@code cryptcp -verify} падает с {@code 0x200001fb}
     * «Signers certificates are not in certificate criterion».
     *
     * @return DER-файл сертификата (для передачи в {@code -f} при verify)
     */
    public static Path installCert(Path dir, byte[] certDer, String fileName)
            throws IOException, InterruptedException {
        Path certFile = dir.resolve(fileName);
        Files.write(certFile, certDer);
        requireCertmgrSuccess(
                "certmgr -inst (сертификат)",
                resolveCertmgrBinary(),
                "-inst",
                "-file",
                certFile.toString(),
                "-store",
                USER_STORE);
        return certFile;
    }

    /**
     * Устанавливает CRL в личное хранилище {@link #USER_STORE}.
     * Нужно для {@code -cadesbes/-cadest}: КриптоПро обязательно проверяет
     * статус отзыва и без CRL/OCSP падает с {@code 0x800B010E}. Установленный
     * CRL делает статус «известным».
     */
    public static void installCrl(Path crlFile) throws IOException, InterruptedException {
        requireCertmgrSuccess(
                "certmgr -inst -crl",
                resolveCertmgrBinary(),
                "-inst",
                "-crl",
                "-file",
                crlFile.toString(),
                "-store",
                USER_STORE);
    }

    /**
     * Запускает {@code certmgr} под таймаутом и требует и нулевой код возврата, и
     * {@code [ErrorCode: 0x00000000]} в выводе: одного кода возврата мало, часть ошибок КриптоПро
     * проходит только строкой вывода.
     */
    private static void requireCertmgrSuccess(String what, String... command)
            throws IOException, InterruptedException {
        Result r =
                runResult(Path.of(System.getProperty("java.io.tmpdir")), CERTMGR_TIMEOUT, command);
        var matcher = ERROR_CODE.matcher(r.output());
        String code = "";
        while (matcher.find()) {
            code = matcher.group(1);
        }
        if (r.exitCode() != 0 || !"0x00000000".equalsIgnoreCase(code)) {
            fail(
                    what
                            + " не выполнен (exit="
                            + r.exitCode()
                            + ", ErrorCode="
                            + code
                            + "): "
                            + r.output());
        }
    }

    // ========================================================================
    // Запуск процессов
    // ========================================================================

    /**
     * Запускает команду, закрывает stdin, дожидается завершения и возвращает
     * exit-code. stdin закрыт: cryptcp при untrusted-root задаёт вопрос через
     * stdin — закрытие потока приводит к отказу, поэтому для сценариев,
     * требующих подтверждения, использовать {@link #runWithConfirm(String...)}.
     */
    public static int run(String... cmd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        p.getInputStream().readAllBytes();
        return p.waitFor();
    }

    /**
     * Запускает команду в заданном каталоге с закрытым stdin и ограничением по времени.
     * Нужен для утилит, которые пишут файлы в текущий каталог ({@code csptest -tlsc -file})
     * и могут зависнуть, если партнёр по соединению молчит: по истечении времени процесс
     * убивается, а результат получает код {@link #TIMEOUT_EXIT_CODE}.
     */
    public static Result runResult(Path workDir, Duration timeout, String... cmd)
            throws IOException, InterruptedException {
        return execute(workDir, timeout, "", cmd);
    }

    /**
     * Общий запуск: подаёт заданный ввод, ограничивает время, читает вывод отдельно от ожидания.
     * Ввод подаётся терпимо к закрытому каналу: утилита может завершиться, не читая stdin (например,
     * когда подтверждение не понадобилось), и запись тогда не ошибка.
     */
    private static Result execute(Path workDir, Duration timeout, String stdin, String... cmd)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (workDir != null) {
            pb.directory(workDir.toFile());
        }
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (var in = p.getOutputStream()) {
            in.write(stdin.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException processAlreadyFinished) {
            // не читал stdin: подтверждение не требовалось
        }
        // вывод читаем в отдельном виртуальном потоке: readAllBytes блокируется до закрытия потока
        // процесса и не дал бы сработать таймауту
        CompletableFuture<String> output =
                CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                return new String(p.getInputStream().readAllBytes());
                            } catch (IOException e) {
                                return "";
                            }
                        },
                        task -> Thread.ofVirtual().start(task));
        if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();
            p.waitFor();
            return new Result(TIMEOUT_EXIT_CODE, "timeout after " + timeout + "\n" + output.join());
        }
        return new Result(p.exitValue(), output.join());
    }

    /** Предел времени запуска утилит {@link #runResult(String...)} и {@link #runWithConfirm(String...)} по умолчанию. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(180);

    /** Условный код возврата результата, когда процесс убит по таймауту. */
    public static final int TIMEOUT_EXIT_CODE = -1;

    /**
     * Запускает команду с закрытым stdin и возвращает exit-code вместе с выводом.
     * Нужен там, где {@link #run(String...)} недостаточно: утилиты КриптоПро (например,
     * {@code tsputil}) пишут причину отказа в вывод, и без неё assert теряет смысл.
     */
    public static Result runResult(String... cmd) throws IOException, InterruptedException {
        return execute(null, DEFAULT_TIMEOUT, "", cmd);
    }

    /**
     * Запускает команду, подавая на stdin несколько подтверждений «Y», и
     * возвращает результат (exit-code + stdout). Нужно для {@code cryptcp -verify}:
     * утилита может задать несколько вопросов подряд (недоверенный корень,
     * неизвестный статус отзыва для каждого сертификата цепочки) и ждёт ответа
     * на stdin. Подаём запас подтверждений, чтобы покрыть все запросы.
     */
    public static Result runWithConfirm(String... cmd) throws IOException, InterruptedException {
        return runWithConfirm(DEFAULT_TIMEOUT, cmd);
    }

    /**
     * То же, но с заданным пределом времени: по его истечении процесс убивается, результат получает
     * код {@link #TIMEOUT_EXIT_CODE}. Без предела зависшая утилита (например, ждущая окна) повесила бы
     * всю сборку.
     */
    public static Result runWithConfirm(Duration timeout, String... cmd)
            throws IOException, InterruptedException {
        return execute(null, timeout, "Y\nY\nY\nY\n", cmd);
    }

    /**
     * Результат запуска процесса: exit-code и объединённый вывод (stdout+stderr).
     */
    public record Result(int exitCode, String output) {}
}
