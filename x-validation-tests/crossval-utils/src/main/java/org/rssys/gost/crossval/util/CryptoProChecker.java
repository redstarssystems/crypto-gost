package org.rssys.gost.crossval.util;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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

    private static volatile String cachedCryptcpBinary;
    private static volatile String cachedCertmgrBinary;
    private static volatile Boolean cachedCadesLibrary;

    private CryptoProChecker() {}

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
        int code =
                run(
                        resolveCertmgrBinary(),
                        "-inst",
                        "-file",
                        certFile.toString(),
                        "-store",
                        USER_STORE);
        if (code != 0) {
            fail("certmgr -inst не смог установить сертификат (exit=" + code + ")");
        }
        return certFile;
    }

    /**
     * Устанавливает CRL в личное хранилище {@link #USER_STORE}.
     * Нужно для {@code -cadesbes/-cadest}: КриптоПро обязательно проверяет
     * статус отзыва и без CRL/OCSP падает с {@code 0x800B010E}. Установленный
     * CRL делает статус «известным».
     */
    public static void installCrl(Path crlFile) throws IOException, InterruptedException {
        int code =
                run(
                        resolveCertmgrBinary(),
                        "-inst",
                        "-crl",
                        "-file",
                        crlFile.toString(),
                        "-store",
                        USER_STORE);
        if (code != 0) {
            fail("certmgr -inst -crl не смог установить CRL (exit=" + code + ")");
        }
    }

    /**
     * Удаляет сертификат из {@link #USER_STORE} по Subject DN.
     * Ошибки удаления игнорируются (best-effort очистка после теста).
     */
    public static void deleteCertByDn(String subjectDn) {
        try {
            run(resolveCertmgrBinary(), "-delete", "-store", USER_STORE, "-dn", subjectDn);
        } catch (Exception ignored) {
            // очистка best-effort — не влияет на результат теста
        }
    }

    /**
     * Удаляет CRL из {@link #USER_STORE} по DN издателя.
     * Симметрично {@link #installCrl(Path)}: без этого установленный в setUp CRL
     * остаётся в личном хранилище машины после прогона тестов. Ошибки удаления
     * игнорируются (best-effort очистка).
     */
    public static void deleteCrlByIssuerDn(String issuerDn) {
        try {
            run(resolveCertmgrBinary(), "-delete", "-crl", "-store", USER_STORE, "-dn", issuerDn);
        } catch (Exception ignored) {
            // очистка best-effort — не влияет на результат теста
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
     * Запускает команду, подавая на stdin несколько подтверждений «Y», и
     * возвращает результат (exit-code + stdout). Нужно для {@code cryptcp -verify}:
     * утилита может задать несколько вопросов подряд (недоверенный корень,
     * неизвестный статус отзыва для каждого сертификата цепочки) и ждёт ответа
     * на stdin. Подаём запас подтверждений, чтобы покрыть все запросы.
     */
    public static Result runWithConfirm(String... cmd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().write("Y\nY\nY\nY\n".getBytes());
        p.getOutputStream().flush();
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes());
        int code = p.waitFor();
        return new Result(code, out);
    }

    /**
     * Результат запуска процесса: exit-code и объединённый вывод (stdout+stderr).
     */
    public record Result(int exitCode, String output) {}
}
