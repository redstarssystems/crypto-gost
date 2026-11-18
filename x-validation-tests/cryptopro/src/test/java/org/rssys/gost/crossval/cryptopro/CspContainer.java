package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.time.Duration;
import org.rssys.gost.crossval.util.CryptoProChecker;

/**
 * Временный файловый ({@code HDIMAGE}) контейнер КриптоПро для тестов: создаётся с уникальным
 * именем и удаляется в {@link #close()}, чтобы не оставлять ключей на машине.
 */
final class CspContainer implements AutoCloseable {

    /** Тип провайдера КриптоПро CSP с ГОСТ Р 34.10-2012 (256 бит). */
    static final String PROVIDER_TYPE_256 = "80";
    /** Тип провайдера КриптоПро CSP с ГОСТ Р 34.10-2012 (512 бит). */
    static final String PROVIDER_TYPE_512 = "81";

    /**
     * Пароль тестовых контейнеров: пустой, но заданный явно. Если параметр {@code -password} не
     * передан, КриптоПро открывает графическое окно запроса пароля и ждёт человека. Непустой
     * пароль контейнера тоже не годится: {@code certmgr -export -pfx} спрашивает его отдельно от
     * PIN самого PFX.
     */
    static final String PASSWORD = "";

    private static final String CONTAINER_PATH_PREFIX = "\\\\.\\HDIMAGE\\";
    private static final String CONTAINER_NAME_PREFIX = "crossval_";
    private static final String KEY_TYPE_SIGNATURE = "signature";
    private static final Duration TOOL_TIMEOUT = Duration.ofSeconds(60);

    private final String path;

    private CspContainer(String path) {
        this.path = path;
    }

    /**
     * Создаёт контейнер с ключом подписи и самоподписанным сертификатом.
     *
     * @param tag        короткая метка в имени контейнера (для диагностики)
     * @param providerType {@link #PROVIDER_TYPE_256} или {@link #PROVIDER_TYPE_512}
     * @param exportable допускать экспорт закрытого ключа (нужно для PFX)
     */
    static CspContainer create(String tag, String providerType, boolean exportable)
            throws Exception {
        return create(tag, providerType, exportable, null);
    }

    /**
     * То же, но с явным выбором кривой ключа подписи.
     *
     * @param signOid OID набора параметров кривой ({@code PP_SIGNATUREOID}); {@code null} -
     *                кривая по умолчанию провайдера (CryptoPro-A для 256 бит, TC26-A для 512)
     */
    static CspContainer create(
            String tag, String providerType, boolean exportable, String signOid)
            throws Exception {
        // Генерация ключа может открыть окно датчика случайных чисел: только по явному запросу.
        CryptoProChecker.assumeContainersEnabled();
        CspContainer container =
                new CspContainer(CONTAINER_PATH_PREFIX + CONTAINER_NAME_PREFIX + tag + "_" + System.nanoTime());
        try {
            String csptest = CryptoProChecker.resolveCsptestBinary();
            java.util.List<String> command = new java.util.ArrayList<>(java.util.List.of(
                    csptest, "-notime", "-keyset", "-newkeyset",
                    "-container", container.path, "-provtype", providerType,
                    "-keytype", KEY_TYPE_SIGNATURE, "-password", PASSWORD));
            if (exportable) {
                command.add("-exportable");
            }
            if (signOid != null) {
                command.add("-signoid");
                command.add(signOid);
            }
            runOk("создание контейнера", command.toArray(new String[0]));
            runOk("выпуск сертификата", csptest, "-notime", "-keyset", "-makecert",
                    "-container", container.path, "-provtype", providerType, "-password", PASSWORD);
        } catch (Throwable failure) {
            container.close();
            throw failure;
        }
        return container;
    }

    String path() {
        return path;
    }

    /** Сохраняет сертификат контейнера (DER) в файл. */
    void exportCertificate(Path target, String providerType) throws Exception {
        runOk("экспорт сертификата", CryptoProChecker.resolveCsptestBinary(), "-notime",
                "-keyset", "-expcert", target.toString(), "-container", path,
                "-provtype", providerType, "-keytype", KEY_TYPE_SIGNATURE, "-password", PASSWORD);
    }

    @Override
    public void close() throws Exception {
        // ключ, оставшийся на машине, нельзя молча пропускать: проверяем результат удаления
        runOk("удаление контейнера " + path, CryptoProChecker.resolveCsptestBinary(), "-notime",
                "-keyset", "-deletekeyset", "-container", path, "-password", PASSWORD);
    }

    static void runOk(String step, String... command) throws Exception {
        CryptoProChecker.Result result =
                CryptoProChecker.runResult(Path.of("."), TOOL_TIMEOUT, command);
        assertEquals(0, result.exitCode(), step + " должен завершиться кодом 0: " + result.output());
    }
}
