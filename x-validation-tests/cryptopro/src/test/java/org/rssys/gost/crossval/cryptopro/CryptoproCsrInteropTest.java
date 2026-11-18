package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.CsrAttribute;
import org.rssys.gost.pkix.cert.GostCsrParser;

/**
 * Строгий разбор запроса PKCS#10, созданного {@code cryptcp -createrqst}.
 *
 * <p>Разборщик не принимает внутренний {@code SET} в блоке атрибутов и повтор атрибутов, как
 * требует RFC 2986. Тест проверяет, что КриптоПро пишет блок {@code [0]} по стандарту. Если
 * КриптоПро пишет иначе, терпимость добавляется только на уровне всего блока и отдельным решением.
 *
 * <p>Создание ключа может открыть окно датчика случайных чисел, поэтому тест идёт только при
 * {@code -Dcrossval.cryptopro.containers=true} (то есть в {@code make crossval-full}).
 */
@DisplayName("Запрос PKCS#10: cryptcp -createrqst против строгого разбора crypto-gost")
class CryptoproCsrInteropTest {

    private static final String CONTAINER_PATH_PREFIX = "\\\\.\\HDIMAGE\\";
    private static final Duration TOOL_TIMEOUT = Duration.ofSeconds(60);

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCryptcpAvailable();
        CryptoProChecker.assumeCsptestAvailable();
        CryptoProChecker.assumeContainersEnabled();
    }

    @Test
    @DisplayName("Запрос КриптоПро разбирается строго, подпись (proof-of-possession) верна")
    void cryptoProRequestParsesStrictly() throws Exception {
        String container = CONTAINER_PATH_PREFIX + "crossval_csr_" + System.nanoTime();
        try {
            TempDirUtils.withTempDir("cp-csr-", dir -> {
                Path request = dir.resolve("signer.req");
                CryptoProChecker.Result result = CryptoProChecker.runResult(
                        dir, TOOL_TIMEOUT,
                        CryptoProChecker.resolveCryptcpBinary(), "-createrqst",
                        "-rdn", "CN=Crossval CryptoPro CSR,O=crypto-gost,C=RU",
                        "-provtype", CspContainer.PROVIDER_TYPE_256,
                        "-hashalg", "1.2.643.7.1.1.2.2",
                        "-sg", "-ku", "-exprt",
                        "-cont", container, "-pin", CspContainer.PASSWORD,
                        request.toString());
                assertEquals(0, result.exitCode(),
                        "cryptcp -createrqst должен завершиться кодом 0: " + result.output());

                GostCsrParser parsed = GostCsrParser.fromPemOrDer(Files.readAllBytes(request));
                assertTrue(parsed.verifySelf(),
                        "подпись запроса КриптоПро должна проходить проверку");
                assertTrue(parsed.getSubjectDn().contains("CN=Crossval CryptoPro CSR"),
                        "ожидалось имя субъекта из -rdn: " + parsed.getSubjectDn());
                // Все атрибуты разобраны без повторов; пароль КриптоПро в запрос не кладёт
                assertTrue(parsed.getChallengePassword().isEmpty());
                for (CsrAttribute attribute : parsed.getAttributes()) {
                    assertFalse(attribute.valuesDer().isEmpty(),
                            "у атрибута " + attribute.oid() + " нет значений");
                }
                return null;
            });
        } finally {
            // ключ, оставшийся на машине, нельзя молча пропускать
            CspContainer.runOk("удаление контейнера " + container,
                    CryptoProChecker.resolveCsptestBinary(), "-notime", "-keyset",
                    "-deletekeyset", "-container", container, "-password", CspContainer.PASSWORD);
        }
    }
}
