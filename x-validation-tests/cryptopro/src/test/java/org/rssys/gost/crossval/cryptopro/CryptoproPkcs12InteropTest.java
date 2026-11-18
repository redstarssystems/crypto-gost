package org.rssys.gost.crossval.cryptopro;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.util.CryptoProChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cms.CmsSignedDataVerifier;
import org.rssys.gost.pkix.cms.SignerSelection;
import org.rssys.gost.pkix.cms.VerifiedSignedData;
import org.rssys.gost.pkix.cms.VerifyOptions;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.GostPkcs12Parser;

/**
 * Интероп PKCS#12: PFX, который экспортирует КриптоПро, читает {@link GostPkcs12Loader}.
 *
 * <p>Контейнер создаётся файловым ({@code HDIMAGE}), с экспортируемым ключом подписи и
 * самоподписанным сертификатом, и удаляется в любом исходе. Экспортированный КриптоПро PFX
 * шифрует ключ собственной схемой PBE, которую {@link GostPkcs12Loader} не читает.
 *
 * <p>Обратное направление (наш PFX -> импорт в КриптоПро -> подпись ключом из PFX) проверяет, что
 * КриптоПро читает {@code MacData} и ГОСТ PBES2 нашего PFX (RFC 9548). Импорт ключ не генерирует,
 * поэтому окна датчика случайных чисел нет, и тест не требует разрешения на создание контейнеров.
 */
@DisplayName("PKCS#12: PFX, экспортированный КриптоПро, читает crypto-gost")
class CryptoproPkcs12InteropTest {

    /** Одноразовый PIN тестового PFX; без параметра {@code -pin} КриптоПро открывает окно запроса. */
    private static final String PFX_PIN = "crossval-pfx-pin";

    /** OID PBE, которым КриптоПро шифрует ключ в PFX; в RFC 7292 не определён. */
    private static final String PROPRIETARY_PBE_OID = "1.2.840.113549.1.12.1.80";
    /** DER-кодирование того же OID (без тега и длины). */
    private static final byte[] PROPRIETARY_PBE_OID_DER = {
        0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x50
    };

    private static final byte[] PAYLOAD = "pkcs12 interop".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void preconditions() {
        CryptoProChecker.assumeCsptestAvailable();
        CryptoProChecker.assumeCryptcpAvailable();
    }

    @Test
    @DisplayName("PFX от certmgr: схема шифрования ключа не поддерживается и отвергается fail-closed")
    void cryptoproPfxWithProprietaryPbeIsRejected() throws Exception {
        withExportedPfx(pfx -> {
            byte[] pfxBytes = Files.readAllBytes(pfx);
            // без этого условия отказ ниже мог бы объясняться чем угодно, а не схемой PBE
            assertTrue(contains(pfxBytes, PROPRIETARY_PBE_OID_DER),
                    "PFX КриптоПро должен шифровать ключ PBE с OID " + PROPRIETARY_PBE_OID);

            // MacData КриптоПро разбирается нашим парсером, в том числе соль в диапазоне 8..32
            // (RFC 9548 §7): иначе отказ ниже объяснялся бы солью или структурой, а не схемой PBE
            GostPkcs12Parser.PfxData parsed = assertDoesNotThrow(
                    () -> GostPkcs12Parser.parsePfx(pfxBytes, 1),
                    "MacData из PFX КриптоПро должен разбираться парсером");
            assertNotNull(parsed.getMacData(), "PFX КриптоПро должен содержать MacData");
            // Факты фиксируются в выводе теста: соль и OID MacData у КриптоПро нигде больше не записываются
            System.out.println("КриптоПро PFX: MacData OID=" + parsed.getMacData().getDigestAlgorithm()
                    + ", соль " + parsed.getMacData().getSalt().length + " байт, итераций "
                    + parsed.getMacData().getIterations());

            assertThrows(IllegalArgumentException.class,
                    () -> GostPkcs12Loader.load(pfxBytes, PFX_PIN.toCharArray(), false),
                    "PFX с PBE вне RFC 7292 и без ГОСТ PBES2 не должен читаться");
        });
    }

    @Test
    @Disabled("Находка: PFX КриптоПро шифрует ключ PBE с OID 1.2.840.113549.1.12.1.80, "
            + "GostPkcs12Loader его не читает, поддержка схемы требует отдельной работы")
    @DisplayName("PFX от certmgr: ключ и сертификат читаются, подпись ключа проверяется ключом сертификата")
    void exportedPfxLoadsAndKeyMatchesCertificate() throws Exception {
        withExportedPfx(pfx -> {
            byte[] pfxBytes = Files.readAllBytes(pfx);
            GostPkcs12Loader.Result loaded =
                    GostPkcs12Loader.load(pfxBytes, PFX_PIN.toCharArray(), false);

            assertNotNull(loaded.getPrivateKey(), "закрытый ключ должен быть прочитан из PFX");
            List<GostCertificate> chain = loaded.getCertificateChain();
            assertFalse(chain.isEmpty(), "в PFX должен быть сертификат");

            // ключ и сертификат из PFX обязаны быть парой: иначе PFX прочитан, но не пригоден
            byte[] signature = Signature.sign(PAYLOAD, loaded.getPrivateKey());
            assertTrue(Signature.verify(PAYLOAD, signature, chain.get(0).getPublicKey()),
                    "подпись ключа из PFX должна проверяться открытым ключом сертификата из PFX");

            char[] wrongPin = (PFX_PIN + "x").toCharArray();
            assertThrows(RuntimeException.class,
                    () -> GostPkcs12Loader.load(pfxBytes, wrongPin, false),
                    "PFX с неверным паролем не должен читаться");
        });
    }

    /** Пароль PFX из RFC 9548: стандарт требует UTF-8, поэтому проверяем именно кириллицу. */
    private static final String OUR_PFX_PASSWORD = "Пароль для PFX";

    /** Префикс имени контейнера, который certmgr даёт ключу, импортированному из PFX. */
    private static final String IMPORTED_CONTAINER_NAME_PREFIX = "\\pfx-";

    /** ПИН контейнера, в который КриптоПро импортирует ключ из PFX. */
    private static final String IMPORTED_CONTAINER_PIN = "1234";

    @Test
    @DisplayName("наш PFX: certmgr импортирует его, КриптоПро подписывает ключом из PFX, подпись проверяет crypto-gost")
    void ourPfxIsImportedAndItsKeySigns() throws Exception {
        // кириллица в аргументах команды передаётся в кодировке окружения JVM; при другой кодировке
        // пароль исказился бы, и отказ импорта нельзя было бы отличить от ошибки формата PFX
        assumeTrue("UTF-8".equalsIgnoreCase(System.getProperty("sun.jnu.encoding")),
                "кодировка аргументов JVM не UTF-8: кириллический пароль не передать certmgr");
        // уникальное имя: по нему сертификат находится и удаляется, чужие сертификаты хранилища не затрагиваются
        byte[] suffix = new byte[6];
        CryptoRandom.INSTANCE.nextBytes(suffix);
        String commonName = "crossval-pfx-" + HexFormat.of().formatHex(suffix);
        String distinguishedName = "CN=" + commonName;

        ECParameters params = ECParameters.cryptoProA();
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        GostCertificate cert = GostCertificateBuilder.create(params, distinguishedName)
                .publicKey(keyPair.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("21010101000000Z")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .serial(BigInteger.valueOf(7))
                .sign(keyPair.getPrivate());
        byte[] pfx = GostPkcs12Builder.create()
                .key(keyPair.getPrivate())
                .certificate(cert)
                .password(OUR_PFX_PASSWORD.toCharArray())
                .friendlyName(commonName)
                .build();
        keyPair.getPrivate().destroy();

        TempDirUtils.withTempDir("cp-our-pfx-", dir -> {
            Path pfxFile = dir.resolve("ours.pfx");
            Files.write(pfxFile, pfx);
            Path data = dir.resolve("data.txt");
            Files.write(data, PAYLOAD);
            Path signature = dir.resolve("data.txt.sig");

            String certmgr = CryptoProChecker.resolveCertmgrBinary();
            Set<String> containersBefore = listContainers();
            Throwable bodyFailure = null;
            try {
                // -pin - пароль PFX, -newpin - ПИН контейнера, в который КриптоПро кладёт ключ
                CspContainer.runOk("импорт нашего PFX", certmgr, "-install", "-pfx",
                        "-file", pfxFile.toString(), "-pin", OUR_PFX_PASSWORD,
                        "-newpin", IMPORTED_CONTAINER_PIN, "-silent");
                CspContainer.runOk("подпись ключом из нашего PFX", CryptoProChecker.resolveCryptcpBinary(),
                        "-sign", "-dn", distinguishedName, "-pin", IMPORTED_CONTAINER_PIN,
                        "-nochain", "-norev", "-der", data.toString(), signature.toString());

                VerifiedSignedData verified = CmsSignedDataVerifier.verify(
                        Files.readAllBytes(signature),
                        VerifyOptions.signatureOnly(SignerSelection.ANY));
                assertArrayEquals(PAYLOAD, verified.data(), "подписанные данные должны совпасть");
                assertArrayEquals(cert.getEncoded(), verified.signerCertificate().getEncoded(),
                        "подписант должен быть сертификатом из нашего PFX");
            } catch (Throwable t) {
                bodyFailure = t;
                throw t;
            } finally {
                AssertionError cleanupFailure = cleanUpImport(certmgr, distinguishedName, containersBefore);
                if (cleanupFailure != null) {
                    if (bodyFailure != null) {
                        // ошибка уборки не должна затирать исходную причину падения
                        bodyFailure.addSuppressed(cleanupFailure);
                    } else {
                        throw cleanupFailure;
                    }
                }
            }
            return null;
        });
    }

    /** Удаляет импортированные сертификат и контейнер; ключ, оставшийся на машине, молча не пропускаем. */
    private static AssertionError cleanUpImport(
            String certmgr, String distinguishedName, Set<String> containersBefore) throws Exception {
        List<String> problems = new ArrayList<>();
        CryptoProChecker.Result deleted = CryptoProChecker.runResult(
                certmgr, "-delete", "-store", CryptoProChecker.USER_STORE, "-dn", distinguishedName, "-silent");
        if (deleted.exitCode() != 0) {
            problems.add("удаление сертификата " + distinguishedName + ": " + deleted.output());
        }
        Set<String> added = listContainers();
        added.removeAll(containersBefore);
        // Удаляем только контейнеры, созданные импортом PFX (имя pfx-<uuid>), и только если он один:
        // оператор или другой процесс мог создать свой контейнер в это же время, чужой ключ не трогаем
        added.removeIf(container -> !container.contains(IMPORTED_CONTAINER_NAME_PREFIX));
        if (added.size() > 1) {
            problems.add("после импорта появилось несколько контейнеров " + added + ": не удаляю, проверьте вручную");
            added.clear();
        }
        for (String container : added) {
            CryptoProChecker.Result removed = CryptoProChecker.runResult(
                    CryptoProChecker.resolveCsptestBinary(), "-notime", "-keyset", "-deletekeyset",
                    "-container", container, "-password", IMPORTED_CONTAINER_PIN);
            if (removed.exitCode() != 0) {
                problems.add("удаление контейнера " + container + ": " + removed.output());
            }
        }
        return problems.isEmpty() ? null : new AssertionError("после теста остались следы на машине: " + problems);
    }

    /** Полные имена контейнеров КриптоПро (строки вида {@code \\.\HDIMAGE\name}). */
    private static Set<String> listContainers() throws Exception {
        CryptoProChecker.Result result = CryptoProChecker.runResult(
                CryptoProChecker.resolveCsptestBinary(), "-notime", "-keyset", "-enum_cont", "-fqcn", "-verifyc");
        assertEquals(0, result.exitCode(), "перечисление контейнеров: " + result.output());
        Set<String> containers = new TreeSet<>();
        for (String line : result.output().split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("\\\\.\\")) {
                containers.add(trimmed);
            }
        }
        return containers;
    }

    /** Выполняет проверку над свежим PFX и гарантированно удаляет контейнер. */
    private static void withExportedPfx(PfxCheck check) throws Exception {
        try (CspContainer container =
                CspContainer.create("p12", CspContainer.PROVIDER_TYPE_256, true)) {
            TempDirUtils.withTempDir("cp-pfx-", dir -> {
                Path pfx = dir.resolve("container.pfx");
                // -silent здесь нельзя: провайдер падает с NTE_SILENT_CONTEXT (0x80090022);
                // -at_signature нужен, так как ключ контейнера - ключ подписи
                CspContainer.runOk("экспорт в PFX", CryptoProChecker.resolveCertmgrBinary(),
                        "-export", "-pfx", "-container", container.path(),
                        "-dest", pfx.toString(), "-pin", PFX_PIN, "-at_signature");
                assertTrue(Files.size(pfx) > 0, "certmgr должен создать непустой PFX");
                check.run(pfx);
                return null;
            });
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    @FunctionalInterface
    private interface PfxCheck {
        void run(Path pfx) throws Exception;
    }
}
