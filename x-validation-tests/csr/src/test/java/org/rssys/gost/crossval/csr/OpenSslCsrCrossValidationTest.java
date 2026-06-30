package org.rssys.gost.crossval.csr;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.cert.GostCsrBuilder;
import org.rssys.gost.pkix.cert.GostCsrParser;
import org.rssys.gost.pkix.cert.GostExtensionParser;
import org.rssys.gost.signature.ECParameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Кросс-валидация CSR: библиотека <-> openssl")
class OpenSslCsrCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    static boolean opensslAvailable() {
        return Files.exists(Path.of(opensslBinary()));
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary",
                "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String[] engineFlags() {
        return OpenSslChecker.resolveEngineFlag();
    }

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
    }

    // ========================================================================
    // Сценарий 1: библиотека строит CSR -> openssl req -verify верифицирует
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 1: библиотека -> openssl req -verify (proof-of-possession)")
    void testLibraryCsrVerifiedByOpenssl() throws Exception {
        TempDirUtils.withTempDir("csr-lib-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

            // Строим CSR библиотекой
            byte[] csrDer = GostCsrBuilder.buildCsr(kp.getPrivate(), kp.getPublic(),
                    "CN=OsslVerify,O=Test");
            Path csrPath = dir.resolve("csr.der");
            Files.write(csrPath, csrDer);

            // OpenSSL req -verify — CSR самоподписан, проверка proof-of-possession
            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "req", "-verify"},
                    engineFlags(),
                    new String[]{"-in", csrPath.toString(),
                            "-inform", "DER", "-noout"}
            );
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl req -verify должно подтвердить proof-of-possession");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 2: openssl req -new генерирует CSR -> библиотека парсит
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 2: openssl req -new -> библиотека парсит и верифицирует")
    void testOpensslCsrParsedByLibrary() throws Exception {
        TempDirUtils.withTempDir("csr-ossl-", dir -> {
            // Генерируем ключ openssl
            Path keyPath = dir.resolve("key.pem");
            genKey(dir, keyPath, PARAMS_256);

            // OpenSSL req -new -> CSR
            Path csrPath = dir.resolve("csr.der");
            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "req", "-new"},
                    engineFlags(),
                    new String[]{"-key", keyPath.toString(),
                            "-out", csrPath.toString(),
                            "-outform", "DER",
                            "-subj", "/CN=OsslGen/O=CrossVal",
                            "-config", "/dev/null"}
            );
            OpenSslChecker.exec(cmd);

            // Библиотека парсит и проверяет
            byte[] csrDer = Files.readAllBytes(csrPath);
            GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

            assertNotNull(parsed.getSubjectDn());
            assertTrue(parsed.getSubjectDn().contains("CN=OsslGen"));
            assertTrue(parsed.getSubjectDn().contains("O=CrossVal"));
            assertNotNull(parsed.getPublicKey());
            assertEquals(0, parsed.getVersion(), "Версия CSR должна быть 0 (v1)");
            assertTrue(parsed.verifySelf(), "proof-of-possession: CSR должен быть самоподписан");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 3: библиотека портит подпись -> openssl req -verify отвергает
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 3: порченая подпись -> openssl req -verify отвергает")
    void testTamperedCsrRejectedByOpenssl() throws Exception {
        TempDirUtils.withTempDir("csr-tamper-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);

            byte[] csrDer = GostCsrBuilder.buildCsr(kp.getPrivate(), kp.getPublic(),
                    "CN=Tamper");
            // Портим последний байт сигнатуры
            csrDer[csrDer.length - 1] ^= 0x01;

            Path csrPath = dir.resolve("tampered.der");
            Files.write(csrPath, csrDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "req", "-verify"},
                    engineFlags(),
                    new String[]{"-in", csrPath.toString(),
                            "-inform", "DER", "-noout"}
            );
            int exit = OpenSslChecker.run(cmd);
            // OpenSSL 3.3+ возвращает 1 при failed verify
            assertNotEquals(0, exit, "openssl req -verify должно отвергнуть порченую подпись");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 4: openssl CSR с extensionRequest -> библиотека парсит расширения
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 4: openssl CSR с SAN -> библиотека парсит extensionRequest")
    void testOpensslCsrWithExtensionsParsed() throws Exception {
        TempDirUtils.withTempDir("csr-ext-", dir -> {
            Path keyPath = dir.resolve("extkey.pem");
            genKey(dir, keyPath, PARAMS_256);

            Path csrPath = dir.resolve("extcsr.der");
            // OpenSSL 3.x: -addext добавляет расширения в CSR
            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "req", "-new"},
                    engineFlags(),
                    new String[]{"-key", keyPath.toString(),
                            "-out", csrPath.toString(),
                            "-outform", "DER",
                            "-subj", "/CN=SanTest",
                            "-addext", "subjectAltName=DNS:test.example.com,DNS:www.example.com",
                            "-config", "/dev/null"}
            );
            OpenSslChecker.exec(cmd);

            byte[] csrDer = Files.readAllBytes(csrPath);
            GostCsrParser parsed = GostCsrParser.fromDer(csrDer);

            assertTrue(parsed.verifySelf());
            assertTrue(parsed.hasExtensions(), "CSR с -addext должен содержать extensionRequest");

            GostExtensionParser.ExtensionsResult ext = parsed.getExtensions();
            assertNotNull(ext.sanDnsNames, "SAN должен быть распарсен");
            assertEquals(2, ext.sanDnsNames.length);
            // Проверяем присутствие dNSName (порядок может варьироваться)
            boolean hasTest = false;
            boolean hasWww = false;
            for (String name : ext.sanDnsNames) {
                if ("test.example.com".equals(name)) hasTest = true;
                if ("www.example.com".equals(name)) hasWww = true;
            }
            assertTrue(hasTest, "SAN должен содержать test.example.com");
            assertTrue(hasWww, "SAN должен содержать www.example.com");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 5: обе кривые (256, 512)
    // ========================================================================

    static Stream<ECParameters> curves() {
        return Stream.of(PARAMS_256, PARAMS_512);
    }

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 5: roundtrip библиотека<->openssl для обеих кривых")
    void testBothCurves(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("csr-curve-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(params);
            String curveName = params.hlen == 64 ? "512" : "256";

            // Библиотека -> DER -> openssl verify
            byte[] csrDer = GostCsrBuilder.buildCsr(kp.getPrivate(), kp.getPublic(),
                    "CN=Curve" + curveName);
            Path csrPath = dir.resolve("csr.der");
            Files.write(csrPath, csrDer);

            String[] verifyCmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "req", "-verify"},
                    engineFlags(),
                    new String[]{"-in", csrPath.toString(),
                            "-inform", "DER", "-noout"}
            );
            assertEquals(0, OpenSslChecker.run(verifyCmd),
                    "openssl req -verify для кривой " + curveName);

            // Библиотека парсит свой же CSR
            GostCsrParser parsed = GostCsrParser.fromDer(csrDer);
            assertEquals("CN=Curve" + curveName, parsed.getSubjectDn());
            assertTrue(parsed.verifySelf());
            assertNotNull(parsed.getPublicKey());
            return null;
        });
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /**
     * Генерирует ключ GOST2012 через openssl genpkey.
     */
    private static void genKey(Path dir, Path keyPath, ECParameters params) throws Exception {
        String paramset = params.hlen == 64 ? "B" : "A";
        String algo = "gost2012_" + (params.hlen * 8);
        String[] cmd = CrossValUtils.concat(
                new String[]{opensslBinary(), "genpkey"},
                engineFlags(),
                new String[]{"-algorithm", algo,
                        "-pkeyopt", "paramset:" + paramset,
                        "-out", keyPath.toString()}
        );
        OpenSslChecker.exec(cmd);
    }
}
