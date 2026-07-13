package org.rssys.gost.crossval.cert;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.*;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Кросс-валидация сертификатов X.509: библиотека <-> openssl")
class OpenSslCertCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    static boolean opensslAvailable() {
        try {
            String[] cmd = {opensslBinary(), "version"};
            return OpenSslChecker.run(cmd) == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String[] opensslCommand(String... args) {
        // Флаги провайдера (-provider-path, -provider) должны идти после subcommand (x509, verify...),
        // не перед ним. Первый элемент args — subcommand.
        String[] engine = OpenSslChecker.resolveEngineFlag();
        String[] head = {opensslBinary(), args[0]};
        String[] tail = java.util.Arrays.copyOfRange(args, 1, args.length);
        return CrossValUtils.concat(head, engine, tail);
    }

    static String[] engineFlags() {
        return OpenSslChecker.resolveEngineFlag();
    }

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
    }

    static Stream<ECParameters> curves() {
        return Stream.of(PARAMS_256, PARAMS_512);
    }

    // ========================================================================
    // Сценарий 1: самоподписанный сертификат -> openssl verify
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 1: библиотека -> openssl verify (самоподписанный)")
    void testSelfSignedVerify(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("cert-self-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(params);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=Test CA,O=GostTest", params);
            Path certPem = dir.resolve("cert.pem");
            Files.writeString(certPem, GostPemUtils.toPem(cert.getEncoded()));

            String[] cmd = opensslCommand("verify", "-CAfile", certPem.toString(), certPem.toString());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl verify должен подтвердить самоподписанный сертификат");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 2: цепочка root->int->leaf -> openssl verify
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 2: цепочка root->int->leaf -> openssl verify")
    void testChainVerify() throws Exception {
        TempDirUtils.withTempDir("cert-chain-", dir -> {
            KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS_256);
            KeyPair intKp = KeyGenerator.generateKeyPair(PARAMS_256);
            KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS_256);

            GostCertificate root = buildSelfSignedCa(rootKp, "CN=Root,O=Test", PARAMS_256);
            GostCertificate intCert = buildCa(intKp, PARAMS_256, rootKp, root, "CN=Intermediate,O=Test");
            GostCertificate leaf = buildLeaf(leafKp, PARAMS_256, intKp, intCert, "CN=leaf,O=Test");

            Path rootPem = dir.resolve("root.pem");
            Path intPem = dir.resolve("int.pem");
            Path leafPem = dir.resolve("leaf.pem");
            Files.writeString(rootPem, GostPemUtils.toPem(root.getEncoded()));
            Files.writeString(intPem, GostPemUtils.toPem(intCert.getEncoded()));
            Files.writeString(leafPem, GostPemUtils.toPem(leaf.getEncoded()));

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "verify", "-CAfile", rootPem.toString(),
                            "-untrusted", intPem.toString()},
                    engineFlags(),
                    new String[]{leafPem.toString()});
            OpenSslChecker.exec(cmd);
            return null;
        });
    }

    // ========================================================================
    // Сценарий 3: x509 -text — все расширения в листовом сертификате
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 3: листовой сертификат с расширениями -> openssl x509 -text")
    void testLeafWithExtensionsText() throws Exception {
        TempDirUtils.withTempDir("cert-ext-", dir -> {
            KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS_256);
            KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate root = buildSelfSignedCa(rootKp, "CN=CA,O=Test", PARAMS_256);
            GostCertificate leaf = buildLeaf(leafKp, PARAMS_256, rootKp, root, "CN=leaf,O=Test");

            Path pemPath = dir.resolve("leaf.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(leaf.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(), "-text", "-noout");
            OpenSslChecker.exec(cmd);
            return null;
        });
    }

    // ========================================================================
    // Сценарий 4: x509 -pubkey — извлечение публичного ключа
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 4: библиотека -> openssl x509 -pubkey (извлечение ключа)")
    void testPubkeyExtraction(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("cert-key-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(params);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=keytest,O=Test", params);
            Path pemPath = dir.resolve("cert.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(cert.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(), "-pubkey", "-noout");
            OpenSslChecker.exec(cmd);
            return null;
        });
    }

    // ========================================================================
    // Сценарий 5: x509 -checkhost — проверка SAN dNSName
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 5: SAN dNSName -> openssl x509 -checkhost localhost")
    void testCheckHost() throws Exception {
        TempDirUtils.withTempDir("cert-host-", dir -> {
            KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS_256);
            KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate root = buildSelfSignedCa(rootKp, "CN=CA,O=Test", PARAMS_256);
            GostCertificate leaf = buildLeaf(leafKp, PARAMS_256, rootKp, root, "CN=leaf,O=Test");

            Path pemPath = dir.resolve("leaf.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(leaf.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(), "-checkhost", "localhost", "-noout");
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "SAN dNSName localhost должен совпадать");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 6: x509 -issuer не пуст для self-signed (регрессия)
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 6: self-signed -> issuer не пустой (регрессия)")
    void testSelfSignedIssuerNotEmpty() throws Exception {
        TempDirUtils.withTempDir("cert-issuer-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=My Issuer,O=GostTest", PARAMS_256);
            Path pemPath = dir.resolve("cert.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(cert.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(), "-issuer", "-noout");
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "-issuer должен отработать без ошибок");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 7: x509 -fingerprint
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 7: библиотека -> openssl x509 -fingerprint")
    void testFingerprint() throws Exception {
        TempDirUtils.withTempDir("cert-fp-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=fptest,O=Test", PARAMS_256);
            Path pemPath = dir.resolve("cert.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(cert.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(), "-fingerprint", "-noout");
            OpenSslChecker.exec(cmd);
            return null;
        });
    }

    // ========================================================================
    // Сценарий 8: PEM roundtrip DER -> PEM -> DER
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 8: DER -> PEM -> DER roundtrip (байты идентичны)")
    void testPemRoundtrip() throws Exception {
        TempDirUtils.withTempDir("cert-pem-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=pemtest,O=Test", PARAMS_256);
            byte[] originalDer = cert.getEncoded();

            Path pemPath = dir.resolve("cert.pem");
            String pem = GostPemUtils.toPem(originalDer);
            Files.writeString(pemPath, pem);

            Path derPath = dir.resolve("from_pem.der");
            String[] cmd = opensslCommand("x509", "-inform", "PEM", "-in", pemPath.toString(),
                    "-outform", "DER", "-out", derPath.toString());
            OpenSslChecker.exec(cmd);

            byte[] roundtrippedDer = Files.readAllBytes(derPath);
            assertArrayEquals(originalDer, roundtrippedDer, "PEM roundtrip должен сохранить байты");
            return null;
        });
    }

    // ========================================================================
    // Сценарий 9: порченая подпись -> openssl verify отвергает
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 9: порченая подпись -> openssl verify отвергает")
    void testTamperedSignatureRejected() throws Exception {
        TempDirUtils.withTempDir("cert-tamper-", dir -> {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate cert = buildSelfSignedCa(kp, "CN=tamper,O=Test", PARAMS_256);

            Path goodPath = dir.resolve("good.pem");
            String goodPem = GostPemUtils.toPem(cert.getEncoded());
            Files.writeString(goodPath, goodPem);

            // Проверяем что исходный сертификат валиден
            String[] goodCmd = opensslCommand("verify", "-check_ss_sig", "-CAfile", goodPath.toString(), goodPath.toString());
            int goodExit = OpenSslChecker.run(goodCmd);
            assertEquals(0, goodExit, "Исходный сертификат должен верифицироваться");

            // Модифицируем байт внутри signatureValue (последний BIT STRING в DER)
            byte[] der = cert.getEncoded().clone();
            int sigBitStrPos = findLastBitStringOffset(der);
            assertTrue(sigBitStrPos > 0, "Должен быть найден BIT STRING подписи");
            der[sigBitStrPos + 3] ^= 0xFF; // портим первый байт значения подписи (пропускаем unused_bits)

            Path tamperedPath = dir.resolve("tampered.pem");
            Files.writeString(tamperedPath, GostPemUtils.toPem(der));

            String[] tamperedCmd = opensslCommand("verify", "-check_ss_sig", "-CAfile", tamperedPath.toString(),
                    tamperedPath.toString());
            int tamperedExit = OpenSslChecker.run(tamperedCmd);
            assertNotEquals(0, tamperedExit, "openssl verify должен отвергнуть порченую подпись");
            return null;
        });
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    static GostCertificate buildSelfSignedCa(KeyPair kp, String dn, ECParameters params) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(kp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("20351231235959Z")
                .basicConstraints(true, null)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .serial(BigInteger.ONE)
                .sign(kp.getPrivate());
    }

    static GostCertificate buildCa(KeyPair kp, ECParameters params,
            KeyPair issuerKp, GostCertificate issuerCert, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(kp.getPublic())
                .issuerDn(issuerCert.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20301231235959Z")
                .basicConstraints(true, 0)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .serial(BigInteger.TWO)
                .sign(issuerKp.getPrivate());
    }

    static GostCertificate buildLeaf(KeyPair kp, ECParameters params,
            KeyPair issuerKp, GostCertificate issuerCert, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(kp.getPublic())
                .issuerDn(issuerCert.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20261231235959Z")
                .sanDns("localhost", "test.local")
                .sanIp("127.0.0.1")
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                .extendedKeyUsage(GostOids.EXT_SERVER_AUTH, GostOids.EXT_CLIENT_AUTH)
                .crlDistributionPoints("http://crl.test.local/crl.crl")
                .ocspResponder("http://ocsp.test.local")
                .serial(BigInteger.valueOf(3))
                .sign(issuerKp.getPrivate());
    }

    /**
     * Находит смещение последнего BIT STRING в DER-сертификате (signatureValue).
     * <p>
     * Входит во внешний SEQUENCE сертификата и итерирует только прямых детей
     * (tbsCertificate, signatureAlgorithm, signatureValue). BIT STRING среди них
     * ровно один — signatureValue.
     */
    static int findLastBitStringOffset(byte[] der) {
        int lastBitStr = -1;
        if (der.length < 4 || (der[0] & 0xFF) != 0x30) {
            return -1;
        }
        int contentStart, contentEnd;
        int len = der[1] & 0xFF;
        if ((len & 0x80) != 0) {
            int numLenOctets = len & 0x7F;
            int dataLen = 0;
            for (int i = 0; i < numLenOctets; i++) {
                dataLen = (dataLen << 8) | (der[2 + i] & 0xFF);
            }
            contentStart = 2 + numLenOctets;
            contentEnd = contentStart + dataLen;
        } else {
            contentStart = 2;
            contentEnd = contentStart + len;
        }
        int pos = contentStart;
        while (pos < contentEnd - 1) {
            int tag = der[pos] & 0xFF;
            int childLen = der[pos + 1] & 0xFF;
            if (tag == 0x03) {
                lastBitStr = pos;
            }
            if ((childLen & 0x80) != 0) {
                int numLenOctets = childLen & 0x7F;
                int dataLen = 0;
                for (int i = 0; i < numLenOctets; i++) {
                    dataLen = (dataLen << 8) | (der[pos + 2 + i] & 0xFF);
                }
                pos += 2 + numLenOctets + dataLen;
            } else {
                pos += 2 + childLen;
            }
        }
        return lastBitStr;
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("SAN с rfc822Name, URI, directoryName, otherName (UPN) в openssl x509 -text")
    void testSanWithNewGeneralNameTypes() throws Exception {
        TempDirUtils.withTempDir("cert-san-", dir -> {
            KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS_256);
            KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS_256);
            GostCertificate root = buildSelfSignedCa(rootKp, "CN=CA,O=Test", PARAMS_256);

            byte[] dnDer = GostDnParser.encodeDn("CN=AltDirName");
            GostCertificate leaf = GostCertificateBuilder.create(PARAMS_256, "CN=leaf,O=Test")
                    .publicKey(leafKp.getPublic())
                    .issuerDn(root.getSubjectDnBytes())
                    .notBefore("20250101000000Z")
                    .notAfter("20261231235959Z")
                    .sanDns("localhost")
                    .sanRfc822Name("admin@example.com")
                    .sanUri("https://example.com")
                    .sanDirectoryName(dnDer)
                    .sanUpn("user@domain.ru")
                    .serial(BigInteger.valueOf(10))
                    .sign(rootKp.getPrivate());

            Path pemPath = dir.resolve("leaf-san.pem");
            Files.writeString(pemPath, GostPemUtils.toPem(leaf.getEncoded()));

            String[] cmd = opensslCommand("x509", "-in", pemPath.toString(),
                    "-text", "-noout");
            String output = OpenSslChecker.runAndCapture(cmd);
            assertNotNull(output, "openssl x509 -text должен выдать текст");
            // openssl без ошибок прочитал сертификат — структура DER корректна
            assertTrue(output.contains("Subject Alternative Name"),
                    "openssl должен показать секцию Subject Alternative Name");

            // cross-check: библиотека читает собственный сертификат

            assertEquals("admin@example.com", leaf.getSanRfc822Names()[0]);
            assertEquals("https://example.com", leaf.getSanUris()[0]);
            assertArrayEquals(dnDer, leaf.getSanDirectoryNames()[0]);
            assertEquals(1, leaf.getSanOtherNames().length);
            assertEquals(GostOids.ID_MS_UPN, leaf.getSanOtherNames()[0].oid());

            return null;
        });
    }

    /**
     * Обратная кросс-валидация: OpenSSL строит сертификат с rfc822Name и otherName (UPN)
     * в SAN, библиотека парсит — поля заполнены корректно.
     */
    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Обратная кросс-валидация: openssl собирает SAN с email + otherName(UPN) -> библиотека читает")
    void testSanReverseCrossvalOpenSslBuildsLibraryReads() throws Exception {
        TempDirUtils.withTempDir("cert-san-rev-", dir -> {
            Path keyPath = dir.resolve("key.pem");
            Path certPath = dir.resolve("cert.pem");
            Path configPath = dir.resolve("san.cnf");

            String config =
                    ""
                            + "[req]\n"
                            + "distinguished_name = req_dn\n"
                            + "x509_extensions = v3_ext\n"
                            + "prompt = no\n"
                            + "[req_dn]\n"
                            + "CN = Test SAN Reverse\n"
                            + "[v3_ext]\n"
                            + "subjectAltName = email:reverse@example.com,"
                            + "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:reverse-upn@domain.ru\n";
            Files.writeString(configPath, config);

            String[] genKey =
                    opensslCommand(
                            "genpkey",
                            "-algorithm",
                            "gost2012_256",
                            "-pkeyopt",
                            "paramset:A",
                            "-out",
                            keyPath.toString());
            assertEquals(0, OpenSslChecker.run(genKey),
                    "openssl genpkey должен завершиться успешно");

            String[] req =
                    opensslCommand(
                            "req",
                            "-x509",
                            "-new",
                            "-key",
                            keyPath.toString(),
                            "-out",
                            certPath.toString(),
                            "-config",
                            configPath.toString(),
                            "-days",
                            "365");
            assertEquals(0, OpenSslChecker.run(req),
                    "openssl req -x509 должен завершиться успешно");

            // Verify with openssl itself
            String[] verify =
                    opensslCommand("x509", "-in", certPath.toString(), "-text", "-noout");
            String output = OpenSslChecker.runAndCapture(verify);
            assertTrue(output.contains("Subject Alternative Name"),
                    "openssl должен показать Subject Alternative Name");
            assertTrue(output.contains("reverse@example.com"),
                    "openssl должен показать rfc822Name");

            // Now parse with the library
            byte[] pemBytes = Files.readAllBytes(certPath);
            GostCertificate cert = GostCertificate.fromPemOrDer(pemBytes);

            assertNotNull(cert.getSanRfc822Names(), "библиотека должна прочитать rfc822Name");
            assertEquals(1, cert.getSanRfc822Names().length);
            assertEquals("reverse@example.com", cert.getSanRfc822Names()[0]);

            assertNotNull(cert.getSanOtherNames(), "библиотека должна прочитать otherName (UPN)");
            assertEquals(1, cert.getSanOtherNames().length);
            assertEquals(GostOids.ID_MS_UPN, cert.getSanOtherNames()[0].oid());

            return null;
        });
    }
}
