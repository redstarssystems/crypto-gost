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
            String[] cmd = opensslCommand("version");
            return OpenSslChecker.run(cmd) == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String[] opensslCommand(String... args) {
        return CrossValUtils.concat(new String[]{opensslBinary()}, OpenSslChecker.resolveEngineFlag(), args);
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
            String[] goodCmd = opensslCommand("verify", "-CAfile", goodPath.toString(), goodPath.toString());
            int goodExit = OpenSslChecker.run(goodCmd);
            assertEquals(0, goodExit, "Исходный сертификат должен верифицироваться");

            // Модифицируем байт внутри signatureValue (последний BIT STRING в DER)
            byte[] der = cert.getEncoded().clone();
            int sigBitStrPos = findLastBitStringOffset(der);
            assertTrue(sigBitStrPos > 0, "Должен быть найден BIT STRING подписи");
            der[sigBitStrPos + 3] ^= 0xFF; // портим первый байт значения подписи (пропускаем unused_bits)

            Path tamperedPath = dir.resolve("tampered.pem");
            Files.writeString(tamperedPath, GostPemUtils.toPem(der));

            String[] tamperedCmd = opensslCommand("verify", "-CAfile", tamperedPath.toString(),
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
                .assembleCert(kp.getPrivate());
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
                .assembleCert(issuerKp.getPrivate());
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
                .assembleCert(issuerKp.getPrivate());
    }

    /**
     * Находит смещение последнего BIT STRING в DER-сертификате (signatureValue).
     */
    static int findLastBitStringOffset(byte[] der) {
        int lastBitStr = -1;
        int pos = 0;
        while (pos < der.length - 2) {
            int tag = der[pos] & 0xFF;
            if (pos + 1 >= der.length) break;
            int len = der[pos + 1] & 0xFF;
            if (len < 0) break;
            if (tag == 0x03) {
                lastBitStr = pos;
            }
            // Длинная форма
            if ((len & 0x80) != 0) {
                int numLenOctets = len & 0x7F;
                if (pos + 1 + numLenOctets >= der.length) break;
                int dataLen = 0;
                for (int i = 0; i < numLenOctets; i++) {
                    dataLen = (dataLen << 8) | (der[pos + 2 + i] & 0xFF);
                }
                pos += 2 + numLenOctets + dataLen;
            } else {
                pos += 2 + len;
            }
        }
        return lastBitStr;
    }
}
