package org.rssys.gost.crossval.crl;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.cert.*;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Кросс-валидация CRL (RFC 5280) между библиотекой crypto-gost и openssl crl.
 */
@DisplayName("Кросс-валидация CRL: библиотека <-> openssl")
class OpenSslCrlCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();

    static boolean opensslAvailable() {
        return Files.exists(Path.of(opensslBinary()));
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeEngineGost();
    }

    // ========================================================================
    // Хелперы генерации
    // ========================================================================

    private static KeyPair genKey(ECParameters params) {
        return KeyGenerator.generateKeyPair(params);
    }

    private static GostCertificate buildCa(
            ECParameters params, KeyPair caKp, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(caKp.getPublic())
                .notBefore("20250101000000Z")
                .notAfter("20351231235959Z")
                .basicConstraints(true, null)
                .keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN)
                .assembleCert(caKp.getPrivate());
    }

    private static byte[] buildCrl(
            PrivateKeyParameters caPriv, PublicKeyParameters caPub,
            byte[] issuerDnDer,
            byte[][] revokedSerials, String[] revocationDates,
            String thisUpdate, String nextUpdate) {
        GostCrlBuilder builder = GostCrlBuilder.create(caPriv, issuerDnDer)
                .thisUpdate(thisUpdate)
                .nextUpdate(nextUpdate);
        if (revokedSerials != null) {
            for (int i = 0; i < revokedSerials.length; i++) {
                builder.addRevoked(revokedSerials[i], revocationDates[i]);
            }
        }
        return builder.build();
    }

    // ========================================================================
    // Сценарий 1: пустой CRL — openssl crl -text и -verify
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 1: пустой CRL — openssl crl -text + -verify")
    void testEmptyCrlTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-empty-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] crlDer = buildCrl(caKp.getPrivate(), caKp.getPublic(),
                    ca.getSubjectDnBytes(), null, null,
                    "20260101000000Z", "20260701000000Z");
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // L1: -text
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitText = OpenSslChecker.run(cmdText);
            assertEquals(0, exitText, "openssl crl -text пустого CRL должен пройти");

            // L3: -verify (ожидаем OK)
            String[] cmdVerify = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitVerify = OpenSslChecker.run(cmdVerify);
            assertEquals(0, exitVerify, "openssl crl -verify пустого CRL должен дать verify OK");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 2: CRL с отозванным — openssl crl -text (поля) и -verify
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 2: CRL с отозванным сертификатом — -text + -verify")
    void testRevokedCrlTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-revoked-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            // Генерируем leaf-сертификат с "серийным номером" из KeyPair
            KeyPair leafKp = genKey(PARAMS_256);
            GostCertificate leaf = GostCertificateBuilder.create(PARAMS_256, "CN=leaf,O=Test")
                    .publicKey(leafKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .notBefore("20250101000000Z")
                    .notAfter("20261231235959Z")
                    .assembleCert(caKp.getPrivate());

            byte[] crlDer = buildCrl(caKp.getPrivate(), caKp.getPublic(),
                    ca.getSubjectDnBytes(),
                    new byte[][]{leaf.getSerialNumber()},
                    new String[]{"20260315120000Z"},
                    "20260101000000Z", "20260701000000Z");
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // L1: -text — видимость Serial Number и Revocation Date
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitText = OpenSslChecker.run(cmdText);
            assertEquals(0, exitText, "openssl crl -text CRL с отозванным должен пройти");

            // L3: -verify (CRL подписан CA, CA-сертификат валиден — ожидаем verify OK)
            String[] cmdVerify = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitVerify = OpenSslChecker.run(cmdVerify);
            assertEquals(0, exitVerify, "openssl crl -verify CRL с отозванным должен дать verify OK");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 3: CRL с reasonCode — openssl crl -text
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 3: CRL с reasonCode KEY_COMPROMISE — -text")
    void testCrlWithReasonCode() throws Exception {
        TempDirUtils.withTempDir("crl-reason-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] crlDer = GostCrlBuilder.create(caKp.getPrivate(),
                            ca.getSubjectDnBytes())
                    .thisUpdate("20260101000000Z")
                    .nextUpdate("20260701000000Z")
                    .addRevoked(new RevokedEntry(
                            ca.getSerialNumber(),
                            "20260401120000Z",
                            ReasonCode.KEY_COMPROMISE,
                            null, null))
                    .build();
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl crl -text с reasonCode должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 4: CRL — openssl crl -fingerprint
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 4: fingerprint CRL")
    void testCrlFingerprint() throws Exception {
        TempDirUtils.withTempDir("crl-fp-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] crlDer = buildCrl(caKp.getPrivate(), caKp.getPublic(),
                    ca.getSubjectDnBytes(), null, null,
                    "20260101000000Z", "20260701000000Z");
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-fingerprint", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl crl -fingerprint должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 5: CRL с порченой подписью — openssl crl -verify должен упасть
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 5: порченая подпись CRL — verify должен отвергнуть")
    void testTamperedCrlRejected() throws Exception {
        TempDirUtils.withTempDir("crl-tampered-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] crlDer = buildCrl(caKp.getPrivate(), caKp.getPublic(),
                    ca.getSubjectDnBytes(), null, null,
                    "20260101000000Z", "20260701000000Z");

            // Портим последние байты подписи
            byte[] tampered = crlDer.clone();
            for (int i = tampered.length - 20; i < tampered.length; i++) {
                tampered[i] ^= 0xFF;
            }
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, tampered);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertNotEquals(0, exit, "openssl crl -verify порченого CRL должен упасть");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 6: Delta CRL с deltaCRLIndicator + cRLNumber — openssl crl -text + -verify
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 6: Delta CRL с deltaCRLIndicator + cRLNumber — -text + -verify")
    void testDeltaCrlTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-delta-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] crlDer = GostCrlBuilder.create(caKp.getPrivate(),
                            ca.getSubjectDnBytes())
                    .thisUpdate("20260101000000Z")
                    .nextUpdate("20260701000000Z")
                    .withCrlNumber(2)
                    .withDeltaCrlIndicator(1)
                    .build();
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // L1: -text — парсинг расширений deltaCRLIndicator + cRLNumber
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitText = OpenSslChecker.run(cmdText);
            assertEquals(0, exitText, "openssl crl -text delta CRL должен пройти");

            // L3: -verify — подпись delta CRL верифицируется CA-сертификатом
            String[] cmdVerify = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitVerify = OpenSslChecker.run(cmdVerify);
            assertEquals(0, exitVerify, "openssl crl -verify delta CRL должен дать verify OK");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 7: Base CRL с freshestCRL — openssl -text + read-path round-trip
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 7: Base CRL с freshestCRL — openssl -text + round-trip read-path")
    void testFreshestCrlTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-freshest-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            String deltaUri = "http://ca.example/delta.crl";
            byte[] crlDer = GostCrlBuilder.create(caKp.getPrivate(),
                            ca.getSubjectDnBytes())
                    .thisUpdate("20260706120000Z")
                    .nextUpdate("20270706120000Z")
                    .withCrlNumber(3)
                    .withFreshestCrl(deltaUri)
                    .build();
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // L1: -text — захват stdout для проверки read-path
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            String textOut = OpenSslChecker.runAndCapture(cmdText);

            // Извлечь URI из вывода openssl: строка вида "URI:http://..."
            String uriFromOpenssl = textOut.lines()
                    .filter(l -> l.contains("URI:"))
                    .map(l -> l.substring(l.indexOf("URI:") + 4).trim())
                    .findFirst()
                    .orElse(null);
            assertEquals(deltaUri, uriFromOpenssl,
                    "openssl crl -text должен содержать URI " + deltaUri);

            // L2: read-path библиотеки — парсинг того же DER
            GostCrl crl = new GostCrl(crlDer);
            crl.verify(caKp.getPublic());
            assertTrue(crl.isFreshestCrl(), "GostCrl.isFreshestCrl() должен быть true");
            assertEquals(deltaUri, crl.getFreshestCrlUris()[0],
                    "GostCrl.getFreshestCrlUris()[0] должен совпадать с исходным URI");

            // L3: -verify
            String[] cmdVerify = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitVerify = OpenSslChecker.run(cmdVerify);
            assertEquals(0, exitVerify, "openssl crl -verify с freshestCRL должен дать verify OK");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 8: CRL с AKI — openssl -text + round-trip read-path
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 8: CRL с AKI — openssl -text + round-trip read-path")
    void testAkiCrlTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-aki-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");

            byte[] caPubPoint = GostDerCodec.subjectPublicKeyPointBytes(caKp.getPublic());
            byte[] caSki = Digest.digest256(caPubPoint);

            byte[] crlDer = GostCrlBuilder.create(caKp.getPrivate(),
                            ca.getSubjectDnBytes())
                    .thisUpdate("20260706120000Z")
                    .nextUpdate("20270706120000Z")
                    .withAki(caSki)
                    .build();
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // L1: -text — AKI должен быть виден в выводе
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            String textOut = OpenSslChecker.runAndCapture(cmdText);
            assertTrue(
                    textOut.contains("X509v3 Authority Key Identifier"),
                    "openssl crl -text должен показывать AKI");

            // L2: read-path библиотеки — round-trip
            GostCrl crl = new GostCrl(crlDer);
            crl.verify(caKp.getPublic());
            assertNotNull(crl.getAuthorityKeyIdentifier(),
                    "GostCrl.getAuthorityKeyIdentifier() должен быть не null");
            assertEquals(caSki.length, crl.getAuthorityKeyIdentifier().length,
                    "AKI байты должны быть той же длины, что и SKI");

            // L3: -verify
            String[] cmdVerify = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-verify",
                            "-CAfile", caPath.toString(), "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            int exitVerify = OpenSslChecker.run(cmdVerify);
            assertEquals(0, exitVerify, "openssl crl -verify с AKI должен дать verify OK");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 9: Делегированный CRL с AKI — openssl -text + verifyDelegated
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 9: Делегированный CRL с AKI — openssl -text + verifyDelegated")
    void testDelegatedCrlWithAkiTextAndVerify() throws Exception {
        TempDirUtils.withTempDir("crl-deleg-aki-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");
            byte[] issuerDn = ca.getSubjectDnBytes();

            byte[] caPubPoint = GostDerCodec.subjectPublicKeyPointBytes(caKp.getPublic());
            byte[] caSki = Digest.digest256(caPubPoint);

            // Делегированный CRL-подписант
            KeyPair signerKp = genKey(PARAMS_256);
            byte[] signerPubPoint = GostDerCodec.subjectPublicKeyPointBytes(signerKp.getPublic());
            byte[] signerSki = Digest.digest256(signerPubPoint);

            GostCertificate signer =
                    GostCertificateBuilder.create(PARAMS_256, "CN=CRL Signer,O=Test")
                            .publicKey(signerKp.getPublic())
                            .issuerDn(issuerDn)
                            .notBefore("20250101000000Z")
                            .notAfter("20351231235959Z")
                            .keyUsage(KeyUsage.CRL_SIGN)
                            .assembleCert(caKp.getPrivate());

            byte[] crlDer = GostCrlBuilder.create(signerKp.getPrivate(), issuerDn)
                    .thisUpdate("20260706120000Z")
                    .nextUpdate("20270706120000Z")
                    .withCrlNumber(1)
                    .withAki(signerSki)
                    .build();
            Path crlPath = dir.resolve("crl.der");
            Files.write(crlPath, crlDer);

            // L1: openssl -text — AKI виден, issuer = CA
            String[] cmdText = CrossValUtils.concat(
                    new String[]{opensslBinary(), "crl", "-inform", "DER",
                            "-in", crlPath.toString(), "-text", "-noout"},
                    OpenSslChecker.resolveEngineFlag());
            String textOut = OpenSslChecker.runAndCapture(cmdText);
            assertTrue(
                    textOut.contains("X509v3 Authority Key Identifier"),
                    "openssl crl -text должен показывать AKI для делегированного CRL");

            // L2: verifyDelegated — библиотека должна верифицировать
            assertDoesNotThrow(
                    () -> CrlVerifier.verifyDelegated(
                            crlDer,
                            ca.getSerialNumber(),
                            caKp.getPublic(),
                            issuerDn,
                            ca,
                            java.util.List.of(signer.getEncoded())),
                    "Делегированный CRL с AKI должен верифицироваться");

            return null;
        });
    }
}
