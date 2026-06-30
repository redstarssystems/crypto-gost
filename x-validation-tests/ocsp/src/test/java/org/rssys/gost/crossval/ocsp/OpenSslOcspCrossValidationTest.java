package org.rssys.gost.crossval.ocsp;

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
import org.rssys.gost.pkix.cert.*;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;

/**
 * Кросс-валидация OCSP-ответов (RFC 6960) между библиотекой и openssl ocsp.
 */
@DisplayName("Кросс-валидация OCSP: библиотека <-> openssl")
class OpenSslOcspCrossValidationTest {

    private static final ECParameters PARAMS_256 = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();

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
    // Хелперы
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
                .keyUsage(KeyUsage.KEY_CERT_SIGN)
                .assembleCert(caKp.getPrivate());
    }

    private static GostCertificate buildLeaf(
            ECParameters params, KeyPair leafKp, KeyPair caKp,
            GostCertificate ca, String dn) {
        return GostCertificateBuilder.create(params, dn)
                .publicKey(leafKp.getPublic())
                .issuerDn(ca.getSubjectDnBytes())
                .notBefore("20250101000000Z")
                .notAfter("20261231235959Z")
                .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                .assembleCert(caKp.getPrivate());
    }

    // ========================================================================
    // Сценарий 1: OCSP good — openssl ocsp -respin -noverify -text
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 1: OCSP good — openssl ocsp -noverify -text")
    void testOcspGoodNoVerifyText() throws Exception {
        TempDirUtils.withTempDir("ocsp-good-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(PARAMS_256);
            GostCertificate leaf = buildLeaf(PARAMS_256, leafKp, caKp, ca, "CN=leaf,O=Test");

            byte[] ocspDer = GostOcspResponseBuilder.create(leaf.getSerialNumber())
                    .signer(caKp.getPrivate(), caKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .caPublicKey(caKp.getPublic())
                    .producedAt("20260601000000Z")
                    .thisUpdate("20260601000000Z")
                    .nextUpdate("20260608000000Z")
                    .good()
                    .build();
            Path ocspPath = dir.resolve("ocsp.der");
            Files.write(ocspPath, ocspDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "ocsp", "-respin",
                            ocspPath.toString(), "-noverify", "-text"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp good -noverify -text должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 2: OCSP revoked — openssl ocsp -noverify -text
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 2: OCSP revoked — openssl ocsp -noverify -text")
    void testOcspRevokedNoVerifyText() throws Exception {
        TempDirUtils.withTempDir("ocsp-revoked-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(PARAMS_256);
            GostCertificate leaf = buildLeaf(PARAMS_256, leafKp, caKp, ca, "CN=leaf,O=Test");

            byte[] ocspDer = GostOcspResponseBuilder.create(leaf.getSerialNumber())
                    .signer(caKp.getPrivate(), caKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .caPublicKey(caKp.getPublic())
                    .producedAt("20260601000000Z")
                    .thisUpdate("20260601000000Z")
                    .nextUpdate("20260608000000Z")
                    .revoked("20260515120000Z", ReasonCode.KEY_COMPROMISE)
                    .build();
            Path ocspPath = dir.resolve("ocsp.der");
            Files.write(ocspPath, ocspDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "ocsp", "-respin",
                            ocspPath.toString(), "-noverify", "-text"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp revoked -noverify -text должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 3: OCSP unknown — openssl ocsp -noverify -text
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 3: OCSP unknown — openssl ocsp -noverify -text")
    void testOcspUnknownNoVerifyText() throws Exception {
        TempDirUtils.withTempDir("ocsp-unknown-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(PARAMS_256);
            GostCertificate leaf = buildLeaf(PARAMS_256, leafKp, caKp, ca, "CN=leaf,O=Test");

            byte[] ocspDer = GostOcspResponseBuilder.create(leaf.getSerialNumber())
                    .signer(caKp.getPrivate(), caKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .caPublicKey(caKp.getPublic())
                    .producedAt("20260601000000Z")
                    .thisUpdate("20260601000000Z")
                    .nextUpdate("20260608000000Z")
                    .unknown()
                    .build();
            Path ocspPath = dir.resolve("ocsp.der");
            Files.write(ocspPath, ocspDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "ocsp", "-respin",
                            ocspPath.toString(), "-noverify", "-text"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp unknown -noverify -text должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 4: OCSP — openssl ocsp -verify (L3)
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 4: OCSP good — openssl ocsp -verify")
    void testOcspGoodVerify() throws Exception {
        TempDirUtils.withTempDir("ocsp-verify-", dir -> {
            KeyPair caKp = genKey(PARAMS_256);
            GostCertificate ca = buildCa(PARAMS_256, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(PARAMS_256);
            GostCertificate leaf = buildLeaf(PARAMS_256, leafKp, caKp, ca, "CN=leaf,O=Test");

            byte[] ocspDer = GostOcspResponseBuilder.create(leaf.getSerialNumber())
                    .signer(caKp.getPrivate(), caKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .caPublicKey(caKp.getPublic())
                    .producedAt("20260601000000Z")
                    .thisUpdate("20260601000000Z")
                    .nextUpdate("20260608000000Z")
                    .good()
                    .build();
            Path ocspPath = dir.resolve("ocsp.der");
            Files.write(ocspPath, ocspDer);
            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());

            // openssl ocsp -respin <ocsp.der> -CAfile <ca.der> -verify_other ...
            // Неделегированный OCSP: CA подписывает свой собственный ответ.
            // -trust_other разрешает доверять сертификату подписанта без цепочки
            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "ocsp", "-respin",
                            ocspPath.toString(), "-trust_other",
                            "-verify_other", caPath.toString(),
                            "-CAfile", caPath.toString(),
                            "-no_nonce"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp -verify должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 5: OCSP 512-битная кривая
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 5: OCSP good для всех кривых — -noverify -text")
    void testOcspBothCurves(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("ocsp-curve-", dir -> {
            KeyPair caKp = genKey(params);
            GostCertificate ca = buildCa(params, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(params);
            GostCertificate leaf = buildLeaf(params, leafKp, caKp, ca, "CN=leaf,O=Test");

            byte[] ocspDer = GostOcspResponseBuilder.create(leaf.getSerialNumber())
                    .signer(caKp.getPrivate(), caKp.getPublic())
                    .issuerDn(ca.getSubjectDnBytes())
                    .caPublicKey(caKp.getPublic())
                    .producedAt("20260601000000Z")
                    .thisUpdate("20260601000000Z")
                    .nextUpdate("20260608000000Z")
                    .good()
                    .build();
            Path ocspPath = dir.resolve("ocsp.der");
            Files.write(ocspPath, ocspDer);

            String[] cmd = CrossValUtils.concat(
                    new String[]{opensslBinary(), "ocsp", "-respin",
                            ocspPath.toString(), "-noverify", "-text"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp -noverify -text должен пройти");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 6: библиотека строит запрос -> openssl ocsp -reqin -text
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 6: библиотека строит запрос -> openssl ocsp -reqin -text")
    void testOcspRequestToOpenSsl(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("ocsp-req-", dir -> {
            KeyPair caKp = genKey(params);
            GostCertificate ca = buildCa(params, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(params);
            GostCertificate leaf =
                    buildLeaf(params, leafKp, caKp, ca, "CN=leaf,O=Test");

            GostOcspRequestBuilder builder =
                    GostOcspRequestBuilder.create()
                            .targetCert(leaf.getEncoded())
                            .issuerCert(ca.getEncoded());
            if (params.hlen == 64) {
                builder.hashLen(64);
            }
            byte[] reqDer = builder.build();
            Path reqPath = dir.resolve("req.der");
            Files.write(reqPath, reqDer);

            String[] cmd = CrossValUtils.concat(
                    new String[] {opensslBinary(), "ocsp", "-reqin",
                            reqPath.toString(), "-text"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            assertEquals(0, exit, "openssl ocsp -reqin -text должен принять запрос");

            return null;
        });
    }

    // ========================================================================
    // Сценарий 7: openssl строит запрос -> библиотека парсит
    // ========================================================================

    @ParameterizedTest
    @MethodSource("curves")
    @EnabledIf("opensslAvailable")
    @DisplayName("Сценарий 7: openssl строит запрос -> библиотека парсит")
    void testOcspRequestFromOpenSsl(ECParameters params) throws Exception {
        TempDirUtils.withTempDir("ocsp-reqout-", dir -> {
            KeyPair caKp = genKey(params);
            GostCertificate ca = buildCa(params, caKp, "CN=Test CA,O=Test");
            KeyPair leafKp = genKey(params);
            GostCertificate leaf =
                    buildLeaf(params, leafKp, caKp, ca, "CN=leaf,O=Test");

            Path caPath = dir.resolve("ca.der");
            Files.write(caPath, ca.getEncoded());
            Path leafPath = dir.resolve("leaf.der");
            Files.write(leafPath, leaf.getEncoded());
            Path reqPath = dir.resolve("req.der");

            String[] cmd = CrossValUtils.concat(
                    new String[] {opensslBinary(), "ocsp", "-reqout",
                            reqPath.toString(),
                            "-issuer", caPath.toString(),
                            "-cert", leafPath.toString(),
                            "-no_nonce"},
                    OpenSslChecker.resolveEngineFlag());
            int exit = OpenSslChecker.run(cmd);
            if (exit != 0) {
                fail("openssl ocsp -reqout не удался с кодом " + exit);
            }

            byte[] reqDer = Files.readAllBytes(reqPath);
            GostOcspRequest parsed = GostOcspRequest.fromDer(reqDer);

            assertEquals(1, parsed.getCertIds().size(),
                    "Запрос должен содержать один CertID");
            CertId certId = parsed.getCertIds().get(0);

            assertArrayEquals(
                    leaf.getSerialNumber(),
                    certId.serialNumber(),
                    "Серийный номер должен совпадать с сертификатом");
            assertNotNull(certId.hashAlgOid(),
                    "hashAlgOid должен присутствовать");
            assertFalse(certId.hashAlgOid().isEmpty(),
                    "hashAlgOid не должен быть пустым");
            assertTrue(certId.issuerNameHash().length > 0,
                    "issuerNameHash должен быть непустым");
            assertTrue(certId.issuerKeyHash().length > 0,
                    "issuerKeyHash должен быть непустым");
            assertNull(parsed.getNonce(),
                    "Nonce должен отсутствовать (флаг -no_nonce)");
            assertFalse(parsed.isSigned(),
                    "Запрос от openssl не должен быть подписан");

            return null;
        });
    }

    static Stream<ECParameters> curves() {
        return Stream.of(PARAMS_256, PARAMS_512);
    }
}
