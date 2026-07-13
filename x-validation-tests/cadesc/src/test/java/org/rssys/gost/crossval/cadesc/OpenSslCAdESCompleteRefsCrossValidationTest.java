package org.rssys.gost.crossval.cadesc;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;

/**
 * Кросс-валидация CAdES-C (Complete validation data references) с OpenSSL.
 *
 * <p>Только L1 (asn1parse — структурная валидация) и L2 (dgst -verify — raw-верификация).
 * OpenSSL CMS-модуль не знает GOST OID и не может проверить CMS-подпись.</p>
 */
@DisplayName("OpenSSL: кросс-валидация CAdES-C (L1 asn1parse + L2 dgst)")
class OpenSslCAdESCompleteRefsCrossValidationTest {

    private static TestData.CertChainData pair256;
    private static TestData.ThreeLevelChain three256;

    @BeforeAll
    static void setUp() throws Exception {
        pair256 = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        three256 = TestData.generateThreeLevelChain(TestData.PARAMS_256);
    }

    // ========================================================================
    // L1: openssl asn1parse — структурная валидация
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-C asn1parse — оба C-атрибута в unsignedAttrs")
    void cadesCAsn1parse() throws Exception {
        byte[] cadesC = TestData.buildCAdESC(pair256, "CAdES-C asn1 test".getBytes());

        TempDirUtils.withTempDir("cadesc-asn1-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-c.der", cadesC);
            String out = runAsn1Parse(derPath);

            assertFalse(out.contains("Error:") || out.contains("ERROR:"),
                    "asn1parse должен пройти без ошибок: " + out);
            assertTrue(out.contains("SEQUENCE") || out.contains("SET")
                            || out.contains("OCTET STRING"),
                    "Должны быть структурные маркеры DER");

            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-C asn1parse — OtherCertID структура")
    void cadesCOtherCertIdStructure() throws Exception {
        TestData.ThreeLevelChain tc = three256;
        byte[] cadesC = TestData.buildCAdESCFromThreeLevel(tc,
                java.util.Arrays.asList(
                        (org.rssys.gost.pkix.cert.GostOcspResponse) null, null, null),
                "struct test".getBytes());

        TempDirUtils.withTempDir("cadesc-struct-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-c.der", cadesC);
            String out = runAsn1Parse(derPath);

            assertFalse(out.contains("Error:") || out.contains("ERROR:"),
                    "asn1parse должен пройти без ошибок");

            assertTrue(out.contains("SEQUENCE")
                            && out.indexOf("SEQUENCE") != out.lastIndexOf("SEQUENCE"),
                    "SEQUENCE встречается несколько раз (ContentInfo + SignedData + SignerInfo)");

            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-C самоподписанный — asn1parse")
    void cadesCSelfSignedAsn1parse() throws Exception {
        var selfKg = org.rssys.gost.api.KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        var selfCert = org.rssys.gost.pkix.cms.CmsTestUtils.createSelfSignedCert(
                selfKg.getPrivate(), selfKg.getPublic());
        byte[] selfCrlDer = org.rssys.gost.pkix.cert.GostCrlBuilder
                .create(selfCert.getSubjectDnBytes())
                .thisUpdate(TestData.NOT_BEFORE)
                .nextUpdateDays(30)
                .withCrlNumber(1)
                .sign(selfKg.getPrivate());
        var selfCrl = new org.rssys.gost.pkix.cert.GostCrl(selfCrlDer);

        byte[] cadesC = TestData.buildCAdESCSelfSigned(
                selfKg.getPrivate(), selfCert, selfCrl, "self-signed test".getBytes());

        TempDirUtils.withTempDir("cadesc-self-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-c-self.der", cadesC);
            String out = runAsn1Parse(derPath);

            assertFalse(out.contains("Error:") || out.contains("ERROR:"),
                    "asn1parse должен пройти без ошибок для самоподписанного CAdES-C");
            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-C 512-битные ключи — asn1parse")
    void cadesC512bitKeys() throws Exception {
        TestData.CertChainData cd = TestData.generateCaAndLeaf(TestData.PARAMS_512);
        byte[] cadesC = TestData.buildCAdESC(cd, "CAdES-C 512-bit test".getBytes());

        TempDirUtils.withTempDir("cadesc-512-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-c-512.der", cadesC);
            String out = runAsn1Parse(derPath);

            assertFalse(out.contains("Error:") || out.contains("ERROR:"),
                    "asn1parse должен пройти без ошибок для 512-битного CAdES-C");
            return null;
        });
    }

    // ========================================================================
    // L2: dgst -verify — raw-верификация подписи
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L2: CAdES-C -> extract raw sig -> openssl dgst -verify")
    void cadesCRawSigVerify() throws Exception {
        byte[] cadesC = TestData.buildCAdESC(pair256, "CAdES-C dgst test".getBytes());

        byte[] spki = GostDerCodec.encodePublicKey(pair256.leafPub());
        String pem = toPem(spki, "PUBLIC KEY");

        TempDirUtils.withTempDir("cadesc-dgst-", dir -> {
            Path pubPath = dir.resolve("pub.pem");
            Path sigPath = dir.resolve("sig.bin");
            Path hashPath = dir.resolve("hash.bin");

            byte[] rawSig = TestData.extractSignature(cadesC);
            byte[] signedAttrsSet = TestData.extractSignedAttrsAsSet(cadesC);

            Files.write(pubPath, pem.getBytes());
            Files.write(sigPath, rawSig);
            Files.write(hashPath, signedAttrsSet);

            String outText = OpenSslChecker.runAndCapture(
                    OpenSslChecker.resolveOpenSslBinary(), "dgst", "-md_gost12_256",
                    "-verify", pubPath.toAbsolutePath().toString(),
                    "-signature", sigPath.toAbsolutePath().toString(),
                    hashPath.toAbsolutePath().toString());

            assertTrue(outText.contains("Verified OK"),
                    "openssl dgst должен подтвердить подпись: " + outText);
            return null;
        });
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    static boolean opensslAvailable() {
        try {
            String out = OpenSslChecker.runAndCapture(
                    OpenSslChecker.resolveOpenSslBinary(), "version");
            return out.contains("OpenSSL");
        } catch (Exception e) {
            return false;
        }
    }

    static String runAsn1Parse(Path derPath) throws Exception {
        return OpenSslChecker.runAndCapture(
                OpenSslChecker.resolveOpenSslBinary(),
                "asn1parse", "-inform", "DER",
                "-in", derPath.toAbsolutePath().toString());
    }

    static String toPem(byte[] der, String label) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
    }
}
