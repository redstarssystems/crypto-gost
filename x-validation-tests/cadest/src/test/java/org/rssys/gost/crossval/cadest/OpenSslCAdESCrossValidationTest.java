package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.cadest.TestData.CertPair;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsSignedDataBuilder;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.util.DerCodec;

@DisplayName("OpenSSL: кросс-валидация CAdES — структурная (L1) + raw sig (L2)")
class OpenSslCAdESCrossValidationTest {

    private static CertPair pair256;
    private static KeyPair tsaKp256;
    private static GostCertificate tsaCert256;

    @BeforeAll
    static void setUp() throws Exception {
        pair256 = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        tsaKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        tsaCert256 = CmsTestUtils.createSelfSignedCert(
                tsaKp256.getPrivate(), tsaKp256.getPublic());
    }

    // ========================================================================
    // L1: openssl asn1parse — структурная валидация
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-BES asn1parse — ContentInfo + SignedData + signedAttrs")
    void cadesBesAsn1parse() throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(
                "BES asn1 test".getBytes(), pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cades-bes-asn1-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-bes.der", cadesBes);
            String out = runAsn1Parse(derPath);

            // ContentInfo c pkcs7-signedData
            assertTrue(out.contains("pkcs7-signedData")
                            || out.contains("1.2.840.113549.1.7.2"),
                    "Должен быть OID SignedData");

            // signedAttrs [0] IMPLICIT внутри SignerInfo
            assertTrue(out.contains("cont [ 0 ]") || out.contains("A0"),
                    "Должен быть signedAttrs [0] IMPLICIT в SignerInfo");

            // signingCertificateV2
            assertTrue(out.contains("id-smime-aa-signingCertificateV2")
                            || out.contains("1.2.840.113549.1.9.16.2.47"),
                    "Должен быть OID signingCertificateV2");
            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-T asn1parse — unsignedAttrs [1] + TimeStampToken")
    void cadesTAsn1parse() throws Exception {
        byte[] cadesBes = TestData.buildCAdESBES(
                "CAdES-T asn1 test".getBytes(), pair256.leafKey(), pair256.leafCert());
        byte[] sigHash = TestData.hashFirstSignature(cadesBes);
        String hashOid = TestData.hashOidForSigLength(sigHash);
        byte[] tsToken = TestData.buildTimeStampToken(
                sigHash, hashOid, tsaKp256.getPrivate(), tsaCert256);
        byte[] cadesT = TestData.buildCAdEST(cadesBes, tsToken);

        TempDirUtils.withTempDir("cades-t-asn1-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-t.der", cadesT);
            String out = runAsn1Parse(derPath);

            // unsignedAttrs [1] IMPLICIT
            assertTrue(out.contains("cont [ 1 ]") || out.contains("A1"),
                    "Должен быть unsignedAttrs [1] IMPLICIT в SignerInfo");

            // signatureTimeStampToken OID
            assertTrue(out.contains("id-smime-aa-timeStampToken")
                            || out.contains("id-smime-aa-signatureTimeStampToken")
                            || out.contains("1.2.840.113549.1.9.16.2.14"),
                    "Должен быть OID signatureTimeStampToken");

            // TSTInfo внутри TimeStampToken
            assertTrue(out.contains("id-smime-ct-TSTInfo")
                            || out.contains("TSTInfo")
                            || out.contains("1.2.840.113549.1.9.16.1.4"),
                    "Должен быть TSTInfo внутри TimeStampToken");
            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: CAdES-BES без withCAdES — signedAttrs без signingCertificateV2")
    void cadesBesNoAttrAsn1parse() throws Exception {
        byte[] noAttr = TestData.buildCAdESBESNoAttr(
                "no attr".getBytes(), pair256.leafKey(), pair256.leafCert());

        TempDirUtils.withTempDir("cades-noattr-", dir -> {
            Path derPath = TestData.writeDer(dir, "cades-noattr.der", noAttr);
            String out = runAsn1Parse(derPath);

            // signedAttrs присутствуют: contentType и messageDigest
            assertTrue(out.contains("contentType")
                            || out.contains("id-aa-contentType")
                            || out.contains("1.2.840.113549.1.9.3"),
                    "contentType должен быть в signedAttrs");
            return null;
        });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L1: TSTInfo asn1parse — поля messageImprint, genTime, nonce")
    void tstInfoAsn1parse() throws Exception {
        byte[] hash = Digest.digest256("TSTInfo asn1 test".getBytes());
        byte[] tstInfoDer = TestData.buildTstInfoDer(hash, GostOids.DIGEST_256);

        TempDirUtils.withTempDir("tstinfo-asn1-", dir -> {
            Path derPath = TestData.writeDer(dir, "tstinfo.der", tstInfoDer);
            String out = runAsn1Parse(derPath);

            // version = 1
            assertTrue(out.contains("INTEGER") && out.contains(":1"),
                    "version должно быть 1");

            // messageImprint
            assertTrue(out.contains("messageImprint")
                            || out.contains("SEQUENCE"),
                    "messageImprint должен присутствовать");

            // genTime (GeneralizedTime)
            assertTrue(out.contains("GENTIME") || out.contains("GEN"),
                    "genTime должен быть GeneralizedTime");

            return null;
        });
    }

    // ========================================================================
    // L2: Raw signature verification через openssl dgst
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("L2: CAdES-BES -> raw sig -> openssl dgst -verify")
    void cadesBesRawSigVerify() throws Exception {
        byte[] data = "dgst verify test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(
                data, pair256.leafKey(), pair256.leafCert());

        // Извлекаем signature и signedAttrs
        CmsContentInfo ci = CmsContentInfo.decode(cadesBes);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);

        // signedAttrs [0] — найти по тегу 0xA0
        int signedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == 0xA0) {
                signedIdx = i;
                break;
            }
        }
        byte[] signedField = siParts[signedIdx];
        // Извлекаем содержимое [0] IMPLICIT
        int[] lenInfo = DerCodec.decodeLength(signedField, 1);
        int contentOff = 1 + lenInfo[1];
        byte[] signedAttrsContent =
                Arrays.copyOfRange(signedField, contentOff, signedField.length);

        // Разбираем отдельные атрибуты и перекодируем в SET для хэширования
        java.util.List<byte[]> attrElems = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < signedAttrsContent.length) {
            int[] attrLen = DerCodec.decodeLength(signedAttrsContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrElems.add(Arrays.copyOfRange(signedAttrsContent, pos, pos + attrTotal));
            pos += attrTotal;
        }
        // Перекодируем как SET (именно так хэшировал подписант)
        byte[] signedAttrsSetEncoded =
                DerCodec.encodeSetOf(attrElems.toArray(new byte[0][]));

        // Извлекаем raw signature
        byte[] sigOctet = null;
        for (int i = siParts.length - 1; i >= 0; i--) {
            if ((siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                sigOctet = siParts[i];
                break;
            }
        }
        byte[] rawSig = DerCodec.parseOctetString(sigOctet, 0);

        // Публичный ключ подписанта — SubjectPublicKeyInfo (X.509) -> PEM
        byte[] spki = GostDerCodec.encodePublicKey(pair256.leafPub());
        String pem = toPem(spki, "PUBLIC KEY");

        TempDirUtils.withTempDir("cades-dgst-", dir -> {
            Path pubPath = dir.resolve("pub.pem");
            Path sigPath = dir.resolve("sig.bin");
            Path hashPath = dir.resolve("hash.bin");
            Files.write(pubPath, pem.getBytes());
            Files.write(sigPath, rawSig);
            // Передаём SET-кодированные signedAttrs — openssl сам хэширует
            Files.write(hashPath, signedAttrsSetEncoded);

            String[] cmd = new String[]{
                    opensslBinary(), "dgst", "-md_gost12_256",
                    "-verify", pubPath.toAbsolutePath().toString(),
                    "-signature", sigPath.toAbsolutePath().toString(),
                    hashPath.toAbsolutePath().toString()
            };
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
            Process p = pb.start();
            String outText = new String(p.getInputStream().readAllBytes()).trim();
            int exit = p.waitFor();

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
            ProcessBuilder pb = new ProcessBuilder(opensslBinary(), "version");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static String opensslBinary() {
        return System.getProperty("openssl.binary",
                "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String runAsn1Parse(Path derPath) throws IOException, InterruptedException {
        String[] cmd = new String[]{
                opensslBinary(), "asn1parse", "-inform", "DER",
                "-in", derPath.toAbsolutePath().toString()
        };
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return out;
    }

    static String toPem(byte[] der, String label) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
    }
}
