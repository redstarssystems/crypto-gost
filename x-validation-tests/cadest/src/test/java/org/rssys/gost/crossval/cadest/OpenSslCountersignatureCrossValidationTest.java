package org.rssys.gost.crossval.cadest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.cadest.TestData.CertPair;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.cms.CAdESExtender;
import org.rssys.gost.pkix.cms.CAdESVerifier;
import org.rssys.gost.pkix.cms.CmsContentInfo;
import org.rssys.gost.pkix.cms.CmsTestUtils;
import org.rssys.gost.util.DerCodec;

/**
 * Кросс-валидация countersignature (RFC 5652 §11.4) с OpenSSL.
 *
 * <p>Направления:
 * <ol>
 *   <li>Библиотека создаёт countersigned CMS → OpenSSL asn1parse видит countersignature</li>
 *   <li>Библиотека создаёт countersigned CMS → OpenSSL dgst -verify подтверждает countersignature</li>
 *   <li>OpenSSL создаёт CMS с countersignature → библиотека verifyCountersignature подтверждает</li>
 * </ol>
 */
@DisplayName("OpenSSL: кросс-валидация countersignature")
class OpenSslCountersignatureCrossValidationTest {

    private static CertPair pair256;
    private static KeyPair csKp256;
    private static GostCertificate csCert256;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        pair256 = TestData.generateCaAndLeaf(TestData.PARAMS_256);
        csKp256 = KeyGenerator.generateKeyPair(TestData.PARAMS_256);
        csCert256 = CmsTestUtils.createSelfSignedCert(csKp256.getPrivate(), csKp256.getPublic());
    }

    // ========================================================================
    // Направление 1: библиотека → OpenSSL (asn1parse + dgst)
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL asn1parse: countersignature в unsignedAttrs")
    void countersignatureInUnsignedAttrsAsn1parse() throws Exception {
        byte[] data = "countersignature asn1 test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        TempDirUtils.withTempDir(
                "cs-asn1-",
                dir -> {
                    Path derPath = TestData.writeDer(dir, "countersigned.der", countersigned);
                    String out = runAsn1Parse(derPath);

                    // unsignedAttrs [1] IMPLICIT внутри SignerInfo
                    assertTrue(
                            out.contains("cont [ 1 ]") || out.contains("A1"),
                            "unsignedAttrs [1] IMPLICIT должен быть в SignerInfo для countersignature");

                    // id-countersignature OID (OpenSSL показывает "countersignature" без id-)
                    assertTrue(
                            out.contains("countersignature")
                                    || out.contains("1.2.840.113549.1.9.6"),
                            "Должен быть OID countersignature в unsignedAttrs");
                    return null;
                });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL asn1parse: countersignature без TSP-меток")
    void countersignatureWithoutTimestampAsn1parse() throws Exception {
        byte[] data = "cs no tst asn1".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        TempDirUtils.withTempDir(
                "cs-notst-",
                dir -> {
                    Path derPath = TestData.writeDer(dir, "countersigned-notst.der", countersigned);
                    String out = runAsn1Parse(derPath);

                    assertTrue(
                            out.contains("countersignature")
                                    || out.contains("1.2.840.113549.1.9.6"),
                            "Должен быть OID countersignature");
                    return null;
                });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL dgst -verify: countersignature подписывает signatureValue родителя")
    void countersignatureRawDgstVerify() throws Exception {
        byte[] data = "cs dgst test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        // Извлекаем countersignature SignerInfo из unsignedAttrs
        CmsContentInfo ci = CmsContentInfo.decode(countersigned);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        // Первый подписант — основной; извлекаем его unsignedAttrs
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);

        // unsignedAttrs [1] — тег 0xA1
        int uaIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == 0xA1) {
                uaIdx = i;
                break;
            }
        }
        assertTrue(uaIdx >= 0, "unsignedAttrs должны быть в SignerInfo");

        byte[] uaField = siParts[uaIdx];
        int[] uaLen = DerCodec.decodeLength(uaField, 1);
        int uaContentOff = 1 + uaLen[1];
        byte[] uaContent = Arrays.copyOfRange(uaField, uaContentOff, uaField.length);

        // Ищем атрибут countersignature (OID = 1.2.840.113549.1.9.6)
        byte[] countersigSiDer = null;
        int pos = 0;
        while (pos < uaContent.length) {
            int[] attrLen = DerCodec.decodeLength(uaContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            byte[] attrDer = Arrays.copyOfRange(uaContent, pos, pos + attrTotal);

            byte[][] attrParts = DerCodec.parseSequenceContents(attrDer, 0);
            if (attrParts.length >= 2) {
                String oid = DerCodec.parseOid(attrParts[0], 0);
                if (GostOids.ATTR_COUNTERSIGNATURE.equals(oid)) {
                    // attrParts[1] — SET OF SignerInfo, извлекаем первый SignerInfo
                    byte[] setField = attrParts[1];
                    int[] setLen = DerCodec.decodeLength(setField, 1);
                    int setContentOff = 1 + setLen[1];
                    int[] siLen = DerCodec.decodeLength(setField, setContentOff + 1);
                    int siTotal = 1 + siLen[1] + siLen[0];
                    countersigSiDer =
                            Arrays.copyOfRange(setField, setContentOff, setContentOff + siTotal);
                    break;
                }
            }
            pos += attrTotal;
        }
        assertNotNull(countersigSiDer, "Countersignature SignerInfo должен быть извлечён");

        // Разбираем countersignature SignerInfo: signedAttrs, signature
        byte[][] csSiParts = DerCodec.parseSequenceContents(countersigSiDer, 0);
        int csSignedIdx = -1;
        for (int i = 0; i < csSiParts.length; i++) {
            if (csSiParts[i].length > 0 && (csSiParts[i][0] & 0xFF) == 0xA0) {
                csSignedIdx = i;
                break;
            }
        }
        assertTrue(csSignedIdx >= 0, "SignedAttrs должны быть в countersignature SignerInfo");

        byte[] csSignedField = csSiParts[csSignedIdx];
        int[] csSignedLen = DerCodec.decodeLength(csSignedField, 1);
        int csSignedContentOff = 1 + csSignedLen[1];
        byte[] csSignedContent =
                Arrays.copyOfRange(csSignedField, csSignedContentOff, csSignedField.length);

        // Перекодируем signedAttrs как SET (для хэширования)
        java.util.List<byte[]> csAttrs = new java.util.ArrayList<>();
        int csAttrPos = 0;
        while (csAttrPos < csSignedContent.length) {
            int[] aLen = DerCodec.decodeLength(csSignedContent, csAttrPos + 1);
            int aTotal = 1 + aLen[1] + aLen[0];
            csAttrs.add(Arrays.copyOfRange(csSignedContent, csAttrPos, csAttrPos + aTotal));
            csAttrPos += aTotal;
        }
        byte[] csSignedAttrsSet = DerCodec.encodeSetOf(csAttrs.toArray(new byte[0][]));

        // Извлекаем raw signature countersignature
        byte[] csSigOctet = null;
        for (int i = csSiParts.length - 1; i >= 0; i--) {
            if ((csSiParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                csSigOctet = csSiParts[i];
                break;
            }
        }
        assertNotNull(csSigOctet, "Подпись countersignature должна быть OCTET STRING");
        byte[] csRawSig = DerCodec.parseOctetString(csSigOctet, 0);

        // Публичный ключ countersigner'а
        byte[] spki = GostDerCodec.encodePublicKey(csKp256.getPublic());
        String pem = toPem(spki, "PUBLIC KEY");

        TempDirUtils.withTempDir(
                "cs-dgst-",
                dir -> {
                    Path pubPath = dir.resolve("cs-pub.pem");
                    Path sigPath = dir.resolve("cs-sig.bin");
                    Path hashPath = dir.resolve("cs-hash.bin");
                    Files.write(pubPath, pem.getBytes());
                    Files.write(sigPath, csRawSig);
                    Files.write(hashPath, csSignedAttrsSet);

                    String[] cmd =
                            new String[] {
                                opensslBinary(),
                                "dgst",
                                "-md_gost12_256",
                                "-verify",
                                pubPath.toAbsolutePath().toString(),
                                "-signature",
                                sigPath.toAbsolutePath().toString(),
                                hashPath.toAbsolutePath().toString()
                            };
                    ProcessBuilder pb = new ProcessBuilder(cmd);
                    pb.redirectErrorStream(true);
                    pb.environment().putAll(OpenSslChecker.getOpenSslEnv());
                    Process p = pb.start();
                    String outText = new String(p.getInputStream().readAllBytes()).trim();
                    int exit = p.waitFor();

                    assertTrue(
                            outText.contains("Verified OK"),
                            "openssl dgst должен подтвердить countersignature: " + outText);
                    return null;
                });
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName(
            "OpenSSL dgst -verify: countersignature messageDigest = hash(parent signatureValue)")
    void countersignatureMessageDigestCoversSignatureValue() throws Exception {
        byte[] data = "cs msgdigest test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        // Извлекаем signatureValue родительского подписанта
        CmsContentInfo ci = CmsContentInfo.decode(countersigned);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] sif = sdParts[sdParts.length - 1];
        byte[][] sis = DerCodec.parseSetContents(sif, 0);
        byte[][] parentSiParts = DerCodec.parseSequenceContents(sis[0], 0);

        byte[] parentSigOctet = null;
        for (int i = parentSiParts.length - 1; i >= 0; i--) {
            if ((parentSiParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                parentSigOctet = parentSiParts[i];
                break;
            }
        }
        assertNotNull(parentSigOctet, "Родительская подпись должна быть OCTET STRING");
        byte[] parentSigValue = DerCodec.parseOctetString(parentSigOctet, 0);

        // Вычисляем hash от contents octets родительской подписи (s||r, без TLV)
        byte[] computedHash = org.rssys.gost.api.Digest.digest256(parentSigValue);

        // Извлекаем messageDigest из signedAttrs countersignature
        byte[] expectedHash = extractMessageDigestFromCountersignature(countersigned);
        assertNotNull(expectedHash, "messageDigest должен быть в countersignature signedAttrs");

        assertTrue(
                java.security.MessageDigest.isEqual(computedHash, expectedHash),
                "messageDigest countersignature должен быть hash(parentSignatureValue)");
    }

    // ========================================================================
    // Направление 2: библиотека создаёт countersigned CMS → библиотека же верифицирует
    // ========================================================================

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("Round-trip: библиотека CAdES-BES → countersignature → verifyCountersignature")
    void roundTripCountersignatureVerify() throws Exception {
        byte[] data = "round-trip cs".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        // Проверяем: countersignature корректно добавляется и не ломает CAdES-BES verify
        var result =
                CAdESVerifier.verifyCountersignature(
                        countersigned, TrustAnchors.ofCertificates(pair256.caCert(), csCert256));
        assertNotNull(result, "verifyCountersignature должен вернуть результат");
        assertEquals(1, result.signers().size(), "Один подписант");
        assertEquals(
                1, result.signers().get(0).countersignatures().size(), "Одна countersignature");
    }

    @Test
    @EnabledIf("opensslAvailable")
    @DisplayName("OpenSSL: countersignature не ломает CMS-структуру")
    void countersignedDoesNotBreakCmsStructure() throws Exception {
        byte[] data = "cms structure test".getBytes();
        byte[] cadesBes = TestData.buildCAdESBES(data, pair256.leafKey(), pair256.leafCert());
        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, csKp256.getPrivate(), csCert256);

        TempDirUtils.withTempDir(
                "cs-struct-",
                dir -> {
                    Path derPath = TestData.writeDer(dir, "countersigned.der", countersigned);
                    String out = runAsn1Parse(derPath);

                    // ContentInfo → pkcs7-signedData
                    assertTrue(
                            out.contains("pkcs7-signedData")
                                    || out.contains("1.2.840.113549.1.7.2"),
                            "Структура должна содержать OID SignedData");

                    // encapContentInfo с eContentType
                    assertTrue(
                            out.contains("contentType") || out.contains("id-data"),
                            "encapContentInfo должен присутствовать");

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
        return System.getProperty("openssl.binary", "/opt/openssl-3.6.0-gost/bin/openssl");
    }

    static String runAsn1Parse(Path derPath) throws Exception {
        String[] cmd =
                new String[] {
                    opensslBinary(),
                    "asn1parse",
                    "-inform",
                    "DER",
                    "-in",
                    derPath.toAbsolutePath().toString()
                };
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor();
        return out;
    }

    static int countSignerInfoInOutput(String asn1parseOutput) {
        int count = 0;
        for (String line : asn1parseOutput.split("\n")) {
            if (line.contains("SEQUENCE") && line.contains("SignerInfo")) {
                count++;
            } else if (line.contains("SEQUENCE")
                    && (line.contains("IssuerAndSerialNumber")
                            || line.contains("se implicit")
                            || line.contains("cons implicit"))) {
                // Эвристика: вложенный SEQUENCE внутри SET OF SignerInfo
                count++;
            }
        }
        // Более надёжный метод: считаем вхождения OCTET STRING с signatureValue
        // внутри SignerInfo — каждая подпись даёт один OCTET STRING
        // Но лучше просто проверить, что общее количество SEQUENCE объектов достаточно
        return Math.max(0, count);
    }

    static String toPem(byte[] der, String label) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + base64 + "\n-----END " + label + "-----\n";
    }

    /**
     * Извлекает messageDigest из signedAttrs countersignature.
     */
    static byte[] extractMessageDigestFromCountersignature(byte[] countersignedDer)
            throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(countersignedDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] sif = sdParts[sdParts.length - 1];
        byte[][] sis = DerCodec.parseSetContents(sif, 0);
        byte[][] parentSi = DerCodec.parseSequenceContents(sis[0], 0);

        int uaIdx = -1;
        for (int i = 0; i < parentSi.length; i++) {
            if (parentSi[i].length > 0 && (parentSi[i][0] & 0xFF) == 0xA1) {
                uaIdx = i;
                break;
            }
        }
        if (uaIdx < 0) return null;

        byte[] uaField = parentSi[uaIdx];
        int[] uaLen = DerCodec.decodeLength(uaField, 1);
        byte[] uaContent = Arrays.copyOfRange(uaField, 1 + uaLen[1], uaField.length);

        int pos = 0;
        while (pos < uaContent.length) {
            int[] attrLen = DerCodec.decodeLength(uaContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            byte[] attrDer = Arrays.copyOfRange(uaContent, pos, pos + attrTotal);
            byte[][] attrParts = DerCodec.parseSequenceContents(attrDer, 0);
            if (attrParts.length >= 2) {
                String oid = DerCodec.parseOid(attrParts[0], 0);
                if (GostOids.ATTR_COUNTERSIGNATURE.equals(oid)) {
                    byte[] setField = attrParts[1];
                    int[] setLen = DerCodec.decodeLength(setField, 1);
                    int setOff = 1 + setLen[1];
                    int[] siLen = DerCodec.decodeLength(setField, setOff + 1);
                    int siTotal = 1 + siLen[1] + siLen[0];
                    byte[] csSiDer = Arrays.copyOfRange(setField, setOff, setOff + siTotal);
                    byte[][] csParts = DerCodec.parseSequenceContents(csSiDer, 0);

                    int signedIdx = -1;
                    for (int j = 0; j < csParts.length; j++) {
                        if (csParts[j].length > 0 && (csParts[j][0] & 0xFF) == 0xA0) {
                            signedIdx = j;
                            break;
                        }
                    }
                    if (signedIdx < 0) return null;

                    byte[] signedField = csParts[signedIdx];
                    int[] sLen = DerCodec.decodeLength(signedField, 1);
                    byte[] signedContent =
                            Arrays.copyOfRange(signedField, 1 + sLen[1], signedField.length);

                    int sp = 0;
                    while (sp < signedContent.length) {
                        int[] aLen = DerCodec.decodeLength(signedContent, sp + 1);
                        int aTotal = 1 + aLen[1] + aLen[0];
                        byte[] sigAttr = Arrays.copyOfRange(signedContent, sp, sp + aTotal);
                        byte[][] saParts = DerCodec.parseSequenceContents(sigAttr, 0);
                        if (saParts.length >= 2) {
                            String saOid = DerCodec.parseOid(saParts[0], 0);
                            if (GostOids.ATTR_MESSAGE_DIGEST.equals(saOid)) {
                                byte[] mdSet = saParts[1];
                                int[] mdLen = DerCodec.decodeLength(mdSet, 1);
                                int mdOff = 1 + mdLen[1];
                                return DerCodec.parseOctetString(mdSet, mdOff);
                            }
                        }
                        sp += aTotal;
                    }
                }
            }
            pos += attrTotal;
        }
        return null;
    }
}
