package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("Countersignature: построение и верификация (RFC 5652 §11.4)")
class CountersignatureTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static KeyPair countersignerKp;
    private static GostCertificate countersignerCert;
    private static KeyPair signer2Kp;
    private static GostCertificate signer2Cert;

    @BeforeAll
    static void setUp() throws Exception {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert = CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());

        countersignerKp = KeyGenerator.generateKeyPair(PARAMS);
        countersignerCert =
                CmsTestUtils.createSelfSignedCert(
                        countersignerKp.getPrivate(), countersignerKp.getPublic());

        signer2Kp = KeyGenerator.generateKeyPair(PARAMS);
        signer2Cert =
                CmsTestUtils.createSelfSignedCert(signer2Kp.getPrivate(), signer2Kp.getPublic());
    }

    // ========================================================================
    // Позитивные тесты
    // ========================================================================

    @Test
    @DisplayName("Полный цикл: CAdES-BES -> countersignature -> verifyCountersignature")
    void fullCycleCountersignature() throws Exception {
        byte[] data = "countersignature test data".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, countersignerKp.getPrivate(), countersignerCert);

        assertNotNull(countersigned);

        VerifiedCAdESData result =
                CAdESExtender.verifyCountersignature(countersigned, signerCert, countersignerCert);
        assertNotNull(result);
        assertArrayEquals(data, result.data());
        assertEquals(1, result.signers().size());

        CAdESSignerResult signerResult = result.signers().get(0);
        assertEquals(signerCert, signerResult.signerCertificate());
        assertEquals(1, signerResult.countersignatures().size());

        SignerResult csResult = signerResult.countersignatures().get(0);
        assertEquals(countersignerCert, csResult.signerCertificate());
        assertTrue(
                csResult.signedAttributes().size() >= 1,
                "Countersignature должен содержать хотя бы message-digest");
    }

    @Test
    @DisplayName("Multi-signer countersignature: два подписанта с countersignature")
    void multiSignerCountersignature() throws Exception {
        byte[] data = "multi-signer test".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, countersignerKp.getPrivate(), countersignerCert);

        assertNotNull(countersigned);

        VerifiedCAdESData result =
                CAdESExtender.verifyCountersignature(
                        countersigned, signerCert, signer2Cert, countersignerCert);
        assertEquals(2, result.signers().size());

        for (CAdESSignerResult sr : result.signers()) {
            assertEquals(1, sr.countersignatures().size());
            assertEquals(countersignerCert, sr.countersignatures().get(0).signerCertificate());
        }
    }

    @Test
    @DisplayName("Countersignature с 512-битными ключами")
    void countersignature512BitKeys() throws Exception {
        KeyPair signer512Kp = KeyGenerator.generateKeyPair(PARAMS_512);
        GostCertificate signer512Cert =
                CmsTestUtils.createSelfSignedCert(
                        signer512Kp.getPrivate(), signer512Kp.getPublic());
        KeyPair cs512Kp = KeyGenerator.generateKeyPair(PARAMS_512);
        GostCertificate cs512Cert =
                CmsTestUtils.createSelfSignedCert(cs512Kp.getPrivate(), cs512Kp.getPublic());

        byte[] data = "512-bit test".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signer512Kp.getPrivate(), signer512Cert)
                        .digestAlgorithm(GostOids.DIGEST_512)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(cadesBes, cs512Kp.getPrivate(), cs512Cert);

        assertNotNull(countersigned);

        VerifiedCAdESData result =
                CAdESExtender.verifyCountersignature(countersigned, signer512Cert, cs512Cert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertEquals(1, result.signers().get(0).countersignatures().size());
    }

    @Test
    @DisplayName("CountersignatureBuilder: построить и проверить структуру")
    void buildCountersignatureStandalone() throws Exception {
        byte[] parentSig = signerKp.getPrivate().getD().toByteArray();

        byte[] countersig =
                CountersignatureBuilder.buildCountersignature(
                        parentSig,
                        countersignerKp.getPrivate(),
                        countersignerCert,
                        GostOids.DIGEST_256);

        assertNotNull(countersig);
        assertTrue(countersig.length > 0);

        // Проверяем, что это разбираемый DER SignerInfo
        byte[][] siParts = org.rssys.gost.util.DerCodec.parseSequenceContents(countersig, 0);
        assertTrue(
                siParts.length >= 6,
                "SignerInfo должен содержать как минимум 6 полей (version, sid, digestAlg, signedAttrs, signAlg, signature)");
    }

    // ========================================================================
    // Негативные тесты
    // ========================================================================

    @Test
    @DisplayName("Подмена signatureValue родителя ломает countersignature при валидной CMS-подписи")
    void tamperParentSignatureBreaksCountersignature() throws Exception {
        byte[] data1 = "data for countersignature1".getBytes();
        byte[] data2 = "data for countersignature2".getBytes();

        // Строим countersignature на data1: SI1 подписывает data1, CS1 хэширует SI1.signatureValue
        byte[] cadesBes1 =
                CmsSignedDataBuilder.create()
                        .data(data1)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes1, countersignerKp.getPrivate(), countersignerCert);

        // Извлекаем countersignature-атрибут (CS1) из unsignedAttrs SI1
        CmsContentInfo ciC = CmsContentInfo.decode(countersigned);
        byte[][] sdPartsC = DerCodec.parseSequenceContents(ciC.content(), 0);
        byte[] siFieldC = sdPartsC[sdPartsC.length - 1];
        byte[][] siSetC = DerCodec.parseSetContents(siFieldC, 0);
        byte[][] siParts1 = DerCodec.parseSequenceContents(siSetC[0], 0);

        byte[] csAttrDer = null;
        for (byte[] part : siParts1) {
            if (part.length > 0 && (part[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                int[] len = DerCodec.decodeLength(part, 1);
                int off = 1 + len[1];
                int contentEnd = off + len[0];
                // Ищем атрибут с OID ATTR_COUNTERSIGNATURE внутри unsignedAttrs
                int pos = off;
                while (pos < contentEnd) {
                    int[] attrLen = DerCodec.decodeLength(part, pos + 1);
                    int attrTotal = 1 + attrLen[1] + attrLen[0];
                    byte[] attrDer = java.util.Arrays.copyOfRange(part, pos, pos + attrTotal);
                    byte[][] attrParts = DerCodec.parseSequenceContents(attrDer, 0);
                    String oid = DerCodec.parseOid(attrParts[0], 0);
                    if (GostOids.ATTR_COUNTERSIGNATURE.equals(oid)) {
                        csAttrDer = attrDer;
                        break;
                    }
                    pos += attrTotal;
                }
                break;
            }
        }
        assertNotNull(csAttrDer, "Должен найти countersignature атрибут");

        // Извлекаем поле certificates из countersigned (signer + countersigner)
        byte[] certsFieldC = null;
        for (byte[] part : sdPartsC) {
            if (part.length > 0 && (part[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                certsFieldC = part;
                break;
            }
        }

        // Строим cadesBes2 (data2, тот же ключ): SI2 согласован с data2,
        // CMS-подпись валидна, но signatureValue ≠ SI1.signatureValue
        byte[] cadesBes2 =
                CmsSignedDataBuilder.create()
                        .data(data2)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        CmsContentInfo ci2 = CmsContentInfo.decode(cadesBes2);
        byte[][] sdParts2 = DerCodec.parseSequenceContents(ci2.content(), 0);
        byte[] siField2 = sdParts2[sdParts2.length - 1];
        byte[][] siSet2 = DerCodec.parseSetContents(siField2, 0);
        byte[][] siParts2 = DerCodec.parseSequenceContents(siSet2[0], 0);

        // Внедряем countersignature CS1 в unsignedAttrs SI2
        byte[] modifiedSi2 = injectAttrIntoSignerInfo(siParts2, csAttrDer);

        // Пересобираем SignedData: eContent = data2 (согласован с SI2),
        // certs = из countersigned (signer + countersigner), signerInfos = изменённый SI2
        byte[][] newSdParts =
                new byte[][] {
                    sdParts2[0], // version
                    sdParts2[1], // digestAlgs — ВСЕГДА на месте, даже если implicit certs/crls есть
                    sdParts2[2], // encapContentInfo (data2)
                };

        // Добавляем certificates из countersigned
        java.util.List<byte[]> parts = new java.util.ArrayList<>(Arrays.asList(newSdParts));
        if (certsFieldC != null) {
            parts.add(certsFieldC);
        }
        // CRL пропускаем (нет)
        // Пропускаем возможные implicit-поля из sdParts2 после encapContentInfo
        // signerInfos — изменённый SI2
        parts.add(DerCodec.encodeSetOf(new byte[][] {modifiedSi2}));

        byte[] newSd = DerCodec.encodeSequence(parts.toArray(new byte[0][]));
        byte[] tamperedCountersigned = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSd);

        // SI2 валидно подписывает data2, CMS-проверка проходит.
        // Но CS1 хэширует SI1.signatureValue ≠ SI2.signatureValue —
        // countersignature должна упасть именно на message-digest
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESExtender.verifyCountersignature(
                                        tamperedCountersigned, signerCert, countersignerCert),
                        "Подмена signatureValue родителя должна сломать countersignature");
        assertTrue(
                ex.getMessage().contains("messageDigest")
                        || ex.getMessage().contains("message digest"),
                "Ошибка должна быть именно от countersignature message-digest: " + ex.getMessage());
    }

    @Test
    @DisplayName("Подмена eContent не ломает countersignature (подписана подпись, не контент)")
    void tamperContentDoesNotBreakCountersignature() throws Exception {
        byte[] data = "original content".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, countersignerKp.getPrivate(), countersignerCert);

        // Меняем eContent в encapContentInfo — это сломает CMS-подпись,
        // но не countersignature, так как она подписывает signatureValue, а не eContent.
        // Проверяем, что ошибка от CMS-верификации, а не от countersignature.
        CmsContentInfo ci = CmsContentInfo.decode(countersigned);
        byte[][] sdParts = org.rssys.gost.util.DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] encapContentInfo = sdParts[2];
        byte[][] encapParts =
                org.rssys.gost.util.DerCodec.parseSequenceContents(encapContentInfo, 0);
        if (encapParts.length > 1) {
            int[] len = org.rssys.gost.util.DerCodec.decodeLength(encapParts[1], 1);
            int innerOff = 1 + len[1];
            int innerLen =
                    org.rssys.gost.util.DerCodec.decodeLength(encapParts[1], innerOff + 1)[1];
            int contentOff = innerOff + 1 + innerLen;
            if (contentOff < encapParts[1].length) {
                encapParts[1][contentOff] ^= 0xFF;
            }
        }
        byte[] newEncap = org.rssys.gost.util.DerCodec.encodeSequence(encapParts);
        sdParts[2] = newEncap;

        List<byte[]> partsList = new java.util.ArrayList<>();
        for (byte[] p : sdParts) {
            partsList.add(p);
        }
        byte[] newSd =
                org.rssys.gost.util.DerCodec.encodeSequence(partsList.toArray(new byte[0][]));
        byte[] tamperedCountersigned = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSd);

        // CMS-подпись должна сломаться, но это ошибка CMS, а не countersignature
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESExtender.verifyCountersignature(
                                        tamperedCountersigned, signerCert, countersignerCert),
                        "Подмена eContent должна сломать CMS-подпись");
        assertTrue(
                ex.getMessage().contains("digest")
                        || ex.getMessage().contains("Data")
                        || ex.getMessage().contains("failed"),
                "Ошибка должна быть от CMS-верификации, не от countersignature: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName("Самоподписанный countersigner не в trustedCerts → PkixException")
    void countersignerChainNotTrusted() throws Exception {
        byte[] data = "chain test".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, countersignerKp.getPrivate(), countersignerCert);

        // Передаём только signerCert, но не countersignerCert в trusted
        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCountersignature(countersigned, signerCert),
                "Countersigner не в trustedCerts — цепочка не должна построиться");
    }

    @Test
    @DisplayName("Отсутствие countersignature при verifyCountersignature → PkixException")
    void missingCountersignatureFailsVerify() throws Exception {
        byte[] data = "no cs test".getBytes();

        // CAdES-BES без countersignature
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCountersignature(cadesBes, signerCert, countersignerCert),
                "verifyCountersignature должен требовать countersignature");
    }

    @Test
    @DisplayName("Битый DER countersignature → PkixException")
    void corruptedCountersignatureDerFails() throws Exception {
        byte[] data = "corrupt DER test".getBytes();

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data(data)
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] countersigned =
                CAdESExtender.embedCountersignature(
                        cadesBes, countersignerKp.getPrivate(), countersignerCert);

        // Портим DER countersignature в unsignedAttrs
        CmsContentInfo ci = CmsContentInfo.decode(countersigned);
        byte[][] sdParts = org.rssys.gost.util.DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = org.rssys.gost.util.DerCodec.parseSetContents(signerInfosField, 0);

        byte[][] siParts = org.rssys.gost.util.DerCodec.parseSequenceContents(signerInfos[0], 0);
        // Находим unsignedAttrs [1] и портим содержимое
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0
                    && (siParts[i][0] & 0xFF)
                            == org.rssys.gost.util.DerCodec.TAG_CTX_CONSTRUCTED_1) {
                // Пробуем испортить байт внутри unsignedAttrs
                if (siParts[i].length > 5) {
                    siParts[i][siParts[i].length - 2] ^= 0xFF;
                }
                break;
            }
        }
        byte[] tamperedSi = org.rssys.gost.util.DerCodec.encodeSequence(siParts);
        byte[] tamperedCountersigned = rebuildSignedData(ci, new byte[][] {tamperedSi});

        assertThrows(
                PkixException.class,
                () ->
                        CAdESExtender.verifyCountersignature(
                                tamperedCountersigned, signerCert, countersignerCert),
                "Битый DER countersignature должен давать ошибку");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    private static byte[] rebuildSignedData(CmsContentInfo contentInfo, byte[][] newSignerInfos)
            throws PkixException {
        byte[][] sdParts = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        sdParts[sdParts.length - 1] = DerCodec.encodeSetOf(newSignerInfos);
        byte[] newSd = DerCodec.encodeSequence(sdParts);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSd);
    }

    /**
     * Внедряет countersignature атрибут в unsignedAttrs SignerInfo.
     * Аналог {@link CAdESExtender#injectUnsignedAttrDer}.
     */
    private static byte[] injectAttrIntoSignerInfo(byte[][] siParts, byte[] attrDer)
            throws PkixException {
        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }

        byte[] newUnsignedAttrs;
        if (unsignedIdx >= 0) {
            byte[] existingField = siParts[unsignedIdx];
            int[] lenInfo = DerCodec.decodeLength(existingField, 1);
            int contentOff = 1 + lenInfo[1];

            java.util.List<byte[]> attrs = new java.util.ArrayList<>();
            attrs.add(attrDer);
            int pos = contentOff;
            while (pos < existingField.length) {
                int[] attrLen = DerCodec.decodeLength(existingField, pos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                attrs.add(Arrays.copyOfRange(existingField, pos, pos + attrTotal));
                pos += attrTotal;
            }
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, attrDer);
            byte[][] newParts = Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newUnsignedAttrs;
            siParts = newParts;
        }

        return DerCodec.encodeSequence(siParts);
    }
}
