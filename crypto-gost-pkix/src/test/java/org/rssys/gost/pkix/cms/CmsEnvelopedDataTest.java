package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CMS EnvelopedData: шифрование и расшифровка")
class CmsEnvelopedDataTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static PrivateKeyParameters privateKey;
    private static GostCertificate selfSignedCert;
    private static CmsKeyWrap keyWrap;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        var kp = KeyGenerator.generateKeyPair(PARAMS);
        privateKey = kp.getPrivate();

        selfSignedCert = CmsTestUtils.createSelfSignedCert(kp.getPrivate(), kp.getPublic());
        keyWrap = new Kexp15CmsKeyWrap();
    }

    @Test
    @DisplayName("EnvelopedData: шифрование и расшифровка")
    void encryptAndDecrypt() throws PkixException {
        byte[] data = "Confidential CMS EnvelopedData content".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        assertNotNull(envelopedData);
        assertTrue(envelopedData.length > 0);

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(
                        envelopedData, privateKey, selfSignedCert, keyWrap);

        assertNotNull(decrypted);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("EnvelopedData: большой объём данных")
    void largeData() throws PkixException {
        byte[] data = new byte[10000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(
                        envelopedData, privateKey, selfSignedCert, keyWrap);

        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("EnvelopedData: декодирование ContentInfo")
    void contentInfoRoundtrip() throws PkixException {
        byte[] data = "test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        CmsContentInfo info = CmsContentInfo.decode(envelopedData);
        assertEquals(GostOids.CMS_ENVELOPED_DATA, info.contentType());
        assertNotNull(info.content());
    }

    @Test
    @DisplayName("EnvelopedData: неверный ключ — ошибка")
    void wrongKey() throws PkixException {
        byte[] data = "secret".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);

        assertThrows(
                PkixException.class,
                () ->
                        CmsEnvelopedDataDecryptor.decrypt(
                                envelopedData, wrongKp.getPrivate(), selfSignedCert, keyWrap));
    }

    @Test
    @DisplayName("P0-T1: wire-формат — независимая расшифровка через CtrAcpkmMode напрямую")
    void encryptUsesCtrAcpkmMode() throws PkixException {
        byte[] data = "verify CTR-ACPKM mode".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        byte[] decrypted = decryptIndependently(envelopedData);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("P0-T2: параметры алгоритма — SEQUENCE, а не голый OCTET STRING")
    void cipherParamsAreSequence() throws PkixException {
        byte[] data = "params test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[] envData = ci.content();
        byte[][] envParts = DerCodec.parseSequenceContents(envData, 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                algParts[1][0] & 0xFF,
                "Параметры должны начинаться с тега SEQUENCE (0x30), а не OCTET STRING (0x04)");
        byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
        assertEquals(
                DerCodec.TAG_OCTET_STRING,
                ivSeq[0][0] & 0xFF,
                "Внутри SEQUENCE должен быть OCTET STRING (IV)");
    }

    @Test
    @DisplayName("KeyAgreeRecipientInfo: структурная верификация DER-тегов и OID")
    void keyAgreeRecipientInfoStructure() throws PkixException {
        byte[] data = "structural DER verification".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] recipientInfosField = envParts[1];

        byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
        assertEquals(1, riElems.length, "Ожидается один RecipientInfo");

        byte[] riElem = riElems[0];
        assertEquals(
                DerCodec.TAG_CTX_CONSTRUCTED_1,
                riElem[0] & 0xFF,
                "RecipientInfo должен быть kari [1] EXPLICIT KeyAgreeRecipientInfo");

        int[] kariLen = DerCodec.decodeLength(riElem, 1);
        int off = 1 + kariLen[1];
        byte[] kariDer = Arrays.copyOfRange(riElem, off, off + kariLen[0]);
        byte[][] kaParts = DerCodec.parseSequenceContents(kariDer, 0);
        assertEquals(5, kaParts.length, "KeyAgreeRecipientInfo SEQUENCE должен содержать 5 полей");

        assertEquals(
                3,
                DerCodec.parseInteger(kaParts[0], 0).intValue(),
                "version KeyAgreeRecipientInfo должен быть 3");

        byte[] originatorField = kaParts[1];
        assertEquals(
                DerCodec.TAG_CTX_CONSTRUCTED_0,
                originatorField[0] & 0xFF,
                "originator должен быть [0] EXPLICIT");
        int[] oLen = DerCodec.decodeLength(originatorField, 1);
        int oStart = 1 + oLen[1];
        byte[] originatorInner = Arrays.copyOfRange(originatorField, oStart, oStart + oLen[0]);
        assertEquals(
                DerCodec.TAG_CTX_CONSTRUCTED_1,
                originatorInner[0] & 0xFF,
                "originator внутренний тег должен быть [1] EXPLICIT OriginatorPublicKey");
        int[] pkLen = DerCodec.decodeLength(originatorInner, 1);
        int pkStart = 1 + pkLen[1];
        byte[] originatorKey = Arrays.copyOfRange(originatorInner, pkStart, pkStart + pkLen[0]);
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                originatorKey[0] & 0xFF,
                "OriginatorPublicKey должен быть SEQUENCE");

        byte[] ukmField = kaParts[2];
        assertEquals(
                DerCodec.TAG_CTX_CONSTRUCTED_1, ukmField[0] & 0xFF, "ukm должен быть [1] EXPLICIT");
        int[] uLen = DerCodec.decodeLength(ukmField, 1);
        int uStart = 1 + uLen[1];
        assertEquals(
                DerCodec.TAG_OCTET_STRING,
                ukmField[uStart] & 0xFF,
                "ukm должен содержать OCTET STRING");
        byte[] ukmBytes = DerCodec.parseOctetString(ukmField, uStart);
        assertEquals(8, ukmBytes.length, "UKM должен быть 8 байт");

        byte[] keyEncAlgField = kaParts[3];
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                keyEncAlgField[0] & 0xFF,
                "keyEncryptionAlgorithm должен быть SEQUENCE");
        byte[][] algParts = DerCodec.parseSequenceContents(keyEncAlgField, 0);
        assertEquals(
                2,
                algParts.length,
                "keyEncryptionAlgorithm SEQUENCE должен содержать OID и параметры");
        String algOid = DerCodec.parseOid(algParts[0], 0);
        assertEquals(
                GostOids.AGREEMENT_VKO_256,
                algOid,
                "keyEncryptionAlgorithm OID должен быть AGREEMENT_VKO_256");

        byte[] paramsField = algParts[1];
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                paramsField[0] & 0xFF,
                "Параметры keyEncryptionAlgorithm должны быть SEQUENCE");
        byte[][] paramsParts = DerCodec.parseSequenceContents(paramsField, 0);
        assertEquals(1, paramsParts.length, "Параметры должны содержать ровно один OID key wrap");
        String wrapOid = DerCodec.parseOid(paramsParts[0], 0);
        assertEquals(
                keyWrap.algorithmOid(),
                wrapOid,
                "OID key wrap должен совпадать с keyWrap.algorithmOid()");

        byte[] rekSeqField = kaParts[4];
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                rekSeqField[0] & 0xFF,
                "recipientEncryptedKeys должен быть SEQUENCE");
        byte[][] rekSeq = DerCodec.parseSequenceContents(rekSeqField, 0);
        assertEquals(1, rekSeq.length, "Ожидается один RecipientEncryptedKey (один получатель)");
        byte[][] rkParts = DerCodec.parseSequenceContents(rekSeq[0], 0);
        assertEquals(2, rkParts.length, "RecipientEncryptedKey должен содержать rid и encKey");
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                rkParts[0][0] & 0xFF,
                "rid должен быть SEQUENCE (IssuerAndSerialNumber)");
        byte[] encKey = DerCodec.parseOctetString(rkParts[1], 0);
        assertEquals(
                48,
                encKey.length,
                "wrapped CEK (KExp15 на Кузнечике) должен быть 48 байт: 32 CEK + 16 CMAC");
    }

    @Test
    @DisplayName("KeyAgreeRecipientInfo: многополучательский EnvelopedData")
    void multiRecipientEnvelopedData() throws PkixException {
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        byte[] data = "multi-recipient test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .addRecipient(cert2)
                        .keyWrap(keyWrap)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] riElems = DerCodec.parseSetContents(envParts[1], 0);
        assertEquals(2, riElems.length, "Ожидается два RecipientInfo в SET");

        for (int i = 0; i < riElems.length; i++) {
            assertEquals(
                    DerCodec.TAG_CTX_CONSTRUCTED_1,
                    riElems[i][0] & 0xFF,
                    "RecipientInfo[" + i + "] должен быть kari [1] EXPLICIT");
        }
    }

    @Test
    @DisplayName("EnvelopedData: encryptedContent должен быть [0] IMPLICIT (примитивный 0x80)")
    void encryptedContentIsImplicitPrimitive() throws PkixException {
        byte[] data = "implicit tag test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .keyWrap(keyWrap)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);

        assertEquals(
                DerCodec.TAG_CTX_PRIMITIVE_0,
                eciParts[2][0] & 0xFF,
                "encryptedContent должен быть [0] IMPLICIT (примитивный 0x80) по RFC 5652 §6.1");
    }

    /**
     * Независимая расшифровка: извлекает CEK и IV из DER, расшифровывает CtrAcpkmMode напрямую.
     * Не использует CmsEnvelopedDataDecryptor — верифицирует wire-формат.
     */
    private byte[] decryptIndependently(byte[] envelopedDataDer) throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(envelopedDataDer);
        byte[] envData = ci.content();
        byte[][] envParts = DerCodec.parseSequenceContents(envData, 0);
        byte[] recipientInfosField = envParts[1];
        byte[] encryptedContentInfo = envParts[2];

        byte[][] eciParts = DerCodec.parseSequenceContents(encryptedContentInfo, 0);
        byte[] paramsDer = eciParts[1];
        byte[][] algParts = DerCodec.parseSequenceContents(paramsDer, 0);
        byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
        byte[] iv = DerCodec.parseOctetString(ivSeq[0], 0);
        byte[] encContentField = eciParts[2];
        if ((encContentField[0] & 0xFF) != DerCodec.TAG_CTX_PRIMITIVE_0) {
            throw new IllegalArgumentException(
                    "encryptedContent must be [0] IMPLICIT (primitive 0x80), got 0x"
                            + Integer.toHexString(encContentField[0] & 0xFF).toUpperCase());
        }
        int[] ecLen = DerCodec.decodeLength(encContentField, 1);
        int ecStart = 1 + ecLen[1];
        byte[] encryptedContent = Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLen[0]);

        byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
        byte[] cek = null;
        for (byte[] riElem : riElems) {
            int[] kariLen = DerCodec.decodeLength(riElem, 1);
            int off = 1 + kariLen[1];
            byte[] kariDer = Arrays.copyOfRange(riElem, off, off + kariLen[0]);
            byte[][] kaParts = DerCodec.parseSequenceContents(kariDer, 0);
            byte[] ukmField = kaParts[2];
            int[] uLen = DerCodec.decodeLength(ukmField, 1);
            int uStart = 1 + uLen[1];
            byte[] ukmBytes = DerCodec.parseOctetString(ukmField, uStart);

            int[] oLen = DerCodec.decodeLength(kaParts[1], 1);
            int oStart2 = 1 + oLen[1];
            byte[] inner = Arrays.copyOfRange(kaParts[1], oStart2, oStart2 + oLen[0]);
            int[] pkLen = DerCodec.decodeLength(inner, 1);
            int pkStart = 1 + pkLen[1];
            byte[] originatorKey = Arrays.copyOfRange(inner, pkStart, pkStart + pkLen[0]);
            byte[][] opkParts = DerCodec.parseSequenceContents(originatorKey, 0);
            byte[] spki = DerCodec.encodeSequence(opkParts[0], opkParts[1]);
            PublicKeyParameters ephemeralPub =
                    org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);

            java.math.BigInteger ukm = new java.math.BigInteger(1, ukmBytes);
            byte[] kek =
                    org.rssys.gost.api.KeyAgreement.vkoGostR3410_2012_256(
                            privateKey, ephemeralPub, ukm);

            byte[][] rekSeq = DerCodec.parseSequenceContents(kaParts[4], 0);
            for (byte[] rkDer : rekSeq) {
                byte[][] rkParts = DerCodec.parseSequenceContents(rkDer, 0);
                byte[] wrappedCek = DerCodec.parseOctetString(rkParts[1], 0);
                cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes);
            }
            Arrays.fill(kek, (byte) 0);
            if (cek != null) break;
        }
        assertNotNull(cek, "CEK не найден в RecipientInfos");

        SymmetricKey cekKey = new SymmetricKey(cek);
        byte[] result;
        try {
            result = CtrAcpkmMode.decryptOnly(cekKey, iv, encryptedContent);
        } finally {
            cekKey.destroy();
            Arrays.fill(cek, (byte) 0);
        }
        return result;
    }
}
