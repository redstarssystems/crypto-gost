package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
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
    @DisplayName("EnvelopedData (ktri): шифрование и расшифровка")
    void encryptAndDecrypt() throws PkixException {
        byte[] data = "Confidential CMS EnvelopedData content".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        assertNotNull(envelopedData);
        assertTrue(envelopedData.length > 0);

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, privateKey, selfSignedCert);

        assertNotNull(decrypted);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("EnvelopedData (kari): шифрование и расшифровка")
    void encryptAndDecryptKari() throws PkixException {
        byte[] data = "Kari format test".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.createKari()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .build();

        assertNotNull(envelopedData);
        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, privateKey, selfSignedCert);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("EnvelopedData (ktri): большой объём данных")
    void largeData() throws PkixException {
        byte[] data = new byte[10000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i & 0xFF);
        }

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, privateKey, selfSignedCert);

        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("EnvelopedData (ktri): декодирование ContentInfo")
    void contentInfoRoundtrip() throws PkixException {
        byte[] data = "test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        CmsContentInfo info = CmsContentInfo.decode(envelopedData);
        assertEquals(GostOids.CMS_ENVELOPED_DATA, info.contentType());
        assertNotNull(info.content());
    }

    @Test
    @DisplayName("EnvelopedData (ktri): version = 0 по RFC 5652 §6.1")
    void ktriEnvelopedVersionIsZero() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data("v".getBytes())
                        .addRecipient(selfSignedCert)
                        .withoutIntegrity()
                        .build();

        // ktri (issuerAndSerialNumber) -> все RecipientInfo v0, нет originatorInfo/
        // unprotectedAttrs -> EnvelopedData.version обязан быть 0.
        assertEquals(
                0,
                envelopedDataVersion(envelopedData),
                "ktri EnvelopedData.version должен быть 0 (RFC 5652 §6.1)");
    }

    @Test
    @DisplayName("EnvelopedData (kari): version = 2 по RFC 5652 §6.1")
    void kariEnvelopedVersionIsTwo() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.createKari()
                        .data("v".getBytes())
                        .addRecipient(selfSignedCert)
                        .build();

        // KeyAgreeRecipientInfo имеет version 3 (§6.2.2) -> не все RecipientInfo v0,
        // pwri/ori отсутствуют -> ветвь ELSE §6.1 -> EnvelopedData.version = 2.
        assertEquals(
                2,
                envelopedDataVersion(envelopedData),
                "kari EnvelopedData.version должен быть 2 (RFC 5652 §6.1)");
    }

    private static int envelopedDataVersion(byte[] contentInfoDer) throws PkixException {
        byte[] envelopedData = CmsContentInfo.decode(contentInfoDer).content();
        byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
        return DerCodec.parseInteger(envParts[0], 0).intValueExact();
    }

    @Test
    @DisplayName("EnvelopedData (ktri): эфемерный ключ несёт paramSet получателя (§8.4.2.2)")
    void ktriEphemeralKeyCarriesRecipientParamSet() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data("p".getBytes())
                        .addRecipient(selfSignedCert)
                        .build();

        // AlgorithmIdentifier эфемерного ключа обязан в точности совпадать с представлением
        // в сертификате получателя (Р 1323565.1.025-2019 §8.4.2.2, шаг 4) — иначе КриптоПро не
        // согласует ключ. Регресс к канонизации paramSet (XchA -> CryptoPro-A).
        byte[] ephemeralAlgId = ktriEphemeralAlgId(envelopedData);
        assertArrayEquals(
                selfSignedCert.getSpkiAlgorithmId(),
                ephemeralAlgId,
                "algId эфемерного ключа должен совпадать с algId сертификата получателя");
    }

    @Test
    @DisplayName("EnvelopedData (kari): originator-ключ несёт paramSet получателя (§8.4.2.2)")
    void kariOriginatorKeyCarriesRecipientParamSet() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.createKari()
                        .data("p".getBytes())
                        .addRecipient(selfSignedCert)
                        .build();

        byte[] originatorAlgId = kariOriginatorAlgId(envelopedData);
        assertArrayEquals(
                selfSignedCert.getSpkiAlgorithmId(),
                originatorAlgId,
                "algId originator-ключа должен совпадать с algId сертификата получателя");
    }

    /** Извлекает AlgorithmIdentifier эфемерного ключа из ktri GostR3410-KeyTransport. */
    private static byte[] ktriEphemeralAlgId(byte[] contentInfoDer) throws PkixException {
        byte[] envelopedData = CmsContentInfo.decode(contentInfoDer).content();
        byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
        byte[][] ktri =
                DerCodec.parseSequenceContents(DerCodec.parseSetContents(envParts[1], 0)[0], 0);
        byte[] keyTransport = DerCodec.parseOctetString(ktri[3], 0);
        byte[][] ktParts = DerCodec.parseSequenceContents(keyTransport, 0);
        // ktParts[1] = ephemeralPublicKey SubjectPublicKeyInfo
        return DerCodec.parseSequenceContents(ktParts[1], 0)[0];
    }

    /** Извлекает AlgorithmIdentifier originator-ключа из kari (originator [0] -> [1] -> SPKI). */
    private static byte[] kariOriginatorAlgId(byte[] contentInfoDer) throws PkixException {
        byte[] envelopedData = CmsContentInfo.decode(contentInfoDer).content();
        byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
        // recipientInfos [1] EXPLICIT kari -> SEQUENCE
        byte[] kariElem = DerCodec.parseSetContents(envParts[1], 0)[0];
        int[] kariLen = DerCodec.decodeLength(kariElem, 1);
        byte[] kari =
                java.util.Arrays.copyOfRange(kariElem, 1 + kariLen[1], 1 + kariLen[1] + kariLen[0]);
        // kari [1] IMPLICIT -> переоборачиваем поля в SEQUENCE.
        byte[][] kaParts = DerCodec.parseSequenceContents(DerCodec.encodeSequence(kari), 0);
        // kaParts[1] = originator [0] EXPLICIT { [1] IMPLICIT originatorKey { algId, bitstring } }
        int[] oLen = DerCodec.decodeLength(kaParts[1], 1);
        byte[] originatorInner =
                java.util.Arrays.copyOfRange(kaParts[1], 1 + oLen[1], 1 + oLen[1] + oLen[0]);
        int[] okLen = DerCodec.decodeLength(originatorInner, 1);
        byte[] originatorKey =
                java.util.Arrays.copyOfRange(
                        originatorInner, 1 + okLen[1], 1 + okLen[1] + okLen[0]);
        // originatorKey [1] IMPLICIT: algId — первый TLV; переоборачиваем в SEQUENCE, берём algId.
        return DerCodec.parseSequenceContents(DerCodec.encodeSequence(originatorKey), 0)[0];
    }

    @Test
    @DisplayName("EnvelopedData (ktri): неверный ключ — ошибка")
    void wrongKey() throws PkixException {
        byte[] data = "secret".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);

        assertThrows(
                PkixException.class,
                () ->
                        CmsEnvelopedDataDecryptor.decrypt(
                                envelopedData, wrongKp.getPrivate(), selfSignedCert));
    }

    @Test
    @DisplayName("P0-T1 (ktri): wire-формат — независимая расшифровка через CtrAcpkmMode напрямую")
    void encryptUsesCtrAcpkmModeKtri() throws PkixException {
        byte[] data = "verify CTR-ACPKM mode ktri".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .withoutIntegrity()
                        .build();

        byte[] decrypted = decryptIndependentlyKtri(envelopedData);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("P0-T1 (kari): wire-формат — независимая расшифровка через CtrAcpkmMode напрямую")
    void encryptUsesCtrAcpkmModeKari() throws PkixException {
        byte[] data = "verify CTR-ACPKM mode kari".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.createKari()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .withoutIntegrity()
                        .build();

        byte[] decrypted = decryptIndependentlyKari(envelopedData);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("P0-T2: параметры алгоритма — SEQUENCE, а не голый OCTET STRING")
    void cipherParamsAreSequence() throws PkixException {
        byte[] data = "params test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

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
                CmsEnvelopedDataBuilder.createKari()
                        .data(data)
                        .addRecipient(selfSignedCert)
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
                "RecipientInfo должен быть kari [1] IMPLICIT KeyAgreeRecipientInfo");

        int[] kariLen = DerCodec.decodeLength(riElem, 1);
        int off = 1 + kariLen[1];
        byte[] kariBody = Arrays.copyOfRange(riElem, off, off + kariLen[0]);
        // kari [1] IMPLICIT: тег [1] заменяет SEQUENCE, поэтому переоборачиваем поля в SEQUENCE.
        byte[][] kaParts = DerCodec.parseSequenceContents(DerCodec.encodeSequence(kariBody), 0);
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
                "originator внутренний тег должен быть [1] IMPLICIT OriginatorPublicKey");
        int[] pkLen = DerCodec.decodeLength(originatorInner, 1);
        int pkStart = 1 + pkLen[1];
        byte[] originatorKey = Arrays.copyOfRange(originatorInner, pkStart, pkStart + pkLen[0]);
        // originatorKey [1] IMPLICIT: поля { algorithm, subjectPublicKey } идут напрямую,
        // поэтому первым TLV лежит AlgorithmIdentifier (SEQUENCE).
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                originatorKey[0] & 0xFF,
                "OriginatorPublicKey.algorithm должен быть SEQUENCE");

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
        assertEquals(32, ukmBytes.length, "UKM должен быть 32 байта (ТК26 §8.2.2)");

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
                GostOids.WRAP_KUZNYECHIK_KEXP15,
                algOid,
                "keyEncryptionAlgorithm OID должен быть алгоритмом key wrap (kexp15)");

        byte[] paramsField = algParts[1];
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                paramsField[0] & 0xFF,
                "Параметры keyEncryptionAlgorithm должны быть SEQUENCE");
        byte[][] paramsParts = DerCodec.parseSequenceContents(paramsField, 0);
        assertEquals(1, paramsParts.length, "Параметры должны содержать ровно один agreement-OID");
        String wrapOid = DerCodec.parseOid(paramsParts[0], 0);
        assertEquals(
                GostOids.AGREEMENT_VKO_256,
                wrapOid,
                "Параметр должен нести OID согласования AGREEMENT_VKO_256");

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
    @DisplayName("KeyTransRecipientInfo: структурная верификация DER-тегов и OID")
    void keyTransRecipientInfoStructure() throws PkixException {
        byte[] data = "ktri structural DER verification".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] recipientInfosField = envParts[1];

        byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
        assertEquals(1, riElems.length, "Ожидается один RecipientInfo");

        byte[] riElem = riElems[0];
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                riElem[0] & 0xFF,
                "RecipientInfo должен быть SEQUENCE (ktri — первый элемент CHOICE без номера тега)");

        byte[][] ktParts = DerCodec.parseSequenceContents(riElem, 0);
        assertEquals(4, ktParts.length, "KeyTransRecipientInfo должен содержать 4 поля");

        // version = 0 (rid = issuerAndSerialNumber)
        assertEquals(0, DerCodec.parseInteger(ktParts[0], 0).intValue(), "version должен быть 0");

        // rid: IssuerAndSerialNumber
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                ktParts[1][0] & 0xFF,
                "rid должен быть SEQUENCE (IssuerAndSerialNumber)");

        // keyEncryptionAlgorithm: kuznyechik-kexp15, params = SEQUENCE { VKO-256 }
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                ktParts[2][0] & 0xFF,
                "keyEncryptionAlgorithm должен быть SEQUENCE");
        byte[][] algParts = DerCodec.parseSequenceContents(ktParts[2], 0);
        String algOid = DerCodec.parseOid(algParts[0], 0);
        assertEquals(
                GostOids.WRAP_KUZNYECHIK_KEXP15,
                algOid,
                "keyEncryptionAlgorithm OID должен быть kuznyechik-kexp15");

        byte[][] paramsParts = DerCodec.parseSequenceContents(algParts[1], 0);
        String paramOid = DerCodec.parseOid(paramsParts[0], 0);
        assertEquals(GostOids.AGREEMENT_VKO_256, paramOid, "params должны содержать OID VKO-256");

        // encryptedKey = OCTET STRING { GostR3410-KeyTransport }
        assertEquals(
                DerCodec.TAG_OCTET_STRING,
                ktParts[3][0] & 0xFF,
                "encryptedKey должен быть OCTET STRING");

        byte[] encKeyDer = DerCodec.parseOctetString(ktParts[3], 0);
        byte[][] keyTransParts = DerCodec.parseSequenceContents(encKeyDer, 0);
        assertEquals(3, keyTransParts.length, "GostR3410-KeyTransport должен содержать 3 поля");

        // sessionEncryptedKey OCTET STRING (KExp15 output)
        byte[] sessionKey = DerCodec.parseOctetString(keyTransParts[0], 0);
        assertEquals(
                48,
                sessionKey.length,
                "sessionEncryptedKey должен быть 48 байт (32 CEK + 16 CMAC)");

        // ephemeralPublicKey SubjectPublicKeyInfo
        assertEquals(
                DerCodec.TAG_SEQUENCE,
                keyTransParts[1][0] & 0xFF,
                "ephemeralPublicKey должен быть SEQUENCE (SubjectPublicKeyInfo)");

        // ukm OCTET STRING (32 байта)
        byte[] ukmBytes = DerCodec.parseOctetString(keyTransParts[2], 0);
        assertEquals(32, ukmBytes.length, "ukm должен быть 32 байта (ТК26 §8.2.1)");
    }

    @Test
    @DisplayName("EnvelopedData (ktri+omac): шифрование с имитовставкой, roundtrip")
    void encryptAndDecryptKtriOmac() throws PkixException {
        byte[] data = "Confidential + integrity via OMAC".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        assertNotNull(envelopedData);

        // Проверяем, что OID контентного шифра — KUZ_CTR_ACPKM_OMAC
        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);
        byte[][] algParts = DerCodec.parseSequenceContents(eciParts[1], 0);
        String contentOid = DerCodec.parseOid(algParts[0], 0);
        assertEquals(
                GostOids.KUZ_CTR_ACPKM_OMAC,
                contentOid,
                "OID контентного шифра должен быть KUZ_CTR_ACPKM_OMAC");

        // UKM = 16 байт
        byte[][] ukmlvSeq = DerCodec.parseSequenceContents(algParts[1], 0);
        byte[] ukm = DerCodec.parseOctetString(ukmlvSeq[0], 0);
        assertEquals(16, ukm.length, "UKM контентного шифра должен быть 16 байт");

        // Расшифровка с проверкой MAC
        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, privateKey, selfSignedCert);
        assertArrayEquals(data, decrypted, "Расшифрованные данные должны совпадать");
    }

    @Test
    @DisplayName("EnvelopedData (ktri+omac): fail-closed при подделке MAC")
    void omacTamperDetection() throws PkixException {
        byte[] data = "data with OMAC integrity".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        // Парсим DER, модифицируем encryptedMac в unprotectedAttrs
        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] unprotectedAttrsField = envParts[3];

        // unprotectedAttrs = [1] IMPLICIT SET OF Attribute
        // Содержимое [1]: непосредственно SEQUENCE (Attribute), без явного SET-тега
        int[] uaLen = DerCodec.decodeLength(unprotectedAttrsField, 1);
        int uaStart = 1 + uaLen[1];
        byte[] uaContent = Arrays.copyOfRange(unprotectedAttrsField, uaStart, uaStart + uaLen[0]);

        // Атрибут — непосредственно SEQUENCE { OID, SET { OCTET STRING } }
        byte[][] attrParts = DerCodec.parseSequenceContents(uaContent, 0);
        String attrOid = DerCodec.parseOid(attrParts[0], 0);
        assertEquals(GostOids.ID_CMS_MAC_ATTR, attrOid);

        // attrParts[1] = SET { OCTET STRING (encryptedMac) }
        byte[][] setValues = DerCodec.parseSetContents(attrParts[1], 0);
        byte[] encMac = DerCodec.parseOctetString(setValues[0], 0);
        // Подделываем последний байт encryptedMac
        encMac[encMac.length - 1] ^= 0xFF;
        byte[] tamperedSet = DerCodec.encodeSetOf(DerCodec.encodeOctetString(encMac));
        byte[] tamperedAttr = DerCodec.encodeSequence(attrParts[0], tamperedSet);

        // Пересобираем DER с изменённым unprotectedAttrs
        byte[] tamperedUa = DerCodec.encodeContextConstructed(1, tamperedAttr);
        byte[] tamperedEnv =
                DerCodec.encodeSequence(envParts[0], envParts[1], envParts[2], tamperedUa);
        byte[] tamperedCi = CmsContentInfo.encode(GostOids.CMS_ENVELOPED_DATA, tamperedEnv);

        assertThrows(
                PkixException.class,
                () -> CmsEnvelopedDataDecryptor.decrypt(tamperedCi, privateKey, selfSignedCert),
                "Подделка MAC должна приводить к PkixException (fail-closed)");
    }

    @Test
    @DisplayName("EnvelopedData (ktri+omac): version = 2 из-за unprotectedAttrs")
    void ktriOmacEnvelopedVersionIsTwo() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data("omac version check".getBytes())
                        .addRecipient(selfSignedCert)
                        .build();

        // OMAC добавляет unprotectedAttrs -> EnvelopedData.version = 2
        assertEquals(
                2,
                envelopedDataVersion(envelopedData),
                "ktri+OMAC EnvelopedData.version должен быть 2 (unprotectedAttrs присутствуют)");
    }

    @Test
    @DisplayName("EnvelopedData (ktri+omac): unprotectedAttrs содержит content-mac")
    void omacUnprotectedAttrsContainsContentMac() throws PkixException {
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data("unprotected attrs test".getBytes())
                        .addRecipient(selfSignedCert)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        assertEquals(
                4,
                envParts.length,
                "OMAC EnvelopedData должен содержать 4 компонента (включая unprotectedAttrs)");

        // Проверяем тег [1] у unprotectedAttrs
        assertEquals(
                DerCodec.TAG_CTX_CONSTRUCTED_1,
                envParts[3][0] & 0xFF,
                "unprotectedAttrs должен быть [1] IMPLICIT");

        // Проверяем наличие content-mac атрибута
        // Содержимое [1]: непосредственно SEQUENCE (Attribute), без явного SET-тега
        int[] uaLen = DerCodec.decodeLength(envParts[3], 1);
        int uaStart = 1 + uaLen[1];
        byte[] uaContent = Arrays.copyOfRange(envParts[3], uaStart, uaStart + uaLen[0]);
        byte[][] attrParts = DerCodec.parseSequenceContents(uaContent, 0);
        String attrOid = DerCodec.parseOid(attrParts[0], 0);
        assertEquals(
                GostOids.ID_CMS_MAC_ATTR,
                attrOid,
                "unprotectedAttrs должен содержать атрибут content-mac");
    }

    @Test
    @DisplayName("KeyAgreeRecipientInfo: многополучательский EnvelopedData")
    void multiRecipientEnvelopedDataKari() throws PkixException {
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        byte[] data = "multi-recipient kari test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.createKari()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .addRecipient(cert2)
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
    @DisplayName("KeyTransRecipientInfo: многополучательский EnvelopedData")
    void multiRecipientEnvelopedDataKtri() throws PkixException {
        var kp2 = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert2 =
                CmsTestUtils.createSelfSignedCert(kp2.getPrivate(), kp2.getPublic());

        byte[] data = "multi-recipient ktri test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data(data)
                        .addRecipient(selfSignedCert)
                        .addRecipient(cert2)
                        .build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] riElems = DerCodec.parseSetContents(envParts[1], 0);
        assertEquals(2, riElems.length, "Ожидается два RecipientInfo в SET");

        for (int i = 0; i < riElems.length; i++) {
            assertEquals(
                    DerCodec.TAG_SEQUENCE,
                    riElems[i][0] & 0xFF,
                    "RecipientInfo[" + i + "] должен быть ktri SEQUENCE");
        }

        // Расшифровка для первого получателя
        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, privateKey, selfSignedCert);
        assertArrayEquals(data, decrypted);

        // Расшифровка для второго получателя
        byte[] decrypted2 =
                CmsEnvelopedDataDecryptor.decrypt(envelopedData, kp2.getPrivate(), cert2);
        assertArrayEquals(data, decrypted2);
    }

    @Test
    @DisplayName("EnvelopedData: encryptedContent должен быть [0] IMPLICIT (примитивный 0x80)")
    void encryptedContentIsImplicitPrimitive() throws PkixException {
        byte[] data = "implicit tag test".getBytes();
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        CmsContentInfo ci = CmsContentInfo.decode(envelopedData);
        byte[][] envParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);

        assertEquals(
                DerCodec.TAG_CTX_PRIMITIVE_0,
                eciParts[2][0] & 0xFF,
                "encryptedContent должен быть [0] IMPLICIT (примитивный 0x80) по RFC 5652 §6.1");
    }

    // ========================================================================
    // Независимая расшифровка: извлекает CEK и IV из DER, расшифровывает CtrAcpkmMode напрямую.
    // Не использует CmsEnvelopedDataDecryptor — верифицирует wire-формат.
    // ========================================================================

    private byte[] decryptIndependentlyKari(byte[] envelopedDataDer) throws PkixException {
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
        int[] ecLen = DerCodec.decodeLength(encContentField, 1);
        int ecStart = 1 + ecLen[1];
        byte[] encryptedContent = Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLen[0]);

        byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
        byte[] cek = null;
        for (byte[] riElem : riElems) {
            int[] kariLen = DerCodec.decodeLength(riElem, 1);
            int off = 1 + kariLen[1];
            byte[] kariBody = Arrays.copyOfRange(riElem, off, off + kariLen[0]);
            byte[][] kaParts = DerCodec.parseSequenceContents(DerCodec.encodeSequence(kariBody), 0);
            byte[] ukmField = kaParts[2];
            int[] uLen = DerCodec.decodeLength(ukmField, 1);
            int uStart = 1 + uLen[1];
            byte[] ukmBytes = DerCodec.parseOctetString(ukmField, uStart);

            byte[] kek = computeVkoKek(kaParts, ukmBytes);

            byte[] ivKexp = Arrays.copyOfRange(ukmBytes, 24, 32);

            byte[][] rekSeq = DerCodec.parseSequenceContents(kaParts[4], 0);
            for (byte[] rkDer : rekSeq) {
                byte[][] rkParts = DerCodec.parseSequenceContents(rkDer, 0);
                byte[] wrappedCek = DerCodec.parseOctetString(rkParts[1], 0);
                cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes, ivKexp);
                Arrays.fill(ivKexp, (byte) 0);
            }
            Arrays.fill(kek, (byte) 0);
            if (cek != null) break;
        }
        assertNotNull(cek, "CEK не найден в RecipientInfos (kari)");

        return decryptWithCek(cek, iv, encryptedContent);
    }

    private byte[] decryptIndependentlyKtri(byte[] envelopedDataDer) throws PkixException {
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
        int[] ecLen = DerCodec.decodeLength(encContentField, 1);
        int ecStart = 1 + ecLen[1];
        byte[] encryptedContent = Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLen[0]);

        byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
        byte[] cek = null;
        for (byte[] riElem : riElems) {
            // ktri: KeyTransRecipientInfo SEQUENCE { version, rid, keyEncAlg, encryptedKey }
            byte[][] ktParts = DerCodec.parseSequenceContents(riElem, 0);

            // encryptedKey OCTET STRING → GostR3410-KeyTransport
            byte[] encKeyDer = DerCodec.parseOctetString(ktParts[3], 0);
            byte[][] keyTransParts = DerCodec.parseSequenceContents(encKeyDer, 0);

            byte[] wrappedCek = DerCodec.parseOctetString(keyTransParts[0], 0);
            byte[] ukmBytes = DerCodec.parseOctetString(keyTransParts[2], 0);

            // ephemeralPublicKey → PublicKeyParameters
            byte[][] spkiParts = DerCodec.parseSequenceContents(keyTransParts[1], 0);
            byte[] spki = DerCodec.encodeSequence(spkiParts[0], spkiParts[1]);
            PublicKeyParameters ephemeralPub =
                    org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);

            java.math.BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
            byte[] kek =
                    org.rssys.gost.api.KeyAgreement.vkoGostR3410_2012_256(
                            privateKey, ephemeralPub, ukm);

            byte[] ivKexp = Arrays.copyOfRange(ukmBytes, 24, 32);
            cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes, ivKexp);
            Arrays.fill(ivKexp, (byte) 0);
            Arrays.fill(kek, (byte) 0);
            if (cek != null) break;
        }
        assertNotNull(cek, "CEK не найден в RecipientInfos (ktri)");

        return decryptWithCek(cek, iv, encryptedContent);
    }

    private byte[] computeVkoKek(byte[][] kaParts, byte[] ukmBytes) {
        int[] oLen = DerCodec.decodeLength(kaParts[1], 1);
        int oStart2 = 1 + oLen[1];
        byte[] inner = Arrays.copyOfRange(kaParts[1], oStart2, oStart2 + oLen[0]);
        int[] pkLen = DerCodec.decodeLength(inner, 1);
        int pkStart = 1 + pkLen[1];
        byte[] originatorKey = Arrays.copyOfRange(inner, pkStart, pkStart + pkLen[0]);
        // originatorKey [1] IMPLICIT: содержимое — уже { algId, bitstring }; оборачиваем в SPKI.
        byte[] spki = DerCodec.encodeSequence(originatorKey);
        PublicKeyParameters ephemeralPub =
                org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);

        java.math.BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
        return org.rssys.gost.api.KeyAgreement.vkoGostR3410_2012_256(privateKey, ephemeralPub, ukm);
    }

    private byte[] decryptWithCek(byte[] cek, byte[] iv, byte[] encryptedContent) {
        SymmetricKey cekKey = new SymmetricKey(cek);
        try {
            return CtrAcpkmMode.decryptOnly(cekKey, iv, encryptedContent);
        } finally {
            cekKey.destroy();
            Arrays.fill(cek, (byte) 0);
        }
    }

    private byte[] buildTamperedEci(byte[][] eciParts, byte[] tamperedContent) {
        byte[] encContent = DerCodec.encodeTlv(DerCodec.TAG_CTX_PRIMITIVE_0, tamperedContent);
        return DerCodec.encodeSequence(eciParts[0], eciParts[1], encContent);
    }

    // ========================================================================
    // BER indefinite-length encryptedContent (совместимость с КриптоПРО CMS 5.0)
    // ========================================================================

    @Test
    @DisplayName("EnvelopedData (ktri): encryptedContent как constructed [0] BER indefinite")
    void decryptBerIndefiniteEncryptedContent() throws PkixException {
        byte[] data = "BER indefinite-length encryptedContent (КриптоПРО-стиль)".getBytes();

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        // crypto-gost выдаёт primitive [0] (0x80). Перекодируем encryptedContent в
        // BER-эквивалент A0 80 04 <len> <ct> 00 00, как это делает КриптоПРО.
        byte[] berEnveloped = reencodeEncryptedContentAsBer(envelopedData, false);

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(berEnveloped, privateKey, selfSignedCert);
        assertArrayEquals(
                data, decrypted, "BER indefinite-length должен расшифровываться идентично DER");
    }

    @Test
    @DisplayName("EnvelopedData (ktri): encryptedContent как сегментированный constructed [0]")
    void decryptBerSegmentedEncryptedContent() throws PkixException {
        byte[] data = new byte[512];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 7 + 3);
        }

        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create().data(data).addRecipient(selfSignedCert).build();

        // Два OCTET STRING-сегмента внутри A0 80 -> должны склеиться при расшифровке.
        byte[] berEnveloped = reencodeEncryptedContentAsBer(envelopedData, true);

        byte[] decrypted =
                CmsEnvelopedDataDecryptor.decrypt(berEnveloped, privateKey, selfSignedCert);
        assertArrayEquals(data, decrypted, "сегментированный OCTET STRING должен склеиваться");
    }

    /**
     * Перекодирует {@code encryptedContent} в EnvelopedData из DER primitive [0]
     * ({@code 80 <len> <ct>}) в BER constructed [0] indefinite
     * ({@code A0 80 04 <len> <ct> 00 00}). Остальные структуры остаются DER —
     * тест нацелен строго на извлечение октетов в {@code decryptContent}.
     */
    private static byte[] reencodeEncryptedContentAsBer(byte[] envelopedDataDer, boolean segmented)
            throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(envelopedDataDer);
        byte[] envelopedData = ci.content();
        byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
        byte[][] eciParts = DerCodec.parseSequenceContents(envParts[2], 0);

        byte[] primField = eciParts[2];
        int[] len = DerCodec.decodeLength(primField, 1);
        int start = 1 + len[1];
        byte[] ct = Arrays.copyOfRange(primField, start, start + len[0]);

        byte[] berEncContent = buildBerImplicitOctets(ct, segmented);

        byte[] newEci = DerCodec.encodeSequence(eciParts[0], eciParts[1], berEncContent);
        byte[][] newEnvParts = envParts.clone();
        newEnvParts[2] = newEci;
        byte[] newEnveloped = DerCodec.encodeSequence(newEnvParts);
        return CmsContentInfo.encode(ci.contentType(), newEnveloped);
    }

    /** Строит {@code A0 80 ... 00 00} с одним или двумя вложенными OCTET STRING. */
    private static byte[] buildBerImplicitOctets(byte[] ct, boolean segmented) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(DerCodec.TAG_CTX_CONSTRUCTED_0);
        out.write(0x80); // indefinite-length
        if (segmented && ct.length >= 2) {
            int mid = ct.length / 2;
            byte[] seg1 =
                    DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING, Arrays.copyOfRange(ct, 0, mid));
            byte[] seg2 =
                    DerCodec.encodeTlv(
                            DerCodec.TAG_OCTET_STRING, Arrays.copyOfRange(ct, mid, ct.length));
            out.write(seg1, 0, seg1.length);
            out.write(seg2, 0, seg2.length);
        } else {
            byte[] octet = DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING, ct);
            out.write(octet, 0, octet.length);
        }
        out.write(0x00);
        out.write(0x00); // EOC
        return out.toByteArray();
    }
}
