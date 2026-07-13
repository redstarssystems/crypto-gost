package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.DerCodec;

/**
 * Расшифровка CMS EnvelopedData.
 *
 * <p>Поддерживает оба типа RecipientInfo:
 * <ul>
 *   <li><b>ktri</b> (KeyTransRecipientInfo, тег {@code 0x30}) —
 *       основной формат по ТК26 §8.2.1, используется КриптоПРО 5.0.</li>
 *   <li><b>kari</b> (KeyAgreeRecipientInfo, тег {@code 0xA1}) —
 *       RFC 5652 §6.2.2, VKO + KExp15.</li>
 * </ul>
 *
 * <p>Формат определяется автоматически по тегу первого байта RecipientInfo.
 */
public final class CmsEnvelopedDataDecryptor {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor");

    private static final int TAG_KARI = 0xA1;
    private static final int TAG_KTRI = 0x30;

    private CmsEnvelopedDataDecryptor() {}

    /**
     * Расшифровывает EnvelopedData.
     *
     * @param envelopedDataDer DER-кодированный ContentInfo(id-envelopedData)
     * @param recipientKey     закрытый ключ получателя
     * @param recipientCert    сертификат получателя (для поиска в SET OF)
     * @param keyWrap          алгоритм обёртывания ключа
     * @return расшифрованные данные
     * @throws PkixException если расшифрование не удалось
     */
    public static byte[] decrypt(
            byte[] envelopedDataDer,
            PrivateKeyParameters recipientKey,
            GostCertificate recipientCert,
            CmsKeyWrap keyWrap)
            throws PkixException {
        // 1. ContentInfo -> EnvelopedData
        CmsContentInfo contentInfo = CmsContentInfo.decode(envelopedDataDer);
        if (!GostOids.CMS_ENVELOPED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Invalid contentType: expected id-envelopedData");
        }
        byte[] envelopedData = contentInfo.content();
        if (envelopedData == null)
            throw new PkixException(
                    PkixException.Reason.OTHER, "ContentInfo does not contain EnvelopedData");

        byte[][] envParts = DerCodec.parseSequenceContents(envelopedData, 0);
        byte[] recipientInfosField = envParts[1];
        byte[] encryptedContentInfo = envParts[2];

        // unprotectedAttrs [1] IMPLICIT SET OF Attribute (присутствуют для OMAC)
        byte[] unprotectedAttrsField = envParts.length > 3 ? envParts[3] : null;

        // 2. Ищем свой RecipientEncryptedKey в SET OF
        try {
            BigInteger mySerial = recipientCert.getSerialNumberBigInt();
            byte[] myIssuer = recipientCert.getIssuerDnBytes();

            byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
            for (byte[] riElem : riElems) {
                int tag = riElem[0] & 0xFF;

                if (tag == TAG_KARI) {
                    byte[] result =
                            decryptKeyAgree(
                                    riElem,
                                    recipientKey,
                                    mySerial,
                                    myIssuer,
                                    encryptedContentInfo,
                                    unprotectedAttrsField,
                                    keyWrap);
                    if (result != null) return result;
                } else if (tag == TAG_KTRI) {
                    byte[] result =
                            decryptKeyTrans(
                                    riElem,
                                    recipientKey,
                                    mySerial,
                                    myIssuer,
                                    encryptedContentInfo,
                                    unprotectedAttrsField,
                                    keyWrap);
                    if (result != null) return result;
                } else {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "Unsupported RecipientInfo tag 0x"
                                    + Integer.toHexString(tag).toUpperCase());
                }
            }

            throw new PkixException(PkixException.Reason.OTHER, "Recipient key not found");
        } catch (RuntimeException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Decryption failed: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // kari (KeyAgreeRecipientInfo, тег 0xA1)
    // ========================================================================

    private static byte[] decryptKeyAgree(
            byte[] riElem,
            PrivateKeyParameters recipientKey,
            BigInteger mySerial,
            byte[] myIssuer,
            byte[] encryptedContentInfo,
            byte[] unprotectedAttrsField,
            CmsKeyWrap keyWrap)
            throws PkixException {

        int[] kariLen = DerCodec.decodeLength(riElem, 1);
        int off = 1 + kariLen[1];
        byte[] kariDer = Arrays.copyOfRange(riElem, off, off + kariLen[0]);

        // RecipientInfo CHOICE kari [1] IMPLICIT:
        // тег 0xA1 заменяет SEQUENCE, поэтому kariDer начинается c version INTEGER 0x02.
        // Оборачиваем обратно в SEQUENCE для совместимости с общим парсером.
        byte[] kariSeq = DerCodec.encodeSequence(kariDer);
        byte[][] kaParts = DerCodec.parseSequenceContents(kariSeq, 0);
        int idx = 0;
        idx++;

        PublicKeyParameters ephemeralPub = extractEphemeralPublicKey(kaParts[idx++]);
        byte[] ukmBytes = extractUkm(kaParts[idx++]);
        idx++;

        // recipientEncryptedKeys SEQUENCE OF
        byte[][] rekSeq = DerCodec.parseSequenceContents(kaParts[idx], 0);
        for (byte[] rkDer : rekSeq) {
            byte[][] rkParts = DerCodec.parseSequenceContents(rkDer, 0);
            CmsIssuerAndSerialNumber rid = CmsIssuerAndSerialNumber.decode(rkParts[0]);
            if (!mySerial.equals(rid.serial()) || !Arrays.equals(myIssuer, rid.issuer())) {
                LOG.log(
                        Level.DEBUG,
                        "RecipientKey serial {0} does not match, skipping",
                        rid.serial().toString(16));
                continue;
            }

            byte[] wrappedCek = DerCodec.parseOctetString(rkParts[1], 0);

            BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
            byte[] kek =
                    (recipientKey.getParams().hlen == GostOids.STREEBOG_512_HASH_LEN)
                            ? KeyAgreement.vkoGostR3410_2012_512(recipientKey, ephemeralPub, ukm)
                            : KeyAgreement.vkoGostR3410_2012_256(recipientKey, ephemeralPub, ukm);

            // IV = UKM[24..31] (формула ТК26)
            byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

            byte[] cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes, iv);
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(iv, (byte) 0);

            try {
                byte[] decrypted = decryptContent(encryptedContentInfo, unprotectedAttrsField, cek);
                LOG.log(
                        Level.INFO,
                        "EnvelopedData (kari) decrypted successfully for recipient serial 0x{0}",
                        mySerial.toString(16));
                return decrypted;
            } finally {
                Arrays.fill(cek, (byte) 0);
            }
        }
        return null;
    }

    // ========================================================================
    // ktri (KeyTransRecipientInfo, тег 0x30) — ТК26 §8.2.1
    // ========================================================================

    private static byte[] decryptKeyTrans(
            byte[] riDer,
            PrivateKeyParameters recipientKey,
            BigInteger mySerial,
            byte[] myIssuer,
            byte[] encryptedContentInfo,
            byte[] unprotectedAttrsField,
            CmsKeyWrap keyWrap)
            throws PkixException {

        // KeyTransRecipientInfo: SEQUENCE { version, rid, keyEncAlg, encryptedKey }
        byte[][] ktParts = DerCodec.parseSequenceContents(riDer, 0);

        // Проверка rid (RecipientIdentifier)
        byte[][] ridParts = DerCodec.parseSequenceContents(ktParts[1], 0);
        CmsIssuerAndSerialNumber rid = CmsIssuerAndSerialNumber.decode(ktParts[1]);
        if (!mySerial.equals(rid.serial()) || !Arrays.equals(myIssuer, rid.issuer())) {
            LOG.log(
                    Level.DEBUG,
                    "RecipientKey serial {0} does not match (ktri), skipping",
                    rid.serial().toString(16));
            return null;
        }

        // Проверка keyEncryptionAlgorithm
        byte[][] algParts = DerCodec.parseSequenceContents(ktParts[2], 0);
        String keyAlgOid = DerCodec.parseOid(algParts[0], 0);
        if (!GostOids.WRAP_KUZNYECHIK_KEXP15.equals(keyAlgOid)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unsupported key encryption algorithm in ktri: " + keyAlgOid);
        }

        // encryptedKey OCTET STRING -> GostR3410-KeyTransport SEQUENCE
        byte[] encKeyDer = DerCodec.parseOctetString(ktParts[3], 0);
        byte[][] keyTransParts = DerCodec.parseSequenceContents(encKeyDer, 0);

        // [0] sessionEncryptedKey OCTET STRING (KExp15 output: 48 байт для Кузнечика)
        byte[] wrappedCek = DerCodec.parseOctetString(keyTransParts[0], 0);

        // [1] ephemeralPublicKey SubjectPublicKeyInfo
        PublicKeyParameters ephemeralPub = parseEphemeralPublicKey(keyTransParts[1]);

        // [2] ukm OCTET STRING (32 байта)
        byte[] ukmBytes = DerCodec.parseOctetString(keyTransParts[2], 0);

        // VKO + KExp15: вариант VKO (256/512) — по hlen ключа получателя.
        boolean is512 = recipientKey.getParams().hlen == GostOids.STREEBOG_512_HASH_LEN;
        BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);
        byte[] kek =
                is512
                        ? KeyAgreement.vkoGostR3410_2012_512(recipientKey, ephemeralPub, ukm)
                        : KeyAgreement.vkoGostR3410_2012_256(recipientKey, ephemeralPub, ukm);

        // IV = UKM[24..31] (формула ТК26: UKM[25..24+n/2] для n=16)
        byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

        byte[] cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes, iv);
        Arrays.fill(kek, (byte) 0);
        Arrays.fill(iv, (byte) 0);

        try {
            byte[] decrypted = decryptContent(encryptedContentInfo, unprotectedAttrsField, cek);
            LOG.log(
                    Level.INFO,
                    "EnvelopedData (ktri) decrypted successfully for recipient serial 0x{0}",
                    mySerial.toString(16));
            return decrypted;
        } finally {
            Arrays.fill(cek, (byte) 0);
        }
    }

    /**
     * Парсит SubjectPublicKeyInfo из GostR3410-KeyTransport.ephemeralPublicKey.
     *
     * <p>Формат: SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
     * Использует тот же кодировщик, что и X.509-сертификаты.
     */
    private static PublicKeyParameters parseEphemeralPublicKey(byte[] spkiDer)
            throws PkixException {
        byte[][] spkiParts = DerCodec.parseSequenceContents(spkiDer, 0);
        byte[] spki = DerCodec.encodeSequence(spkiParts[0], spkiParts[1]);
        return org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);
    }

    // ========================================================================
    // Общие методы
    // ========================================================================

    private static PublicKeyParameters extractEphemeralPublicKey(byte[] originatorField)
            throws PkixException {
        int[] oLenInfo = DerCodec.decodeLength(originatorField, 1);
        int oStart = 1 + oLenInfo[1];
        byte[] inner = Arrays.copyOfRange(originatorField, oStart, oStart + oLenInfo[0]);

        if ((inner[0] & 0xFF) == 0xA1) {
            int[] pkLen = DerCodec.decodeLength(inner, 1);
            int pkStart = 1 + pkLen[1];
            // originatorKey [1] IMPLICIT OriginatorPublicKey (RFC 5652 §6.2.2): тег [1]
            // заменяет тег SEQUENCE, поэтому содержимое — уже конкатенация
            // { algorithm, subjectPublicKey } без внешней обёртки. Возвращаем SEQUENCE-тег
            // на место, чтобы получить корректный SubjectPublicKeyInfo.
            byte[] originatorKey = Arrays.copyOfRange(inner, pkStart, pkStart + pkLen[0]);
            byte[] spki = DerCodec.encodeSequence(originatorKey);
            return org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);
        }
        throw new PkixException(PkixException.Reason.PARSE_ERROR, "Unsupported originator type");
    }

    private static byte[] extractUkm(byte[] ukmField) {
        int[] uLenInfo = DerCodec.decodeLength(ukmField, 1);
        int uStart = 1 + uLenInfo[1];
        return DerCodec.parseOctetString(ukmField, uStart);
    }

    private static byte[] decryptContent(
            byte[] encryptedContentInfo, byte[] unprotectedAttrsField, byte[] cek)
            throws PkixException {
        byte[][] eciParts = DerCodec.parseSequenceContents(encryptedContentInfo, 0);
        byte[] paramsDer = eciParts[1];
        byte[][] algParts = DerCodec.parseSequenceContents(paramsDer, 0);

        // Разбираем OID контентного шифра
        String contentAlgOid = DerCodec.parseOid(algParts[0], 0);
        boolean isOmac = GostOids.KUZ_CTR_ACPKM_OMAC.equals(contentAlgOid);

        byte[] ukm;
        if (algParts.length > 1 && (algParts[1][0] & 0xFF) == DerCodec.TAG_SEQUENCE) {
            byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
            if (ivSeq.length > 0 && (ivSeq[0][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                ukm = DerCodec.parseOctetString(ivSeq[0], 0);
            } else {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "IV/UKM (OCTET STRING) not found in cipher params SEQUENCE");
            }
        } else {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Cipher params (SEQUENCE) not found");
        }

        byte[] encContentField = eciParts[2];
        int encContentTag = encContentField[0] & 0xFF;
        byte[] encryptedContent;
        if (encContentTag == DerCodec.TAG_CTX_PRIMITIVE_0) {
            // Горячий путь crypto-gost (DER): [0] IMPLICIT primitive definite-length
            int[] ecLenInfo = DerCodec.decodeLength(encContentField, 1);
            int ecStart = 1 + ecLenInfo[1];
            encryptedContent = Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLenInfo[0]);
        } else if (encContentTag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
            // BER КриптоПРО: [0] IMPLICIT как constructed context-тег (A0 80 ... 00 00),
            // возможна сегментация OCTET STRING — собираем и склеиваем октеты
            try {
                encryptedContent = DerCodec.collectImplicitOctets(encContentField, 0);
            } catch (IllegalArgumentException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Failed to parse constructed [0] encryptedContent: " + e.getMessage());
            }
        } else {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "encryptedContent must be [0] IMPLICIT (primitive 0x80 or constructed 0xA0), got 0x"
                            + Integer.toHexString(encContentTag).toUpperCase());
        }

        SymmetricKey key = new SymmetricKey(cek);
        try {
            if (isOmac) {
                byte[] encryptedMac = extractEncryptedMac(unprotectedAttrsField);
                try {
                    return CmsOmacHelper.decrypt(encryptedContent, encryptedMac, cek, ukm);
                } catch (AuthenticationException e) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "OMAC verification failed: " + e.getMessage());
                }
            } else {
                return CtrAcpkmMode.decryptOnly(key, ukm, encryptedContent, AcpkmSectionSize.CMS);
            }
        } finally {
            key.destroy();
        }
    }

    /**
     * Извлекает значение {@code encryptedMac} из атрибута content-mac в unprotectedAttrs.
     *
     * @param unprotectedAttrsField поле unprotectedAttrs [1] IMPLICIT SET OF Attribute, или null
     * @return 16-байтовый зашифрованный MAC
     * @throws PkixException если атрибут не найден или имеет неверную структуру
     */
    private static byte[] extractEncryptedMac(byte[] unprotectedAttrsField) throws PkixException {
        if (unprotectedAttrsField == null) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "OMAC container missing unprotectedAttrs (content-mac attribute required)");
        }

        // unprotectedAttrs — [1] IMPLICIT SET OF Attribute (контекстный constructed тег 0xA1)
        int tag = unprotectedAttrsField[0] & 0xFF;
        if (tag != DerCodec.TAG_CTX_CONSTRUCTED_1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "unprotectedAttrs must be [1] IMPLICIT, got tag 0x"
                            + Integer.toHexString(tag).toUpperCase());
        }

        int[] uaLen = DerCodec.decodeLength(unprotectedAttrsField, 1);
        int uaStart = 1 + uaLen[1];
        int uaContentLen = uaLen[0];
        byte[] uaContent =
                Arrays.copyOfRange(unprotectedAttrsField, uaStart, uaStart + uaContentLen);

        // [1] IMPLICIT SET OF Attribute — тег 0xA1 заменяет тег SET OF.
        // Содержимое SET: непосредственно Attribute SEQUENCE (без явного 0x31).
        // Поддерживаем и вариант с явным SET внутри (старая кодировка).
        byte[][] attributes;
        int contentTag = uaContent[0] & 0xFF;
        if (contentTag == DerCodec.TAG_SET) {
            attributes = DerCodec.parseSetContents(uaContent, 0);
        } else {
            // Непосредственно SEQUENCE (или несколько) — собираем по одному
            List<byte[]> attrs = new ArrayList<>();
            int pos = 0;
            while (pos < uaContentLen) {
                int seqTag = uaContent[pos] & 0xFF;
                if (seqTag != DerCodec.TAG_SEQUENCE) {
                    break;
                }
                int[] seqLen = DerCodec.decodeLength(uaContent, pos + 1);
                int seqStart = pos + 1 + seqLen[1];
                int seqTotal = seqStart - pos + seqLen[0];
                attrs.add(Arrays.copyOfRange(uaContent, pos, seqTotal));
                pos = seqTotal;
            }
            attributes = attrs.toArray(new byte[0][]);
        }
        for (byte[] attrDer : attributes) {
            byte[][] attrParts = DerCodec.parseSequenceContents(attrDer, 0);
            String attrOid = DerCodec.parseOid(attrParts[0], 0);
            if (!GostOids.ID_CMS_MAC_ATTR.equals(attrOid)) {
                continue;
            }

            // attrParts[1] = SET { OCTET STRING }
            byte[][] setValues = DerCodec.parseSetContents(attrParts[1], 0);
            if (setValues.length != 1) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "content-mac attribute: expected 1 value, got " + setValues.length);
            }
            return DerCodec.parseOctetString(setValues[0], 0);
        }

        throw new PkixException(
                PkixException.Reason.PARSE_ERROR,
                "content-mac attribute ("
                        + GostOids.ID_CMS_MAC_ATTR
                        + ") not found in unprotectedAttrs");
    }
}
