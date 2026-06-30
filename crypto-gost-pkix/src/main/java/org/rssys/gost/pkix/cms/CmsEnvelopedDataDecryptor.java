package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.util.Arrays;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Расшифровка CMS EnvelopedData.
 *
 * <p><b>Совместимость:</b> библиотека реализует KeyAgreeRecipientInfo
 * (RFC 5652 §6.2.2, VKO + KExp15). КриптоПРО 5.0 использует
 * KeyTransRecipientInfo с ГОСТ 28147-89 (RFC 4490 §5).
 * Совместимость на уровне RecipientInfo отсутствует:
 * разные поколения стандартов GOST CMS.</p>
 */
public final class CmsEnvelopedDataDecryptor {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsEnvelopedDataDecryptor");

    static {
        if (java.security.Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            java.security.Security.insertProviderAt(new RssysGostProvider(), 1);
        }
    }

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
        // [0] version, [1] recipientInfos (SET OF), [2] encryptedContentInfo
        byte[] recipientInfosField = envParts[1];
        byte[] encryptedContentInfo = envParts[2];

        // 2. Ищем свой RecipientEncryptedKey в SET OF
        try {
            BigInteger mySerial = recipientCert.getSerialNumberBigInt();
            byte[] myIssuer = recipientCert.getIssuerDnBytes();

            byte[][] riElems = DerCodec.parseSetContents(recipientInfosField, 0);
            for (byte[] riElem : riElems) {
                if ((riElem[0] & 0xFF) != 0xA1) { // только kari [1] EXPLICIT
                    LOG.log(
                            Level.DEBUG,
                            "Skipping non-KeyAgreeRecipientInfo (tag=0x{0})",
                            Integer.toHexString(riElem[0] & 0xFF).toUpperCase());
                    continue;
                }

                int[] kariLen = DerCodec.decodeLength(riElem, 1);
                int off = 1 + kariLen[1];
                byte[] kariDer = Arrays.copyOfRange(riElem, off, off + kariLen[0]);

                byte[][] kaParts = DerCodec.parseSequenceContents(kariDer, 0);
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

                    BigInteger ukm = new BigInteger(1, ukmBytes);
                    byte[] kek =
                            KeyAgreement.vkoGostR3410_2012_256(recipientKey, ephemeralPub, ukm);
                    byte[] cek = keyWrap.unwrap(wrappedCek, kek, ukmBytes);
                    Arrays.fill(kek, (byte) 0);

                    try {
                        byte[] decrypted = decryptContent(encryptedContentInfo, cek);
                        LOG.log(
                                Level.INFO,
                                "EnvelopedData decrypted successfully for recipient serial 0x{0}",
                                mySerial.toString(16));
                        return decrypted;
                    } finally {
                        Arrays.fill(cek, (byte) 0);
                    }
                }
            }

            throw new PkixException(PkixException.Reason.OTHER, "Recipient key not found");
        } catch (RuntimeException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Decryption failed: " + e.getMessage(), e);
        }
    }

    private static PublicKeyParameters extractEphemeralPublicKey(byte[] originatorField)
            throws PkixException {
        int[] oLenInfo = DerCodec.decodeLength(originatorField, 1);
        int oStart = 1 + oLenInfo[1];
        byte[] inner = Arrays.copyOfRange(originatorField, oStart, oStart + oLenInfo[0]);

        // originator: [0] EXPLICIT -> [1] EXPLICIT OriginatorPublicKey
        if ((inner[0] & 0xFF) == 0xA1) {
            int[] pkLen = DerCodec.decodeLength(inner, 1);
            int pkStart = 1 + pkLen[1];
            byte[] originatorKey = Arrays.copyOfRange(inner, pkStart, pkStart + pkLen[0]);
            // originatorKey = SEQUENCE { algId, BIT STRING } -> SubjectPublicKeyInfo
            byte[][] opkParts = DerCodec.parseSequenceContents(originatorKey, 0);
            byte[] spki = DerCodec.encodeSequence(opkParts[0], opkParts[1]);
            return org.rssys.gost.jca.spec.GostDerCodec.decodePublicKey(spki);
        }
        throw new PkixException(PkixException.Reason.PARSE_ERROR, "Unsupported originator type");
    }

    private static byte[] extractUkm(byte[] ukmField) {
        int[] uLenInfo = DerCodec.decodeLength(ukmField, 1);
        int uStart = 1 + uLenInfo[1];
        return DerCodec.parseOctetString(ukmField, uStart);
    }

    private static byte[] decryptContent(byte[] encryptedContentInfo, byte[] cek)
            throws PkixException {
        byte[][] eciParts = DerCodec.parseSequenceContents(encryptedContentInfo, 0);
        // [0] contentType OID, [1] contentEncryptionAlgorithm, [2] encryptedContent [0] IMPLICIT
        byte[] paramsDer = eciParts[1];
        // Параметры: SEQUENCE { ukm OCTET STRING } (RFC 9337 §7.3)
        byte[][] algParts = DerCodec.parseSequenceContents(paramsDer, 0);
        byte[] iv;
        if (algParts.length > 1 && (algParts[1][0] & 0xFF) == DerCodec.TAG_SEQUENCE) {
            byte[][] ivSeq = DerCodec.parseSequenceContents(algParts[1], 0);
            if (ivSeq.length > 0 && (ivSeq[0][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                iv = DerCodec.parseOctetString(ivSeq[0], 0);
            } else {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "IV (OCTET STRING) not found in cipher params SEQUENCE");
            }
        } else {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "IV (SEQUENCE) not found in cipher parameters");
        }

        byte[] encContentField = eciParts[2];
        if ((encContentField[0] & 0xFF) != DerCodec.TAG_CTX_PRIMITIVE_0) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "encryptedContent must be [0] IMPLICIT (primitive 0x80), got 0x"
                            + Integer.toHexString(encContentField[0] & 0xFF).toUpperCase());
        }
        int[] ecLenInfo = DerCodec.decodeLength(encContentField, 1);
        int ecStart = 1 + ecLenInfo[1];
        byte[] encryptedContent =
                Arrays.copyOfRange(encContentField, ecStart, ecStart + ecLenInfo[0]);

        SymmetricKey key = new SymmetricKey(cek);
        try {
            return CtrAcpkmMode.decryptOnly(key, iv, encryptedContent);
        } finally {
            key.destroy();
        }
    }
}
