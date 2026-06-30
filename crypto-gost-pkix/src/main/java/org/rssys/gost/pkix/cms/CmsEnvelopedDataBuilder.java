package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.CtrAcpkmMode;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель EnvelopedData (RFC 5652 §6) с ГОСТ-шифрованием.
 *
 * <p>Использует VKO ГОСТ Р 34.10-2012 для согласования ключа,
 * KExp15 для обёртывания CEK и Кузнечик CTR-ACPKM для шифрования данных.
 *
 * <p><b>Совместимость:</b> библиотека реализует KeyAgreeRecipientInfo
 * (RFC 5652 §6.2.2, VKO + KExp15). КриптоПРО 5.0 использует
 * KeyTransRecipientInfo с ГОСТ 28147-89 (RFC 4490 §5).
 * Совместимость на уровне RecipientInfo отсутствует:
 * разные поколения стандартов GOST CMS.</p>
 */
public final class CmsEnvelopedDataBuilder {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder");

    private static final int CEK_LENGTH = 32;
    private static final int IV_LENGTH = 8;
    private static final int UKM_LENGTH = 8;

    private byte[] data;
    private final List<RecipientEntry> recipients = new ArrayList<>();
    private String contentEncryptionOid = GostOids.KUZ_CTR_ACPKM;
    private String encryptedContentTypeOid = GostOids.PKCS7_DATA;
    private CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();

    private CmsEnvelopedDataBuilder() {}

    public static CmsEnvelopedDataBuilder create() {
        return new CmsEnvelopedDataBuilder();
    }

    /** Данные для шифрования. */
    public CmsEnvelopedDataBuilder data(byte[] data) {
        this.data = data.clone();
        return this;
    }

    /** Добавляет получателя (сертификат). */
    public CmsEnvelopedDataBuilder addRecipient(GostCertificate cert) {
        recipients.add(new RecipientEntry(cert));
        return this;
    }

    /** OID алгоритма шифрования содержимого (по умолчанию Кузнечик CTR-ACPKM). */
    public CmsEnvelopedDataBuilder contentEncryptionOid(String oid) {
        this.contentEncryptionOid = oid;
        return this;
    }

    /**
     * OID типа зашифрованного содержимого.
     * По умолчанию {@link GostOids#PKCS7_DATA id-data}.
     * Для вложения CMS-структур (SignedData внутри EnvelopedData)
     * устанавливается {@link GostOids#CMS_SIGNED_DATA id-signedData}.
     */
    public CmsEnvelopedDataBuilder encryptedContentType(String oid) {
        this.encryptedContentTypeOid = oid;
        return this;
    }

    /** Алгоритм обёртывания ключа (по умолчанию Kexp15CmsKeyWrap). */
    public CmsEnvelopedDataBuilder keyWrap(CmsKeyWrap keyWrap) {
        this.keyWrap = keyWrap;
        return this;
    }

    /**
     * Собирает EnvelopedData в DER.
     *
     * @return DER-байты ContentInfo(id-envelopedData)
     */
    public byte[] build() {
        if (data == null) throw new IllegalStateException("data not set");
        if (recipients.isEmpty()) throw new IllegalStateException("no recipients");

        LOG.log(
                Level.INFO,
                "Building EnvelopedData for {0} recipient(s), {1} byte(s) of data",
                recipients.size(),
                data.length);

        // 1. Генерируем CEK
        byte[] cek = new byte[CEK_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(cek);

        // 2. Генерируем IV для контентного шифра
        byte[] contentIv = new byte[IV_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(contentIv);

        try {
            // 3. Шифруем данные
            byte[] encryptedContent = encryptContent(cek, contentIv);

            // 4. Строим RecipientInfos
            List<byte[]> recipientInfoList = new ArrayList<>();
            for (RecipientEntry entry : recipients) {
                recipientInfoList.add(buildKeyAgreeRecipientInfo(entry, cek));
            }

            // 5. Строим EncryptedContentInfo
            byte[] encryptedContentInfo = buildEncryptedContentInfo(encryptedContent, contentIv);

            // 6. Строим EnvelopedData
            byte[] envelopedData = buildEnvelopedData(recipientInfoList, encryptedContentInfo);

            // 7. Оборачиваем в ContentInfo
            byte[] result = CmsContentInfo.encode(GostOids.CMS_ENVELOPED_DATA, envelopedData);
            LOG.log(
                    Level.INFO,
                    "EnvelopedData built successfully ({0} byte(s) encrypted)",
                    data.length);
            return result;
        } finally {
            // Затираем CEK и IV при любом исходе
            Arrays.fill(cek, (byte) 0);
            Arrays.fill(contentIv, (byte) 0);
        }
    }

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private byte[] encryptContent(byte[] cek, byte[] iv) {
        SymmetricKey key = new SymmetricKey(cek);
        try {
            return CtrAcpkmMode.encryptOnly(key, iv, data);
        } finally {
            key.destroy();
        }
    }

    private byte[] buildKeyAgreeRecipientInfo(RecipientEntry entry, byte[] cek) {
        // Извлекаем публичный ключ получателя
        PublicKeyParameters recipientPub = entry.certificate.getPublicKey();

        // Генерируем эфемерную пару
        ECParameters params = recipientPub.getParams();
        var ephemeralKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters ephemeralPriv = ephemeralKp.getPrivate();
        PublicKeyParameters ephemeralPub = ephemeralKp.getPublic();

        // Генерируем UKM
        byte[] ukmBytes = new byte[UKM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(ukmBytes);
        BigInteger ukm = new BigInteger(1, ukmBytes);

        // VKO: KEK = H_256(X_LE((h*UKM*d)*Q_peer))
        byte[] kek = KeyAgreement.vkoGostR3410_2012_256(ephemeralPriv, recipientPub, ukm);

        // Оборачиваем CEK
        byte[] wrappedCek;
        try {
            wrappedCek = keyWrap.wrap(cek, kek, ukmBytes);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }

        // Уничтожаем эфемерный приватный ключ после VKO
        ephemeralPriv.destroy();

        // version
        byte[] version = DerCodec.encodeInteger(CmsConstants.KEY_AGREE_V3);

        // originator: [0] EXPLICIT originatorKey
        byte[] originatorKey = buildOriginatorPublicKey(ephemeralPub);
        byte[] originator = DerCodec.encodeContextConstructed(0, originatorKey);

        // ukm: [1] EXPLICIT OCTET STRING
        byte[] ukmOctet = DerCodec.encodeOctetString(ukmBytes);
        byte[] ukmField = DerCodec.encodeContextConstructed(1, ukmOctet);

        // keyEncryptionAlgorithm: AGREEMENT_VKO_256 + key wrap OID параметры
        byte[] keyWrapParam = DerCodec.encodeSequence(DerCodec.encodeOid(keyWrap.algorithmOid()));
        byte[] keyEncryptAlg =
                CmsAlgorithmIdentifier.encode(GostOids.AGREEMENT_VKO_256, keyWrapParam);

        // recipientEncryptedKeys: SEQUENCE OF RecipientEncryptedKey
        byte[] rid = buildRecipientIdentifier(entry.certificate);
        byte[] encKey = DerCodec.encodeOctetString(wrappedCek);
        byte[] recipientKey = DerCodec.encodeSequence(rid, encKey);
        byte[] recipientKeys = DerCodec.encodeSequence(recipientKey);

        // RecipientInfo CHOICE: kari [1] EXPLICIT KeyAgreeRecipientInfo
        return DerCodec.encodeContextConstructed(
                1,
                DerCodec.encodeSequence(
                        version, originator, ukmField, keyEncryptAlg, recipientKeys));
    }

    private byte[] buildOriginatorPublicKey(PublicKeyParameters pubKey) {
        // OriginatorPublicKey: SEQUENCE { algorithm, publicKey BIT STRING }
        byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pubKey);
        // spki = SEQUENCE { algId, BIT STRING { OCTET STRING { pubKey } } }
        byte[][] spkiParts = DerCodec.parseSequenceContents(spki, 0);
        byte[] algId = spkiParts[0];
        byte[] pubKeyBitStr = spkiParts[1];

        // Для originatorKey формата:
        // [1] EXPLICIT OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey BIT STRING }
        byte[] originatorKey = DerCodec.encodeSequence(algId, pubKeyBitStr);
        return DerCodec.encodeContextConstructed(1, originatorKey);
    }

    private byte[] buildRecipientIdentifier(GostCertificate cert) {
        // rid: IssuerAndSerialNumber
        return CmsIssuerAndSerialNumber.encode(
                cert.getIssuerDnBytes(), cert.getSerialNumberBigInt());
    }

    private byte[] buildEncryptedContentInfo(byte[] encryptedContent, byte[] iv) {
        // EncryptedContentInfo:
        // SEQUENCE { contentType OID, contentEncryptionAlg AlgId, encryptedContent [0] IMPLICIT
        // OCTET STRING }
        byte[] contentTypeOid = DerCodec.encodeOid(encryptedContentTypeOid);

        // contentEncryptionAlgorithm с параметрами (IV)
        byte[] cipherParams = buildCipherParams(iv);
        byte[] cipherAlg = CmsAlgorithmIdentifier.encode(contentEncryptionOid, cipherParams);

        // encryptedContent: [0] IMPLICIT OCTET STRING (RFC 5652 §6.1)
        byte[] encContent = DerCodec.encodeTlv(DerCodec.TAG_CTX_PRIMITIVE_0, encryptedContent);

        return DerCodec.encodeSequence(contentTypeOid, cipherAlg, encContent);
    }

    private byte[] buildCipherParams(byte[] iv) {
        // Параметры для Кузнечик CTR-ACPKM по RFC 9337 §7.3:
        // Gost3412-15-Encryption-Parameters ::= SEQUENCE { ukm OCTET STRING }
        return DerCodec.encodeSequence(DerCodec.encodeOctetString(iv));
    }

    private byte[] buildEnvelopedData(List<byte[]> recipientInfoList, byte[] encryptedContentInfo) {
        // EnvelopedData:
        // SEQUENCE { version INTEGER, recipientInfos SET OF, encryptedContentInfo }
        byte[] version = DerCodec.encodeInteger(CmsConstants.ENVELOPED_DATA_V3);
        byte[] recipientInfos = DerCodec.encodeSetOf(recipientInfoList.toArray(new byte[0][]));

        return DerCodec.encodeSequence(version, recipientInfos, encryptedContentInfo);
    }

    // ========================================================================
    // Вспомогательные типы
    // ========================================================================

    private static class RecipientEntry {
        final GostCertificate certificate;

        RecipientEntry(GostCertificate certificate) {
            this.certificate = certificate;
        }
    }
}
