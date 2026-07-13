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
import org.rssys.gost.cipher.mode.AcpkmSectionSize;
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
 * <p>По умолчанию используется KeyTransRecipientInfo (ktri)
 * в соответствии с ТК26 §8.2: ktri — обязателен для совместимых реализаций,
 * kari — опционален.
 *
 * <p>Использует VKO ГОСТ Р 34.10-2012 для согласования ключа,
 * KExp15 для обёртывания CEK и Кузнечик CTR-ACPKM для шифрования данных.
 */
public final class CmsEnvelopedDataBuilder {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsEnvelopedDataBuilder");

    private static final int CEK_LENGTH = 32;
    private static final int CONTENT_UKM_LENGTH = 16;
    private static final int IV_LENGTH = 8;
    private static final int UKM_LENGTH = 32;

    private byte[] data;
    private final List<RecipientEntry> recipients = new ArrayList<>();
    private String contentEncryptionOid = GostOids.KUZ_CTR_ACPKM;
    private String encryptedContentTypeOid = GostOids.PKCS7_DATA;
    private CmsKeyWrap keyWrap = new Kexp15CmsKeyWrap();
    private final boolean useKari;
    private boolean useOmac;

    private CmsEnvelopedDataBuilder(boolean useKari) {
        this.useKari = useKari;
    }

    /**
     * Создаёт построитель с KeyTransRecipientInfo (ktri) — основной формат по ТК26 §8.2.
     */
    public static CmsEnvelopedDataBuilder create() {
        return new CmsEnvelopedDataBuilder(false);
    }

    /**
     * Создаёт построитель с KeyAgreeRecipientInfo (kari) — опциональный формат по ТК26 §8.2.2.
     */
    public static CmsEnvelopedDataBuilder createKari() {
        return new CmsEnvelopedDataBuilder(true);
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
     * Включает имитовставку (OMAC) для контентного шифрования по ТК26 §8.3.1.
     *
     * <p>Устанавливает OID {@code id-gostr3412-2015-kuznyechik-ctracpkm-omac}
     * и CMS-профильный Mac-and-Encrypt согласно Р 1323565.1.025-2019 §8.3.2:
     * CMAC вычисляется по открытому тексту, шифруется и выносится в
     * {@code unprotectedAttrs} как атрибут {@code content-mac}.
     *
     * <p><b>ACPKM-рекейинг.</b> Секционная смена ключа выполняется каждые 256 КБ
     * (ГОСТ Р 34.13-2015 §6.2).
     */
    public CmsEnvelopedDataBuilder withOmac() {
        this.useOmac = true;
        this.contentEncryptionOid = GostOids.KUZ_CTR_ACPKM_OMAC;
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
                "Building EnvelopedData ({0}{1}) for {2} recipient(s), {3} byte(s) of data",
                useKari ? "kari" : "ktri",
                useOmac ? "+omac" : "",
                recipients.size(),
                data.length);

        // 1. Генерируем CEK
        byte[] cek = new byte[CEK_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(cek);

        // 2. Генерируем UKM/IV для контентного шифра
        byte[] contentUkm = new byte[CONTENT_UKM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(contentUkm);
        byte[] contentIv = Arrays.copyOf(contentUkm, IV_LENGTH);

        try {
            // 3. Шифруем данные
            byte[] encryptedContent;
            byte[] unprotectedAttrsField = null;
            if (useOmac) {
                CmsOmacHelper.EncryptResult omacResult =
                        CmsOmacHelper.encrypt(data, cek, contentUkm);
                encryptedContent = omacResult.encryptedContent();
                // unprotectedAttrs [1] IMPLICIT SET OF Attribute
                // [1] IMPLICIT означает, что A1-тег заменяет тег SET OF:
                // содержимое — непосредственно Attribute SEQUENCE, без явного 0x31
                unprotectedAttrsField =
                        DerCodec.encodeContextConstructed(
                                1, omacResult.macAttribute().derEncoded());
            } else {
                encryptedContent = encryptContent(cek, contentIv);
            }

            // 4. Строим RecipientInfos
            List<byte[]> recipientInfoList = new ArrayList<>();
            for (RecipientEntry entry : recipients) {
                if (useKari) {
                    recipientInfoList.add(buildKeyAgreeRecipientInfo(entry, cek));
                } else {
                    recipientInfoList.add(buildKeyTransRecipientInfo(entry, cek));
                }
            }

            // 5. Строим EncryptedContentInfo
            byte[] encryptedContentInfo = buildEncryptedContentInfo(encryptedContent, contentUkm);

            // 6. Строим EnvelopedData
            byte[] envelopedData =
                    buildEnvelopedData(
                            recipientInfoList, encryptedContentInfo, unprotectedAttrsField);

            // 7. Оборачиваем в ContentInfo
            byte[] result = CmsContentInfo.encode(GostOids.CMS_ENVELOPED_DATA, envelopedData);
            LOG.log(
                    Level.INFO,
                    "EnvelopedData built successfully ({0} byte(s) encrypted)",
                    data.length);
            return result;
        } finally {
            Arrays.fill(cek, (byte) 0);
            Arrays.fill(contentIv, (byte) 0);
            Arrays.fill(contentUkm, (byte) 0);
        }
    }

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private byte[] encryptContent(byte[] cek, byte[] iv) {
        SymmetricKey key = new SymmetricKey(cek);
        try {
            return CtrAcpkmMode.encryptOnly(key, iv, data, AcpkmSectionSize.CMS);
        } finally {
            key.destroy();
        }
    }

    /**
     * Строит KeyTransRecipientInfo (ktri) по ТК26 §8.2.1.
     *
     * <p>Структура:
     * <pre>
     * KeyTransRecipientInfo ::= SEQUENCE {
     *     version               CMSVersion,
     *     rid                   RecipientIdentifier,
     *     keyEncryptionAlgorithm SEQUENCE {
     *         algorithm  OID (kuznyechik-kexp15),
     *         parameters SEQUENCE { algorithm OID (VKO-256) }},
     *     encryptedKey          OCTET STRING {
     *         GostR3410-KeyTransport SEQUENCE {
     *             encryptedKey       OCTET STRING (KExp15 output),
     *             ephemeralPublicKey SubjectPublicKeyInfo,
     *             ukm                OCTET STRING (32 байта) }}}
     * </pre>
     */
    private byte[] buildKeyTransRecipientInfo(RecipientEntry entry, byte[] cek) {
        PublicKeyParameters recipientPub = entry.certificate.getPublicKey();
        ECParameters params = recipientPub.getParams();

        var ephemeralKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters ephemeralPriv = ephemeralKp.getPrivate();
        PublicKeyParameters ephemeralPub = ephemeralKp.getPublic();

        byte[] ukmBytes = new byte[UKM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(ukmBytes);
        BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);

        boolean is512 = params.hlen == GostOids.STREEBOG_512_HASH_LEN;
        byte[] kek =
                is512
                        ? KeyAgreement.vkoGostR3410_2012_512(ephemeralPriv, recipientPub, ukm)
                        : KeyAgreement.vkoGostR3410_2012_256(ephemeralPriv, recipientPub, ukm);

        // IV = UKM[24..31] (последние 8 из 32, формула ТК26: UKM[25..24+n/2])
        byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

        byte[] wrappedCek;
        try {
            wrappedCek = keyWrap.wrap(cek, kek, ukmBytes, iv);
        } finally {
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }

        ephemeralPriv.destroy();

        // version = 0 (rid = issuerAndSerialNumber)
        byte[] version = DerCodec.encodeInteger(0);

        // rid: IssuerAndSerialNumber
        byte[] rid =
                CmsIssuerAndSerialNumber.encode(
                        entry.certificate.getIssuerDnBytes(),
                        entry.certificate.getSerialNumberBigInt());

        // keyEncryptionAlgorithm: kuznyechik-kexp15, params = SEQUENCE { VKO-256 }
        byte[] kegParams = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.AGREEMENT_VKO_256));
        byte[] keyEncAlg =
                CmsAlgorithmIdentifier.encode(GostOids.WRAP_KUZNYECHIK_KEXP15, kegParams);

        // GostR3410-KeyTransport
        byte[] sessionEncryptedKey = DerCodec.encodeOctetString(wrappedCek);
        byte[] ephemeralPubKeyDer =
                buildSubjectPublicKeyInfo(ephemeralPub, entry.certificate.getSpkiAlgorithmId());
        byte[] ukmOctet = DerCodec.encodeOctetString(ukmBytes);
        byte[] keyTransport =
                DerCodec.encodeSequence(sessionEncryptedKey, ephemeralPubKeyDer, ukmOctet);

        // encryptedKey = OCTET STRING { GostR3410-KeyTransport }
        byte[] encryptedKey = DerCodec.encodeOctetString(keyTransport);

        // KeyTransRecipientInfo — plain SEQUENCE (первый элемент CHOICE без номера тега)
        return DerCodec.encodeSequence(version, rid, keyEncAlg, encryptedKey);
    }

    /**
     * Строит KeyAgreeRecipientInfo (kari) по RFC 5652 §6.2.2.
     *
     * <p>Использует UKM=32 байта (ТК26 §8.2.2), IV из UKM[24..31].
     */
    private byte[] buildKeyAgreeRecipientInfo(RecipientEntry entry, byte[] cek) {
        PublicKeyParameters recipientPub = entry.certificate.getPublicKey();

        ECParameters params = recipientPub.getParams();
        var ephemeralKp = KeyGenerator.generateKeyPair(params);
        PrivateKeyParameters ephemeralPriv = ephemeralKp.getPrivate();
        PublicKeyParameters ephemeralPub = ephemeralKp.getPublic();

        byte[] ukmBytes = new byte[UKM_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(ukmBytes);
        BigInteger ukm = Kexp15CmsKeyWrap.kegVkoUkm(ukmBytes);

        // Вариант VKO (256/512) определяется кривой ключа получателя (ТК26 CMS-профиль).
        boolean is512 = params.hlen == GostOids.STREEBOG_512_HASH_LEN;
        String agreementOid = is512 ? GostOids.AGREEMENT_VKO_512 : GostOids.AGREEMENT_VKO_256;
        byte[] kek =
                is512
                        ? KeyAgreement.vkoGostR3410_2012_512(ephemeralPriv, recipientPub, ukm)
                        : KeyAgreement.vkoGostR3410_2012_256(ephemeralPriv, recipientPub, ukm);

        // IV = UKM[24..31] (последние 8 из 32, формула ТК26)
        byte[] iv = Arrays.copyOfRange(ukmBytes, 24, 32);

        byte[] wrappedCek;
        try {
            wrappedCek = keyWrap.wrap(cek, kek, ukmBytes, iv);
        } finally {
            Arrays.fill(kek, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }

        ephemeralPriv.destroy();

        // version
        byte[] version = DerCodec.encodeInteger(CmsConstants.KEY_AGREE_V3);

        // originator: [0] EXPLICIT originatorKey
        byte[] originatorKey =
                buildOriginatorPublicKey(ephemeralPub, entry.certificate.getSpkiAlgorithmId());
        byte[] originator = DerCodec.encodeContextConstructed(0, originatorKey);

        // ukm: [1] EXPLICIT OCTET STRING
        byte[] ukmOctet = DerCodec.encodeOctetString(ukmBytes);
        byte[] ukmField = DerCodec.encodeContextConstructed(1, ukmOctet);

        // keyEncryptionAlgorithm: внешний OID — алгоритм key wrap (kexp15), а параметры —
        // SEQUENCE { agreement-OID } (ТК26/gost-engine: id-tc26-agreement-...). Именно такую
        // вложенность продуцируют и принимают эталонные реализации.
        byte[] keyWrapParam = DerCodec.encodeSequence(DerCodec.encodeOid(agreementOid));
        byte[] keyEncryptAlg = CmsAlgorithmIdentifier.encode(keyWrap.algorithmOid(), keyWrapParam);

        // recipientEncryptedKeys: SEQUENCE OF RecipientEncryptedKey
        byte[] rid = buildRecipientIdentifier(entry.certificate);
        byte[] encKey = DerCodec.encodeOctetString(wrappedCek);
        byte[] recipientKey = DerCodec.encodeSequence(rid, encKey);
        byte[] recipientKeys = DerCodec.encodeSequence(recipientKey);

        // RecipientInfo CHOICE: kari [1] IMPLICIT KeyAgreeRecipientInfo (RFC 5652 §6.2.1).
        // Модуль CMS объявлен DEFINITIONS IMPLICIT TAGS, поэтому тег [1] ЗАМЕНЯЕТ тег SEQUENCE:
        // поля идут напрямую под [1], без вложенного SEQUENCE. Иначе контейнер не читается
        // эталонными реализациями (openssl gost-engine, КриптоПро).
        byte[] kariBody =
                DerCodec.concat(version, originator, ukmField, keyEncryptAlg, recipientKeys);
        return DerCodec.encodeContextConstructed(1, kariBody);
    }

    /**
     * Кодирует SubjectPublicKeyInfo через существующий кодировщик
     * (тот же, что используется для X.509-сертификатов).
     */
    private byte[] buildSubjectPublicKeyInfo(
            PublicKeyParameters pubKey, byte[] recipientSpkiAlgId) {
        byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pubKey);
        byte[][] spkiParts = DerCodec.parseSequenceContents(spki, 0);
        // Р 1323565.1.025-2019 §8.4.2.2 (шаг 4): AlgorithmIdentifier эфемерного ключа обязан
        // в точности совпадать с представлением в сертификате получателя (иначе КриптоПро
        // не может согласовать ключ). Берём algId получателя дословно, оставляя только
        // BIT STRING эфемерного ключа. Без этого paramSet канонизируется (XchA -> CryptoPro-A).
        return DerCodec.encodeSequence(recipientSpkiAlgId, spkiParts[1]);
    }

    private byte[] buildOriginatorPublicKey(PublicKeyParameters pubKey, byte[] recipientSpkiAlgId) {
        byte[] spki = org.rssys.gost.jca.spec.GostDerCodec.encodePublicKey(pubKey);
        byte[][] spkiParts = DerCodec.parseSequenceContents(spki, 0);
        byte[] pubKeyBitStr = spkiParts[1];
        // См. buildSubjectPublicKeyInfo: algId эфемерного ключа = algId получателя.
        // originatorKey [1] IMPLICIT OriginatorPublicKey (RFC 5652 §6.2.2): тег [1] заменяет
        // тег SEQUENCE, поэтому поля { algorithm, subjectPublicKey } идут напрямую под [1].
        byte[] originatorBody = DerCodec.concat(recipientSpkiAlgId, pubKeyBitStr);
        return DerCodec.encodeContextConstructed(1, originatorBody);
    }

    private byte[] buildRecipientIdentifier(GostCertificate cert) {
        return CmsIssuerAndSerialNumber.encode(
                cert.getIssuerDnBytes(), cert.getSerialNumberBigInt());
    }

    private byte[] buildEncryptedContentInfo(byte[] encryptedContent, byte[] contentUkm) {
        byte[] contentTypeOid = DerCodec.encodeOid(encryptedContentTypeOid);

        byte[] cipherParams = buildCipherParams(contentUkm);
        byte[] cipherAlg = CmsAlgorithmIdentifier.encode(contentEncryptionOid, cipherParams);

        byte[] encContent = DerCodec.encodeTlv(DerCodec.TAG_CTX_PRIMITIVE_0, encryptedContent);

        return DerCodec.encodeSequence(contentTypeOid, cipherAlg, encContent);
    }

    private byte[] buildCipherParams(byte[] ukm) {
        return DerCodec.encodeSequence(DerCodec.encodeOctetString(ukm));
    }

    private byte[] buildEnvelopedData(
            List<byte[]> recipientInfoList,
            byte[] encryptedContentInfo,
            byte[] unprotectedAttrsField) {
        // RFC 5652 §6.1: version = 0, если все RecipientInfo version 0 (ktri с
        // issuerAndSerialNumber) и нет originatorInfo/unprotectedAttrs; иначе (kari
        // даёт RecipientInfo version 3) — ветвь ELSE -> version 2. pwri/ori (-> 3)
        // и originatorInfo (-> 4) билдер не формирует.
        // OMAC добавляет unprotectedAttrs — тоже version 2.
        int envelopedVersion =
                (useKari || useOmac)
                        ? CmsConstants.ENVELOPED_DATA_V2
                        : CmsConstants.ENVELOPED_DATA_V0;
        byte[] version = DerCodec.encodeInteger(envelopedVersion);
        byte[] recipientInfos = DerCodec.encodeSetOf(recipientInfoList.toArray(new byte[0][]));

        if (unprotectedAttrsField != null) {
            return DerCodec.encodeSequence(
                    version, recipientInfos, encryptedContentInfo, unprotectedAttrsField);
        }
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
