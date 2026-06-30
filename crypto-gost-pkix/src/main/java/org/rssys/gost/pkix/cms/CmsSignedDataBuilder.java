package org.rssys.gost.pkix.cms;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель SignedData (RFC 5652 §5.1—§5.3) с ГОСТ подписью.
 *
 * <p>Собирает CMS SignedData, совместимую с российскими профилями.
 * Подпись вычисляется от DER-кодированных signedAttrs (Стрибог-256 + ГОСТ Р 34.10-2012).
 */
public final class CmsSignedDataBuilder {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.pkix.cms.CmsSignedDataBuilder");

    private byte[] data;
    private boolean encapsulated = true;
    private String digestOid = GostOids.DIGEST_256;
    private String eContentTypeOid = GostOids.PKCS7_DATA;
    private final List<SignerEntry> signers = new ArrayList<>();
    private final List<GostCertificate> certificates = new ArrayList<>();
    private final List<SignerAttribute> extraAttrs = new ArrayList<>();
    private final List<SignerAttribute> unsignedAttrs = new ArrayList<>();
    private boolean cadesAttributes;

    private CmsSignedDataBuilder() {}

    public static CmsSignedDataBuilder create() {
        return new CmsSignedDataBuilder();
    }

    /** Данные для подписи. */
    public CmsSignedDataBuilder data(byte[] data) {
        this.data = data.clone();
        return this;
    }

    /**
     * Режим detached-подписи (RFC 5652 §5.2).
     * {@code true} — detached подпись (данные не вкладываются в SignedData),
     * {@code false} — данные инкапсулированы в SignedData (по умолчанию).
     */
    public CmsSignedDataBuilder detached(boolean detached) {
        this.encapsulated = !detached;
        return this;
    }

    /**
     * Алгоритм дайджеста. По умолчанию {@link GostOids#DIGEST_256 Streebog-256}.
     * Допустимые значения: {@link GostOids#DIGEST_256}, {@link GostOids#DIGEST_512}.
     */
    public CmsSignedDataBuilder digestAlgorithm(String digestOid) {
        this.digestOid = digestOid;
        return this;
    }

    /**
     * OID типа инкапсулированного содержимого.
     * По умолчанию {@link GostOids#PKCS7_DATA id-data}.
     * Для вложения CMS-структур (EnvelopedData внутри SignedData)
     * устанавливается {@link GostOids#CMS_ENVELOPED_DATA id-envelopedData}.
     * При отличии от id-data версия SignedData автоматически повышается до 3 (RFC 5652 §5.1).
     */
    public CmsSignedDataBuilder contentType(String eContentTypeOid) {
        this.eContentTypeOid = eContentTypeOid;
        return this;
    }

    /** Добавляет подписанта. */
    public CmsSignedDataBuilder addSigner(PrivateKeyParameters privateKey, GostCertificate cert) {
        signers.add(new SignerEntry(privateKey, cert));
        return this;
    }

    /** Добавляет дополнительный сертификат (промежуточный CA и т.д.). */
    public CmsSignedDataBuilder addCertificate(GostCertificate cert) {
        certificates.add(cert);
        return this;
    }

    /** Добавляет пользовательский signed-атрибут. */
    public CmsSignedDataBuilder addSignedAttribute(String attrOid, byte[] value) {
        extraAttrs.add(new SignerAttribute(attrOid, value));
        return this;
    }

    /** Добавляет unsigned-атрибут (RFC 5652 §5.3). Используется для CAdES-T меток времени. */
    public CmsSignedDataBuilder addUnsignedAttribute(String attrOid, byte[] value) {
        unsignedAttrs.add(new SignerAttribute(attrOid, value));
        return this;
    }

    /**
     * Включает автоматическое добавление CAdES signed-атрибутов
     * ({@code signingCertificateV2}) для каждого подписанта.
     */
    public CmsSignedDataBuilder withCAdES() {
        this.cadesAttributes = true;
        return this;
    }

    /**
     * Собирает SignedData в DER.
     *
     * @return DER-байты ContentInfo(id-signedData)
     */
    public byte[] build() {
        if (data == null) throw new IllegalStateException("data not set");
        if (signers.isEmpty()) throw new IllegalStateException("no signers");

        LOG.log(
                Level.INFO,
                "Building SignedData with {0} signer(s), {1} byte(s) of data",
                signers.size(),
                data.length);

        boolean is512 = GostOids.DIGEST_512.equals(digestOid);

        // 1. Вычисляем дайджест данных
        byte[] dataDigest = is512 ? Digest.digest512(data) : Digest.digest256(data);

        // Предвычисляем OID-кодирования для переиспользования
        byte[] digestAlgIdDer = CmsAlgorithmIdentifier.encodeOnlyOid(digestOid);
        String signAlgOid = is512 ? GostOids.SIGN_ALG_512 : GostOids.SIGN_ALG_256;
        byte[] signAlgIdDer = CmsAlgorithmIdentifier.encodeOnlyOid(signAlgOid);
        byte[] eContentTypeOidDer = DerCodec.encodeOid(eContentTypeOid);

        // 2. Строим SignerInfo для каждого подписанта
        List<byte[]> signerInfoList = new ArrayList<>();
        List<byte[]> digestAlgIds = new ArrayList<>();

        for (SignerEntry entry : signers) {
            signerInfoList.add(
                    buildSignerInfo(
                            entry,
                            dataDigest,
                            digestAlgIdDer,
                            signAlgIdDer,
                            eContentTypeOidDer,
                            is512));
            digestAlgIds.add(digestAlgIdDer);
        }

        // 3. Собираем EncapsulatedContentInfo
        byte[] encapContentInfo = buildEncapsulatedContentInfo(eContentTypeOidDer);

        // 4. Собираем сертификаты
        byte[] certsField = buildCertificates();

        // 5. Собираем SignedData
        byte[] signedData =
                buildSignedData(digestAlgIds, encapContentInfo, certsField, signerInfoList);

        // 6. Оборачиваем в ContentInfo
        byte[] result = CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
        LOG.log(Level.INFO, "SignedData built successfully ({0} byte(s) data)", data.length);
        return result;
    }

    // ========================================================================
    // Приватные методы
    // ========================================================================

    private byte[] buildSignerInfo(
            SignerEntry entry,
            byte[] dataDigest,
            byte[] digestAlgIdDer,
            byte[] signAlgIdDer,
            byte[] eContentTypeOidDer,
            boolean is512) {
        // signedAttrs: contentType + messageDigest + пользовательские
        List<byte[]> attrList = new ArrayList<>();

        // contentType
        attrList.add(CmsAttribute.encode(GostOids.ATTR_CONTENT_TYPE, eContentTypeOidDer));

        // messageDigest
        byte[] digestOctet = DerCodec.encodeOctetString(dataDigest);
        attrList.add(CmsAttribute.encode(GostOids.ATTR_MESSAGE_DIGEST, digestOctet));

        // Пользовательские атрибуты
        for (SignerAttribute sa : extraAttrs) {
            attrList.add(CmsAttribute.encode(sa.oid, sa.value));
        }

        // CAdES-BES: signingCertificateV2 для этого подписанта
        if (cadesAttributes) {
            attrList.add(
                    CmsAttribute.encode(
                            GostOids.SIGNING_CERTIFICATE_V2,
                            CAdESAttributes.signingCertificateV2(entry.certificate)));
        }

        // SET OF signedAttrs (DER-сортировка) — для хэширования используется
        // кодирование с тегом SET (0x31), а не [0] IMPLICIT (RFC 5652 §5.4)
        byte[][] sortedAttrs = attrList.toArray(new byte[0][]);
        DerCodec.sortDer(sortedAttrs);
        byte[] signedAttrsForHash = DerCodec.encodeSet(sortedAttrs);

        // [0] IMPLICIT SET OF Attribute — для включения в SignerInfo
        byte[] signedAttrsWrapped =
                DerCodec.encodeContextConstructed(0, DerCodec.concat(sortedAttrs));

        // Вычисляем хэш SET-кодированных signedAttrs и подписываем
        byte[] signedAttrsHash =
                is512 ? Digest.digest512(signedAttrsForHash) : Digest.digest256(signedAttrsForHash);
        byte[] signatureValue = Signature.signHash(signedAttrsHash, entry.privateKey);

        // sid
        byte[] sid =
                CmsIssuerAndSerialNumber.encode(
                        entry.certificate.getIssuerDnBytes(),
                        entry.certificate.getSerialNumberBigInt());

        // signature — вложить в OCTET STRING
        byte[] sigOctet = DerCodec.encodeOctetString(signatureValue);

        // [1] IMPLICIT unsignedAttrs — если есть
        byte[] unsignedAttrsWrapped = new byte[0];
        if (!unsignedAttrs.isEmpty()) {
            byte[][] unsignedAttrDer = new byte[unsignedAttrs.size()][];
            for (int i = 0; i < unsignedAttrs.size(); i++) {
                SignerAttribute sa = unsignedAttrs.get(i);
                unsignedAttrDer[i] = CmsAttribute.encode(sa.oid, sa.value);
            }
            unsignedAttrsWrapped =
                    DerCodec.encodeContextConstructed(1, DerCodec.concat(unsignedAttrDer));
        }

        // SignerInfo SEQUENCE
        byte[][] signerInfoParts;
        if (unsignedAttrsWrapped.length > 0) {
            signerInfoParts =
                    new byte[][] {
                        DerCodec.encodeInteger(CmsConstants.SIGNER_INFO_V1),
                        sid,
                        digestAlgIdDer,
                        signedAttrsWrapped,
                        signAlgIdDer,
                        sigOctet,
                        unsignedAttrsWrapped
                    };
        } else {
            signerInfoParts =
                    new byte[][] {
                        DerCodec.encodeInteger(CmsConstants.SIGNER_INFO_V1),
                        sid,
                        digestAlgIdDer,
                        signedAttrsWrapped,
                        signAlgIdDer,
                        sigOctet
                    };
        }
        return DerCodec.encodeSequence(signerInfoParts);
    }

    private byte[] buildEncapsulatedContentInfo(byte[] eContentTypeOidDer) {
        if (encapsulated) {
            byte[] content = DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data));
            return DerCodec.encodeSequence(eContentTypeOidDer, content);
        } else {
            // detached: content отсутствует
            return DerCodec.encodeSequence(eContentTypeOidDer);
        }
    }

    private byte[] buildCertificates() {
        List<byte[]> certList = new ArrayList<>();
        for (SignerEntry entry : signers) {
            certList.add(entry.getCertDer());
        }
        for (GostCertificate c : certificates) {
            certList.add(c.getEncoded());
        }
        if (certList.isEmpty()) {
            return new byte[0];
        }
        // [0] IMPLICIT SET OF Certificate — тег 0xA0 заменяет SET (X.690 §8.14)
        byte[][] sorted = certList.toArray(new byte[0][]);
        java.util.Arrays.sort(sorted, DerCodec::compareDer);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
    }

    private byte[] buildSignedData(
            List<byte[]> digestAlgIds,
            byte[] encapContentInfo,
            byte[] certsField,
            List<byte[]> signerInfoList) {
        // version: 3 если eContentType != id-data, иначе 1 (RFC 5652 §5.1)
        int versionNum =
                GostOids.PKCS7_DATA.equals(eContentTypeOid)
                        ? CmsConstants.SIGNED_DATA_V1
                        : CmsConstants.SIGNED_DATA_V3;
        byte[] version = DerCodec.encodeInteger(versionNum);

        // digestAlgorithms (SET OF)
        byte[] digestAlgs = DerCodec.encodeSetOf(digestAlgIds.toArray(new byte[0][]));

        // signerInfos (SET OF)
        byte[] signerInfos = DerCodec.encodeSetOf(signerInfoList.toArray(new byte[0][]));

        // SignedData SEQUENCE (RFC 5652 §5.1)
        if (certsField.length == 0) {
            return DerCodec.encodeSequence(version, digestAlgs, encapContentInfo, signerInfos);
        } else {
            return DerCodec.encodeSequence(
                    version, digestAlgs, encapContentInfo, certsField, signerInfos);
        }
    }

    // ========================================================================
    // Вспомогательные типы
    // ========================================================================

    private static class SignerEntry {
        final PrivateKeyParameters privateKey;
        final GostCertificate certificate;
        private byte[] certDer;

        SignerEntry(PrivateKeyParameters privateKey, GostCertificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        byte[] getCertDer() {
            if (certDer == null) {
                certDer = certificate.getEncoded();
            }
            return certDer;
        }
    }

    private static class SignerAttribute {
        final String oid;
        final byte[] value;

        SignerAttribute(String oid, byte[] value) {
            this.oid = oid;
            this.value = value.clone();
        }
    }
}
