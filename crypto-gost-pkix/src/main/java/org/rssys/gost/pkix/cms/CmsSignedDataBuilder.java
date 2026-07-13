package org.rssys.gost.pkix.cms;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
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
    private boolean digestExplicitlySet;
    private String eContentTypeOid = GostOids.PKCS7_DATA;
    private final List<SignerEntry> signers = new ArrayList<>();
    private final List<GostCertificate> certificates = new ArrayList<>();
    private final List<GostCrl> crls = new ArrayList<>();
    private final List<SignerAttribute> extraAttrs = new ArrayList<>();
    private final List<SignerAttribute> unsignedAttrs = new ArrayList<>();
    private boolean cadesAttributes;
    private boolean certsOnly;
    private String contentTspUrl;
    private TspTransport contentTspTransport;
    private List<GostCertificate> contentTspTrustedCerts;

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
        this.digestExplicitlySet = true;
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

    /** Добавляет подписанта (может быть HSM-адаптером). */
    public CmsSignedDataBuilder addSigner(GostSigner signer, GostCertificate cert) {
        if (!digestExplicitlySet) {
            int keySize = cert.getKeySize();
            String autoOid = GostSignatureHelper.keySizeToDigestOid(keySize);
            if (!signers.isEmpty() && !autoOid.equals(digestOid)) {
                throw new IllegalStateException(
                        "Mixed key sizes (256/512) require explicit digestAlgorithm() call. "
                                + "Previous signers use "
                                + digestOid
                                + ", current signer requires "
                                + autoOid);
            }
            digestOid = autoOid;
        }
        signers.add(new SignerEntry(signer, cert));
        return this;
    }

    /**
     * Добавляет подписанта (удобная перегрузка с ключом в памяти).
     *
     * <p>Делегирует в {@link #addSigner(GostSigner, GostCertificate)}
     * через {@link GostSigner#of(PrivateKeyParameters)}.
     */
    public CmsSignedDataBuilder addSigner(PrivateKeyParameters privateKey, GostCertificate cert) {
        return addSigner(GostSigner.of(privateKey), cert);
    }

    /** Добавляет дополнительный сертификат (промежуточный CA и т.д.). */
    public CmsSignedDataBuilder addCertificate(GostCertificate cert) {
        certificates.add(cert);
        return this;
    }

    /**
     * Добавляет CRL для встраивания в SignedData (RFC 5652 §5.1, поле crls [1] IMPLICIT).
     * Используется выбор crl (CertificateList), other-ветка (OCSP-ответы и т.п.) не поддерживается.
     */
    public CmsSignedDataBuilder addCrl(GostCrl crl) {
        crls.add(crl);
        return this;
    }

    /**
     * Добавляет CRL в SignedData из DER-кодированных байтов (RFC 5652 §5.1, поле crls [1] IMPLICIT).
     *
     * <p>Байты проходят структурный парсинг через конструктор {@link GostCrl} — невалидный DER
     * отбрасывается сразу. Верификация подписи CRL (verify) не выполняется — это ответственность
     * получателя CMS-сообщения.</p>
     *
     * @param crlDer DER-кодированный CertificateList (результат {@link GostCrlBuilder#sign})
     * @return this
     */
    public CmsSignedDataBuilder addCrl(byte[] crlDer) {
        return addCrl(new GostCrl(crlDer));
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
     * Включает режим certs-only (RFC 5652 §5.1): SignedData без подписантов,
     * несущая только сертификаты (формат {@code .p7b} для обмена цепочками).
     *
     * <p>В этом режиме {@link #data(byte[])} и {@link #addSigner} не используются;
     * требуется хотя бы один {@link #addCertificate}. Результат зеркален тому,
     * что читает {@link GostPkcs7#extractCertificates(byte[])}.
     */
    public CmsSignedDataBuilder certsOnly() {
        this.certsOnly = true;
        return this;
    }

    /**
     * Добавляет content-time-stamp (ES-C time-mark, RFC 5126 §5.11.1) как signed-атрибут.
     *
     * <p>TSP-запрос делается на хэш контента (eContent), nonce обязателен.
     * ContentTimestamp кодируется как SignedData с TSTInfo в EncapsulatedContentInfo.
     *
     * @param tspUrl          URL службы штампов времени
     * @param tspTransport    HTTP-транспорт для TSP
     * @param trustedTsaCerts доверенные сертификаты TSA (fail-closed)
     * @return this
     */
    public CmsSignedDataBuilder contentTimestamp(
            String tspUrl, TspTransport tspTransport, GostCertificate... trustedTsaCerts) {
        this.contentTspUrl = tspUrl;
        this.contentTspTransport = tspTransport;
        this.contentTspTrustedCerts = List.of(trustedTsaCerts);
        return this;
    }

    /**
     * Собирает SignedData в DER.
     *
     * @return DER-байты ContentInfo(id-signedData)
     */
    public byte[] build() {
        // certs-only режим (RFC 5652 §5.1): проверяем и возвращаемся ДО guard'ов на
        // data/signers ниже — в этом режиме data не задаётся, а signers пуст, иначе
        // старые guard'ы бросили бы исключение раньше и ветка стала бы мёртвой.
        if (certsOnly) {
            if (certificates.isEmpty()) {
                throw new IllegalStateException("no certificates for certs-only mode");
            }
            if (!signers.isEmpty()) {
                throw new IllegalStateException("certs-only mode does not accept signers");
            }
            byte[] eContentTypeOidDer = DerCodec.encodeOid(eContentTypeOid);
            // encapContentInfo без content: SEQUENCE { eContentType }
            byte[] encapContentInfo = DerCodec.encodeSequence(eContentTypeOidDer);
            byte[] certsField = buildCertificates();
            byte[] crlsField = buildCrls();
            byte[] signedData =
                    buildSignedData(List.of(), encapContentInfo, certsField, crlsField, List.of());
            LOG.log(
                    Level.INFO,
                    "Building certs-only SignedData with {0} certificate(s), {1} CRL(s)",
                    certificates.size(),
                    crls.size());
            return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
        }

        if (data == null) throw new IllegalStateException("data not set");
        if (signers.isEmpty()) throw new IllegalStateException("no signers");

        LOG.log(
                Level.INFO,
                "Building SignedData with {0} signer(s), {1} byte(s) of data",
                signers.size(),
                data.length);

        boolean is512 = GostOids.DIGEST_512.equals(digestOid);

        // 1. Вычисляем дайджест данных
        byte[] dataDigest = GostSignatureHelper.digestByOid(digestOid, data);

        // 1a. Если задан content-time-stamp — делаем TSP-запрос и строим ContentTimestamp
        byte[] contentTimestampDer = null;
        if (contentTspUrl != null) {
            contentTimestampDer = buildContentTimestamp(dataDigest);
        }

        // Предвычисляем OID-кодирования для переиспользования.
        // digestAlgorithm (в SignedData.digestAlgorithms и SignerInfo.digestAlgorithm)
        // несёт NULL-параметры: правило id-tc26-gost3411-2012-256/512 (Р 1323565.1.025
        // §4.1/4.2), эталон openssl gost-engine кодирует NULL. Без NULL строгие
        // ГОСТ-верификаторы вправе отвергнуть.
        byte[] digestAlgIdDer = CmsAlgorithmIdentifier.encode(digestOid);
        // SignerInfo.signatureAlgorithm несёт OID открытого ключа с NULL-параметрами
        // (RFC 4490 §3.2), а не комбинированный signWithDigest-OID сертификата —
        // иначе КриптоПро/openssl отвергают подпись (0x80090008 Invalid algorithm).
        String signAlgOid = is512 ? GostOids.PUBLIC_KEY_512 : GostOids.PUBLIC_KEY_256;
        byte[] signAlgIdDer = CmsAlgorithmIdentifier.encode(signAlgOid);
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
                            digestOid,
                            contentTimestampDer));
            digestAlgIds.add(digestAlgIdDer);
        }

        // 3. Собираем EncapsulatedContentInfo
        byte[] encapContentInfo = buildEncapsulatedContentInfo(eContentTypeOidDer);

        // 4. Собираем сертификаты и CRL
        byte[] certsField = buildCertificates();
        byte[] crlsField = buildCrls();

        // 5. Собираем SignedData
        byte[] signedData =
                buildSignedData(
                        digestAlgIds, encapContentInfo, certsField, crlsField, signerInfoList);

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
            String digestOid,
            byte[] contentTimestampDer) {
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

        // ES-C: content-time-stamp (RFC 5126 §5.11.1)
        if (contentTimestampDer != null) {
            attrList.add(CmsAttribute.encode(GostOids.CONTENT_TIME_STAMP, contentTimestampDer));
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
        byte[] signedAttrsHash = GostSignatureHelper.digestByOid(digestOid, signedAttrsForHash);
        byte[] signatureValue = GostSignatureHelper.signHashChecked(signedAttrsHash, entry.signer);

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

    private byte[] buildCrls() {
        if (crls.isEmpty()) {
            return new byte[0];
        }
        byte[][] derCrls = new byte[crls.size()][];
        for (int i = 0; i < crls.size(); i++) {
            derCrls[i] = crls.get(i).getEncoded();
        }
        // [1] IMPLICIT SET OF CertificateList — тег 0xA1 заменяет SET (X.690 §8.14)
        java.util.Arrays.sort(derCrls, DerCodec::compareDer);
        return DerCodec.encodeContextConstructed(1, DerCodec.concat(derCrls));
    }

    private byte[] buildSignedData(
            List<byte[]> digestAlgIds,
            byte[] encapContentInfo,
            byte[] certsField,
            byte[] crlsField,
            List<byte[]> signerInfoList) {
        int versionNum =
                GostOids.PKCS7_DATA.equals(eContentTypeOid)
                        ? CmsConstants.SIGNED_DATA_V1
                        : CmsConstants.SIGNED_DATA_V3;
        byte[] version = DerCodec.encodeInteger(versionNum);

        byte[] digestAlgs = DerCodec.encodeSetOf(digestAlgIds.toArray(new byte[0][]));

        byte[] signerInfos = DerCodec.encodeSetOf(signerInfoList.toArray(new byte[0][]));

        List<byte[]> parts = new ArrayList<>();
        parts.add(version);
        parts.add(digestAlgs);
        parts.add(encapContentInfo);
        if (certsField.length > 0) {
            parts.add(certsField);
        }
        if (crlsField.length > 0) {
            parts.add(crlsField);
        }
        parts.add(signerInfos);

        return DerCodec.encodeSequence(parts.toArray(new byte[0][]));
    }

    // ========================================================================
    // Вспомогательные типы
    // ========================================================================

    private static class SignerEntry {
        final GostSigner signer;
        final GostCertificate certificate;
        private byte[] certDer;

        SignerEntry(GostSigner signer, GostCertificate certificate) {
            this.signer = signer;
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

    /**
     * Строит ContentTimestamp (SignedData с TSTInfo) через TSP-запрос на хэш контента.
     *
     * <p>ContentTimestamp = TimeStampToken, то есть SignedData с TSTInfo как eContent.
     * Nonce обязателен, ответ проверяется: messageImprint, nonce, подпись TSA, цепочка
     * TSA до доверенных сертификатов (fail-closed).
     *
     * @param dataDigest хэш контента (eContent)
     * @return DER ContentTimestamp (TimeStampToken)
     */
    private byte[] buildContentTimestamp(byte[] dataDigest) {
        if (contentTspTrustedCerts == null || contentTspTrustedCerts.isEmpty()) {
            throw new IllegalStateException("contentTimestamp requires trusted TSA certificates");
        }

        try {
            TspRequestBuilder reqBuilder =
                    TspRequestBuilder.create().messageImprint(dataDigest, digestOid);
            byte[] request = reqBuilder.build();
            byte[] response = contentTspTransport.send(request, contentTspUrl);

            TspResponse tspResponse = TspResponse.fromDer(response);
            tspResponse.verify(
                    dataDigest,
                    digestOid,
                    reqBuilder.getNonce(),
                    contentTspTrustedCerts.toArray(GostCertificate[]::new));

            return tspResponse.timeStampTokenDer();
        } catch (IOException | PkixException e) {
            throw new IllegalStateException("Content-time-stamp TSP request failed", e);
        }
    }
}
