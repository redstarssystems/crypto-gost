package org.rssys.gost.pkix.cms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Общие низкоуровневые функции CAdES-сборки и CAdES-проверки: разбор атрибутов, поиск и слияние
 * сертификатов, вычисление хеш-входов. Прикладной логики здесь нет: сюда выносится только то, что
 * нужно и {@link CAdESExtender}, и {@link CAdESVerifier}.
 */
final class CAdESSupport {

    private CAdESSupport() {}

    /**
     * Проверяет OID из {@code signatureAlgorithm} подписанта (RFC 5652 §5.3) в режиме fail-closed.
     *
     * <p>Легитимные продюсеры используют два семейства OID для ГОСТ Р 34.10-2012:
     * OID открытого ключа ({@code 1.2.643.7.1.1.1.1/.2}; так делают КриптоПро, openssl gost-engine
     * и данная библиотека) и signWithDigest ({@code 1.2.643.7.1.1.3.2/.3}; так делает BouncyCastle).
     * Оба принимаются. Реальная защита от подмены алгоритма - сверка объявленной OID-битности
     * (256/512) с кривой открытого ключа сертификата: несоответствие означает попытку
     * algorithm-confusion и отклоняется. Параметры алгоритма не проверяются строго - допустимы
     * и NULL, и их отсутствие (разные продюсеры кодируют по-разному).
     *
     * <p>Общая для основной подписи и контрподписи: правило не должно расходиться между путями.</p>
     *
     * @param signatureAlgOid OID из signatureAlgorithm подписанта
     * @param keyHlen         длина хэша кривой ключа сертификата (32 -> 256-бит, 64 -> 512-бит)
     * @param owner           чьё поле проверяется ("SignerInfo" или "Countersignature"); только
     *                        для текста исключения
     * @throws PkixException если OID не из ожидаемого множества либо его битность не совпадает
     *     с битностью ключа сертификата
     */
    static void validateSignatureAlgorithm(String signatureAlgOid, int keyHlen, String owner)
            throws PkixException {
        boolean is256Oid =
                GostOids.PUBLIC_KEY_256.equals(signatureAlgOid)
                        || GostOids.SIGN_WITH_DIGEST_256.equals(signatureAlgOid);
        boolean is512Oid =
                GostOids.PUBLIC_KEY_512.equals(signatureAlgOid)
                        || GostOids.SIGN_WITH_DIGEST_512.equals(signatureAlgOid);

        if (!is256Oid && !is512Oid) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unexpected " + owner + " signatureAlgorithm OID: " + signatureAlgOid);
        }

        boolean keyIs512 = keyHlen == GostOids.STREEBOG_512_HASH_LEN;
        if (is512Oid != keyIs512) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    owner
                            + " signatureAlgorithm OID "
                            + signatureAlgOid
                            + " does not match signer key size ("
                            + (keyHlen * 8)
                            + " bit)");
        }
    }

    /**
     * Отвергает OCSP-ответ со статусом не {@code successful}: у такого ответа нет
     * {@code responseBytes} и времени выдачи, поэтому ссылку на него построить нельзя. В
     * {@code CAdESCompleteData} попытка взять время выдачи даёт {@link NullPointerException}, а
     * {@code CAdESXLongData.encodeRevocationValues} молча положил бы такой ответ в
     * {@code RevocationValues}, которые при чтении потом отвергаются. Ответ приходит от службы и
     * может быть, например, {@code tryLater}.
     *
     * @param ocsp ответ или {@code null} (нет данных - ничего не проверяется)
     * @throws PkixException если статус ответа не успешный
     */
    static void requireSuccessfulOcsp(GostOcspResponse ocsp) throws PkixException {
        if (ocsp != null && !ocsp.isSuccessful()) {
            throw new PkixException(
                    "OCSP: response with non-successful status "
                            + ocsp.getResponseStatus()
                            + " cannot be embedded");
        }
    }

    /**
     * Хэширует данные дайджестом, заданным OID из недоверенной структуры.
     *
     * <p>{@link GostSignatureHelper#digestByOid} бросает unchecked-исключение: на локальных
     * параметрах это ошибка программиста, но OID из чужого SignerInfo или CAdES-атрибута
     * контролирует атакующий, и такое исключение прорвало бы контракт {@link PkixException}.</p>
     *
     * @param digestOid OID дайджеста (Стрибог-256/512)
     * @param data      хэшируемые данные
     * @return хэш
     * @throws PkixException если OID не поддерживается
     */
    static byte[] digestByOidOrThrow(String digestOid, byte[] data) throws PkixException {
        try {
            return GostSignatureHelper.digestByOid(digestOid, data);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Unsupported digest algorithm: " + digestOid, e);
        }
    }

    /**
     * Добавляет сертификаты в поле certificates [0] IMPLICIT.
     * Сохраняет существующие, удаляет DER-дубликаты, сортирует, кодирует.
     *
     * @param existingCertsField существующее поле [0] или null
     * @param newCertDers        DER-байты новых сертификатов
     * @param maxTotalCerts      максимум сертификатов после слияния (DoS)
     * @return новое поле [0] или null если пусто
     */
    static byte[] mergeCertsIntoField(
            byte[] existingCertsField, List<byte[]> newCertDers, int maxTotalCerts)
            throws PkixException {
        List<byte[]> allCerts = new ArrayList<>();

        if (existingCertsField != null) {
            int[] lenInfo = DerCodec.decodeLength(existingCertsField, 1);
            int contentOff = 1 + lenInfo[1];
            int pos = contentOff;
            int end = existingCertsField.length;
            while (pos < end) {
                if (allCerts.size() >= maxTotalCerts) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many certificates in SignedData: "
                                    + (allCerts.size() + 1)
                                    + " (max "
                                    + maxTotalCerts
                                    + ")");
                }
                int[] certLen = DerCodec.decodeLength(existingCertsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                allCerts.add(
                        java.util.Arrays.copyOfRange(existingCertsField, pos, pos + certTotal));
                pos += certTotal;
            }
        }

        for (byte[] certDer : newCertDers) {
            boolean duplicate = false;
            for (byte[] existing : allCerts) {
                if (java.util.Arrays.equals(existing, certDer)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                if (allCerts.size() >= maxTotalCerts) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many certificates in SignedData: "
                                    + (allCerts.size() + 1)
                                    + " (max "
                                    + maxTotalCerts
                                    + ")");
                }
                allCerts.add(certDer);
            }
        }

        if (allCerts.isEmpty()) {
            return null;
        }
        byte[][] sorted = allCerts.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
    }

    static void addIfAbsent(List<GostCertificate> certs, GostCertificate candidate) {
        byte[] der = candidate.getEncoded();
        for (GostCertificate existing : certs) {
            if (Arrays.equals(existing.getEncoded(), der)) {
                return;
            }
        }
        certs.add(candidate);
    }

    /** Проверяет DER-равенство сертификата хотя бы одному элементу списка. */
    static boolean containsDer(List<GostCertificate> certs, GostCertificate cert) {
        byte[] encoded = cert.getEncoded();
        for (GostCertificate c : certs) {
            if (Arrays.equals(encoded, c.getEncoded())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Извлекает сертификаты из поля {@code [0] IMPLICIT certificates}
     * SignedData без полной верификации подписей.
     */
    static List<GostCertificate> extractEmbeddedCerts(byte[] signedDataDer) throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(ci.contentType())) {
            return List.of();
        }
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        if (sdParts.length < 4) {
            return List.of();
        }
        // Пропускаем version, digestAlgorithms, encapContentInfo
        int sdIdx = 3;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0)) {
            return CmsSignedDataVerifier.parseEmbeddedCertificates(
                    sdParts[sdIdx], CmsConstants.MAX_EMBEDDED_CERTS);
        }
        return List.of();
    }

    /** Индекс поля unsignedAttrs {@code [1] IMPLICIT} в разобранном SignerInfo. */
    static int findUnsignedAttrsIndex(byte[][] siParts) {
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                return i;
            }
        }
        return -1;
    }

    /** Содержимое поля unsignedAttrs {@code [1] IMPLICIT} или {@code null}, если поля нет. */
    static byte[] unsignedAttrsContent(byte[][] siParts) throws PkixException {
        int unsignedIdx = findUnsignedAttrsIndex(siParts);
        if (unsignedIdx < 0) {
            return null;
        }
        byte[] field = siParts[unsignedIdx];
        int[] lenInfo = DerCodec.decodeLength(field, 1);
        int contentOff = 1 + lenInfo[1];
        return Arrays.copyOfRange(field, contentOff, field.length);
    }

    /** Разбирает содержимое SET на отдельные CmsAttribute TLV. */
    static List<byte[]> parseAttributeTlvs(byte[] content) throws PkixException {
        List<byte[]> attrs = new ArrayList<>();
        int pos = 0;
        while (pos < content.length) {
            int[] attrLen = DerCodec.decodeLength(content, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrs.add(Arrays.copyOfRange(content, pos, pos + attrTotal));
            pos += attrTotal;
        }
        return attrs;
    }

    /**
     * Хеш-вход escTimeStamp по RFC 5126 §6.3.5: SignatureValue, все
     * signature-time-stamp, complete-certificate-references,
     * complete-revocation-references. Атрибуты входят как attrType+attrValues
     * без внешнего SEQUENCE; используется исходный DER.
     */
    static byte[] buildEscHashInput(byte[] signatureValue, List<CmsAttribute> unsignedAttributes)
            throws PkixException {
        List<byte[]> parts = new ArrayList<>();
        parts.add(signatureValue);
        for (CmsAttribute attr : unsignedAttributes) {
            if (GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                parts.add(hashableAttributeContent(attr));
            }
        }

        // По RFC 5126 §6.3.5 в хеш входят обе ссылки независимо от того,
        // пусты они или нет: важен сам Attribute с attrType и attrValues.
        CmsAttribute certRefs =
                singleAttribute(unsignedAttributes, GostOids.COMPLETE_CERTIFICATE_REFS);
        CmsAttribute revocRefs =
                singleAttribute(unsignedAttributes, GostOids.COMPLETE_REVOCATION_REFS);
        parts.add(hashableAttributeContent(certRefs));
        parts.add(hashableAttributeContent(revocRefs));
        return DerCodec.concat(parts.toArray(new byte[0][]));
    }

    static CmsAttribute singleAttribute(List<CmsAttribute> attrs, String oid) throws PkixException {
        CmsAttribute found = null;
        for (CmsAttribute attr : attrs) {
            if (!oid.equals(attr.attrType())) {
                continue;
            }
            if (found != null) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "escTimeStamp: multiple attributes with OID " + oid);
            }
            found = attr;
        }
        if (found == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "escTimeStamp: required attribute missing: " + oid);
        }
        return found;
    }

    static byte[] hashableAttributeContent(CmsAttribute attr) throws PkixException {
        byte[] encoded = attr.encoded();
        if (encoded.length == 0 || (encoded[0] & 0xFF) != DerCodec.TAG_SEQUENCE) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "CmsAttribute is not a SEQUENCE");
        }
        int[] lenInfo = DerCodec.decodeLength(encoded, 1);
        int contentOff = 1 + lenInfo[1];
        return Arrays.copyOfRange(encoded, contentOff, encoded.length);
    }

    /**
     * Хэш подписи для messageImprint запроса метки времени.
     *
     * <p>Дайджест выбирается по <b>заявленному</b> алгоритму подписанта ({@code signerDigestOid}),
     * а не по длине подписи: критичный параметр messageImprint не выводится из косвенного признака.
     * Для сырых ГОСТ Р 34.10-2012 подписей длина фиксирована (64/128 байт), но принцип «брать из
     * объявленного значения» сохраняем как общее правило (fail-closed на неизвестный OID).
     *
     * <p>{@code signerDigestOid} приходит из разбора чужого SignerInfo (потенциально недоверенный
     * вход), поэтому неизвестный OID транслируется в {@link PkixException}, а не в сырой
     * {@link IllegalArgumentException} — чтобы не нарушить контракт метода для вызывающего кода.
     */
    static SignatureHashResult computeTspMessageImprint(String signerDigestOid, byte[] signature)
            throws PkixException {
        try {
            byte[] sigHash = GostSignatureHelper.digestByOid(signerDigestOid, signature);
            return new SignatureHashResult(sigHash, signerDigestOid);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TSP messageImprint: unsupported signer digest algorithm OID: "
                            + signerDigestOid);
        }
    }

    record SignatureHashResult(byte[] hash, String oid) {}
}
