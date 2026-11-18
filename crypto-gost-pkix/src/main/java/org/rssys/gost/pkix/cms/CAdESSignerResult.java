package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.tsp.TstInfo;

/**
 * Результат верификации одного подписанта в CAdES.
 *
 * @param signerCertificate  сертификат подписанта
 * @param signedAttributes   signed-атрибуты подписанта (contentType, messageDigest,
 *                           signingCertificateV2, commitmentTypeIndication, signingTime и др.)
 * @param timestamps         проверенные метки времени из его unsignedAttrs
 * @param countersignatures  проверенные countersignature (RFC 5652 §11.4); пустой список для CAdES-BES/T
 * @param completeCertRefs   complete-certificate-references (CAdES-C, RFC 5126 §6.2.1);
 *                           пустой список для CAdES-BES/T
 * @param completeRevocRefs  complete-revocation-references (CAdES-C, RFC 5126 §6.2.2);
 *                           пустой список для CAdES-BES/T
 * @param certificateValues  для CAdES-X Long — канонизированная первичная проверенная
 *                           цепочка leaf-first, а не сырой атрибут certificate-values;
 *                           порядок атрибута произвольный, посторонние сертификаты
 *                           отклоняются. Пустой список для BES/T/C
 * @param revocationValues   для CAdES-X Long - CRL и OCSP-ответы из revocation-values, прошедшие
 *                           проверку: подпись проверена, статус не "отозван". Значения, не вошедшие
 *                           в доказательства сертификатов ниже якоря (например, относящиеся к
 *                           самому якорю), в результат не попадают, хотя
 *                           {@code completeRevocRefs} может на них ссылаться. Свежесть
 *                           гарантируется на уровне сертификата (хотя бы одно значение в окне),
 *                           остальные значения могут лежать вне окна.
 *                           {@link CAdESXLongData.RevocationValuesDecoded#EMPTY} для BES/T/C
 * @param contentTimestamp   content-time-stamp (ES-C, RFC 5126 §5.11.1); null для BES/T/C
 */
public record CAdESSignerResult(
        GostCertificate signerCertificate,
        List<CmsAttribute> signedAttributes,
        List<TstInfo> timestamps,
        List<SignerResult> countersignatures,
        List<CAdESCompleteData.OtherCertID> completeCertRefs,
        List<CAdESCompleteData.CrlOcspRef> completeRevocRefs,
        List<GostCertificate> certificateValues,
        CAdESXLongData.RevocationValuesDecoded revocationValues,
        TstInfo contentTimestamp) {

    public CAdESSignerResult {
        signedAttributes =
                signedAttributes != null ? List.copyOf(signedAttributes) : Collections.emptyList();
        timestamps = timestamps != null ? List.copyOf(timestamps) : Collections.emptyList();
        countersignatures =
                countersignatures != null
                        ? List.copyOf(countersignatures)
                        : Collections.emptyList();
        completeCertRefs =
                completeCertRefs != null ? List.copyOf(completeCertRefs) : Collections.emptyList();
        completeRevocRefs =
                completeRevocRefs != null
                        ? List.copyOf(completeRevocRefs)
                        : Collections.emptyList();
        certificateValues =
                certificateValues != null
                        ? List.copyOf(certificateValues)
                        : Collections.emptyList();
        revocationValues =
                revocationValues != null
                        ? revocationValues
                        : CAdESXLongData.RevocationValuesDecoded.EMPTY;
    }
}
