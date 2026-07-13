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
 * @param certificateValues  certificate-values (CAdES-X Long, RFC 5126 §6.3.3);
 *                           пустой список для BES/T/C
 * @param revocationValues   revocation-values со встроенными CRL и OCSP-ответами (CAdES-X Long);
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
