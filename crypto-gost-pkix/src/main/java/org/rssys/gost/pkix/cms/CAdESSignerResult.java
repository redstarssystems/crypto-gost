package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.tsp.TstInfo;

/**
 * Результат верификации одного подписанта в CAdES.
 *
 * @param signerCertificate сертификат подписанта
 * @param signedAttributes  signed-атрибуты подписанта (contentType, messageDigest,
 *                          signingCertificateV2, commitmentTypeIndication, signingTime и др.)
 * @param timestamps        проверенные метки времени из его unsignedAttrs
 */
public record CAdESSignerResult(
        GostCertificate signerCertificate,
        List<CmsAttribute> signedAttributes,
        List<TstInfo> timestamps) {

    public CAdESSignerResult {
        signedAttributes =
                signedAttributes != null ? List.copyOf(signedAttributes) : Collections.emptyList();
        timestamps = timestamps != null ? List.copyOf(timestamps) : Collections.emptyList();
    }
}
