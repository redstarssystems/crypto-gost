package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Результат верификации одного SignerInfo.
 *
 * @param signerCertificate   сертификат подписанта
 * @param signatureValue      значение подписи (байты s||r)
 * @param signedAttributes    signed-атрибуты этого подписанта (contentType, messageDigest,
 *                            signingCertificateV2 и др.) — проверены при верификации
 * @param unsignedAttributes  unsigned-атрибуты этого подписанта (метки времени CAdES-T и др.)
 *                            — не проверены криптографически, только распарсены
 */
public record SignerResult(
        GostCertificate signerCertificate,
        byte[] signatureValue,
        List<CmsAttribute> signedAttributes,
        List<CmsAttribute> unsignedAttributes) {

    public SignerResult {
        signatureValue = signatureValue.clone();
        signedAttributes =
                signedAttributes != null ? List.copyOf(signedAttributes) : Collections.emptyList();
        unsignedAttributes =
                unsignedAttributes != null
                        ? List.copyOf(unsignedAttributes)
                        : Collections.emptyList();
    }

    @Override
    public byte[] signatureValue() {
        return signatureValue.clone();
    }

    @Override
    public List<CmsAttribute> signedAttributes() {
        return signedAttributes;
    }

    @Override
    public List<CmsAttribute> unsignedAttributes() {
        return unsignedAttributes;
    }

    /** Сигнатура не выводится — ключевой материал не должен попадать в логи. */
    @Override
    public String toString() {
        return "SignerResult[signerCertificate="
                + signerCertificate
                + ", signedAttributes="
                + signedAttributes
                + ", unsignedAttributes="
                + unsignedAttributes
                + ", signatureValue=<"
                + signatureValue.length
                + " bytes>]";
    }
}
