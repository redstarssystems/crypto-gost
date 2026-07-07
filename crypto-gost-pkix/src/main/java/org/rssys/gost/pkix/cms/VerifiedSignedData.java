package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;

/**
 * Результат успешной верификации CMS SignedData.
 *
 * @param data              извлечённые данные (для encapsulated) или {@code null} (detached)
 * @param signerCertificate сертификат подписанта
 * @param unsignedAttributes unsigned-атрибуты SignerInfo (CAdES метки времени и др.)
 * @param embeddedCrls     CRL, встроенные в SignedData (поле crls [1] RFC 5652 §5.1)
 */
public record VerifiedSignedData(
        byte[] data,
        GostCertificate signerCertificate,
        List<CmsAttribute> unsignedAttributes,
        List<GostCrl> embeddedCrls) {

    /**
     * Канонический конструктор — защитные копии.
     */
    public VerifiedSignedData {
        data = data != null ? data.clone() : null;
        unsignedAttributes =
                unsignedAttributes != null
                        ? List.copyOf(unsignedAttributes)
                        : Collections.emptyList();
        embeddedCrls = embeddedCrls != null ? List.copyOf(embeddedCrls) : Collections.emptyList();
    }

    /**
     * Извлечённые данные.
     *
     * @return копия данных или {@code null}
     */
    @Override
    public byte[] data() {
        return data != null ? data.clone() : null;
    }

    /**
     * Сертификат подписанта.
     *
     * @return сертификат (не null при успешной верификации)
     */
    @Override
    public GostCertificate signerCertificate() {
        return signerCertificate;
    }

    /**
     * Unsigned-атрибуты SignerInfo.
     *
     * @return немодифицируемый список (может быть пустым)
     */
    @Override
    public List<CmsAttribute> unsignedAttributes() {
        return unsignedAttributes;
    }

    /** Данные не выводятся — могут содержать ключевой материал. */
    @Override
    public String toString() {
        return "VerifiedSignedData[signerCertificate="
                + signerCertificate
                + ", unsignedAttributes="
                + unsignedAttributes
                + ", embeddedCrls="
                + embeddedCrls.size()
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
