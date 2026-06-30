package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Результат успешной верификации CMS SignedData.
 *
 * @param data              извлечённые данные (для encapsulated) или {@code null} (detached)
 * @param signerCertificate сертификат подписанта
 * @param unsignedAttributes unsigned-атрибуты SignerInfo (CAdES метки времени и др.)
 */
public record VerifiedSignedData(
        byte[] data, GostCertificate signerCertificate, List<CmsAttribute> unsignedAttributes) {

    /**
     * Канонический конструктор — защитные копии.
     */
    public VerifiedSignedData {
        data = data != null ? data.clone() : null;
        unsignedAttributes =
                unsignedAttributes != null
                        ? List.copyOf(unsignedAttributes)
                        : Collections.emptyList();
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
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
