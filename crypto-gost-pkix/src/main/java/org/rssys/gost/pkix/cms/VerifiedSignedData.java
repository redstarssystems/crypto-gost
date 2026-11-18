package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;

/**
 * Результат успешной верификации CMS SignedData.
 *
 * <p>{@link #signers()} содержит прошедших проверку подписантов: при
 * {@link SignerSelection#ANY} - первого валидного (один элемент), при
 * {@link SignerSelection#ALL} - всех. Для единственного подписанта удобны {@link #signer()},
 * {@link #signerCertificate()} и {@link #unsignedAttributes()}; при нескольких подписантах они
 * бросают {@link IllegalStateException}, а не выбирают подписанта молча.
 *
 * <p>{@link #data()} всегда возвращает защитную копию. Для больших документов
 * копирование дорого - не вызывайте метод без необходимости.
 *
 * @param data         извлечённые данные (для encapsulated) или {@code null} (detached)
 * @param signers      прошедшие проверку подписанты (непустой список)
 * @param embeddedCrls CRL, встроенные в SignedData (поле crls [1] RFC 5652 §5.1)
 */
public record VerifiedSignedData(
        byte[] data, List<SignerResult> signers, List<GostCrl> embeddedCrls) {

    /** Канонический конструктор - защитные копии. */
    public VerifiedSignedData {
        if (signers == null || signers.isEmpty()) {
            throw new IllegalArgumentException("signers must not be null or empty");
        }
        data = data != null ? data.clone() : null;
        signers = List.copyOf(signers);
        embeddedCrls = embeddedCrls != null ? List.copyOf(embeddedCrls) : Collections.emptyList();
    }

    /**
     * Извлечённые данные.
     *
     * @return защитная копия данных или {@code null}; для больших документов
     *     копирование дорого, вызывайте только при необходимости
     */
    @Override
    public byte[] data() {
        return data != null ? data.clone() : null;
    }

    /**
     * Единственный прошедший проверку подписант.
     *
     * @return результат подписанта
     * @throws IllegalStateException если подписантов не один (используйте {@link #signers()})
     */
    public SignerResult signer() {
        if (signers.size() != 1) {
            throw new IllegalStateException(
                    "Expected exactly one signer but there are "
                            + signers.size()
                            + "; use signers()");
        }
        return signers.get(0);
    }

    /**
     * Сертификат единственного подписанта.
     *
     * @return сертификат
     * @throws IllegalStateException если подписантов не один
     */
    public GostCertificate signerCertificate() {
        return signer().signerCertificate();
    }

    /**
     * Unsigned-атрибуты единственного подписанта.
     *
     * @return немодифицируемый список (может быть пустым)
     * @throws IllegalStateException если подписантов не один
     */
    public List<CmsAttribute> unsignedAttributes() {
        return signer().unsignedAttributes();
    }

    /** Данные не выводятся - могут содержать ключевой материал. */
    @Override
    public String toString() {
        return "VerifiedSignedData[signers="
                + signers
                + ", embeddedCrls="
                + embeddedCrls.size()
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
