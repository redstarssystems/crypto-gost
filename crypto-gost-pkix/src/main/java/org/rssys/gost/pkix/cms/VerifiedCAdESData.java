package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;

/**
 * Результат верификации CAdES-T подписи.
 *
 * @param data             извлечённые данные (или {@code null} при detached)
 * @param signers          все верифицированные подписанты с их метками времени
 * @param revocationPolicy применённая политика свежести отзыва для X-Long
 *                         ({@code null} для BES/T/C)
 */
public record VerifiedCAdESData(
        byte[] data, List<CAdESSignerResult> signers, RevocationFreshnessPolicy revocationPolicy) {

    public VerifiedCAdESData {
        data = data != null ? data.clone() : null;
        signers = signers != null ? List.copyOf(signers) : Collections.emptyList();
    }

    /** Совместимый конструктор для уровней без политики отзыва. */
    public VerifiedCAdESData(byte[] data, List<CAdESSignerResult> signers) {
        this(data, signers, null);
    }

    @Override
    public byte[] data() {
        return data != null ? data.clone() : null;
    }

    @Override
    public List<CAdESSignerResult> signers() {
        return signers;
    }

    /**
     * Сертификат первого подписанта — удобство для single-signer.
     *
     * @return сертификат первого подписанта (не null при успешной верификации)
     * @throws IndexOutOfBoundsException если подписантов нет
     */
    public GostCertificate signerCertificate() {
        return signers.get(0).signerCertificate();
    }

    /** Данные не выводятся — могут содержать ключевой материал. */
    @Override
    public String toString() {
        return "VerifiedCAdESData[signers="
                + signers
                + ", revocationPolicy="
                + revocationPolicy
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
