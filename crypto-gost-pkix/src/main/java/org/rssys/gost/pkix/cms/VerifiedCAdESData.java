package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Результат верификации CAdES-T подписи.
 *
 * @param data    извлечённые данные (или {@code null} при detached)
 * @param signers все верифицированные подписанты с их метками времени
 */
public record VerifiedCAdESData(byte[] data, List<CAdESSignerResult> signers) {

    public VerifiedCAdESData {
        data = data != null ? data.clone() : null;
        signers = signers != null ? List.copyOf(signers) : Collections.emptyList();
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
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
