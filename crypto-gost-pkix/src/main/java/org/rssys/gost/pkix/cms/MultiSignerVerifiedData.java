package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCrl;

/**
 * Результат верификации CMS SignedData со всеми подписантами.
 *
 * <p>В отличие от {@link VerifiedSignedData}, который возвращает первого валидного
 * подписанта (OR-семантика), этот класс возвращает всех успешно верифицированных
 * подписантов (AND-семантика). Используется {@link CAdESExtender} для multi-signer CAdES-T.
 *
 * @param data    извлечённые данные (или {@code null} при detached)
 * @param signers все успешно верифицированные подписанты (непустой список)
 * @param embeddedCrls CRL, встроенные в SignedData (поле crls [1] RFC 5652 §5.1)
 */
public record MultiSignerVerifiedData(
        byte[] data, List<SignerResult> signers, List<GostCrl> embeddedCrls) {

    public MultiSignerVerifiedData {
        data = data != null ? data.clone() : null;
        signers = signers != null ? List.copyOf(signers) : Collections.emptyList();
        embeddedCrls = embeddedCrls != null ? List.copyOf(embeddedCrls) : Collections.emptyList();
    }

    @Override
    public byte[] data() {
        return data != null ? data.clone() : null;
    }

    /** Данные не выводятся — могут содержать ключевой материал. */
    @Override
    public String toString() {
        return "MultiSignerVerifiedData[signers="
                + signers
                + ", embeddedCrls="
                + embeddedCrls.size()
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
