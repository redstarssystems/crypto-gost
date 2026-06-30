package org.rssys.gost.pkix.cms;

import java.util.Collections;
import java.util.List;

/**
 * Результат верификации CMS SignedData со всеми подписантами.
 *
 * <p>В отличие от {@link VerifiedSignedData}, который возвращает первого валидного
 * подписанта (OR-семантика), этот класс возвращает всех успешно верифицированных
 * подписантов (AND-семантика). Используется {@link CAdESExtender} для multi-signer CAdES-T.
 *
 * @param data    извлечённые данные (или {@code null} при detached)
 * @param signers все успешно верифицированные подписанты (непустой список)
 */
public record MultiSignerVerifiedData(byte[] data, List<SignerResult> signers) {

    public MultiSignerVerifiedData {
        data = data != null ? data.clone() : null;
        signers = signers != null ? List.copyOf(signers) : Collections.emptyList();
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
                + ", data=<"
                + (data != null ? data.length : 0)
                + " bytes>]";
    }
}
