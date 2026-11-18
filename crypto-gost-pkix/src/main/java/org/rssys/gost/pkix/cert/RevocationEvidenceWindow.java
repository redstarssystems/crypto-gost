package org.rssys.gost.pkix.cert;

import java.time.Instant;
import java.util.Objects;

/**
 * Временное окно для проверки доказательств отзыва в CAdES-X Long.
 *
 * <p>{@code signingTime} — самый ранний подтверждённый момент существования
 * подписи, {@code collectionTime} — самый ранний {@code genTime} метки
 * {@code escTimeStamp}. Доказательство должно быть выпущено внутри окна
 * с учётом политики свежести.</p>
 *
 * @param signingTime момент подписи (не {@code null})
 * @param collectionTime момент сбора C-ссылок (не {@code null})
 */
public record RevocationEvidenceWindow(Instant signingTime, Instant collectionTime) {

    public RevocationEvidenceWindow {
        Objects.requireNonNull(signingTime, "signingTime must not be null");
        Objects.requireNonNull(collectionTime, "collectionTime must not be null");
        if (signingTime.isAfter(collectionTime)) {
            throw new IllegalArgumentException("signingTime must not be after collectionTime");
        }
    }
}
