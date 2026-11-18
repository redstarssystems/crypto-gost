package org.rssys.gost.pkix.cert;

/**
 * Результат оценки окна выпуска доказательства отзыва.
 *
 * <p>Не является исключением: {@code OUT_OF_WINDOW} для {@code good}
 * доказательства означает «не участвует», а не ошибку. Все структурные
 * ошибки, неверная подпись, чужой сертификат, {@code revoked}/{@code unknown}
 * по-прежнему бросают {@link PkixException}.</p>
 */
enum EvidenceFreshness {
    IN_WINDOW,
    OUT_OF_WINDOW
}
