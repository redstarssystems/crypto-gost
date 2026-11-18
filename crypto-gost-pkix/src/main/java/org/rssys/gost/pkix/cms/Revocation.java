package org.rssys.gost.pkix.cms;

import java.util.List;
import org.rssys.gost.pkix.cert.GostCrl;

/**
 * Политика проверки отзыва сертификатов цепочки подписанта при верификации CMS.
 *
 * <p>Отзыв проверяется по CRL, встроенным в SignedData (поле {@code crls [1]}), и по CRL, переданным
 * вызывающим. Для каждого сертификата цепочки ниже якоря проверяются все CRL с совпадающим
 * издателем: любой отзыв означает отказ.</p>
 *
 * <ul>
 *   <li>{@link #none()} - отзыв не проверяется;
 *   <li>{@link #required(List)} - для каждого сертификата ниже якоря должен найтись подходящий CRL,
 *       иначе отказ ({@code REVOCATION_STATUS_UNKNOWN}); так отсутствие данных не превращается
 *       молча в «не отозван»;
 *   <li>{@link #ifAvailable(List)} - отзыв проверяется, если подходящий CRL нашёлся; при его
 *       отсутствии пишется предупреждение и подписант проходит. Выбирайте явно: это режим «лучшее
 *       из возможного», а не гарантия.
 * </ul>
 */
public final class Revocation {

    /** Режим проверки отзыва. */
    public enum Mode {
        NONE,
        IF_AVAILABLE,
        REQUIRED
    }

    private static final Revocation NONE = new Revocation(Mode.NONE, List.of());

    private final Mode mode;
    private final List<GostCrl> externalCrls;

    private Revocation(Mode mode, List<GostCrl> externalCrls) {
        this.mode = mode;
        this.externalCrls = externalCrls;
    }

    /** @return политика без проверки отзыва */
    public static Revocation none() {
        return NONE;
    }

    /**
     * Отзыв проверяется, если подходящий CRL найден; иначе предупреждение.
     *
     * @param externalCrls дополнительные CRL (не null; пустой список - только встроенные)
     * @return политика
     * @throws IllegalArgumentException если список null или содержит null
     */
    public static Revocation ifAvailable(List<GostCrl> externalCrls) {
        return new Revocation(Mode.IF_AVAILABLE, copyCrls(externalCrls));
    }

    /**
     * Отзыв проверяется обязательно: нет подходящего CRL - отказ.
     *
     * @param externalCrls дополнительные CRL (не null; пустой список - только встроенные)
     * @return политика
     * @throws IllegalArgumentException если список null или содержит null
     */
    public static Revocation required(List<GostCrl> externalCrls) {
        return new Revocation(Mode.REQUIRED, copyCrls(externalCrls));
    }

    private static List<GostCrl> copyCrls(List<GostCrl> crls) {
        if (crls == null) {
            throw new IllegalArgumentException(
                    "externalCrls must not be null; pass List.of() when there are no external CRLs");
        }
        for (GostCrl crl : crls) {
            if (crl == null) {
                throw new IllegalArgumentException("externalCrls must not contain null");
            }
        }
        return List.copyOf(crls);
    }

    /** @return режим проверки */
    public Mode mode() {
        return mode;
    }

    /** @return неизменяемый список внешних CRL (пустой при {@link #none()}) */
    public List<GostCrl> externalCrls() {
        return externalCrls;
    }

    @Override
    public String toString() {
        return "Revocation[" + mode + ", externalCrls=" + externalCrls.size() + "]";
    }
}
