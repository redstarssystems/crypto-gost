package org.rssys.gost.pkix.cert;

/**
 * Причина отзыва сертификата (RFC 5280 §5.3.1).
 *
 * <p>Используется в {@link RevokedEntry} при построении CRL
 * через {@link GostCrlBuilder}.</p>
 */
public enum ReasonCode {
    /** Причина не указана */
    UNSPECIFIED(0),
    /** Компрометация закрытого ключа */
    KEY_COMPROMISE(1),
    /** Компрометация закрытого ключа CA */
    CA_COMPROMISE(2),
    /** Изменение аффилированности субъекта */
    AFFILIATION_CHANGED(3),
    /** Сертификат заменён новым */
    SUPERSEDED(4),
    /** Прекращение деятельности */
    CESSATION_OF_OPERATION(5),
    /** Временная приостановка действия сертификата */
    CERTIFICATE_HOLD(6),
    // 7 зарезервирован IANA, в RFC 5280 отсутствует
    /** Отзыв из delta-CRL */
    REMOVE_FROM_CRL(8),
    /** Лишение привилегий */
    PRIVILEGE_WITHDRAWN(9),
    /** Компрометация атрибутного органа (AA) */
    AA_COMPROMISE(10);

    private final int value;

    ReasonCode(int value) {
        this.value = value;
    }

    /** Числовое значение reasonCode для кодирования в CRL. */
    public int value() {
        return value;
    }

    /**
     * Возвращает ReasonCode по числовому значению или null.
     *
     * @param value числовое значение reasonCode
     * @return соответствующий ReasonCode или null если значение не распознано
     */
    public static ReasonCode fromValue(int value) {
        for (ReasonCode rc : values()) {
            if (rc.value == value) return rc;
        }
        return null;
    }
}
