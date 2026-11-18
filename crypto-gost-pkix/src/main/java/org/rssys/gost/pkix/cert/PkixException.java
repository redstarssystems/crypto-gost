package org.rssys.gost.pkix.cert;

/**
 * Checked-исключение PKIX-слоя — ошибка верификации или разбора.
 * <p>
 * Вызывающий код (TLS, jsse) обязан обработать — принцип fail-closed.
 * Не содержит TLS-алертов: маппинг в {@code TlsException} делает TLS-слой
 * через {@link Reason}, а не grep по тексту сообщения.
 */
public class PkixException extends Exception {

    /**
     * Типизированная причина ошибки для межмодульного маппинга.
     * TLS-слой использует enum для alert-кода вместо {@code msg.contains()}.
     */
    public enum Reason {
        EXPIRED,
        ROOT_NOT_SIGNED,
        DN_MISMATCH,
        NOT_CA,
        MISSING_KEY_CERT_SIGN,
        PATH_LEN_EXCEEDED,
        ALG_MISMATCH,
        POLICY_VIOLATION,
        UNKNOWN_CRITICAL_EXTENSION,
        SIGNATURE_INVALID,
        PARSE_ERROR,
        THIS_UPDATE_FUTURE,
        IDP_NOT_SUPPORTED,
        DELTA_CRL_NOT_SUPPORTED,
        REVOKED,
        REVOCATION_EVIDENCE_OUT_OF_WINDOW,
        INCOMPLETE_CHAIN,
        CHAIN_LOOP,
        CHAIN_TOO_LONG,
        ROOT_NOT_TRUSTED,
        /** Статус отзыва не удалось установить: нет подходящего CRL при обязательной проверке. */
        REVOCATION_STATUS_UNKNOWN,
        /**
         * Размер или число записей CRL больше настроенного предела ({@link CrlLimits}). CRL может
         * быть подлинным: это отказ, а не признак порчи, и он не равносилен недоступному адресу.
         */
        CRL_LIMIT_EXCEEDED,
        /**
         * В CRL нет {@code nextUpdate}: такой CRL не устаревает, и его можно предъявлять
         * бесконечно, поэтому проверяющая сторона его не принимает.
         */
        NEXT_UPDATE_MISSING,
        /**
         * Контейнер CMS не защищён имитовставкой (OMAC), а вызывающая сторона её требует. Режим CTR
         * не обеспечивает целостность: подмену шифртекста или режима иначе не отличить от успеха.
         */
        INTEGRITY_REQUIRED,
        /**
         * У сертификата издателя CRL задан KeyUsage без {@code cRLSign}: такой издатель не вправе
         * подписывать CRL (RFC 5280 §4.2.1.3), даже если подпись верна.
         */
        MISSING_CRL_SIGN,
        OTHER
    }

    private final Reason reason;
    // Инициализация 0 в каждом конструкторе — явное документирование, что failInfo отсутствует.
    // Стандартный паттерн: константа не добавляет ясности для значений по умолчанию.
    private final int failInfo;

    public PkixException(String message) {
        super(message);
        this.reason = Reason.OTHER;
        this.failInfo = 0;
    }

    public PkixException(Reason reason, String message) {
        super(message);
        this.reason = reason;
        this.failInfo = 0;
    }

    /**
     * Конструктор с кодом отказа PKIFailureInfo (RFC 4210 §D.2).
     * Используется TSP-парсером для rejection-ответов.
     *
     * @param reason   типизированная причина
     * @param message  читаемое сообщение
     * @param failInfo битовая маска причин отказа (0 — отсутствует)
     */
    public PkixException(Reason reason, String message, int failInfo) {
        super(message);
        this.reason = reason;
        this.failInfo = failInfo;
    }

    public PkixException(String message, Throwable cause) {
        super(message, cause);
        this.reason = Reason.OTHER;
        this.failInfo = 0;
    }

    public PkixException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
        this.failInfo = 0;
    }

    /** Типизированная причина ошибки. */
    public Reason reason() {
        return reason;
    }

    /**
     * Битовая маска PKIFailureInfo из PKIStatusInfo (TSP-ответы).
     * См. константы {@link org.rssys.gost.pkix.GostOids#PKI_FAIL_BAD_ALG}.
     * 0 — failInfo отсутствует.
     *
     * @return битовая маска причин отказа
     */
    public int failInfo() {
        return failInfo;
    }
}
