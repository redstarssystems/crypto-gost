package org.rssys.gost.jsse.crl;

import org.rssys.gost.pkix.internal.net.HttpValidators;
import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Результат условной загрузки CRL ({@link CrlFetcher#fetchConditional}): полный ответ с телом,
 * ответ «не изменился» или отсутствие данных.
 *
 * <p>Не запись: у записи {@code equals} и {@code hashCode} по массиву сравнивают ссылки, а не
 * содержимое. Значение {@code Last-Modified} хранится только в допустимой форме
 * ({@link HttpValidators#acceptLastModified}); недопустимое отбрасывается. Оно приходит от
 * недоверенного сервера и возвращается ему в заголовке {@code If-Modified-Since} строкой как есть.
 */
public final class CrlFetchResult {

    private final byte[] der;
    private final String lastModified;
    private final boolean notModified;
    private final FetchFailure failure;

    private CrlFetchResult(
            byte[] der, String lastModified, boolean notModified, FetchFailure failure) {
        this.der = der;
        this.lastModified = HttpValidators.acceptLastModified(lastModified);
        this.notModified = notModified;
        this.failure = failure;
    }

    /**
     * Полный ответ без валидатора.
     *
     * @param der DER-кодированный CertificateList или {@code null} - данных нет
     */
    public static CrlFetchResult full(byte[] der) {
        return new CrlFetchResult(der, null, false, null);
    }

    /**
     * Полный ответ с {@code Last-Modified}.
     *
     * @param der          DER-кодированный CertificateList или {@code null} - данных нет
     * @param lastModified значение заголовка {@code Last-Modified} ответа или {@code null}
     */
    public static CrlFetchResult full(byte[] der, String lastModified) {
        return new CrlFetchResult(der, lastModified, false, null);
    }

    /**
     * Сервер ответил 304 на условный запрос: CRL не изменился. Дата из ответа 304 не передаётся:
     * валидатор двигает только ответ с телом.
     */
    public static CrlFetchResult notModified() {
        return new CrlFetchResult(null, null, true, null);
    }

    /**
     * Данных нет по известной причине. Загрузчик сам в журнал не пишет: причину записывает
     * менеджер доверия вместе с серийным номером и очищенным адресом.
     *
     * @param failure причина отказа
     */
    public static CrlFetchResult failed(FetchFailure failure) {
        return new CrlFetchResult(null, null, false, failure);
    }

    /** DER CRL; {@code null} у «не изменился» и когда данных нет. */
    public byte[] der() {
        return der;
    }

    /** Допустимое значение {@code Last-Modified} ответа или {@code null}. */
    public String lastModified() {
        return lastModified;
    }

    /** Причина, по которой данных нет, или {@code null}: данные есть либо причина не сообщена. */
    public FetchFailure failure() {
        return failure;
    }

    /** {@code true} - сервер ответил 304 на условный запрос, тела нет. */
    public boolean isNotModified() {
        return notModified;
    }

    @Override
    public String toString() {
        return "CrlFetchResult[notModified="
                + notModified
                + ", derLength="
                + (der == null ? "none" : String.valueOf(der.length))
                + (failure == null ? "" : ", failure=" + failure)
                + "]";
    }
}
