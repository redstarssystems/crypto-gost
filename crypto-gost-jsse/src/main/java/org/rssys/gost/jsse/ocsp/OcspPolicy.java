package org.rssys.gost.jsse.ocsp;

/**
 * Политика проверки OCSP-статуса сертификата пира.
 * <p>
 * Определяет, требуется ли OCSP-степплинг и/или client-side fetch.
 */
public enum OcspPolicy {

    /** OCSP не проверять */
    DISABLED,

    /** Проверить stapled OCSP если есть, пропустить если нет */
    IF_PRESENT,

    /** Stapled OCSP обязателен, без fetch */
    STAPLING_REQUIRED,

    /**
     * Stapled OCSP или client-side fetch.
     * <p>
     * При наличии stapled OCSP-ответа — проверка штатно.
     * Если степла нет — client-side OCSP fetch выполняется через
     * {@link org.rssys.gost.jsse.ocsp.OcspFetcher} (если установлен
     * через конструктор {@code GostX509TrustManager}).
     * <p>
     * @apiNote Текущая реализация:
     *          (1) status_request extension отправляется в ClientHello
     *              автоматически (TlsMessageBuilder.buildCommonExtensions);
     *          (2) при отсутствии степла и {@code ocspFetcher != null}
     *              выполняется HTTP POST к OCSP-responder'у из
     *              AIA-расширения сертификата;
     *          (3) если fetch вернул null или {@code ocspFetcher} не
     *              установлен — fail-closed (сертификат считается
     *              невалидным);
     *          (4) HTTP-запросы только http:// (не https) из-за
 *          chicken-and-egg проблема.
     */
    STAPLING_OR_FETCH
}
