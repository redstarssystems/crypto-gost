package org.rssys.gost.jsse.ocsp;

/**
 * Политика проверки OCSP-статуса сертификата пира.
 * <p>
 * Обязательность OCSP относится к <b>серверному</b> сертификату. Для
 * клиентских сертификатов OCSP не обязателен: при {@link #STAPLING_OR_FETCH}
 * выполняется best-effort fetch, при {@link #STAPLING_REQUIRED} загрузка не
 * выполняется. Полученный ответ проверяется; отсутствие ответа не блокирует
 * mTLS. Клиентский staple по TLS управляется отдельной политикой
 * {@link org.rssys.gost.tls13.config.ClientOcspPolicy} (по умолчанию {@code OFF}:
 * не запрашивается). Строгий отзыв клиентов без staple задаётся через
 * {@link org.rssys.gost.jsse.crl.CrlPolicy#REQUIRE}: если OCSP получен и валиден,
 * CRL не проверяется.
 */
public enum OcspPolicy {

    /**
     * Проверить присланный (stapled) OCSP-ответ, если он есть; если нет, пропустить.
     * <p>
     * Присланный ответ проверяется всегда, отключить эту проверку нельзя.
     */
    IF_PRESENT,

    /**
     * Stapled OCSP серверного сертификата обязателен, без fetch.
     * <p>
     * К клиентским сертификатам не применяется.
     */
    STAPLING_REQUIRED,

    /**
     * Для серверного сертификата: stapled OCSP или client-side fetch.
     * <p>
     * При наличии stapled OCSP-ответа — проверка штатно.
     * Если степла нет — client-side OCSP fetch выполняется через
     * {@link org.rssys.gost.jsse.ocsp.OcspFetcher}, заданный при создании менеджера доверия.
     * <p>
     * @apiNote Текущая реализация:
     *          (1) status_request extension отправляется в ClientHello
     *              автоматически (TlsMessageBuilder.buildCommonExtensions);
     *          (2) при отсутствии степла и {@code ocspFetcher != null}
     *              выполняется HTTP POST к OCSP-responder'у из
     *              AIA-расширения сертификата;
     *          (3) для серверного сертификата, если fetch вернул null или
     *              {@code ocspFetcher} не установлен — fail-closed;
     *          (4) для клиентского сертификата fetch выполняется только при
     *              STAPLING_OR_FETCH (best-effort); при STAPLING_REQUIRED
     *              загрузки нет, отсутствие ответа не отказ; строгость
     *              задаётся через
     *              {@link org.rssys.gost.jsse.crl.CrlPolicy#REQUIRE} только
     *              при отсутствии OCSP-ответа;
     *          (5) HTTP-запросы только http:// (не https): для проверки TLS-соединения
     *          к службе OCSP потребовалась бы сама проверка отзыва её сертификата.
     */
    STAPLING_OR_FETCH
}
