package org.rssys.gost.jsse.crl;

import java.io.IOException;

/**
 * Интерфейс для получения CRL (Certificate Revocation List) по URI из CDP.
 * <p>
 * Аналог {@link org.rssys.gost.jsse.ocsp.OcspFetcher} для CRL.
 * Реализация должна быть vthread-safe.
 *
 * <p>Реализация обязана ограничивать время загрузки (таймаут соединения и чтения). Если CRL нет в
 * кэше, менеджер доверия загружает его одним потоком на адрес, а остальные соединения ждут
 * результата без собственного таймаута: зависшая загрузка без ограничения времени задержала бы
 * их все. Ожидание нельзя ограничить на стороне менеджера: срабатывание такого предела считалось
 * бы недоступным адресом и отключало бы проверку отзыва при {@code CrlPolicy.IF_CDP_PRESENT}.
 */
public interface CrlFetcher {

    /** Значение {@link #maxResponseSize()}, когда реализация не сообщает свой предел. */
    int UNKNOWN_LIMIT = -1;

    /**
     * Запрашивает CRL по URI.
     *
     * <p>Если ответ больше предела реализации, нужно бросить {@link CrlSizeLimitException}, а не
     * возвращать {@code null}: иначе подлинный, но большой CRL выглядел бы как «адрес
     * недоступен», и при политике {@code IF_CDP_PRESENT} проверка отзыва молча отключалась бы.
     *
     * @param crlUri URI из CRLDistributionPoints сертификата
     * @return DER-encoded CertificateList (RFC 5280 §5.1) или null при ошибке
     * @throws CrlSizeLimitException если ответ больше предела реализации (отказ проверки)
     * @throws IOException при сетевой ошибке (caller отличает от отсутствия ответа)
     */
    byte[] fetch(String crlUri) throws IOException;

    /**
     * Условная загрузка CRL: с {@code If-Modified-Since}, если реализация это умеет.
     *
     * <p>По умолчанию - полная загрузка через {@link #fetch(String)} без валидатора: лямбды и
     * пользовательские загрузчики, знающие только {@code fetch}, работают как раньше (для них
     * каждая перепроверка кэша полная). Стандартные загрузчики библиотеки переопределяют метод:
     * при допустимом {@code lastModified} они посылают {@code If-Modified-Since} с этим значением
     * строкой как есть (и не посылают {@code If-None-Match}) и возвращают
     * {@link CrlFetchResult#isNotModified() «не изменился»} на ответ 304. Сервер вправе ответить 200
     * вместо 304: это обычная полная загрузка. Ответ 304 не подписан, поэтому его принимает только
     * кэш и только для живой записи.
     *
     * @param crlUri       URI из CRLDistributionPoints сертификата
     * @param lastModified {@code Last-Modified} прошлого ответа по этому адресу или {@code null} -
     *                     безусловная загрузка
     * @return ответ с телом (и, если сервер прислал, допустимым {@code Last-Modified}), «не
     *         изменился» либо результат без данных
     * @throws CrlSizeLimitException если ответ больше предела реализации (отказ проверки)
     * @throws IOException при сетевой ошибке
     */
    default CrlFetchResult fetchConditional(String crlUri, String lastModified) throws IOException {
        return CrlFetchResult.full(fetch(crlUri));
    }

    /**
     * Предел размера ответа в байтах, который применяет эта реализация.
     *
     * <p>Менеджер доверия сверяет его с {@code maxCrlSize} при создании: загрузчик с меньшим
     * пределом оборвал бы загрузку раньше, чем сработает лимит разбора. Собственная реализация
     * может переопределить метод, чтобы участвовать в этой проверке. По умолчанию предел
     * неизвестен ({@link #UNKNOWN_LIMIT}), и проверка такой загрузчик пропускает.
     *
     * @return предел в байтах или {@link #UNKNOWN_LIMIT}
     */
    default int maxResponseSize() {
        return UNKNOWN_LIMIT;
    }

    /**
     * Описание несовместимости загрузчика с лимитом разбора или {@code null}, если всё в порядке.
     * Единственный источник текста для конструктора менеджера доверия и сборщиков.
     *
     * @param fetcher    загрузчик (может быть null)
     * @param maxCrlSize предел размера CRL в {@code GostCrl}
     * @return текст ошибки или null
     */
    static String limitProblem(CrlFetcher fetcher, int maxCrlSize) {
        if (fetcher == null) {
            return null;
        }
        int limit = fetcher.maxResponseSize();
        if (limit > 0 && limit < maxCrlSize) {
            return "CrlFetcher.maxResponseSize ("
                    + limit
                    + ") must be >= maxCrlSize ("
                    + maxCrlSize
                    + "): the fetcher would cut the response before the CRL limit is applied";
        }
        return null;
    }
}
