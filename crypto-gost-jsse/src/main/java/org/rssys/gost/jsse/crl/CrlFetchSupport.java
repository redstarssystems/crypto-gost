package org.rssys.gost.jsse.crl;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Общая часть двух CRL-загрузчиков: проверка входа, вызов транспорта, перевод ошибки размера.
 *
 * <p>Контракт {@link CrlFetcher}: {@code null} - ответа нет (адрес не подошёл, не 200),
 * {@link IOException} - сетевая ошибка или срок, {@link CrlSizeLimitException} - ответ больше
 * предела. Последняя наследует {@link IOException}, поэтому в общем {@code catch} её нельзя
 * проглатывать: подлинный, но большой CRL выглядел бы как недоступный адрес.
 */
final class CrlFetchSupport {

    private CrlFetchSupport() {}

    /**
     * Загрузка с необязательным условным запросом. Без {@code lastModified} запрос безусловный и
     * результат «не изменился» невозможен. Сам в журнал не пишет: отказ возвращается причиной в
     * результате, а запись делает вызывающий, которому известен сертификат.
     */
    static CrlFetchResult runConditional(
            String crlUri,
            String lastModified,
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget,
            FetchTransport transport)
            throws IOException {
        if (crlUri == null || crlUri.isEmpty()) {
            return CrlFetchResult.failed(FetchFailure.BAD_ADDRESS);
        }
        URI uri;
        try {
            uri = URI.create(crlUri);
        } catch (RuntimeException e) {
            return CrlFetchResult.failed(FetchFailure.BAD_ADDRESS);
        }
        // Схема в URI регистронезависима (RFC 3986 §3.1), как и в транспорте
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            return CrlFetchResult.failed(FetchFailure.UNSUPPORTED_SCHEME);
        }
        try {
            // Подробности отказа движок пишет на DEBUG; для CRL отказ - «данных нет»
            FetchOutcome outcome =
                    transport.execute(
                            FetchRequest.crlConditional(
                                    uri, timeout, maxResponseSize, blockedTarget, lastModified));
            if (outcome.notModified()) {
                return CrlFetchResult.notModified();
            }
            if (!outcome.isSuccess()) {
                return CrlFetchResult.failed(outcome.reason());
            }
            return CrlFetchResult.full(outcome.body(), outcome.lastModified());
        } catch (BodyTooLargeException e) {
            long actual =
                    e.actual() == BodyTooLargeException.UNKNOWN_SIZE
                            ? CrlSizeLimitException.UNKNOWN_SIZE
                            : e.actual();
            throw new CrlSizeLimitException(
                    "CRL response exceeds " + maxResponseSize + " bytes", maxResponseSize, actual);
        }
    }
}
