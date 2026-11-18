package org.rssys.gost.jsse.ocsp;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.FetchFailure;

/**
 * Общая часть двух OCSP-загрузчиков: проверка входа, построение запроса, вызов транспорта.
 *
 * <p>Контракт {@link OcspFetcher}: ошибка любого рода даёт {@code null}, непроверяемое исключение
 * наружу не выходит. Адрес OCSP задаёт тот, кто выпустил сертификат, поэтому непредвиденный сбой
 * (битый ответ, неожиданное исключение библиотеки HTTP) не должен ломать проверку сертификата
 * иначе, чем обычная недоступность.
 */
final class OcspFetchSupport {

    private OcspFetchSupport() {}

    /**
     * Загружает OCSP-ответ. Сам в журнал не пишет: отказ возвращается причиной в результате, а
     * запись делает вызывающий, которому известен сертификат (один отказ - одна запись).
     */
    static OcspFetchResult run(
            byte[] certDer,
            byte[] issuerDer,
            String ocspResponderUri,
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget,
            FetchTransport transport) {
        // Пустой сертификат или издатель - ошибка вызова, а не адреса
        if (certDer == null || issuerDer == null) {
            return OcspFetchResult.failed(FetchFailure.INTERNAL);
        }
        if (ocspResponderUri == null) {
            return OcspFetchResult.failed(FetchFailure.BAD_ADDRESS);
        }
        URI uri;
        try {
            uri = URI.create(ocspResponderUri);
        } catch (IllegalArgumentException e) {
            return OcspFetchResult.failed(FetchFailure.BAD_ADDRESS);
        }
        // Схема в URI регистронезависима (RFC 3986 §3.1), как и в транспорте
        if (!"http".equalsIgnoreCase(uri.getScheme())) {
            return OcspFetchResult.failed(FetchFailure.UNSUPPORTED_SCHEME);
        }
        try {
            OcspRequest ocspRequest =
                    OcspRequestBuilder.create().targetCert(certDer).issuerCert(issuerDer).build();
            FetchOutcome outcome =
                    transport.execute(
                            FetchRequest.ocsp(
                                    uri,
                                    ocspRequest.der(),
                                    timeout,
                                    maxResponseSize,
                                    blockedTarget));
            // Подробности отказа движок пишет на DEBUG; для OCSP любой отказ - «ответа нет»
            return outcome.isSuccess()
                    ? new OcspFetchResult(outcome.body(), ocspRequest.nonce())
                    : OcspFetchResult.failed(outcome.reason());
        } catch (IOException e) {
            return OcspFetchResult.failed(FetchFailure.of(e));
        } catch (RuntimeException e) {
            // Контракт OcspFetcher: непроверяемое исключение наружу не выходит
            return OcspFetchResult.failed(FetchFailure.INTERNAL);
        }
    }
}
