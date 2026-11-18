package org.rssys.gost.jsse.ocsp;

import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Общая часть OCSP-загрузчиков: срок, предел размера, проверка адреса и вызов транспорта.
 * Наследники задают только транспорт ({@code HttpClient} или {@code HttpURLConnection}) и
 * конструкторы.
 */
abstract class AbstractOcspFetcher implements OcspFetcher {

    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    /** Предел совпадает с пределом разбора: больший ответ разобрать всё равно нельзя. */
    static final int DEFAULT_MAX_RESPONSE_SIZE = GostOcspResponse.MAX_OCSP_RESPONSE_SIZE;

    private final Duration timeout;
    private final int maxResponseSize;
    private final Predicate<URI> blockedTarget;
    private final FetchTransport transport;

    AbstractOcspFetcher(
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget,
            FetchTransport transport) {
        // Ошибку настройки лучше показать при создании загрузчика, а не при первой загрузке
        this.timeout = Deadline.requireValidTimeout(timeout);
        if (maxResponseSize <= 0) {
            throw new IllegalArgumentException("maxResponseSize must be positive");
        }
        this.maxResponseSize = maxResponseSize;
        this.blockedTarget = blockedTarget;
        this.transport = transport;
    }

    /** Проверка адреса: по умолчанию блокируются приватные адреса, для тестов её можно снять. */
    static Predicate<URI> blockedTarget(boolean skipSsrfCheck) {
        return skipSsrfCheck ? uri -> false : FetchRequest.BLOCK_PRIVATE_ADDRESSES;
    }

    @Override
    public final byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        return fetchWithNonce(certDer, issuerDer, ocspResponderUri).response();
    }

    /** Отправляет OCSP-запрос и возвращает ответ вместе с nonce запроса (RFC 8954). */
    @Override
    public final OcspFetchResult fetchWithNonce(
            byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        return OcspFetchSupport.run(
                certDer,
                issuerDer,
                ocspResponderUri,
                timeout,
                maxResponseSize,
                blockedTarget,
                transport);
    }
}
