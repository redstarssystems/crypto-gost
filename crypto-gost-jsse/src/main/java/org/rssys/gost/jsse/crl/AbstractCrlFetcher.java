package org.rssys.gost.jsse.crl;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Общая часть CRL-загрузчиков: срок, предел размера, проверка адреса и вызов транспорта. Наследники
 * задают только транспорт ({@code HttpClient} или {@code HttpURLConnection}) и конструкторы.
 */
abstract class AbstractCrlFetcher implements CrlFetcher {

    static final int DEFAULT_TIMEOUT_MS = 30_000;
    static final int DEFAULT_MAX_RESPONSE_SIZE = GostCrl.DEFAULT_MAX_CRL_SIZE;

    private final Duration timeout;
    private final int maxResponseSize;
    private final Predicate<URI> blockedTarget;
    private final FetchTransport transport;

    AbstractCrlFetcher(
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
    public final int maxResponseSize() {
        return maxResponseSize;
    }

    @Override
    public final byte[] fetch(String crlUri) throws IOException {
        return fetchConditional(crlUri, null).der();
    }

    @Override
    public final CrlFetchResult fetchConditional(String crlUri, String lastModified)
            throws IOException {
        return CrlFetchSupport.runConditional(
                crlUri, lastModified, timeout, maxResponseSize, blockedTarget, transport);
    }
}
