package org.rssys.gost.pkix.tsp;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.UrlConnectionFetch;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Реализация {@link TspTransport} через {@link HttpURLConnection}.
 *
 * <p>Android-совместимая альтернатива {@link JdkHttpTspTransport}: использует {@link
 * HttpURLConnection} из {@code java.net}, доступный с API level 1, и не требует {@code
 * java.net.http} (его нет в Android core library). Поведение одинаково: те же правила ответа,
 * перенаправлений и сообщений об ошибках.
 *
 * <p><b>Срок.</b> Один общий срок на весь запрос, включая перенаправления (по умолчанию 30 с).
 * Сторож {@link org.rssys.gost.pkix.util.DeadlineWatchdog} защищает соединение и заголовки;
 * тело читается с проверкой срока между чтениями, а блокирующее чтение ограничено таймаутом
 * чтения в четверть срока. Перерасход срока не больше одного такого чтения.
 *
 * <p><b>Перенаправления:</b> {@code POST} следует только за 307 и 308, не более 5 запросов, схема
 * и SSRF проверяются на каждом переходе, понижение {@code https} до {@code http} запрещено.
 *
 * <p>vthread-совместимость не валидирована JFR.
 */
public final class UrlConnectionTspTransport implements TspTransport {

    private final Duration timeout;
    private final Predicate<URI> blockedTarget;

    /** Создаёт транспорт со сроком 30 с. */
    public UrlConnectionTspTransport() {
        this(TspFetchSupport.DEFAULT_TIMEOUT);
    }

    /**
     * @param timeout общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @throws IllegalArgumentException если срок недопустим
     */
    public UrlConnectionTspTransport(Duration timeout) {
        this(timeout, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /** Для тестов: собственная проверка адреса ({@code true} - заблокировать). */
    UrlConnectionTspTransport(Duration timeout, Predicate<URI> blockedTarget) {
        this.timeout = Deadline.requireValidTimeout(timeout);
        this.blockedTarget = blockedTarget;
    }

    @Override
    public byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException {
        return TspFetchSupport.send(
                tspRequestDer, tsaUrl, timeout, blockedTarget, UrlConnectionFetch::execute);
    }
}
