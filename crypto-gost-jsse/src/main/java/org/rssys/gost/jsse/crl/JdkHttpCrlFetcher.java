package org.rssys.gost.jsse.crl;

import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.JdkHttpFetch;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Реализация {@link CrlFetcher} на JDK HttpClient с SSRF-защитой.
 *
 * <p>JVM only. Для Android используйте {@link UrlConnectionCrlFetcher}. vthread-совместимость не
 * валидирована JFR.
 *
 * <p><b>Срок.</b> Один общий срок на весь запрос: соединение, заголовки, тело и перенаправления.
 * Запрос идёт асинхронно, вызывающий поток ждёт не дольше остатка срока, по истечении запрос
 * отменяется и соединение закрывается. Сервер CDP, присылающий тело по байту, срок не продлевает.
 * Это важно ещё и потому, что менеджер доверия грузит CRL одним потоком на адрес, а остальные ждут
 * его без собственного срока.
 *
 * <p><b>Ответ.</b> Принимается только 200; ответ больше предела (по заявленному
 * {@code Content-Length} или фактически) даёт {@link CrlSizeLimitException}, тело ответа не-200 не
 * накапливается. GET следует перенаправлениям 301, 302, 303, 307, 308, не более 5 запросов; SSRF и
 * схема проверяются на каждом переходе, понижение {@code https} до {@code http} запрещено.
 * Допустимы {@code http://} и {@code https://}.
 *
 * <p><b>SSRF.</b> Адрес проверяется до запроса (блокировка private/reserved IP после
 * DNS-разрешения, fail-closed). <b>Остаточный риск:</b> соединение делает {@code HttpClient},
 * который заново обращается к DNS, поэтому тот, кто контролирует ответы DNS, может подменить публичный адрес
 * на внутренний между проверкой и соединением (DNS-rebinding). Риск ограничен: содержимое
 * внутренних ресурсов не раскрывается (ответ CRL проверяется по подписи), возможно лишь
 * зондирование внутренней сети. Само
 * разрешение имени в срок не входит. Подробнее — {@link org.rssys.gost.pkix.util.SsrfGuard}.
 */
public final class JdkHttpCrlFetcher extends AbstractCrlFetcher {

    /** Создаёт загрузчик с таймаутом и пределом размера по умолчанию, с SSRF-защитой. */
    public JdkHttpCrlFetcher() {
        this(Duration.ofMillis(DEFAULT_TIMEOUT_MS), DEFAULT_MAX_RESPONSE_SIZE);
    }

    /**
     * @param timeout         общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @param maxResponseSize максимальный размер CRL-ответа в байтах (защита от OOM), больше нуля
     * @throws IllegalArgumentException если срок или предел размера недопустимы
     */
    public JdkHttpCrlFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    JdkHttpCrlFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
        this(timeout, maxResponseSize, blockedTarget(skipSsrfCheck));
    }

    /**
     * Для тестов — собственная проверка адреса ({@code true} - заблокировать), в том числе на
     * переходах.
     */
    JdkHttpCrlFetcher(Duration timeout, int maxResponseSize, Predicate<URI> blockedTarget) {
        super(timeout, maxResponseSize, blockedTarget, new JdkHttpFetch());
    }
}
