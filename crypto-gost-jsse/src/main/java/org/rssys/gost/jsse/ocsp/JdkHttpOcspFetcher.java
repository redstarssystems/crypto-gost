package org.rssys.gost.jsse.ocsp;

import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.JdkHttpFetch;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Реализация {@link OcspFetcher} на JDK HttpClient с SSRF-защитой.
 *
 * <p>JVM only. Для Android используйте {@link UrlConnectionOcspFetcher}. vthread-совместимость не
 * валидирована JFR.
 *
 * <p><b>Срок.</b> Один общий срок на весь запрос: соединение, заголовки, тело и перенаправления.
 * Запрос идёт асинхронно, вызывающий поток ждёт не дольше остатка срока, по истечении запрос
 * отменяется и соединение закрывается. Медленный сервер, присылающий тело по байту, срок не
 * продлевает.
 *
 * <p><b>Ответ.</b> Принимается только 200; тело больше предела (по заявленному
 * {@code Content-Length} или фактически) отвергается. Перенаправления следуют только для POST
 * 307 и 308, не более 5 запросов; SSRF и схема проверяются на каждом переходе. Принимается только
 * {@code http://}. Метод {@code fetch} никогда не бросает исключений: любая ошибка даёт {@code null}.
 *
 * <p><b>SSRF.</b> Адрес проверяется до запроса (блокировка private/reserved IP после
 * DNS-разрешения, fail-closed). <b>Остаточный риск:</b> само соединение делает {@code HttpClient},
 * который заново обращается к DNS, поэтому тот, кто контролирует ответы DNS, может подменить публичный
 * адрес на внутренний между проверкой и соединением (DNS-rebinding). Штатными средствами
 * HttpClient не закрывается; риск ограничен: содержимое внутренних ресурсов не раскрывается
 * (ответ OCSP проверяется по подписи), возможно лишь зондирование внутренней сети. Само разрешение имени в срок не входит.
 * Подробнее — {@link org.rssys.gost.pkix.util.SsrfGuard}.
 */
public final class JdkHttpOcspFetcher extends AbstractOcspFetcher {

    /** Создаёт fetcher с таймаутом 5 с и лимитом ответа 256 КБ. */
    public JdkHttpOcspFetcher() {
        this(DEFAULT_TIMEOUT, DEFAULT_MAX_RESPONSE_SIZE);
    }

    /**
     * @param timeout         общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @param maxResponseSize максимальный размер OCSP-ответа в байтах (защита от OOM), больше нуля
     * @throws IllegalArgumentException если срок или предел размера недопустимы
     */
    public JdkHttpOcspFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    JdkHttpOcspFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
        this(timeout, maxResponseSize, blockedTarget(skipSsrfCheck));
    }

    /**
     * Для тестов — собственная проверка адреса ({@code true} - заблокировать), в том числе на
     * переходах.
     */
    JdkHttpOcspFetcher(Duration timeout, int maxResponseSize, Predicate<URI> blockedTarget) {
        super(timeout, maxResponseSize, blockedTarget, new JdkHttpFetch());
    }
}
