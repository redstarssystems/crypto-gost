package org.rssys.gost.jsse.ocsp;

import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.UrlConnectionFetch;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Реализация {@link OcspFetcher} на {@link HttpURLConnection} с SSRF-защитой.
 *
 * <p>Android-совместимая альтернатива {@code JdkHttpOcspFetcher}: использует
 * {@link HttpURLConnection} из {@code java.net}, доступный с API level 1. vthread-совместимость не
 * валидирована JFR.
 *
 * <p><b>Срок.</b> Один общий срок на весь запрос, включая перенаправления. Соединение и заголовки
 * ограничивает сторож ({@link org.rssys.gost.pkix.util.DeadlineWatchdog}), тело — проверка срока
 * между чтениями при {@code readTimeout = max(1 мс, срок/4)}. Честная гарантия двусторонняя: тело не
 * позже «срок + одно чтение» (не больше {@code readTimeout} сверх срока), а сервер, молчащий
 * дольше {@code readTimeout}, считается недоступным раньше общего срока; блокирующее чтение прервать
 * нельзя. Разрешение имени в срок не входит.
 *
 * <p><b>Ответ.</b> Принимается только 200; тело больше предела (по заявленному
 * {@code Content-Length} или фактически) отвергается. Перенаправления следуют только для POST
 * 307 и 308, не более 5 запросов; SSRF и схема проверяются на каждом переходе. Принимается только
 * {@code http://}. Метод {@code fetch} никогда не бросает исключений: любая ошибка даёт {@code null}.
 */
public final class UrlConnectionOcspFetcher extends AbstractOcspFetcher {

    /** Создаёт fetcher с таймаутом 5 с и лимитом ответа 256 КБ. */
    public UrlConnectionOcspFetcher() {
        this(DEFAULT_TIMEOUT, DEFAULT_MAX_RESPONSE_SIZE);
    }

    /**
     * @param timeout         общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @param maxResponseSize максимальный размер OCSP-ответа в байтах (защита от OOM), больше нуля
     * @throws IllegalArgumentException если срок или предел размера недопустимы
     */
    public UrlConnectionOcspFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    UrlConnectionOcspFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
        this(timeout, maxResponseSize, blockedTarget(skipSsrfCheck));
    }

    /**
     * Для тестов — собственная проверка адреса ({@code true} - заблокировать), в том числе на
     * переходах.
     */
    UrlConnectionOcspFetcher(Duration timeout, int maxResponseSize, Predicate<URI> blockedTarget) {
        super(timeout, maxResponseSize, blockedTarget, UrlConnectionFetch::execute);
    }
}
