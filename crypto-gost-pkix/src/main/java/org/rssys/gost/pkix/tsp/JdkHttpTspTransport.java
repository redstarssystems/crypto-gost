package org.rssys.gost.pkix.tsp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.JdkHttpFetch;
import org.rssys.gost.pkix.util.Deadline;

/**
 * Реализация {@link TspTransport} через {@link java.net.http.HttpClient} (JDK 11+).
 *
 * <p>Отправляет HTTP POST с Content-Type {@code application/timestamp-query} и принимает ответ с
 * типом {@code application/timestamp-reply}. JVM only. Для Android используйте {@link
 * UrlConnectionTspTransport}. vthread-совместимость не валидирована JFR.
 *
 * <p><b>Срок.</b> Один общий срок на весь запрос: соединение, заголовки, тело и перенаправления
 * (по умолчанию 30 с). Запрос идёт асинхронно, вызывающий поток ждёт не дольше остатка срока, по
 * истечении запрос отменяется и соединение закрывается. Медленный сервер, присылающий тело по
 * байту, срок не продлевает.
 *
 * <p><b>Перенаправления</b> выполняются вручную, а не клиентом: {@code POST} следует только за 307
 * и 308 (301, 302 и 303 клиенты превращают в {@code GET}, что для запроса штампа недопустимо), не
 * более 5 запросов, схема ({@code http} или {@code https}) и SSRF проверяются на каждом переходе,
 * понижение {@code https} до {@code http} запрещено. Поэтому клиент, переданный в конструктор,
 * обязан быть создан с {@code Redirect.NEVER}.
 *
 * <p><b>Ответ.</b> Принимается только 200 с типом {@code application/timestamp-reply}
 * (параметры и регистр не учитываются), не больше 1 МБ. При отказе сервера в сообщении исключения
 * приводится код статуса и начало тела ответа (до 128 знаков, только печатные ASCII).
 *
 * <p><b>Остаточный риск SSRF:</b> адрес проверяется до запроса, но само соединение делает {@code
 * HttpClient}, который заново обращается к DNS, поэтому атакующий с контролем DNS может подменить
 * публичный адрес на внутренний (DNS-rebinding). Штатными средствами {@code HttpClient} не
 * закрывается; адрес TSA обычно задаёт доверенный вызывающий код, поэтому риск ограничен. Само
 * разрешение имени в срок не входит. Подробнее - {@link org.rssys.gost.pkix.util.SsrfGuard}.
 */
public final class JdkHttpTspTransport implements TspTransport {

    private final JdkHttpFetch engine;
    private final Duration timeout;
    private final Predicate<URI> blockedTarget;

    /** Создаёт транспорт со сроком 30 с и клиентом по умолчанию без автоперенаправлений. */
    public JdkHttpTspTransport() {
        this(TspFetchSupport.DEFAULT_TIMEOUT);
    }

    /**
     * Создаёт транспорт с заданным сроком и клиентом по умолчанию.
     *
     * @param timeout общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @throws IllegalArgumentException если срок недопустим
     */
    public JdkHttpTspTransport(Duration timeout) {
        this(defaultClient(timeout), timeout, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /**
     * Создаёт транспорт с заданным клиентом и сроком 30 с.
     *
     * @param httpClient клиент, созданный с {@code Redirect.NEVER}
     * @throws IllegalArgumentException если клиент сам следует перенаправлениям: он обошёл бы
     *                                  проверку адреса и общий срок на переходах
     */
    public JdkHttpTspTransport(HttpClient httpClient) {
        this(httpClient, TspFetchSupport.DEFAULT_TIMEOUT);
    }

    /**
     * @param httpClient клиент, созданный с {@code Redirect.NEVER}
     * @param timeout    общий срок запроса, от 1 мс до {@link Deadline#MAX_FETCH_TIMEOUT}
     * @throws IllegalArgumentException если клиент сам следует перенаправлениям или срок
     *                                  недопустим
     */
    public JdkHttpTspTransport(HttpClient httpClient, Duration timeout) {
        this(httpClient, timeout, FetchRequest.BLOCK_PRIVATE_ADDRESSES);
    }

    /** Для тестов: собственная проверка адреса ({@code true} - заблокировать). */
    JdkHttpTspTransport(Duration timeout, Predicate<URI> blockedTarget) {
        this(defaultClient(timeout), timeout, blockedTarget);
    }

    private JdkHttpTspTransport(
            HttpClient httpClient, Duration timeout, Predicate<URI> blockedTarget) {
        this.timeout = Deadline.requireValidTimeout(timeout);
        this.engine = new JdkHttpFetch(httpClient);
        this.blockedTarget = blockedTarget;
    }

    private static HttpClient defaultClient(Duration timeout) {
        // connectTimeout - запасной ограничитель: общий срок держит сам движок
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Deadline.requireValidTimeout(timeout))
                .build();
    }

    @Override
    public byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException {
        return TspFetchSupport.send(tspRequestDer, tsaUrl, timeout, blockedTarget, engine::execute);
    }
}
