package org.rssys.gost.pkix.internal.net;

import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchOutcome.Failure;

/**
 * Правила перенаправлений загрузчиков и транспортов, одинаковые для всех реализаций.
 *
 * <p>{@code Location} приходит от недоверенного сервера (адрес OCSP, CDP и TSA задаёт тот, кто
 * выпустил сертификат или настроил клиента), поэтому каждый переход проверяется как исходный
 * адрес: схема, SSRF. Внутренний тип, не часть публичного API библиотеки.
 */
public final class RedirectPolicy {

    /** Наибольшее число запросов одной загрузки: исходный и не более четырёх перенаправлений. */
    public static final int MAX_REQUESTS = 5;

    private RedirectPolicy() {}

    /**
     * Результат разбора перенаправления: следующий адрес либо причина отказа.
     *
     * @param target   следующий адрес или {@code null}, если перенаправление недопустимо
     * @param failure  причина отказа или {@code null}, если {@code target} задан
     * @param rejected отвергнутый адрес перехода (при {@link Failure#DISALLOWED_SCHEME} и {@link Failure#DOWNGRADE}) или
     *                 {@code null}, если адрес не получен
     */
    public record Redirect(URI target, Failure failure, URI rejected) {}

    /**
     * Нужно ли следовать ответу как перенаправлению.
     *
     * <p>GET следует 301, 302, 303, 307, 308. POST - только 307 и 308: при 301, 302 и 303 клиенты
     * заменяют POST на GET (RFC 9110 §15.4), а повторный POST на чужой адрес без явного
     * разрешения недопустим.
     */
    public static boolean isRedirect(String method, int status) {
        if ("POST".equals(method)) {
            return status == 307 || status == 308;
        }
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /**
     * Следующий адрес по заголовку {@code Location}.
     *
     * @return адрес либо причина отказа: {@link Failure#MISSING_LOCATION} (нет или пустой
     *         {@code Location}), {@link Failure#BAD_LOCATION} (не разбирается),
     *         {@link Failure#DISALLOWED_SCHEME} (схема не из допустимых),
     *         {@link Failure#DOWNGRADE} (понижение {@code https} до {@code http})
     */
    public static Redirect next(URI current, String location, Set<String> allowedSchemes) {
        if (location == null || location.isEmpty()) {
            return new Redirect(null, Failure.MISSING_LOCATION, null);
        }
        URI next;
        try {
            next = current.resolve(location);
        } catch (IllegalArgumentException e) {
            return new Redirect(null, Failure.BAD_LOCATION, null);
        }
        String scheme = schemeOf(next);
        if (scheme == null || !allowedSchemes.contains(scheme)) {
            return new Redirect(null, Failure.DISALLOWED_SCHEME, next);
        }
        if ("https".equals(schemeOf(current)) && "http".equals(scheme)) {
            return new Redirect(null, Failure.DOWNGRADE, next);
        }
        return new Redirect(next, null, null);
    }

    /**
     * Допустим ли адрес для запроса. Вызывается для исходного адреса и для каждого перехода.
     *
     * @return {@code null}, если допустим; иначе {@link Failure#DISALLOWED_SCHEME} (схема не из
     *         допустимых) или {@link Failure#BLOCKED_TARGET} (адрес заблокирован проверкой SSRF)
     */
    public static Failure checkTarget(
            URI uri, Set<String> allowedSchemes, Predicate<URI> blockedTarget) {
        String scheme = schemeOf(uri);
        if (scheme == null || !allowedSchemes.contains(scheme)) {
            return Failure.DISALLOWED_SCHEME;
        }
        return blockedTarget.test(uri) ? Failure.BLOCKED_TARGET : null;
    }

    private static String schemeOf(URI uri) {
        String scheme = uri.getScheme();
        return scheme == null ? null : scheme.toLowerCase(Locale.ROOT);
    }
}
