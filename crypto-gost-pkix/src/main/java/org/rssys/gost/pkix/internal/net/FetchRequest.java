package org.rssys.gost.pkix.internal.net;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import org.rssys.gost.pkix.util.SsrfGuard;

/**
 * Параметры одной загрузки по HTTP: OCSP-ответа, CRL или штампа времени. Внутренний тип
 * загрузчиков и транспортов, не часть публичного API библиотеки.
 *
 * @param method               {@code GET} (CRL) или {@code POST} (OCSP, TSP)
 * @param uri                  адрес
 * @param body                 тело запроса или {@code null}
 * @param contentType          тип тела запроса (для {@code POST})
 * @param headers              дополнительные заголовки запроса (неизменяемая копия)
 * @param timeout              общий срок на весь запрос, включая перенаправления
 * @param maxResponseSize      предел размера ответа 200 в байтах
 * @param allowedSchemes       допустимые схемы адреса и перенаправлений (строчными буквами)
 * @param expectedMediaType    ожидаемый тип содержимого ответа 200 (без параметров, без учёта
 *                             регистра) или {@code null}, если тип не проверяется; сверяется до
 *                             чтения тела
 * @param errorBodyLimit       предел усечённого тела ответа не 200 в байтах; 0 - тело ошибки не
 *                             читается
 * @param blockedTarget        {@code true} - адрес заблокирован; применяется к исходному адресу и
 *                             к каждому переходу
 * @param ifModifiedSince      значение {@code Last-Modified} прошлой загрузки для условного запроса
 *                             или {@code null}; отправляется как {@code If-Modified-Since} строкой как
 *                             есть, только на первом запросе (до перенаправлений) и только если
 *                             {@link HttpValidators#acceptLastModified допустимо}
 */
public record FetchRequest(
        String method,
        URI uri,
        byte[] body,
        String contentType,
        Map<String, String> headers,
        Duration timeout,
        int maxResponseSize,
        Set<String> allowedSchemes,
        String expectedMediaType,
        int errorBodyLimit,
        Predicate<URI> blockedTarget,
        String ifModifiedSince) {

    /** Проверка по умолчанию: внутренние и зарезервированные адреса блокируются. */
    public static final Predicate<URI> BLOCK_PRIVATE_ADDRESSES = SsrfGuard::isPrivateAddress;

    /** OCSP принимает только http: https идёт через TLS JDK, а не через ГОСТ. */
    public static final Set<String> OCSP_SCHEMES = Set.of("http");

    /** CDP бывает и http, и https; понижение https до http при перенаправлении запрещено. */
    public static final Set<String> CRL_SCHEMES = Set.of("http", "https");

    /** Адрес TSA бывает и http, и https. */
    public static final Set<String> TSP_SCHEMES = Set.of("http", "https");

    /** Предел тела ошибки TSA, попадающего в сообщение исключения. */
    public static final int TSP_ERROR_BODY_LIMIT = 128;

    private static final String METHOD_GET = "GET";
    private static final String METHOD_POST = "POST";
    private static final String OCSP_REQUEST_TYPE = "application/ocsp-request";
    private static final String TSP_REQUEST_TYPE = "application/timestamp-query";

    /** Тип содержимого ответа TSA. */
    public static final String TSP_RESPONSE_TYPE = "application/timestamp-reply";

    private static final String ACCEPT = "Accept";

    public FetchRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(allowedSchemes, "allowedSchemes");
        Objects.requireNonNull(blockedTarget, "blockedTarget");
        if (errorBodyLimit < 0) {
            throw new IllegalArgumentException("errorBodyLimit must not be negative");
        }
        headers = Map.copyOf(headers);
        allowedSchemes = Set.copyOf(allowedSchemes);
    }

    /** Запрос OCSP: POST, ошибка не читается, тип ответа не проверяется. */
    public static FetchRequest ocsp(
            URI uri,
            byte[] ocspRequestDer,
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget) {
        return new FetchRequest(
                METHOD_POST,
                uri,
                ocspRequestDer,
                OCSP_REQUEST_TYPE,
                Map.of(),
                timeout,
                maxResponseSize,
                OCSP_SCHEMES,
                null,
                0,
                blockedTarget,
                null);
    }

    /** Запрос CRL: GET, ошибка не читается, тип ответа не проверяется. */
    public static FetchRequest crl(
            URI uri, Duration timeout, int maxResponseSize, Predicate<URI> blockedTarget) {
        return new FetchRequest(
                METHOD_GET,
                uri,
                null,
                null,
                Map.of(),
                timeout,
                maxResponseSize,
                CRL_SCHEMES,
                null,
                0,
                blockedTarget,
                null);
    }

    /**
     * Условный запрос CRL: как {@link #crl}, но с {@code If-Modified-Since}. Ответ 304 при допустимом
     * значении означает «не изменился» и приходит отдельным исходом без тела.
     *
     * @param ifModifiedSince {@code Last-Modified} прошлой загрузки или {@code null} (безусловный)
     */
    public static FetchRequest crlConditional(
            URI uri,
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget,
            String ifModifiedSince) {
        FetchRequest base = crl(uri, timeout, maxResponseSize, blockedTarget);
        return new FetchRequest(
                base.method(),
                base.uri(),
                base.body(),
                base.contentType(),
                base.headers(),
                base.timeout(),
                base.maxResponseSize(),
                base.allowedSchemes(),
                base.expectedMediaType(),
                base.errorBodyLimit(),
                base.blockedTarget(),
                ifModifiedSince);
    }

    /**
     * Запрос TSP: POST с {@code application/timestamp-query}, ответ 200 обязан быть
     * {@code application/timestamp-reply}, тело ошибки читается и усекается.
     */
    public static FetchRequest tsp(
            URI uri,
            byte[] tspRequestDer,
            Duration timeout,
            int maxResponseSize,
            Predicate<URI> blockedTarget) {
        return new FetchRequest(
                METHOD_POST,
                uri,
                tspRequestDer,
                TSP_REQUEST_TYPE,
                Map.of(ACCEPT, TSP_RESPONSE_TYPE),
                timeout,
                maxResponseSize,
                TSP_SCHEMES,
                TSP_RESPONSE_TYPE,
                TSP_ERROR_BODY_LIMIT,
                blockedTarget,
                null);
    }
}
