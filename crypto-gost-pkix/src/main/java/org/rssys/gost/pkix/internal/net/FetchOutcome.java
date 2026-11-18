package org.rssys.gost.pkix.internal.net;

import java.net.URI;
import java.util.Objects;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.util.SafeText;

/**
 * Результат одной загрузки: тело ответа 200, ответ 304 «не изменилось» на условный запрос либо
 * причина отказа.
 *
 * <p>Политические исходы (не 200, недопустимый адрес или переход, слишком много перенаправлений,
 * неожиданный тип содержимого) возвращаются значением: так вызывающий код различает их без
 * разбора текста сообщений. Операционные сбои остаются исключениями: срок
 * ({@link org.rssys.gost.pkix.util.DeadlineExceededException}), размер
 * ({@link org.rssys.gost.pkix.util.BodyTooLargeException}), сеть ({@link java.io.IOException}).
 * Внутренний тип, не часть публичного API библиотеки.
 *
 * <p>Поля отказа заполнены только у неуспеха. {@code failedUri} хранит полный адрес вместе с
 * параметрами запроса: выводить его в журнал и сообщения можно только через {@link SafeText}.
 *
 * @param body          тело ответа 200 или {@code null} у неуспеха и у «не изменилось»
 * @param failure       причина отказа или {@code null} у успеха и у «не изменилось»
 * @param notModified   {@code true} - ответ 304 на наш условный запрос (тела нет)
 * @param lastModified  допустимое ({@link HttpValidators#acceptLastModified}) значение
 *                      {@code Last-Modified} ответа 200 или {@code null}: заполнено только если ответ
 *                      пришёл без перенаправлений; у «не изменилось» и отказа всегда {@code null}
 * @param status        код статуса ответа, на котором остановились, или 0, если ответа не было
 * @param failedUri     адрес, на котором произошёл отказ, или {@code null} у успеха
 * @param viaRedirect   {@code true}, если отказ относится к перенаправлению (адрес или заголовок
 *                      {@code Location} перехода) либо ответ получен после перенаправления, а не
 *                      по адресу, заданному вызывающим; от этого зависит формулировка отказа
 * @param contentType   значение {@code Content-Type} ответа (очищенное, не длиннее
 *                      {@link SafeText#MAX_HEADER_CHARS} знаков) или {@code null}, если заголовка нет
 * @param errorBody     усечённое тело ответа не 200 или пустой массив; сырые байты недоверенного
 *                      сервера, выводить только через {@link SafeText}
 */
public record FetchOutcome(
        byte[] body,
        Failure failure,
        boolean notModified,
        String lastModified,
        int status,
        URI failedUri,
        boolean viaRedirect,
        String contentType,
        byte[] errorBody) {

    /** Причина отказа. */
    public enum Failure {
        /** Ответ не 200 и не перенаправление, которому следуем. */
        NON_200,
        /** Схема адреса не входит в допустимые. */
        DISALLOWED_SCHEME,
        /** Перенаправление понижает {@code https} до {@code http}. */
        DOWNGRADE,
        /** Адрес отвергнут проверкой SSRF. */
        BLOCKED_TARGET,
        /** Перенаправление без заголовка {@code Location}. */
        MISSING_LOCATION,
        /** {@code Location} не разбирается как адрес. */
        BAD_LOCATION,
        /** Исчерпан предел числа запросов. */
        TOO_MANY_REDIRECTS,
        /** Ответ 200, но тип содержимого не тот, что ожидался. */
        UNEXPECTED_CONTENT_TYPE
    }

    private static final byte[] NO_BYTES = new byte[0];

    /**
     * Причина отказа в виде, пригодном для журнала и результатов загрузчиков.
     *
     * @return причина или {@code null} у успеха и у «не изменилось»
     */
    public FetchFailure reason() {
        if (failure == null) {
            return null;
        }
        return switch (failure) {
            case NON_200 -> FetchFailure.HTTP_STATUS;
            case DISALLOWED_SCHEME -> FetchFailure.UNSUPPORTED_SCHEME;
            case BLOCKED_TARGET -> FetchFailure.ADDRESS_BLOCKED;
            case DOWNGRADE, MISSING_LOCATION, BAD_LOCATION, TOO_MANY_REDIRECTS ->
                    FetchFailure.REDIRECT_REJECTED;
            case UNEXPECTED_CONTENT_TYPE -> FetchFailure.CONTENT_TYPE;
        };
    }

    public FetchOutcome {
        Objects.requireNonNull(errorBody, "errorBody");
        int states = (body != null ? 1 : 0) + (failure != null ? 1 : 0) + (notModified ? 1 : 0);
        if (states != 1) {
            throw new IllegalArgumentException(
                    "Exactly one of body, failure and notModified must be set");
        }
        if (failure != null) {
            Objects.requireNonNull(failedUri, "failedUri");
        }
    }

    /** Успех: тело ответа 200, валидатора нет. */
    public static FetchOutcome success(byte[] body) {
        return success(body, null);
    }

    /**
     * Успех: тело ответа 200 и допустимый {@code Last-Modified} (или {@code null}).
     * Значение проверяется здесь же: недопустимое отбрасывается.
     */
    public static FetchOutcome success(byte[] body, String lastModified) {
        Objects.requireNonNull(body, "body");
        return new FetchOutcome(
                body,
                null,
                false,
                HttpValidators.acceptLastModified(lastModified),
                200,
                null,
                false,
                null,
                NO_BYTES);
    }

    /**
     * Ответ 304 на наш условный запрос: CRL не изменился, тела нет. Заголовок {@code Last-Modified}
     * ответа 304 не читается: по смыслу 304 дата файла не позже отправленного валидатора, более
     * ранняя откатила бы валидатор, а более поздняя противоречит RFC 9110 и увела бы валидатор
     * вперёд без тела. Валидатор двигает только ответ 200.
     */
    public static FetchOutcome unchanged() {
        return new FetchOutcome(null, null, true, null, 304, null, false, null, NO_BYTES);
    }

    /** Отказ без тела ошибки и без значения {@code Content-Type}. */
    public static FetchOutcome failure(
            Failure failure, int status, URI failedUri, boolean viaRedirect) {
        return failure(failure, status, failedUri, viaRedirect, null, NO_BYTES);
    }

    /** Отказ с заголовком {@code Content-Type} и усечённым телом ошибки. */
    public static FetchOutcome failure(
            Failure failure,
            int status,
            URI failedUri,
            boolean viaRedirect,
            String contentType,
            byte[] errorBody) {
        Objects.requireNonNull(failure, "failure");
        return new FetchOutcome(
                null,
                failure,
                false,
                null,
                status,
                failedUri,
                viaRedirect,
                contentType == null ? null : SafeText.printableAscii(contentType),
                errorBody == null ? NO_BYTES : errorBody);
    }

    /** {@code true}, если получено тело ответа 200 («не изменилось» и отказы - нет). */
    public boolean isSuccess() {
        return body != null;
    }
}
