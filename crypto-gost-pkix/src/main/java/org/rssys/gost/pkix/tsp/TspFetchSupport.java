package org.rssys.gost.pkix.tsp;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.function.Predicate;
import org.rssys.gost.pkix.internal.net.FetchOutcome;
import org.rssys.gost.pkix.internal.net.FetchRequest;
import org.rssys.gost.pkix.internal.net.FetchTransport;
import org.rssys.gost.pkix.util.BodyTooLargeException;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.util.SafeText;

/**
 * Общая часть двух транспортов TSP: проверка входа, запрос через движок загрузки, перевод исхода
 * в {@link IOException} с прежними текстами сообщений.
 *
 * <p>Контракт {@link TspTransport}: {@link IllegalArgumentException} - только неверный вход
 * вызывающего (пустой аргумент, синтаксически неверный адрес). Всё, что пришло от сервера
 * ({@code Location}, перенаправления, ответ), - {@link IOException}. Адрес в сообщениях выводится
 * через {@link SafeText}: без учётных данных и параметров запроса.
 */
final class TspFetchSupport {

    /** Срок по умолчанию на весь запрос: соединение, заголовки, тело и перенаправления. */
    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Наибольший размер TSP-ответа - защита от исчерпания памяти. 1 МБ с запасом: типичный ответ
     * содержит подпись, цепочку сертификатов и метаданные (единицы КБ).
     *
     * <p>В отличие от OCSP, где превышение предела даёт «ответа нет» (проверка отзыва
     * необязательна), здесь исход всегда {@link IOException}: проверка штампа детерминирована, и
     * усечённый ответ нельзя выдавать за «TSA недоступна».
     */
    static final int MAX_RESPONSE_SIZE = 1_048_576;

    private TspFetchSupport() {}

    static byte[] send(
            byte[] tspRequestDer,
            String tsaUrl,
            Duration timeout,
            Predicate<URI> blockedTarget,
            FetchTransport engine)
            throws IOException {
        if (tspRequestDer == null || tspRequestDer.length == 0) {
            throw new IllegalArgumentException("tspRequestDer must not be empty");
        }
        if (tsaUrl == null || tsaUrl.isBlank()) {
            throw new IllegalArgumentException("tsaUrl must not be empty");
        }
        // Синтаксическая ошибка адреса - ошибка вызывающего: IllegalArgumentException от URI.create
        URI uri = URI.create(tsaUrl);
        String shownUri = SafeText.uri(uri);
        if (Thread.interrupted()) {
            Thread.currentThread().interrupt();
            throw new IOException("TSP request interrupted for " + shownUri);
        }

        FetchOutcome outcome;
        try {
            outcome =
                    engine.execute(
                            FetchRequest.tsp(
                                    uri, tspRequestDer, timeout, MAX_RESPONSE_SIZE, blockedTarget));
        } catch (BodyTooLargeException e) {
            throw new IOException(
                    "TSP response exceeds maximum size of " + MAX_RESPONSE_SIZE + " bytes", e);
        } catch (DeadlineExceededException e) {
            throw new IOException("TSP request timed out for " + shownUri, e);
        }
        if (outcome.isSuccess()) {
            return outcome.body();
        }
        if (outcome.failure() == null) {
            // Условный запрос TSP не посылает: «не изменилось» невозможно, это сбой движка
            throw new IOException("Unexpected conditional response from " + shownUri);
        }
        throw refusal(outcome, shownUri);
    }

    private static IOException refusal(FetchOutcome outcome, String shownUri) {
        String failed = SafeText.uri(outcome.failedUri());
        return switch (outcome.failure()) {
            case NON_200 -> {
                String errorText = SafeText.printableAscii(outcome.errorBody());
                yield new IOException(
                        "TSA returned HTTP "
                                + outcome.status()
                                + " for "
                                + shownUri
                                + (errorText.isEmpty() ? "" : ": " + errorText));
            }
            case UNEXPECTED_CONTENT_TYPE ->
                    new IOException(
                            "Unexpected Content-Type from TSA: '"
                                    + (outcome.contentType() == null ? "" : outcome.contentType())
                                    + "', expected '"
                                    + FetchRequest.TSP_RESPONSE_TYPE
                                    + "'");
            case DISALLOWED_SCHEME ->
                    outcome.viaRedirect()
                            ? new IOException(
                                    "Unsupported redirect URL scheme: "
                                            + outcome.failedUri().getScheme())
                            : new IOException(
                                    "Unsupported TSP URL scheme: "
                                            + outcome.failedUri().getScheme());
            case DOWNGRADE -> new IOException("Redirect downgrades https to http: " + failed);
            case BLOCKED_TARGET ->
                    outcome.viaRedirect()
                            ? new IOException("Redirect resolves to private address: " + failed)
                            : new IOException("TSP URL resolves to private address: " + failed);
            case MISSING_LOCATION ->
                    new IOException("Redirect without Location header for " + shownUri);
            case BAD_LOCATION ->
                    new IOException("Redirect with invalid Location header for " + shownUri);
            case TOO_MANY_REDIRECTS -> new IOException("Too many redirects for " + shownUri);
        };
    }
}
