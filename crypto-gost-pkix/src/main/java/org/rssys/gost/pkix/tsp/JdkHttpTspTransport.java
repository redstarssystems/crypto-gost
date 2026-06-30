package org.rssys.gost.pkix.tsp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Реализация {@link TspTransport} через {@link java.net.http.HttpClient} (JDK 11+).
 *
 * <p>Отправляет HTTP POST с Content-Type {@code application/timestamp-query}
 * и принимает ответ с типом {@code application/timestamp-reply}.
 * Совместим с virtual threads (JDK 21+): HttpClient не блокирует carrier thread.
 */
public final class JdkHttpTspTransport implements TspTransport {

    private static final String REQUEST_CONTENT_TYPE = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE = "application/timestamp-reply";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;

    /** Создаёт транспорт с HTTP-клиентом по умолчанию (followRedirects=NORMAL). */
    public JdkHttpTspTransport() {
        this(
                HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NORMAL)
                        .connectTimeout(DEFAULT_TIMEOUT)
                        .build());
    }

    /** Создаёт транспорт с заданным HTTP-клиентом. */
    public JdkHttpTspTransport(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException {
        try {
            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(URI.create(tsaUrl))
                            .timeout(DEFAULT_TIMEOUT)
                            .header("Content-Type", REQUEST_CONTENT_TYPE)
                            .header("Accept", RESPONSE_CONTENT_TYPE)
                            .POST(HttpRequest.BodyPublishers.ofByteArray(tspRequestDer))
                            .build();

            HttpResponse<byte[]> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

            int statusCode = response.statusCode();
            if (statusCode != 200) {
                throw new IOException(
                        "TSA returned HTTP "
                                + statusCode
                                + " for "
                                + tsaUrl
                                + (response.body() != null
                                        ? ": "
                                                + new String(
                                                        response.body(),
                                                        0,
                                                        Math.min(128, response.body().length),
                                                        java.nio.charset.StandardCharsets.UTF_8)
                                        : ""));
            }

            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (!contentType.toLowerCase().contains(RESPONSE_CONTENT_TYPE)) {
                throw new IOException(
                        "Unexpected Content-Type from TSA: '"
                                + contentType
                                + "', expected '"
                                + RESPONSE_CONTENT_TYPE
                                + "'");
            }

            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("TSP request interrupted for " + tsaUrl, e);
        }
    }
}
