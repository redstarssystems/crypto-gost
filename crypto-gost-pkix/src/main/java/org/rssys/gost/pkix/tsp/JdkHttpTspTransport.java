package org.rssys.gost.pkix.tsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.pkix.util.GostLogger.Level;
import org.rssys.gost.pkix.util.SsrfGuard;

/**
 * Реализация {@link TspTransport} через {@link java.net.http.HttpClient} (JDK 11+).
 *
 * <p>Отправляет HTTP POST с Content-Type {@code application/timestamp-query}
 * и принимает ответ с типом {@code application/timestamp-reply}.
 * <p>JVM only. Для Android используйте {@link UrlConnectionTspTransport}.</p>
 * <p>vthread-совместимость не валидирована JFR.</p>
 *
 * <p><b>Остаточный риск SSRF (простыми словами):</b> адрес проверяется до
 * запроса, но само соединение делает {@code HttpClient}, который заново
 * обращается к DNS — между этими моментами атакующий с контролем DNS может
 * подменить публичный адрес на внутренний (DNS-rebinding TOCTOU). Штатными
 * средствами HttpClient не закрывается. TSA-URL обычно задаётся доверенным
 * вызывающим кодом, поэтому практический риск ограничен. Полное закрытие требует
 * ручного HTTP (raw socket + SNI), которое мы пока не планируем делать.
 * Подробнее — {@link org.rssys.gost.pkix.util.SsrfGuard}.
 */
public final class JdkHttpTspTransport implements TspTransport {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.tsp.JdkHttpTspTransport");

    private static final String REQUEST_CONTENT_TYPE = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE = "application/timestamp-reply";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Максимальный размер TSP-ответа — защита от Memory DoS.
     * 1 МБ с запасом: типичный TSP-ответ содержит подпись, её цепочку сертификатов
     * и метаданные (единицы КБ).
     *
     * <p>Осознанное отличие от {@code JdkHttpOcspFetcher}: там превышение лимита
     * возвращает {@code null} (soft-fail — OCSP-проверка опциональна).
     * Здесь — fail-closed через {@code IOException}: TSP-верификация детерминирована,
     * урезанный ответ не должен маскироваться как «TSP недоступен».</p>
     */
    private static final int MAX_TSP_RESPONSE_SIZE = 1_048_576; // 1 МБ

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
        URI uri = URI.create(tsaUrl);
        String scheme = uri.getScheme();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IOException("Unsupported TSP URL scheme: " + scheme);
        }
        if (SsrfGuard.isPrivateAddress(uri)) {
            LOG.log(
                    Level.WARNING,
                    "TSP request skipped: private/reserved IP resolved from {0}",
                    tsaUrl);
            throw new IOException("TSP URL resolves to private address: " + tsaUrl);
        }
        try {
            HttpRequest request =
                    HttpRequest.newBuilder()
                            .uri(uri)
                            .timeout(DEFAULT_TIMEOUT)
                            .header("Content-Type", REQUEST_CONTENT_TYPE)
                            .header("Accept", RESPONSE_CONTENT_TYPE)
                            .POST(HttpRequest.BodyPublishers.ofByteArray(tspRequestDer))
                            .build();

            HttpResponse<InputStream> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());

            int statusCode = response.statusCode();
            if (statusCode != 200) {
                byte[] errorBody = readLimited(response.body(), 128);
                throw new IOException(
                        "TSA returned HTTP "
                                + statusCode
                                + " for "
                                + tsaUrl
                                + (errorBody.length > 0
                                        ? ": "
                                                + new String(
                                                        errorBody,
                                                        java.nio.charset.StandardCharsets.UTF_8)
                                        : ""));
            }

            String contentType = response.headers().firstValue("Content-Type").orElse("");
            if (!contentType.toLowerCase().contains(RESPONSE_CONTENT_TYPE)) {
                response.body().close();
                throw new IOException(
                        "Unexpected Content-Type from TSA: '"
                                + contentType
                                + "', expected '"
                                + RESPONSE_CONTENT_TYPE
                                + "'");
            }

            return readLimited(response.body(), MAX_TSP_RESPONSE_SIZE);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("TSP request interrupted for " + tsaUrl, e);
        }
    }

    /**
     * Читает InputStream с ограничением размера.
     *
     * @param is       входной поток (закрывается вызывающей стороной или внутри метода)
     * @param maxBytes максимальный размер в байтах
     * @return прочитанные байты
     * @throws IOException при превышении лимита или ошибке чтения
     */
    private static byte[] readLimited(InputStream is, int maxBytes) throws IOException {
        try (is;
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = is.read(buf)) != -1) {
                if (total > maxBytes - n) {
                    throw new IOException(
                            "TSP response exceeds maximum size of " + maxBytes + " bytes");
                }
                total += n;
                baos.write(buf, 0, n);
            }
            return baos.toByteArray();
        }
    }
}
