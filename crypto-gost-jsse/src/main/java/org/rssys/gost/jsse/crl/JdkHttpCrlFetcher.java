package org.rssys.gost.jsse.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.rssys.gost.pkix.util.SsrfGuard;

/**
 * Реализация {@link CrlFetcher} на JDK HttpClient с SSRF-защитой.
 * <p>
 * vthread-friendly с JDK 21: HttpClient блокирует vthread, не carrier thread.
 * SSRF-защита: только http:// и https:// схемы, блокировка private/reserved IP
 * после DNS-разрешения (проверяются все резолвнутые адреса, fail-closed).
 * <p>
 * <b>Остаточный риск (простыми словами):</b> адрес проверяется до запроса, но
 * само соединение делает {@code HttpClient}, который заново обращается к DNS —
 * между этими моментами атакующий с контролем DNS может подменить публичный
 * адрес на внутренний (DNS-rebinding TOCTOU). Штатными средствами HttpClient не
 * закрывается. Риск ограничен: украсть данные нельзя (ответ CRL проверяется по
 * подписи), возможно лишь probing внутренней сети. Полное закрытие требует
 * ручного HTTP (raw socket + SNI), которое мы пока не планируем делать.
 * Подробнее — {@link org.rssys.gost.pkix.util.SsrfGuard}.
 */
public final class JdkHttpCrlFetcher implements CrlFetcher {

    private static final Logger LOG = System.getLogger("org.rssys.gost.jsse.crl.JdkHttpCrlFetcher");

    private static final int DEFAULT_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 67_108_864; // 64 МБ

    private final HttpClient client;
    private final Duration timeout;
    private final int maxResponseSize;
    private final boolean skipSsrfCheck;

    public JdkHttpCrlFetcher() {
        this(Duration.ofMillis(DEFAULT_TIMEOUT_MS), DEFAULT_MAX_RESPONSE_SIZE);
    }

    /**
     * @param timeout         таймаут HTTP-запроса
     * @param maxResponseSize максимальный размер CRL-ответа в байтах (защита от OOM)
     */
    public JdkHttpCrlFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, false);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    JdkHttpCrlFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
        this.client = HttpClient.newHttpClient();
        this.timeout = timeout;
        this.maxResponseSize = maxResponseSize;
        this.skipSsrfCheck = skipSsrfCheck;
    }

    @Override
    public byte[] fetch(String crlUri) throws IOException {
        if (crlUri == null || crlUri.isEmpty()) {
            return null;
        }
        if (!crlUri.startsWith("http://") && !crlUri.startsWith("https://")) {
            LOG.log(
                    Level.WARNING,
                    "CRL fetch skipped: URI scheme not supported: {0}"
                            + " — only http:// and https:// are supported",
                    crlUri);
            return null;
        }

        URI uri;
        try {
            uri = URI.create(crlUri);
        } catch (RuntimeException e) {
            return null;
        }

        if (!skipSsrfCheck && SsrfGuard.isPrivateAddress(uri)) {
            LOG.log(
                    Level.WARNING,
                    "CRL fetch skipped: private/reserved IP resolved from {0}",
                    crlUri);
            return null;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder().uri(uri).timeout(timeout).GET().build();

            HttpResponse<InputStream> response =
                    client.send(request, HttpResponse.BodyHandlers.ofInputStream());

            if (response.statusCode() != 200) {
                response.body().close();
                LOG.log(
                        Level.WARNING,
                        "CRL fetch failed: HTTP {0} for {1}",
                        response.statusCode(),
                        crlUri);
                return null;
            }

            try (InputStream is = response.body();
                    ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buf = new byte[8192];
                int total = 0;
                int n;
                while ((n = is.read(buf)) != -1) {
                    if (total > maxResponseSize - n) {
                        LOG.log(
                                Level.WARNING,
                                "CRL fetch aborted: response exceeds {0} bytes for {1}",
                                maxResponseSize,
                                crlUri);
                        return null;
                    }
                    total += n;
                    baos.write(buf, 0, n);
                }
                return baos.toByteArray();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("CRL fetch interrupted", e);
        }
    }
}
