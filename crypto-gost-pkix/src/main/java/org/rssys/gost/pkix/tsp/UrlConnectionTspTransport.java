package org.rssys.gost.pkix.tsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import org.rssys.gost.pkix.util.DeadlineWatchdog;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.pkix.util.GostLogger.Level;
import org.rssys.gost.pkix.util.SsrfGuard;

/**
 * Реализация {@link TspTransport} через {@link HttpURLConnection}.
 *
 * <p>Android-совместимая альтернатива {@code JdkHttpTspTransport}: использует
 * {@link HttpURLConnection} из {@code java.net}, доступный с API level 1.
 * Не требует {@code java.net.http} (отсутствует в Android core library).
 *
 * <p>В отличие от {@code JdkHttpTspTransport}:
 * <ul>
 *   <li>таймаут — комбинация {@code setConnectTimeout}/{@code setReadTimeout}
 *       + {@link DeadlineWatchdog} (total deadline);
 *   <li>редиректы обрабатываются вручную с SSRF-проверкой каждого хопа;
 *   <li>нет конструктора с кастомным HTTP-клиентом.
 * </ul>
 *
 * <p>vthread-совместимость не валидирована JFR.
 */
public final class UrlConnectionTspTransport implements TspTransport {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.tsp.UrlConnectionTspTransport");

    private static final String REQUEST_CONTENT_TYPE = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE = "application/timestamp-reply";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final int MAX_TSP_RESPONSE_SIZE = 1_048_576; // 1 МБ
    private static final int MAX_ERROR_BODY_SIZE = 128;
    private static final int MAX_REDIRECTS = 5;

    private final boolean skipSsrfCheck;

    public UrlConnectionTspTransport() {
        this(false);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    UrlConnectionTspTransport(boolean skipSsrfCheck) {
        this.skipSsrfCheck = skipSsrfCheck;
    }

    @Override
    public byte[] send(byte[] tspRequestDer, String tsaUrl) throws IOException {
        if (Thread.interrupted()) {
            throw new IOException("TSP request interrupted for " + tsaUrl);
        }
        URI uri = URI.create(tsaUrl);
        String scheme = uri.getScheme();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IOException("Unsupported TSP URL scheme: " + scheme);
        }
        if (!skipSsrfCheck && SsrfGuard.isPrivateAddress(uri)) {
            LOG.log(
                    Level.WARNING,
                    "TSP request skipped: private/reserved IP resolved from {0}",
                    tsaUrl);
            throw new IOException("TSP URL resolves to private address: " + tsaUrl);
        }

        URI current = uri;
        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) current.toURL().openConnection();
                conn.setConnectTimeout((int) DEFAULT_TIMEOUT.toMillis());
                conn.setReadTimeout((int) DEFAULT_TIMEOUT.toMillis());
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", REQUEST_CONTENT_TYPE);
                conn.setRequestProperty("Accept", RESPONSE_CONTENT_TYPE);
                conn.setDoOutput(true);
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);

                try (DeadlineWatchdog ignored = new DeadlineWatchdog(conn, DEFAULT_TIMEOUT)) {
                    conn.connect();

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(tspRequestDer);
                    }

                    int statusCode = conn.getResponseCode();
                    if (isRedirect(statusCode)) {
                        String location = conn.getHeaderField("Location");
                        if (location == null) {
                            throw new IOException("Redirect without Location header for " + tsaUrl);
                        }
                        URI redirectUri = current.resolve(location);
                        String redirectScheme = redirectUri.getScheme();
                        if (redirectScheme == null
                                || (!redirectScheme.equalsIgnoreCase("https")
                                        && !redirectScheme.equalsIgnoreCase("http"))) {
                            throw new IOException(
                                    "Unsupported redirect URL scheme: " + redirectScheme);
                        }
                        if (!skipSsrfCheck && SsrfGuard.isPrivateAddress(redirectUri)) {
                            throw new IOException(
                                    "Redirect resolves to private address: " + redirectUri);
                        }
                        current = redirectUri;
                        continue;
                    }

                    if (statusCode != 200) {
                        byte[] errorBody = readLimited(conn.getErrorStream(), MAX_ERROR_BODY_SIZE);
                        throw new IOException(
                                "TSA returned HTTP "
                                        + statusCode
                                        + " for "
                                        + tsaUrl
                                        + (errorBody.length > 0
                                                ? ": "
                                                        + new String(
                                                                errorBody,
                                                                java.nio.charset.StandardCharsets
                                                                        .UTF_8)
                                                : ""));
                    }

                    String contentType = conn.getContentType();
                    if (contentType != null) {
                        int semi = contentType.indexOf(';');
                        if (semi >= 0) {
                            contentType = contentType.substring(0, semi).trim();
                        }
                    }
                    if (contentType == null
                            || !contentType.equalsIgnoreCase(RESPONSE_CONTENT_TYPE)) {
                        throw new IOException(
                                "Unexpected Content-Type from TSA: '"
                                        + contentType
                                        + "', expected '"
                                        + RESPONSE_CONTENT_TYPE
                                        + "'");
                    }

                    try (InputStream is = conn.getInputStream()) {
                        return readLimited(is, MAX_TSP_RESPONSE_SIZE);
                    }
                }
            } catch (SocketTimeoutException e) {
                throw new IOException(
                        "TSP request timed out for " + tsaUrl + " (" + e.getMessage() + ")", e);
            } catch (InterruptedIOException e) {
                Thread.currentThread().interrupt();
                throw new IOException("TSP request interrupted for " + tsaUrl, e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        throw new IOException("Too many redirects for " + tsaUrl);
    }

    private static boolean isRedirect(int statusCode) {
        return statusCode == 307 || statusCode == 308;
    }

    private static byte[] readLimited(InputStream is, int maxBytes) throws IOException {
        if (is == null) {
            return new byte[0];
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = is.read(buf)) != -1) {
                // Best-effort: блокирующий read() не прерывается извне,
                // ловим прерывание между успешными чтениями.
                if (Thread.interrupted()) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while reading TSP response");
                }
                total += n;
                if (total > maxBytes) {
                    throw new IOException(
                            "TSP response exceeds maximum size of " + maxBytes + " bytes");
                }
                baos.write(buf, 0, n);
            }
            return baos.toByteArray();
        }
    }
}
