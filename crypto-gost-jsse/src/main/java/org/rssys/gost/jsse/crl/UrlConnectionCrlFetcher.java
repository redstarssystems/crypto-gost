package org.rssys.gost.jsse.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import org.rssys.gost.pkix.util.DeadlineWatchdog;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.pkix.util.GostLogger.Level;
import org.rssys.gost.pkix.util.SsrfGuard;

/**
 * Реализация {@link CrlFetcher} на {@link HttpURLConnection} с SSRF-защитой.
 *
 * <p>Android-совместимая альтернатива {@code JdkHttpCrlFetcher}: использует
 * {@link HttpURLConnection} из {@code java.net}, доступный с API level 1.
 *
 * <p>В отличие от {@code JdkHttpCrlFetcher}:
 * <ul>
 *   <li>таймаут — комбинация {@code setConnectTimeout}/{@code setReadTimeout}
 *       + {@link DeadlineWatchdog} (total deadline);
 *   <li>редиректы обрабатываются вручную с SSRF-проверкой каждого хопа.
 * </ul>
 *
 * <p>vthread-совместимость не валидирована JFR.
 */
public final class UrlConnectionCrlFetcher implements CrlFetcher {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.crl.UrlConnectionCrlFetcher");

    private static final int DEFAULT_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 67_108_864; // 64 МБ
    private static final int MAX_REDIRECTS = 5;

    private final Duration timeout;
    private final int maxResponseSize;
    private final boolean skipSsrfCheck;

    public UrlConnectionCrlFetcher() {
        this(Duration.ofMillis(DEFAULT_TIMEOUT_MS), DEFAULT_MAX_RESPONSE_SIZE, false);
    }

    /**
     * @param timeout         таймаут HTTP-запроса
     * @param maxResponseSize максимальный размер CRL-ответа в байтах (защита от OOM)
     */
    public UrlConnectionCrlFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, false);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    UrlConnectionCrlFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
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

        URI current = uri;
        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) current.toURL().openConnection();
                conn.setConnectTimeout((int) timeout.toMillis());
                conn.setReadTimeout((int) timeout.toMillis());
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);

                try (DeadlineWatchdog ignored = new DeadlineWatchdog(conn, timeout)) {
                    conn.connect();

                    int statusCode = conn.getResponseCode();
                    if (isRedirect(statusCode)) {
                        String location = conn.getHeaderField("Location");
                        if (location == null) {
                            return null;
                        }
                        URI redirectUri = current.resolve(location);
                        if (!skipSsrfCheck && SsrfGuard.isPrivateAddress(redirectUri)) {
                            return null;
                        }
                        current = redirectUri;
                        continue;
                    }

                    if (statusCode != 200) {
                        LOG.log(
                                Level.WARNING,
                                "CRL fetch failed: HTTP {0} for {1}",
                                statusCode,
                                crlUri);
                        return null;
                    }

                    try (InputStream is = conn.getInputStream();
                            ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                        byte[] buf = new byte[8192];
                        int total = 0;
                        int n;
                        while ((n = is.read(buf)) != -1) {
                            // Best-effort: блокирующий read() не прерывается,
                            // ловим прерывание между успешными чтениями.
                            if (Thread.interrupted()) {
                                Thread.currentThread().interrupt();
                                throw new IOException(
                                        "Interrupted while reading CRL response for " + crlUri);
                            }
                            total += n;
                            if (total > maxResponseSize) {
                                LOG.log(
                                        Level.WARNING,
                                        "CRL fetch aborted: response exceeds {0} bytes for {1}",
                                        maxResponseSize,
                                        crlUri);
                                return null;
                            }
                            baos.write(buf, 0, n);
                        }
                        return baos.toByteArray();
                    }
                }
            } catch (SocketTimeoutException e) {
                throw new IOException("CRL fetch timed out for " + crlUri, e);
            } catch (InterruptedIOException e) {
                Thread.currentThread().interrupt();
                throw new IOException("CRL fetch interrupted", e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return null;
    }

    private static boolean isRedirect(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308;
    }
}
