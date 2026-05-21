package org.rssys.gost.jsse.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Реализация {@link CrlFetcher} на JDK HttpClient с SSRF-защитой.
 * <p>
 * vthread-friendly с JDK 21: HttpClient блокирует vthread, не carrier thread.
 * SSRF-защита: только http:// и https:// схемы, блокировка private/reserved IP
 * после DNS-разрешения.
 */
public final class JdkHttpCrlFetcher implements CrlFetcher {

    private static final Logger LOG = System.getLogger("org.rssys.gost.jsse.crl.JdkHttpCrlFetcher");

    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 5 * 1024 * 1024; // 5 MB

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
            LOG.log(Level.WARNING, "CRL fetch skipped: URI scheme not supported: {0}"
                    + " — only http:// and https:// are supported", crlUri);
            return null;
        }

        URI uri;
        try {
            uri = URI.create(crlUri);
        } catch (RuntimeException e) {
            return null;
        }

        if (!skipSsrfCheck && isPrivateAddress(uri)) {
            LOG.log(Level.WARNING, "CRL fetch skipped: private/reserved IP resolved from {0}", crlUri);
            return null;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(timeout)
                    .GET()
                    .build();

            HttpResponse<InputStream> response = client.send(request,
                    HttpResponse.BodyHandlers.ofInputStream());

            if (response.statusCode() != 200) {
                response.body().close();
                LOG.log(Level.WARNING, "CRL fetch failed: HTTP {0} for {1}",
                        response.statusCode(), crlUri);
                return null;
            }

            try (InputStream is = response.body();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buf = new byte[8192];
                int total = 0;
                int n;
                while ((n = is.read(buf)) != -1) {
                    if (total > maxResponseSize - n) {
                        LOG.log(Level.WARNING, "CRL fetch aborted: response exceeds {0} bytes for {1}",
                                maxResponseSize, crlUri);
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

    /**
     * Проверяет, что URI не указывает на private/reserved IP-адрес (SSRF-защита).
     */
    private static boolean isPrivateAddress(URI uri) {
        String host = uri.getHost();
        if (host == null) return true;
        // Локальные имена (localhost, loopback) без резолва
        if ("localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                || "[::1]".equals(host) || "0.0.0.0".equals(host)) {
            return true;
        }
        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isLoopbackAddress()
                    || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress()
                    || addr.isMulticastAddress();
        } catch (UnknownHostException e) {
            // Если хост не резолвится — блокируем (fail-closed)
            return true;
        }
    }
}
