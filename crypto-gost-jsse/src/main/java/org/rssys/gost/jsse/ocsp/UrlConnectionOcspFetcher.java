package org.rssys.gost.jsse.ocsp;

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
 * Реализация {@link OcspFetcher} на {@link HttpURLConnection} с SSRF-защитой.
 *
 * <p>Android-совместимая альтернатива {@code JdkHttpOcspFetcher}: использует
 * {@link HttpURLConnection} из {@code java.net}, доступный с API level 1.
 *
 * <p>В отличие от {@code JdkHttpOcspFetcher}:
 * <ul>
 *   <li>таймаут — комбинация {@code setConnectTimeout}/{@code setReadTimeout}
 *       + {@link DeadlineWatchdog} (total deadline);
 *   <li>редиректы обрабатываются вручную с SSRF-проверкой каждого хопа.
 * </ul>
 *
 * <p>vthread-совместимость не валидирована JFR.
 * <p>fail-closed на ошибках сети (возвращает null).
 */
public final class UrlConnectionOcspFetcher implements OcspFetcher {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.jsse.ocsp.UrlConnectionOcspFetcher");

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 262_144; // 256 KB
    private static final int MAX_REDIRECTS = 5;

    private final Duration timeout;
    private final int maxResponseSize;
    private final boolean skipSsrfCheck;

    /** Создаёт fetcher с таймаутом 5 с и лимитом ответа 256 КБ. */
    public UrlConnectionOcspFetcher() {
        this(DEFAULT_TIMEOUT, DEFAULT_MAX_RESPONSE_SIZE, false);
    }

    /**
     * @param timeout         таймаут HTTP-запроса
     * @param maxResponseSize максимальный размер OCSP-ответа в байтах (защита от OOM)
     */
    public UrlConnectionOcspFetcher(Duration timeout, int maxResponseSize) {
        this(timeout, maxResponseSize, false);
    }

    /** Для тестов — отключает SSRF-проверку (localhost mock). */
    UrlConnectionOcspFetcher(Duration timeout, int maxResponseSize, boolean skipSsrfCheck) {
        this.timeout = timeout;
        this.maxResponseSize = maxResponseSize;
        this.skipSsrfCheck = skipSsrfCheck;
    }

    @Override
    public byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        if (certDer == null || issuerDer == null || ocspResponderUri == null) {
            return null;
        }
        if (!ocspResponderUri.startsWith("http://")) {
            LOG.log(
                    Level.WARNING,
                    "OCSP fetch skipped: URI scheme not supported: {0}"
                            + " — only http:// is supported",
                    ocspResponderUri);
            return null;
        }
        try {
            byte[] ocspRequest =
                    OcspRequestBuilder.create()
                            .targetCert(certDer)
                            .issuerCert(issuerDer)
                            .build()
                            .der();
            return doHttpPost(ocspResponderUri, ocspRequest);
        } catch (SocketTimeoutException e) {
            return null;
        } catch (InterruptedIOException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public OcspFetchResult fetchWithNonce(
            byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        if (certDer == null || issuerDer == null || ocspResponderUri == null) {
            return new OcspFetchResult(null, null);
        }
        if (!ocspResponderUri.startsWith("http://")) {
            LOG.log(
                    Level.WARNING,
                    "OCSP fetch (with nonce) skipped: URI scheme not supported: {0}"
                            + " — only http:// is supported",
                    ocspResponderUri);
            return new OcspFetchResult(null, null);
        }
        try {
            OcspRequest ocspReq =
                    OcspRequestBuilder.create().targetCert(certDer).issuerCert(issuerDer).build();
            byte[] response = doHttpPost(ocspResponderUri, ocspReq.der());
            return new OcspFetchResult(response, ocspReq.nonce());
        } catch (SocketTimeoutException e) {
            return new OcspFetchResult(null, null);
        } catch (InterruptedIOException e) {
            Thread.currentThread().interrupt();
            return new OcspFetchResult(null, null);
        } catch (IOException e) {
            return new OcspFetchResult(null, null);
        }
    }

    private byte[] doHttpPost(String uri, byte[] ocspRequest) throws IOException {
        URI requestUri;
        try {
            requestUri = URI.create(uri);
        } catch (RuntimeException e) {
            return null;
        }

        if (!skipSsrfCheck && SsrfGuard.isPrivateAddress(requestUri)) {
            LOG.log(
                    Level.WARNING,
                    "OCSP fetch skipped: private/reserved IP resolved from {0}",
                    uri);
            return null;
        }

        URI current = requestUri;
        for (int hop = 0; hop < MAX_REDIRECTS; hop++) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) current.toURL().openConnection();
                conn.setConnectTimeout((int) timeout.toMillis());
                conn.setReadTimeout((int) timeout.toMillis());
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/ocsp-request");
                conn.setDoOutput(true);
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);

                try (DeadlineWatchdog ignored = new DeadlineWatchdog(conn, timeout)) {
                    conn.connect();

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(ocspRequest);
                    }

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
                                "OCSP fetch failed: HTTP {0} for {1}",
                                statusCode,
                                uri);
                        return null;
                    }

                    try (InputStream is = conn.getInputStream();
                            ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                        byte[] buf = new byte[4096];
                        int total = 0;
                        int n;
                        while ((n = is.read(buf)) != -1) {
                            // Best-effort: блокирующий read() не прерывается,
                            // ловим прерывание между успешными чтениями.
                            if (Thread.interrupted()) {
                                Thread.currentThread().interrupt();
                                return null;
                            }
                            total += n;
                            if (total > maxResponseSize) {
                                LOG.log(
                                        Level.WARNING,
                                        "OCSP fetch aborted: response exceeds {0} bytes for {1}",
                                        maxResponseSize,
                                        uri);
                                return null;
                            }
                            baos.write(buf, 0, n);
                        }
                        return baos.toByteArray();
                    }
                }
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }
        return null;
    }

    private static boolean isRedirect(int statusCode) {
        return statusCode == 307 || statusCode == 308;
    }
}
