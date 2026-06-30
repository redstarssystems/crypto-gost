package org.rssys.gost.jsse.ocsp;

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

/**
 * Реализация {@link OcspFetcher} на JDK HttpClient.
 * <p>
 * vthread-friendly с JDK 21: HttpClient блокирует vthread, не carrier thread.
 * Используется как singleton поверх TrustManager.
 */
public final class JdkHttpOcspFetcher implements OcspFetcher {

    private static final Logger LOG =
            System.getLogger("org.rssys.gost.jsse.ocsp.JdkHttpOcspFetcher");

    private final HttpClient client;
    private final Duration timeout;
    private final int maxResponseSize;

    /**
     * Создаёт fetcher с таймаутом 5 с и лимитом ответа 64 КБ.
     */
    public JdkHttpOcspFetcher() {
        this(Duration.ofSeconds(5), 65536);
    }

    /**
     * @param timeout          таймаут HTTP-запроса
     * @param maxResponseSize  максимальный размер OCSP-ответа в байтах (защита от OOM)
     */
    public JdkHttpOcspFetcher(Duration timeout, int maxResponseSize) {
        this.client = HttpClient.newHttpClient();
        this.timeout = timeout;
        this.maxResponseSize = maxResponseSize;
    }

    @Override
    public byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        if (certDer == null || issuerDer == null || ocspResponderUri == null) {
            return null;
        }
        if (!ocspResponderUri.startsWith("http://")) {
            LOG.log(
                    Level.WARNING,
                    "OCSP fetch skipped: URI scheme not supported: {0} — only http:// is supported",
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
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Отправляет предварительно построенный OCSP-запрос и возвращает ответ вместе с nonce.
     */
    @Override
    public OcspFetchResult fetchWithNonce(
            byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        if (certDer == null || issuerDer == null || ocspResponderUri == null) {
            return new OcspFetchResult(null, null);
        }
        if (!ocspResponderUri.startsWith("http://")) {
            LOG.log(
                    Level.WARNING,
                    "OCSP fetch (with nonce) skipped: URI scheme not supported: {0} — only http:// is supported",
                    ocspResponderUri);
            return new OcspFetchResult(null, null);
        }
        try {
            OcspRequest ocspReq =
                    OcspRequestBuilder.create().targetCert(certDer).issuerCert(issuerDer).build();
            byte[] response = doHttpPost(ocspResponderUri, ocspReq.der());
            return new OcspFetchResult(response, ocspReq.nonce());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new OcspFetchResult(null, null);
        } catch (IOException e) {
            return new OcspFetchResult(null, null);
        }
    }

    /**
     * Выполняет HTTP POST на OCSP-responder.
     */
    private byte[] doHttpPost(String uri, byte[] ocspRequest)
            throws IOException, InterruptedException {
        URI requestUri;
        try {
            requestUri = URI.create(uri);
        } catch (RuntimeException e) {
            return null;
        }

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(requestUri)
                        .header("Content-Type", "application/ocsp-request")
                        .timeout(timeout)
                        .POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequest))
                        .build();

        HttpResponse<InputStream> response =
                client.send(request, HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() != 200) {
            response.body().close();
            return null;
        }

        try (InputStream is = response.body();
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = is.read(buf)) != -1) {
                if (total > maxResponseSize - n) return null;
                total += n;
                baos.write(buf, 0, n);
            }
            return baos.toByteArray();
        }
    }
}
