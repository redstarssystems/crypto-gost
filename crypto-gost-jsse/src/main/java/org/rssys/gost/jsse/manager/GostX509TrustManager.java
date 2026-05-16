package org.rssys.gost.jsse.manager;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspFetchResult;

import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.ocsp.OcspFetchResult;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsCertificateValidator;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * X509TrustManager для ГОСТ-сертификатов.
 * <p>
 * Валидирует цепочку сертификатов пира через TlsCertificateValidator:
 * срок действия, hostname (для сервера), KeyUsage, EKU, OCSP, цепочка до CA.
 * Поддерживает OCSP для всех сертификатов в цепочке (leaf + intermediate).
 */
public final class GostX509TrustManager extends X509ExtendedTrustManager {

    private static Logger LOG = System.getLogger("org.rssys.gost.jsse.GostX509TrustManager");

    private final PublicKeyParameters caPublicKey;
    private final boolean requireOcspStapling;
    private final OcspPolicy ocspPolicy;
    private final OcspFetcher ocspFetcher;

    /** Кэш OCSP-ответов: key = (issuerSerialHex, certSerialHex) → CachedStatus. TTL = 1 час */
    private long ocspCacheTtlMs = 3600_000L;
    private final ConcurrentHashMap<OcspCacheKey, CachedOcspStatus> ocspCache = new ConcurrentHashMap<>();

    /** setter для тестов */
    public void setOcspCacheTtlMs(long ttlMs) {
        this.ocspCacheTtlMs = ttlMs;
    }

    /**
     * @param caPublicKey        открытый ключ CA (null = без проверки цепочки)
     * @param requireOcspStapling true — OCSP-степплинг обязателен
     */
    public GostX509TrustManager(PublicKeyParameters caPublicKey, boolean requireOcspStapling) {
        this(caPublicKey, requireOcspStapling
                ? OcspPolicy.STAPLING_REQUIRED : OcspPolicy.IF_PRESENT, null);
    }

    /**
     * @param caPublicKey  открытый ключ CA (null = без проверки цепочки)
     * @param ocspPolicy   политика проверки OCSP
     * @param ocspFetcher  fetcher для client-side OCSP-запросов (может быть null)
     */
    public GostX509TrustManager(PublicKeyParameters caPublicKey, OcspPolicy ocspPolicy,
                                OcspFetcher ocspFetcher) {
        this.caPublicKey = caPublicKey;
        this.ocspPolicy = ocspPolicy;
        this.ocspFetcher = ocspFetcher;
        this.requireOcspStapling = ocspPolicy == OcspPolicy.STAPLING_REQUIRED;
    }

    /**
     * Извлекает hostname для endpoint identification, если задан алгоритм HTTPS/LDAPS.
     * <p>
     * Единая точка для {@link GostSSLEngine} и {@link GostX509TrustManager}.
     *
     * @param engine SSLEngine (может быть null)
     * @return peerHost если endpoint identification включён, иначе null
     */
    public static String extractHostnameForEndpointId(SSLEngine engine) {
        if (engine != null && engine.getSSLParameters() != null) {
            String alg = engine.getSSLParameters().getEndpointIdentificationAlgorithm();
            if ("HTTPS".equalsIgnoreCase(alg) || "LDAPS".equalsIgnoreCase(alg)) {
                return engine.getPeerHost();
            }
        }
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkClientTrustedImpl(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkServerTrustedImpl(chain, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkServerTrustedImpl(chain, extractHostnameForEndpointId(engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkServerTrustedImpl(chain, null);
    }

    /**
     * Возвращает пустой список принятых CA-сертификатов.
     * <p>
     * Три причины:
     * <ol>
     *   <li><b>Тактическая:</b> пустой список уменьшает размер CertificateRequest
     *       (RFC 8446 §4.3.2: список Distinguished Names опционален).</li>
     *   <li><b>Security:</b> не раскрываем список доверенных CA клиенту
     *       (защита от fingerprinting CA-инфраструктуры).</li>
     *   <li><b>Техническая:</b> валидация цепочки делается через caPublicKey
     *       в {@link #validateChainWithOcsp}, не через accepted issuers.
     *       Пустой список не влияет на проверку сертификатов.</li>
     * </ol>
     *
     * @return пустой массив (длина 0)
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * Прямая валидация цепочки TlsCertificate с OCSP для всей цепочки.
     * <p>
     * Поддерживает client-side OCSP fetch для leaf и intermediate сертификатов
     * по политике {@code ocspPolicy}. Результаты кэшируются по
     * (issuerSerial, certSerial) до nextUpdate.
     */
    public void validateChainWithOcsp(List<TlsCertificate> chain, String hostname,
                                boolean requireOcsp) throws CertificateException {
        if (chain == null || chain.isEmpty()) {
            throw new CertificateException("Empty certificate chain");
        }

        // OCSP для всех сертификатов в цепочке (кроме root)
        for (int i = 0; i < chain.size() - 1; i++) {
            TlsCertificate cert = chain.get(i);
            TlsCertificate issuer = chain.get(i + 1);
            fetchOcspIfNeeded(cert, issuer);
        }

        try {
            boolean needOcsp = requireOcsp
                    || (ocspPolicy == OcspPolicy.STAPLING_OR_FETCH);
            TlsCertificateValidator.checkServerCertificateChain(
                    chain, hostname, needOcsp, caPublicKey);
        } catch (TlsException e) {
            String msg = e.getMessage();
            if (msg != null && (msg.contains("revoked") || msg.contains("OCSP"))) {
                LOG.log(Level.ERROR, "OCSP status: {0}", msg);
            } else {
                LOG.log(Level.ERROR, "Certificate validation failed: {0}",
                        msg != null && msg.length() > 200 ? msg.substring(0, 200) : msg);
            }
            throw new CertificateException("Certificate validation failed: " + msg, e);
        } catch (Exception e) {
            throw new CertificateException("Certificate validation error: " + e.getMessage(), e);
        }

        // Intermediate OCSP missing (best-effort fallthrough) — только при STAPLING_OR_FETCH
        if (ocspPolicy == OcspPolicy.STAPLING_OR_FETCH) {
            for (int i = 1; i < chain.size() - 1; i++) {
                TlsCertificate ic = chain.get(i);
                if (!ic.hasOcspResponse() && ic.getOcspUris() != null
                        && ic.getOcspUris().length > 0) {
                    LOG.log(Level.WARNING, "Intermediate cert missing OCSP (best-effort fallthrough)");
                }
            }
        }
    }

    public boolean isRequireOcspStapling() {
        return requireOcspStapling;
    }

    private void checkServerTrustedImpl(X509Certificate[] chain, String hostname)
            throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty server certificate chain");
        }
        List<TlsCertificate> tlsChain = CertificateBridge.toTls(chain);
        validateChainWithOcsp(tlsChain, hostname, requireOcspStapling);
    }

    private void checkClientTrustedImpl(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty client certificate chain");
        }
        try {
            List<TlsCertificate> tlsChain = CertificateBridge.toTls(chain);
            TlsCertificateValidator.checkClientCertificateChain(
                    tlsChain, caPublicKey);
        } catch (TlsException e) {
            throw new CertificateException("Client certificate validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateException("Certificate validation error: " + e.getMessage(), e);
        }
    }

    /**
     * Запрашивает OCSP для сертификата, если ещё нет stapled ответа и политика разрешает fetch.
     * Результат кэшируется.
     */
    private void fetchOcspIfNeeded(TlsCertificate cert, TlsCertificate issuer) {
        if (ocspPolicy != OcspPolicy.STAPLING_OR_FETCH || ocspFetcher == null) {
            return;
        }
        if (cert.hasOcspResponse()) {
            return;
        }

        String[] ocspUris = cert.getOcspUris();
        if (ocspUris == null || ocspUris.length == 0) {
            return;
        }

        OcspCacheKey cacheKey = buildCacheKey(cert, issuer);
        CachedOcspStatus cached = ocspCache.get(cacheKey);
        if (cached != null) {
            if (!cached.isExpired()) {
                LOG.log(Level.DEBUG, "OCSP cache hit for {0}", cacheKey.certSerial);
                cert.setOcspResponse(cached.response);
                cert.setOcspNonce(cached.nonce);
                return;
            }
            ocspCache.remove(cacheKey);
        }

        for (String ocspUri : ocspUris) {
            if (ocspUri == null || ocspUri.isEmpty()) continue;
            long start = System.nanoTime();
            OcspFetchResult result = ocspFetcher.fetchWithNonce(
                    cert.getEncoded(), issuer.getEncoded(), ocspUri);
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            if (result.response() != null) {
                cert.setOcspResponse(result.response());
                cert.setOcspNonce(result.nonce());
                ocspCache.put(cacheKey, new CachedOcspStatus(
                        result.response(), result.nonce(),
                        System.currentTimeMillis() + ocspCacheTtlMs));
                LOG.log(Level.INFO, "OCSP fetch success for cert={0} from {1} ({2}ms)",
                        cacheKey.certSerial, ocspUri, elapsedMs);
                break;
            } else {
                LOG.log(Level.WARNING, "OCSP fetch failed for cert={0} from {1}",
                        cacheKey.certSerial, ocspUri);
            }
        }
    }

    /**
     * Строит ключ кэша OCSP по (issuerSerial, certSerial).
     */
    private static OcspCacheKey buildCacheKey(TlsCertificate cert, TlsCertificate issuer) {
        byte[] certSerial = cert.getSerialNumber();
        byte[] issuerSerial = issuer.getSerialNumber();
        return new OcspCacheKey(
                bytesToHex(issuerSerial), bytesToHex(certSerial));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Ключ кэша OCSP по (issuerSerialHex, certSerialHex).
     */
    private record OcspCacheKey(String issuerSerial, String certSerial) {
        OcspCacheKey {
            Objects.requireNonNull(issuerSerial);
            Objects.requireNonNull(certSerial);
        }
    }

    /**
     * Кэшированный OCSP-ответ. Хранит сам response, чтобы избежать повторного HTTP.
     */
    private static final class CachedOcspStatus {
        final byte[] response;
        final byte[] nonce;
        final long expiresAt;

        CachedOcspStatus(byte[] response, byte[] nonce, long expiresAt) {
            this.response = response;
            this.nonce = nonce;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    /** TEST ONLY: подменить logger для capture. Возвращает предыдущий для restore. */
    static System.Logger setLoggerForTest(System.Logger testLogger) {
        System.Logger prev = LOG;
        LOG = testLogger;
        return prev;
    }
}
