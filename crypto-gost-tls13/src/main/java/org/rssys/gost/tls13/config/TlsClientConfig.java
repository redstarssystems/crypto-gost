package org.rssys.gost.tls13.config;

import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Конфигурация клиента TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createClient(new TlsClientConfig(cs)
 *     .withCaPublicKey(caKey)
 *     .withServerHostname("example.com"), transport);
 * }</pre>
 */
public final class TlsClientConfig {
    private final TlsCiphersuite ciphersuite;
    private List<TlsCertificate> clientCertificateChain;
    private PrivateKeyParameters clientPrivateKey;
    private List<PublicKeyParameters> caPublicKeys;
    private String serverHostname;
    private boolean requireOcspStapling;
    private List<String> alpnProtocols;

    /**
     * Создаёт конфигурацию клиента без транспорта.
     * Transport передаётся отдельно в {@code TlsSession.createClient(config, transport)}.
     *
     * @param ciphersuite cipher suite (не null)
     */
    public TlsClientConfig(TlsCiphersuite ciphersuite) {
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        this.ciphersuite = ciphersuite;
    }

    /**
     * @param chain цепочка сертификатов клиента leaf-first (может содержать
     *              только листовой сертификат, если промежуточные не нужны)
     * @return this
     */
    public TlsClientConfig withClientCertificateChain(List<TlsCertificate> chain) {
        this.clientCertificateChain = chain;
        return this;
    }

    /**
     * Перегрузка для цепочки сертификатов.
     * Позволяет передать один или несколько сертификатов без создания списка:
     * <pre>{@code config.withClientCertificateChain(cert)}</pre>
     *
     * @param certs сертификаты клиента leaf-first
     * @return this
     */
    public TlsClientConfig withClientCertificateChain(TlsCertificate... certs) {
        return withClientCertificateChain(Arrays.asList(certs));
    }

    /**
     * @param key закрытый ключ клиента для mTLS
     * @return this
     */
    public TlsClientConfig withClientPrivateKey(PrivateKeyParameters key) {
        this.clientPrivateKey = key;
        return this;
    }

    /**
     * @param caPubKeys список доверенных ключей CA (null или пустой = не проверять цепочку)
     * @return this
     */
    public TlsClientConfig withCaPublicKeys(List<PublicKeyParameters> caPubKeys) {
        this.caPublicKeys = caPubKeys;
        return this;
    }

    /**
     * @param caPub открытый ключ CA (null = не проверять цепочку)
     * @return this
     */
    public TlsClientConfig withCaPublicKey(PublicKeyParameters caPub) {
        return withCaPublicKeys(caPub != null ? Collections.singletonList(caPub) : null);
    }

    /**
     * @param hostname ожидаемое DNS-имя сервера (null = не проверять)
     * @return this
     */
    public TlsClientConfig withServerHostname(String hostname) {
        this.serverHostname = hostname;
        return this;
    }

    /**
     * @param require true  — сервер ОБЯЗАН прислать OCSP-степплинг (ALERT_BAD_CERTIFICATE иначе)
     *                false — мягкий режим (OCSP проверяется если есть, но не обязателен)
     * @return this
     */
    public TlsClientConfig withRequireOcspStapling(boolean require) {
        this.requireOcspStapling = require;
        return this;
    }

    /**
     * @param protocols список протоколов ALPN в порядке убывания предпочтения (RFC 7301)
     * @return this
     */
    public TlsClientConfig withAlpnProtocols(List<String> protocols) {
        TlsUtils.validateAlpnProtocols(protocols);
        this.alpnProtocols = protocols;
        return this;
    }

    public boolean isOcspRequired() {
        return requireOcspStapling;
    }

    // package-private аксессоры для фабрики TlsSession
    public TlsCiphersuite getCiphersuite() { return ciphersuite; }
    public List<TlsCertificate> getClientCertificateChain() {
        return clientCertificateChain;
    }
    public PrivateKeyParameters getClientPrivateKey() { return clientPrivateKey; }
    public List<PublicKeyParameters> getCaPublicKeys() { return caPublicKeys; }

    public PublicKeyParameters getCaPublicKey() {
        return (caPublicKeys != null && !caPublicKeys.isEmpty())
                ? caPublicKeys.get(0) : null;
    }
    public String getServerHostname() { return serverHostname; }
    public List<String> getAlpnProtocols() { return alpnProtocols; }
}
