package org.rssys.gost.tls13.config;

import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTransport;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.util.Collections;
import java.util.List;

/**
 * Конфигурация клиента TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createClient(new TlsClientConfig(transport, cs)
 *     .withCaPublicKey(caKey)
 *     .withServerHostname("example.com"));
 * }</pre>
 */
public final class TlsClientConfig {
    private final TlsTransport transport;
    private final TlsCiphersuite ciphersuite;
    private TlsCertificate clientCertificate;
    private List<TlsCertificate> clientCertificateChain;
    private PrivateKeyParameters clientPrivateKey;
    private PublicKeyParameters caPublicKey;
    private String serverHostname;
    private boolean requireOcspStapling;
    private List<String> alpnProtocols;

    /**
     * @param transport   транспорт (не null)
     * @param ciphersuite cipher suite (не null)
     */
    public TlsClientConfig(TlsTransport transport, TlsCiphersuite ciphersuite) {
        if (transport == null) throw new IllegalArgumentException("transport must not be null");
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        this.transport = transport;
        this.ciphersuite = ciphersuite;
    }

    /**
     * @param cert сертификат клиента для mTLS
     * @return this
     */
    public TlsClientConfig withClientCertificate(TlsCertificate cert) {
        this.clientCertificate = cert;
        return this;
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
     * @param key закрытый ключ клиента для mTLS
     * @return this
     */
    public TlsClientConfig withClientPrivateKey(PrivateKeyParameters key) {
        this.clientPrivateKey = key;
        return this;
    }

    /**
     * @param caPub открытый ключ CA
     * @return this
     */
    public TlsClientConfig withCaPublicKey(PublicKeyParameters caPub) {
        this.caPublicKey = caPub;
        return this;
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
    public TlsTransport getTransport() { return transport; }
    public TlsCiphersuite getCiphersuite() { return ciphersuite; }
    public List<TlsCertificate> getClientCertificateChain() {
        return clientCertificateChain != null ? clientCertificateChain
                : (clientCertificate != null ? Collections.singletonList(clientCertificate) : null);
    }
    public PrivateKeyParameters getClientPrivateKey() { return clientPrivateKey; }
    public PublicKeyParameters getCaPublicKey() { return caPublicKey; }
    public String getServerHostname() { return serverHostname; }
    public List<String> getAlpnProtocols() { return alpnProtocols; }
}
