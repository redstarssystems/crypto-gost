package org.rssys.gost.tls13.config;

import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Конфигурация клиента TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createClient(
 *     new TlsClientConfig(cs, caKey)
 *         .withServerHostname("example.com"), transport);
 * }</pre>
 */
public final class TlsClientConfig {
    private final TlsCiphersuite ciphersuite;
    private List<GostCertificate> clientCertificateChain;
    private PrivateKeyParameters clientPrivateKey;
    private List<PublicKeyParameters> caPublicKeys;
    private String serverHostname;
    private boolean hostnameVerificationDisabled;
    private boolean requireOcspStapling;
    private List<String> alpnProtocols;
    private ClientCertificateSelector clientCertificateSelector;

    /**
     * Создаёт конфигурацию клиента с обязательной аутентификацией сервера.
     * Transport передаётся отдельно в {@code TlsSession.createClient(config, transport)}.
     *
     * @param ciphersuite  cipher suite (не null)
     * @param caPublicKeys список доверенных ключей CA (не null, не пустой)
     * @throws IllegalArgumentException если caPublicKeys null или пуст
     */
    public TlsClientConfig(TlsCiphersuite ciphersuite, List<PublicKeyParameters> caPublicKeys) {
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        if (caPublicKeys == null || caPublicKeys.isEmpty()) {
            throw new IllegalArgumentException("caPublicKeys must not be null or empty");
        }
        this.ciphersuite = ciphersuite;
        this.caPublicKeys = List.copyOf(caPublicKeys);
    }

    /**
     * Создаёт конфигурацию клиента с одним доверенным ключом CA.
     *
     * @param ciphersuite cipher suite (не null)
     * @param caPublicKey доверенный ключ CA (не null)
     * @throws IllegalArgumentException если caPublicKey null
     */
    public TlsClientConfig(TlsCiphersuite ciphersuite, PublicKeyParameters caPublicKey) {
        this(ciphersuite, List.of(caPublicKey));
    }

    /**
     * @param chain цепочка сертификатов клиента leaf-first (может содержать
     *              только листовой сертификат, если промежуточные не нужны)
     * @return this
     */
    public TlsClientConfig withClientCertificateChain(List<GostCertificate> chain) {
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
    public TlsClientConfig withClientCertificateChain(GostCertificate... certs) {
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
     * Заменяет список доверенных ключей CA.
     *
     * @param caPubKeys список доверенных ключей CA (не null, не пустой)
     * @return this
     * @throws IllegalArgumentException если caPubKeys null или пуст
     */
    public TlsClientConfig withCaPublicKeys(List<PublicKeyParameters> caPubKeys) {
        if (caPubKeys == null || caPubKeys.isEmpty()) {
            throw new IllegalArgumentException("caPublicKeys must not be null or empty");
        }
        this.caPublicKeys = List.copyOf(caPubKeys);
        return this;
    }

    /**
     * Заменяет доверенный ключ CA одним ключом.
     *
     * @param caPub открытый ключ CA (не null)
     * @return this
     * @throws IllegalArgumentException если caPub null
     */
    public TlsClientConfig withCaPublicKey(PublicKeyParameters caPub) {
        if (caPub == null) {
            throw new IllegalArgumentException("caPublicKey must not be null");
        }
        return withCaPublicKeys(List.of(caPub));
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
    public TlsCiphersuite getCiphersuite() {
        return ciphersuite;
    }

    public List<GostCertificate> getClientCertificateChain() {
        return clientCertificateChain;
    }

    public PrivateKeyParameters getClientPrivateKey() {
        return clientPrivateKey;
    }

    public List<PublicKeyParameters> getCaPublicKeys() {
        return caPublicKeys;
    }

    public PublicKeyParameters getCaPublicKey() {
        return (caPublicKeys != null && !caPublicKeys.isEmpty()) ? caPublicKeys.get(0) : null;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    /**
     * Отключает проверку hostname в сертификате сервера.
     * Только для mesh-сервисов, внутренних соединений и тестов,
     * где проверка hostname не нужна, но аутентификация CA обязательна.
     *
     * @return this
     */
    public TlsClientConfig withoutHostnameVerification() {
        this.hostnameVerificationDisabled = true;
        return this;
    }

    public boolean isHostnameVerificationDisabled() {
        return hostnameVerificationDisabled;
    }

    public List<String> getAlpnProtocols() {
        return alpnProtocols;
    }

    /**
     * Устанавливает селектор сертификата клиента для mTLS.
     * Вызывается при получении CertificateRequest с oid_filters или
     * certificate_authorities для выбора подходящего сертификата.
     *
     * @param selector селектор, может быть null
     * @return this
     */
    public TlsClientConfig withClientCertificateSelector(ClientCertificateSelector selector) {
        this.clientCertificateSelector = selector;
        return this;
    }

    public ClientCertificateSelector getClientCertificateSelector() {
        return clientCertificateSelector;
    }
}
