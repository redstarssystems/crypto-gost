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
 * Конфигурация сервера TLS 1.3.
 *
 * <pre>{@code
 * TlsSession session = TlsSession.createServer(new TlsServerConfig(transport, cs, chain, priv)
 *     .withCaPublicKey(caKey)); // mTLS required mode
 * }</pre>
 */
public final class TlsServerConfig {
    private final TlsTransport transport;
    private final TlsCiphersuite ciphersuite;
    private final List<TlsCertificate> serverCertificateChain;
    private final PrivateKeyParameters serverPrivateKey;
    private byte[] ocspResponse;
    private PublicKeyParameters caPublicKey;
    private List<String> alpnProtocols;

    /**
     * @param transport               транспорт (не null)
     * @param ciphersuite             cipher suite (не null)
     * @param serverCertificateChain  цепочка сертификатов сервера (leaf первый, root последний; не пуста)
     * @param serverPrivateKey        закрытый ключ для CertificateVerify (должен соответствовать leaf)
     */
    public TlsServerConfig(TlsTransport transport, TlsCiphersuite ciphersuite,
                           List<TlsCertificate> serverCertificateChain,
                           PrivateKeyParameters serverPrivateKey) {
        if (transport == null) throw new IllegalArgumentException("transport must not be null");
        if (ciphersuite == null) throw new IllegalArgumentException("ciphersuite must not be null");
        if (serverCertificateChain == null || serverCertificateChain.isEmpty()) {
            throw new IllegalArgumentException("serverCertificateChain must not be null or empty");
        }
        this.transport = transport;
        this.ciphersuite = ciphersuite;
        this.serverCertificateChain = serverCertificateChain;
        this.serverPrivateKey = serverPrivateKey;
    }

    /**
     * Создаёт конфигурацию с одним сертификатом (без цепочки).
     *
     * @param transport          транспорт (не null)
     * @param ciphersuite        cipher suite (не null)
     * @param serverCertificate  сертификат сервера
     * @param serverPrivateKey   закрытый ключ для CertificateVerify
     */
    public TlsServerConfig(TlsTransport transport, TlsCiphersuite ciphersuite,
                           TlsCertificate serverCertificate,
                           PrivateKeyParameters serverPrivateKey) {
        this(transport, ciphersuite, Collections.singletonList(serverCertificate), serverPrivateKey);
    }

    public TlsServerConfig withOcspResponse(byte[] ocspResponse) {
        this.ocspResponse = ocspResponse;
        return this;
    }

    /**
     * @param protocols список протоколов ALPN в порядке убывания предпочтения (RFC 7301)
     * @return this
     */
    public TlsServerConfig withAlpnProtocols(List<String> protocols) {
        TlsUtils.validateAlpnProtocols(protocols);
        this.alpnProtocols = protocols;
        return this;
    }

    /**
     * @param caPublicKey публичный ключ корневого CA для проверки клиентского сертификата.
     *                    Если задан — сервер ОБЯЗЫВАЕТ клиента предоставить сертификат,
     *                    иначе клиентский Finished отклоняется (mTLS, required mode).
     * @return this
     *
     * <p><b>Ограничение:</b> certificate_authorities extension (RFC 8446 §4.2.4)
     * не отправляется в CertificateRequest. Клиенты с несколькими сертификатами
     * должны выбирать вручную через конфигурацию.</p>
     */
    public TlsServerConfig withCaPublicKey(PublicKeyParameters caPublicKey) {
        this.caPublicKey = caPublicKey;
        return this;
    }

    // package-private аксессоры для фабрики TlsSession
    public TlsTransport getTransport() { return transport; }
    public TlsCiphersuite getCiphersuite() { return ciphersuite; }
    public List<TlsCertificate> getServerCertificateChain() { return serverCertificateChain; }
    public PrivateKeyParameters getServerPrivateKey() { return serverPrivateKey; }
    public PublicKeyParameters getCaPublicKey() { return caPublicKey; }
    public byte[] getOcspResponse() { return ocspResponse; }
    public List<String> getAlpnProtocols() { return alpnProtocols; }
}
