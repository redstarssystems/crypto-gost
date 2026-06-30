package org.rssys.gost.tls13.config;

import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Набор учётных данных сервера для выбора по SNI: цепочка сертификатов,
 * закрытый ключ и опциональный OCSP-ответ для степплинга.
 * <p>
 * Создаётся через {@link SniCertificateSelector} при получении ClientHello.
 * <p>
 * {@code toString()} не раскрывает {@link PrivateKeyParameters}.
 */
public final class TlsServerCredentials {

    private final List<GostCertificate> certificateChain;
    private final PrivateKeyParameters privateKey;
    private final byte[] ocspResponse;

    /**
     * @param certificateChain цепочка сертификатов (leaf первый, root последний)
     * @param privateKey       закрытый ключ для CertificateVerify
     * @param ocspResponse     raw OCSP-ответ DER (может быть null)
     */
    public TlsServerCredentials(
            List<GostCertificate> certificateChain,
            PrivateKeyParameters privateKey,
            byte[] ocspResponse) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new IllegalArgumentException("certificateChain must not be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }
        this.certificateChain = certificateChain;
        this.privateKey = privateKey;
        this.ocspResponse = ocspResponse;
    }

    /**
     * @return цепочка сертификатов (leaf первый, root последний)
     */
    public List<GostCertificate> getCertificateChain() {
        return certificateChain;
    }

    /**
     * @return закрытый ключ для CertificateVerify
     */
    public PrivateKeyParameters getPrivateKey() {
        return privateKey;
    }

    /**
     * @return raw OCSP-ответ DER или null
     */
    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    @Override
    public String toString() {
        return "TlsServerCredentials{certificateChain="
                + certificateChain.size()
                + " cert(s), privateKey=<redacted>"
                + (ocspResponse != null ? ", ocspResponse=" + ocspResponse.length + " bytes" : "")
                + '}';
    }
}
