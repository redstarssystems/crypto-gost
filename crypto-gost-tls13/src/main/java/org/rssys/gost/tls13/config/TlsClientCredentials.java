package org.rssys.gost.tls13.config;

import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;

import java.util.List;

/**
 * Учётные данные клиента для mTLS.
 * <p>
 * Используется {@link ClientCertificateSelector} для возврата выбранного
 * сертификата и ключа, удовлетворяющих фильтрам из CertificateRequest.
 *
 * @param chain      цепочка сертификатов клиента (leaf-first)
 * @param privateKey закрытый ключ для CertificateVerify
 */
public record TlsClientCredentials(List<TlsCertificate> chain, PrivateKeyParameters privateKey) {

    public TlsClientCredentials {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain must not be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key must not be null");
        }
    }

    @Override
    public String toString() {
        return "TlsClientCredentials{chain=" + chain.size() + " cert(s), privateKey=<redacted>}";
    }
}
