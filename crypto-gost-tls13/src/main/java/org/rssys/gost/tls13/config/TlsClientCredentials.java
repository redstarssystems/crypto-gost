package org.rssys.gost.tls13.config;

import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Учётные данные клиента для mTLS.
 * <p>
 * Используется {@link ClientCertificateSelector} для возврата выбранного
 * сертификата и ключа, удовлетворяющих фильтрам из CertificateRequest.
 *
 * @param chain        цепочка сертификатов клиента (leaf-first)
 * @param privateKey   закрытый ключ для CertificateVerify
 * @param ocspResponse OCSP-ответ для leaf (stapling по запросу сервера, RFC 8446 §4.4.2.1)
 *                     или {@code null}
 */
public record TlsClientCredentials(
        List<GostCertificate> chain, PrivateKeyParameters privateKey, byte[] ocspResponse) {

    /** Учётные данные без OCSP-staple. */
    public TlsClientCredentials(List<GostCertificate> chain, PrivateKeyParameters privateKey) {
        this(chain, privateKey, null);
    }

    public TlsClientCredentials {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain must not be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key must not be null");
        }
        TlsUtils.validateOcspResponse(ocspResponse);
    }

    @Override
    public String toString() {
        return "TlsClientCredentials{chain="
                + chain.size()
                + " cert(s), privateKey=<redacted>"
                + (ocspResponse != null ? ", ocspResponse=" + ocspResponse.length + " bytes" : "")
                + "}";
    }
}
