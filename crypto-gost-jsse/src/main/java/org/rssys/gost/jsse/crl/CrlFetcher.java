package org.rssys.gost.jsse.crl;

import java.io.IOException;

/**
 * Интерфейс для получения CRL (Certificate Revocation List) по URI из CDP.
 * <p>
 * Аналог {@link org.rssys.gost.jsse.ocsp.OcspFetcher} для CRL.
 * Реализация должна быть vthread-safe.
 */
public interface CrlFetcher {

    /**
     * Запрашивает CRL по URI.
     *
     * @param crlUri URI из CRLDistributionPoints сертификата
     * @return DER-encoded CertificateList (RFC 5280 §5.1) или null при ошибке
     * @throws IOException при сетевой ошибке (caller отличает от отсутствия ответа)
     */
    byte[] fetch(String crlUri) throws IOException;
}
