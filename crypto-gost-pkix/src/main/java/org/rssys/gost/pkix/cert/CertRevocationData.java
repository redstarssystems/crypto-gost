package org.rssys.gost.pkix.cert;

/**
 * Данные для проверки статуса отзыва одного сертификата.
 * Хотя бы одно из полей должно быть не-null.
 *
 * @param ocspResponse DER-кодированный OCSP-ответ (nullable)
 * @param crlDer       DER-кодированный CRL (nullable)
 */
public record CertRevocationData(byte[] ocspResponse, byte[] crlDer) {
    public CertRevocationData {
        if (ocspResponse == null && crlDer == null) {
            throw new IllegalArgumentException(
                    "At least one of ocspResponse or crlDer must be non-null");
        }
    }
}
