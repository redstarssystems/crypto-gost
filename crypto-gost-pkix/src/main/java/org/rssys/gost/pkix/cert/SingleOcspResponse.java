package org.rssys.gost.pkix.cert;

import java.time.Instant;

/**
 * Один ответ SingleResponse из OCSP-ответа (RFC 6960 §4.1.3).
 *
 * @param certSerialNumber серийный номер сертификата (raw DER INTEGER value)
 * @param certStatusTag    тег статуса: {@code 0xA0} = good, {@code 0xA1} = revoked, {@code 0xA2} = unknown
 * @param thisUpdate       дата выпуска данного статуса (Instant, UTC)
 * @param nextUpdate       дата следующего обновления или {@code null} (Instant, UTC)
 * @param issuerNameHash   issuerNameHash из CertID (для defense-in-depth проверки)
 * @param issuerKeyHash    issuerKeyHash из CertID (для defense-in-depth проверки)
 */
public record SingleOcspResponse(
        byte[] certSerialNumber,
        int certStatusTag,
        Instant thisUpdate,
        Instant nextUpdate,
        byte[] issuerNameHash,
        byte[] issuerKeyHash) {

    /**
     * Статус good (RFC 6960 §2.2).
     */
    public boolean isGood() {
        return certStatusTag == 0xA0 || certStatusTag == 0x80;
    }

    /**
     * Статус revoked.
     */
    public boolean isRevoked() {
        return certStatusTag == 0xA1;
    }

    /**
     * Статус unknown.
     * Принимает оба варианта тега: {@code 0xA2} (constructed) и {@code 0x82} (primitive) —
     * аналогично {@link #isGood()} для симметрии с разными реализациями.
     */
    public boolean isUnknown() {
        return certStatusTag == 0xA2 || certStatusTag == 0x82;
    }
}
