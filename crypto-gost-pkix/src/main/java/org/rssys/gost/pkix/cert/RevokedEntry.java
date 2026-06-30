package org.rssys.gost.pkix.cert;

/**
 * Запись об отозванном сертификате для {@link GostCrlBuilder}.
 *
 * <p>Соответствует структуре записи revokedCertificates в TBSCertList
 * (RFC 5280 §5.1.2.6), включая опциональные CRL entry extensions:
 * reasonCode, invalidityDate, certificateIssuer.</p>
 *
 * @param serial            серийный номер отозванного сертификата (raw DER INTEGER value, обязательно)
 * @param revocationDate    дата отзыва в формате UTCTime или GeneralizedTime (обязательно)
 * @param reason            причина отзыва (опционально, {@code null} — без reasonCode)
 * @param invalidityDate    дата компрометации ключа (опционально, {@code null})
 * @param certificateIssuer DER-encoded GeneralNames издателя записи для indirect CRL
 *                          (опционально, {@code null}, результат
 *                          {@link GeneralNameCodec#encodeGeneralNames(byte[][])})
 */
public record RevokedEntry(
        byte[] serial,
        String revocationDate,
        ReasonCode reason,
        String invalidityDate,
        byte[] certificateIssuer) {

    /** Валидация обязательных полей в каноническом конструкторе. */
    public RevokedEntry {
        if (serial == null || serial.length == 0) {
            throw new IllegalArgumentException("serial is required and must not be empty");
        }
        if (revocationDate == null || revocationDate.isEmpty()) {
            throw new IllegalArgumentException("revocationDate is required and must not be empty");
        }
    }

    /**
     * Запись без расширений — только серийный номер и дата отзыва.
     */
    public RevokedEntry(byte[] serial, String revocationDate) {
        this(serial, revocationDate, null, null, null);
    }
}
