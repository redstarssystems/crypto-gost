package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import org.rssys.gost.util.DerCodec;

/**
 * Идентификатор подписанта (RFC 5652 §10.2.4, SignerIdentifier CHOICE).
 *
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer       Name,
 *   serialNumber CertificateSerialNumber
 * }
 * </pre>
 */
public final class CmsIssuerAndSerialNumber {

    private final byte[] issuer; // DER-кодированный X.501 Name
    private final BigInteger serial;

    private CmsIssuerAndSerialNumber(byte[] issuer, BigInteger serial) {
        this.issuer = issuer.clone();
        this.serial = serial;
    }

    /** DER-байты issuer DN. */
    public byte[] issuer() {
        return issuer.clone();
    }

    /** Серийный номер сертификата. */
    public BigInteger serial() {
        return serial;
    }

    // ========================================================================
    // Кодирование / декодирование
    // ========================================================================

    /**
     * Кодирует IssuerAndSerialNumber в DER.
     *
     * @param issuerDer DER-кодированный X.501 Name
     * @param serial    серийный номер сертификата
     */
    public static byte[] encode(byte[] issuerDer, BigInteger serial) {
        byte[] encodedSerial = DerCodec.encodeInteger(serial);
        return DerCodec.encodeSequence(issuerDer, encodedSerial);
    }

    /**
     * Декодирует IssuerAndSerialNumber из DER.
     */
    public static CmsIssuerAndSerialNumber decode(byte[] der) {
        byte[][] parts = DerCodec.parseSequenceContents(der, 0);
        BigInteger serial = DerCodec.parseInteger(parts[1], 0);
        return new CmsIssuerAndSerialNumber(parts[0], serial);
    }

    /**
     * Извлекает IssuerAndSerialNumber из DER-кодированного X.509 сертификата.
     */
    public static CmsIssuerAndSerialNumber fromCertificate(byte[] certDer) {
        byte[][] tbsParts = DerCodec.parseSequenceContents(certDer, 0);
        byte[] tbsCert = tbsParts[0];
        byte[][] tbsFields = DerCodec.parseSequenceContents(tbsCert, 0);

        // tbsCertificate:
        // [0] version [0] EXPLICIT (опционально)
        // [1] serialNumber
        // [2] signature (algorithm)
        // [3] issuer
        int fieldIdx = 0;

        // Пропускаем version если есть (контекстный тег [0])
        if ((tbsFields[0][0] & 0xFF) == 0xA0) {
            fieldIdx = 1;
        }

        // tbsFields[fieldIdx]     — serialNumber (INTEGER)
        // tbsFields[fieldIdx + 1] — signature (AlgorithmIdentifier)
        // tbsFields[fieldIdx + 2] — issuer (Name)
        byte[] issuer = tbsFields[fieldIdx + 2];
        BigInteger serial = DerCodec.parseInteger(tbsFields[fieldIdx], 0);

        return new CmsIssuerAndSerialNumber(issuer, serial);
    }
}
