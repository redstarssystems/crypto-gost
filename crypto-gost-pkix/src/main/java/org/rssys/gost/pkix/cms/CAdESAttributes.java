package org.rssys.gost.pkix.cms;

import java.util.Objects;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Атрибуты CAdES (ETSI EN 319 122-1).
 *
 * <p>Построение и верификация signed-атрибутов уровня BES: signingCertificateV2.
 */
public final class CAdESAttributes {

    private CAdESAttributes() {}

    /**
     * Строит DER-значение signed-атрибута signingCertificateV2 (ESS, RFC 5035 §3).
     *
     * <p>Структура:
     * <pre>
     * SEQUENCE OF ESSCertIDv2 {
     *   SEQUENCE {
     *     hashAlgorithm  AlgorithmIdentifier,     -- ВСЕГДА явный для ГОСТ
     *     certHash       OCTET STRING,            -- Streebog-256/512 от DER сертификата
     *     issuerSerial   IssuerSerial OPTIONAL
     *   }
     * }
     * </pre>
     *
     * <p>hashAlgorithm всегда кодируется явно. RFC 5035 определяет DEFAULT sha256,
     * но для ГОСТ это значение никогда не совпадает — поле всегда присутствует в DER.
     * Не удалять условную логику «пропустить при совпадении с DEFAULT» — она всегда
     * false-branch для ГОСТ, но должна оставаться для совместимости с RFC.
     *
     * @param signerCert сертификат подписанта
     * @return DER-байты значения атрибута (содержимое SET OF: один ESSCertIDv2)
     */
    public static byte[] signingCertificateV2(GostCertificate signerCert) {
        Objects.requireNonNull(signerCert, "signerCert must not be null");
        byte[] certDer = signerCert.getEncoded();

        int keySize = signerCert.getKeySize();
        boolean is512 = (keySize == 512);
        String digestOid = is512 ? GostOids.DIGEST_512 : GostOids.DIGEST_256;

        // hashAlgorithm: AlgorithmIdentifier БЕЗ параметров (RFC 9215 §4.2)
        byte[] hashAlgId = CmsAlgorithmIdentifier.encodeOnlyOid(digestOid);

        // certHash: hash(certificate DER)
        byte[] certHash = is512 ? Digest.digest512(certDer) : Digest.digest256(certDer);
        byte[] certHashOctet = DerCodec.encodeOctetString(certHash);

        // issuerSerial
        byte[] issuerDn = signerCert.getIssuerDnBytes();
        byte[] generalName = DerCodec.encodeContextConstructed(4, issuerDn);
        byte[] generalNames = DerCodec.encodeSequence(generalName);
        byte[] serialInt = DerCodec.encodeInteger(signerCert.getSerialNumberBigInt());
        byte[] issuerSerial = DerCodec.encodeSequence(generalNames, serialInt);

        // ESSCertIDv2 SEQUENCE
        byte[] essCertIdV2 = DerCodec.encodeSequence(hashAlgId, certHashOctet, issuerSerial);

        // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
        byte[] certs = DerCodec.encodeSequence(essCertIdV2);
        return DerCodec.encodeSequence(certs);
    }

    /**
     * Верифицирует значение атрибута signingCertificateV2.
     *
     * <p>Извлекает ESSCertIDv2, сверяет хэш сертификата из атрибута с фактическим
     * хэшем DER-кодирования сертификата подписанта. Поле IssuerSerial (OPTIONAL)
     * не проверяется отдельно — certHash покрывает весь DER сертификата,
     * включая issuer DN и serialNumber.
     *
     * @param attrValue  DER-байты значения атрибута (SigningCertificateV2 SEQUENCE)
     * @param signerCert сертификат подписанта
     * @throws PkixException при несовпадении хэша
     */
    public static void verifySigningCertificateV2(byte[] attrValue, GostCertificate signerCert)
            throws PkixException {
        Objects.requireNonNull(attrValue, "attrValue must not be null");
        Objects.requireNonNull(signerCert, "signerCert must not be null");

        // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
        byte[][] signingCertV2Parts = DerCodec.parseSequenceContents(attrValue, 0);
        if (signingCertV2Parts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signingCertificateV2: expected at least 1 field (certs), got "
                            + signingCertV2Parts.length);
        }

        // certs: SEQUENCE OF ESSCertIDv2 (хотя бы один элемент)
        byte[][] certsParts = DerCodec.parseSequenceContents(signingCertV2Parts[0], 0);
        if (certsParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "signingCertificateV2: certs SEQUENCE OF is empty");
        }

        // ESSCertIDv2 SEQUENCE = { hashAlgId, certHash, issuerSerial }
        byte[][] essParts = DerCodec.parseSequenceContents(certsParts[0], 0);
        if (essParts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signingCertificateV2: expected at least 2 fields, got " + essParts.length);
        }

        // Парсим hashAlgorithm OID из essParts[0] (RFC 5035 §3: certHash вычисляется
        // алгоритмом, указанным в hashAlgorithm, не по размеру ключа)
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(essParts[0], 0);
        if (hashAlgParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signingCertificateV2: hashAlgorithm SEQUENCE has no OID");
        }
        String hashAlgOid = DerCodec.parseOid(hashAlgParts[0], 0);

        // Поле certHash
        byte[] expectedHash = DerCodec.parseOctetString(essParts[1], 0);

        // Вычисляем фактический хэш по OID из атрибута
        byte[] certDer = signerCert.getEncoded();
        byte[] actualHash;
        if (GostOids.DIGEST_512.equals(hashAlgOid)) {
            actualHash = Digest.digest512(certDer);
        } else if (GostOids.DIGEST_256.equals(hashAlgOid)) {
            actualHash = Digest.digest256(certDer);
        } else {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signingCertificateV2: unsupported hashAlgorithm OID: " + hashAlgOid);
        }

        if (!java.security.MessageDigest.isEqual(expectedHash, actualHash)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signingCertificateV2: certHash does not match signer certificate");
        }
    }
}
