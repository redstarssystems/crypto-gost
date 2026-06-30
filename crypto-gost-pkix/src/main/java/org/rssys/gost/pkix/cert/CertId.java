package org.rssys.gost.pkix.cert;

/**
 * Идентификатор сертификата в OCSP-запросе (RFC 6960 §4.1.1).
 *
 * @param hashAlgOid     dotted-string OID хэш-алгоритма (например "1.2.643.7.1.1.2.2")
 * @param issuerNameHash хэш от DER-encoded subject DN эмитента
 * @param issuerKeyHash  хэш от BIT STRING value SPKI эмитента
 * @param serialNumber   серийный номер сертификата — raw DER INTEGER VALUE (без tag/length)
 */
public record CertId(
        String hashAlgOid, byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber) {

    /** {@return копия issuerNameHash для защиты от модификации} */
    @Override
    public byte[] issuerNameHash() {
        return issuerNameHash.clone();
    }

    /** {@return копия issuerKeyHash для защиты от модификации} */
    @Override
    public byte[] issuerKeyHash() {
        return issuerKeyHash.clone();
    }

    /** {@return копия serialNumber для защиты от модификации} */
    @Override
    public byte[] serialNumber() {
        return serialNumber.clone();
    }
}
