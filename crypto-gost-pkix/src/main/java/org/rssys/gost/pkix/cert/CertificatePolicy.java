package org.rssys.gost.pkix.cert;

/**
 * Политика сертификата с опциональным CPS-квалификатором (RFC 5280 §4.2.1.4).
 *
 * <p>Соответствует структуре {@code PolicyInformation} из ASN.1:
 * <pre>
 * PolicyInformation ::= SEQUENCE {
 *     policyIdentifier   CertPolicyId,
 *     policyQualifiers   SEQUENCE OF PolicyQualifierInfo OPTIONAL
 * }
 * </pre>
 * Используется единообразно в write-пути ({@link GostCertificateBuilder},
 * {@link GostCsrBuilder}) и read-пути ({@link GostCertificate},
 * {@link GostExtensionParser.ExtensionsResult}).</p>
 *
 * @param policyOid OID политики в точечной нотации (например, {@code "1.2.643.100.113.1"})
 * @param cpsUri    URI документа CPS (Certification Practice Statement),
 *                  или {@code null} если квалификатор отсутствует
 */
public record CertificatePolicy(String policyOid, String cpsUri) {

    /** Политика без квалификаторов. */
    public CertificatePolicy(String policyOid) {
        this(policyOid, null);
    }

    /**
     * Создаёт массив {@code CertificatePolicy} из OID без CPS-квалификаторов.
     *
     * @param oids OID политик в точечной нотации
     * @return массив политик, по одной на каждый OID
     */
    public static CertificatePolicy[] fromOids(String... oids) {
        CertificatePolicy[] policies = new CertificatePolicy[oids.length];
        for (int i = 0; i < oids.length; i++) {
            policies[i] = new CertificatePolicy(oids[i]);
        }
        return policies;
    }
}
