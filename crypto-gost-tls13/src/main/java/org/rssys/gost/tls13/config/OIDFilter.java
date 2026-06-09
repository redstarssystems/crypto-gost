package org.rssys.gost.tls13.config;

import java.util.Arrays;

/**
 * OID-фильтр для расширения oid_filters (RFC 8446 §4.2.5).
 * <p>
 * Сервер включает в CertificateRequest список таких фильтров — пар
 * {OID расширения, допустимые значения}. Клиент выбирает сертификат,
 * удовлетворяющий всем фильтрам, или отправляет пустой certificate_list.
 *
 * @param extensionOid     DER-кодированный OID расширения (RFC 5280),
 *                         без тега и длины, только value
 * @param extensionValues  допустимые значения (может быть пустым —
 *                         достаточно присутствия расширения в сертификате)
 */
public record OIDFilter(byte[] extensionOid, byte[] extensionValues) {

    public OIDFilter {
        if (extensionOid == null || extensionOid.length == 0) {
            throw new IllegalArgumentException("extensionOid must not be null or empty");
        }
        if (extensionValues == null) {
            throw new IllegalArgumentException("extensionValues must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OIDFilter that)) return false;
        return Arrays.equals(extensionOid, that.extensionOid)
                && Arrays.equals(extensionValues, that.extensionValues);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(extensionOid);
        result = 31 * result + Arrays.hashCode(extensionValues);
        return result;
    }

    @Override
    public String toString() {
        return "OIDFilter{oid=" + bytesToHex(extensionOid) + ", values=" + bytesToHex(extensionValues) + "}";
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}
