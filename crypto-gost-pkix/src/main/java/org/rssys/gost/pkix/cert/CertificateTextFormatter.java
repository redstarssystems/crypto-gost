package org.rssys.gost.pkix.cert;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Формирует подробный человекочитаемый отчёт по X.509-сертификату ГОСТ.
 *
 * <p>В отличие от {@link GostCertificate#toString()} (компактный, безопасный для
 * логов формат с усечением DN и без OCSP), этот форматтер даёт максимально
 * подробное многострочное представление: полный DN, расшифровка всех расширений
 * (KeyUsage, EKU, SAN, AIA, CDP, SKI/AKI, BasicConstraints, NameConstraints и
 * др.). Предназначен для показа человеку на экране, не для журналов.</p>
 *
 * <p>Вынесен отдельным классом (а не методом {@link GostCertificate}) по образцу
 * {@link GostCertificateBuilder}/{@link ChainValidator}/{@link GostExtensionParser}:
 * операции над сертификатом живут снаружи представления, security-критичный
 * {@link GostCertificate} не разрастается косметической логикой форматирования.</p>
 */
public final class CertificateTextFormatter {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    private static final HexFormat HEX = HexFormat.of().withDelimiter(":");

    private static final String INDENT = "    ";

    // Однобайтовые биты KeyUsage берём из единого источника — enum KeyUsage.mask
    // (GostCertificateBuilder). decipherOnly (бит 8, RFC 5280 §4.2.1.3) в enum
    // отсутствует намеренно: keyUsageFlags() кодирует маску в один байт, и 0x8000
    // там потерялся бы. В упакованном keyUsageBits второй октет BIT STRING сдвинут
    // на 8 -> decipherOnly == 0x8000.
    private static final int KU_DECIPHER_ONLY = 0x8000;

    private CertificateTextFormatter() {}

    /**
     * Формирует многострочный отчёт по сертификату.
     *
     * @param cert разобранный сертификат (не null)
     * @return человекочитаемое представление
     * @throws IllegalArgumentException если cert == null
     */
    public static String format(GostCertificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("cert must not be null");
        }
        StringBuilder sb = new StringBuilder(1024);

        sb.append("Сертификат:\n");
        line(sb, "Версия", "v" + cert.getVersion());
        line(sb, "Серийный номер", "0x" + cert.getSerialNumberBigInt().toString(16));
        line(sb, "Алгоритм подписи", GostOids.displayName(cert.getSignatureAlgorithmOid()));
        line(sb, "Издатель (Issuer)", cert.getIssuerDn());
        line(sb, "Субъект (Subject)", cert.getSubjectDn());
        line(sb, "Действителен с", formatTime(cert.getNotBefore()));
        line(sb, "Действителен по", formatTime(cert.getNotAfter()));
        line(sb, "Открытый ключ", cert.getKeySize() + "-bit GOST R 34.10-2012");
        if (cert.isSelfSigned()) {
            line(sb, "Самоподписанный", "да");
        }

        appendExtensions(sb, cert);

        return sb.toString();
    }

    private static void appendExtensions(StringBuilder sb, GostCertificate cert) {
        sb.append("  Расширения:\n");

        // BasicConstraints
        String bc = "CA=" + (cert.isCA() ? "TRUE" : "FALSE");
        if (cert.isCA() && cert.getPathLen() >= 0) {
            bc += ", pathLen=" + cert.getPathLen();
        }
        ext(sb, "Basic Constraints", bc);

        // KeyUsage
        int ku = cert.getKeyUsageBits();
        if (ku != 0) {
            ext(sb, "Key Usage", formatKeyUsage(ku));
        }

        // Extended Key Usage
        byte[][] ekuOids = cert.getEkuOids();
        if (ekuOids != null && ekuOids.length > 0) {
            ext(sb, "Extended Key Usage", formatOidList(ekuOids));
        }

        // Certificate Policies
        CertificatePolicy[] policyInfos = cert.getCertificatePolicyInfos();
        if (policyInfos != null && policyInfos.length > 0) {
            StringBuilder cpSb = new StringBuilder();
            for (int i = 0; i < policyInfos.length; i++) {
                if (i > 0) {
                    cpSb.append("; ");
                }
                cpSb.append(GostOids.displayName(policyInfos[i].policyOid()));
                if (policyInfos[i].cpsUri() != null) {
                    cpSb.append(" CPS: ").append(policyInfos[i].cpsUri());
                }
            }
            ext(sb, "Certificate Policies", cpSb.toString());
        } else {
            String[] policies = cert.getCertificatePolicies();
            if (policies != null && policies.length > 0) {
                ext(sb, "Certificate Policies", formatDottedOids(policies));
            }
        }

        // Subject Alternative Name
        appendGeneralNames(
                sb,
                "Subject Alt Name",
                cert.getSanDnsNames(),
                cert.getSanIpAddresses(),
                cert.getSanRfc822Names(),
                cert.getSanUris(),
                cert.getSanDirectoryNames(),
                cert.getSanOtherNames());

        // Issuer Alternative Name
        appendGeneralNames(
                sb,
                "Issuer Alt Name",
                cert.getIssuerAltNameDnsNames(),
                cert.getIssuerAltNameIpAddresses(),
                cert.getIssuerAltNameRfc822Names(),
                cert.getIssuerAltNameUris(),
                cert.getIssuerAltNameDirectoryNames(),
                cert.getIssuerAltNameOtherNames());

        // Subject / Authority Key Identifier
        byte[] ski = cert.getSubjectKeyIdentifier();
        if (ski != null) {
            ext(sb, "Subject Key Identifier", HEX.formatHex(ski));
        }
        byte[] aki = cert.getAuthorityKeyIdentifier();
        if (aki != null) {
            ext(sb, "Authority Key Identifier", HEX.formatHex(aki));
        }

        // Authority Info Access
        appendUriList(sb, "OCSP", cert.getOcspUris());
        appendUriList(sb, "CA Issuers", cert.getCaIssuersUris());

        // CRL Distribution Points / Freshest CRL
        appendUriList(sb, "CRL Distribution Points", cert.getCdpUris());
        appendUriList(sb, "Freshest CRL", cert.getFreshestCrlUris());

        // Name Constraints
        NameConstraintsData nc = cert.getNameConstraints();
        if (nc != null && !nc.isEmpty()) {
            ext(sb, "Name Constraints", formatNameConstraints(nc));
        }

        // OCSP-ответ (stapling) — только факт присутствия, без разбора.
        // Для сертификата из .p7b поле пустое (заполняется лишь в TLS-stapling).
        if (cert.hasOcspResponse()) {
            byte[] ocsp = cert.getOcspResponse();
            ext(sb, "OCSP-ответ", "присутствует (" + (ocsp == null ? 0 : ocsp.length) + " байт)");
        }

        // id-pkix-ocsp-nocheck — значение пустое, важен только факт присутствия
        if (cert.hasOcspNoCheck()) {
            ext(sb, "OCSP No Check", "да");
        }

        if (cert.hasUnknownCriticalExtension()) {
            ext(sb, "ВНИМАНИЕ", "присутствует неизвестное критичное расширение");
        }
    }

    private static String formatKeyUsage(int ku) {
        StringBuilder sb = new StringBuilder();
        appendKu(
                sb, ku, GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE.mask, "digitalSignature");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.NON_REPUDIATION.mask, "nonRepudiation");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.KEY_ENCIPHERMENT.mask, "keyEncipherment");
        appendKu(
                sb, ku, GostCertificateBuilder.KeyUsage.DATA_ENCIPHERMENT.mask, "dataEncipherment");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.KEY_AGREEMENT.mask, "keyAgreement");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN.mask, "keyCertSign");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.CRL_SIGN.mask, "cRLSign");
        appendKu(sb, ku, GostCertificateBuilder.KeyUsage.ENCIPHER_ONLY.mask, "encipherOnly");
        appendKu(sb, ku, KU_DECIPHER_ONLY, "decipherOnly");
        return sb.toString();
    }

    private static void appendKu(StringBuilder sb, int ku, int mask, String name) {
        if ((ku & mask) != 0) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(name);
        }
    }

    private static String formatOidList(byte[][] oidTlvs) {
        StringBuilder sb = new StringBuilder();
        for (byte[] oidTlv : oidTlvs) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            // getEkuOids() возвращает content OID без TLV-обёртки — safeParseOid её добавит.
            String dotted = safeParseOid(oidTlv);
            sb.append(GostOids.displayName(dotted));
        }
        return sb.toString();
    }

    private static String formatDottedOids(String[] dottedOids) {
        StringBuilder sb = new StringBuilder();
        for (String oid : dottedOids) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(GostOids.displayName(oid));
        }
        return sb.toString();
    }

    /** Конвертирует DER-байты OID в точечную нотацию.
     *  getEkuOids() / getCpOids() возвращают content OID без тега 0x06;
     *  parseOid ожидает полный TLV — оборачиваем. */
    private static String safeParseOid(byte[] oidContent) {
        try {
            return DerCodec.parseOid(DerCodec.encodeTlv(DerCodec.TAG_OID, oidContent), 0);
        } catch (RuntimeException e) {
            return HexFormat.of().formatHex(oidContent);
        }
    }

    private static void appendGeneralNames(
            StringBuilder sb,
            String label,
            String[] dnsNames,
            byte[][] ipAddresses,
            String[] rfc822Names,
            String[] uris,
            byte[][] directoryNames,
            OtherNameEntry[] otherNames) {
        boolean hasDns = dnsNames != null && dnsNames.length > 0;
        boolean hasIp = ipAddresses != null && ipAddresses.length > 0;
        boolean hasRfc822 = rfc822Names != null && rfc822Names.length > 0;
        boolean hasUri = uris != null && uris.length > 0;
        boolean hasDirName = directoryNames != null && directoryNames.length > 0;
        boolean hasOtherName = otherNames != null && otherNames.length > 0;
        if (!hasDns && !hasIp && !hasRfc822 && !hasUri && !hasDirName && !hasOtherName) {
            return;
        }
        StringBuilder value = new StringBuilder();
        if (hasDns) {
            for (String dns : dnsNames) {
                appendCsv(value, "DNS:" + dns);
            }
        }
        if (hasIp) {
            for (byte[] ip : ipAddresses) {
                appendCsv(value, "IP:" + formatIp(ip));
            }
        }
        if (hasRfc822) {
            for (String email : rfc822Names) {
                appendCsv(value, "EMAIL:" + email);
            }
        }
        if (hasUri) {
            for (String uri : uris) {
                appendCsv(value, "URI:" + uri);
            }
        }
        if (hasDirName) {
            for (byte[] dn : directoryNames) {
                appendCsv(value, "DIRNAME:" + HexFormat.of().formatHex(dn));
            }
        }
        if (hasOtherName) {
            for (OtherNameEntry entry : otherNames) {
                appendCsv(value, "OTHERNAME:" + entry.oid());
            }
        }
        ext(sb, label, value.toString());
    }

    private static void appendUriList(StringBuilder sb, String label, String[] uris) {
        if (uris == null || uris.length == 0) {
            return;
        }
        StringBuilder value = new StringBuilder();
        for (String uri : uris) {
            appendCsv(value, uri);
        }
        ext(sb, label, value.toString());
    }

    private static String formatNameConstraints(NameConstraintsData nc) {
        StringBuilder sb = new StringBuilder();
        appendConstraint(sb, "permitted DNS", nc.permittedDnsNames);
        appendConstraintIps(sb, "permitted IP", nc.permittedIps);
        appendConstraint(sb, "permitted RFC822", nc.permittedRfc822Names);
        appendConstraint(sb, "permitted URI", nc.permittedUris);
        appendConstraintDirNames(sb, "permitted DIRNAME", nc.permittedDirectoryNames);
        appendConstraint(sb, "excluded DNS", nc.excludedDnsNames);
        appendConstraintIps(sb, "excluded IP", nc.excludedIps);
        appendConstraint(sb, "excluded RFC822", nc.excludedRfc822Names);
        appendConstraint(sb, "excluded URI", nc.excludedUris);
        appendConstraintDirNames(sb, "excluded DIRNAME", nc.excludedDirectoryNames);
        if (nc.hasUnsupportedNameType) {
            appendCsv(sb, "есть неподдерживаемые типы имён (otherName)");
        }
        if (nc.hasUnsupportedRfc822Form) {
            appendCsv(sb, "есть неподдерживаемая форма rfc822Name (mailbox)");
        }
        if (nc.nonCritical) {
            appendCsv(sb, "non-critical (нарушение RFC 5280)");
        }
        return sb.toString();
    }

    private static void appendConstraint(StringBuilder sb, String label, String[] names) {
        if (names == null || names.length == 0) {
            return;
        }
        appendCsv(sb, label + "=[" + String.join(", ", names) + "]");
    }

    private static void appendConstraintIps(StringBuilder sb, String label, byte[][] ips) {
        if (ips == null || ips.length == 0) {
            return;
        }
        StringBuilder inner = new StringBuilder();
        for (byte[] ip : ips) {
            appendCsv(inner, formatIp(ip));
        }
        appendCsv(sb, label + "=[" + inner + "]");
    }

    private static void appendConstraintDirNames(
            StringBuilder sb, String label, byte[][] dirNames) {
        if (dirNames == null || dirNames.length == 0) {
            return;
        }
        appendCsv(sb, label + "=[" + dirNames.length + " entries]");
    }

    private static void appendCsv(StringBuilder sb, String value) {
        if (sb.length() > 0) {
            sb.append(", ");
        }
        sb.append(value);
    }

    /**
     * Форматирует сырой IP-адрес. Для SAN — 4 (IPv4) или 16 (IPv6) байт; для
     * NameConstraints — 8 (IPv4+маска) или 32 (IPv6+маска) байта.
     */
    static String formatIp(byte[] ip) {
        if (ip == null) {
            return "?";
        }
        if (ip.length == 4) {
            return ipv4(ip, 0);
        }
        if (ip.length == 8) {
            return ipv4(ip, 0) + "/" + ipv4(ip, 4);
        }
        if (ip.length == 16) {
            return ipv6(ip, 0);
        }
        if (ip.length == 32) {
            return ipv6(ip, 0) + "/" + ipv6(ip, 16);
        }
        return HexFormat.of().formatHex(ip);
    }

    private static String ipv4(byte[] ip, int off) {
        return (ip[off] & 0xFF)
                + "."
                + (ip[off + 1] & 0xFF)
                + "."
                + (ip[off + 2] & 0xFF)
                + "."
                + (ip[off + 3] & 0xFF);
    }

    /** Форматирует IPv6 с сжатием самой длинной группы нулей в "::" (RFC 5952 §4.2). */
    private static String ipv6(byte[] ip, int off) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((ip[off + i * 2] & 0xFF) << 8) | (ip[off + i * 2 + 1] & 0xFF);
        }
        // Ищем самый длинный прогон нулей длиной >= 2 (RFC 5952 §4.2.2).
        int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (curStart < 0) curStart = i;
                curLen++;
                if (curLen > bestLen) {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }
        if (bestLen < 2) {
            bestStart = -1;
        }

        StringBuilder sb = new StringBuilder(39);
        for (int i = 0; i < 8; ) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen;
            } else {
                if (i > 0 && sb.charAt(sb.length() - 1) != ':') {
                    sb.append(':');
                }
                sb.append(Integer.toHexString(groups[i]));
                i++;
            }
        }
        return sb.toString();
    }

    private static String formatTime(Instant instant) {
        return instant == null ? "?" : TIME_FMT.format(instant);
    }

    private static void line(StringBuilder sb, String label, String value) {
        sb.append(INDENT).append(label).append(": ").append(value).append('\n');
    }

    private static void ext(StringBuilder sb, String label, String value) {
        sb.append(INDENT).append(INDENT).append(label).append(": ").append(value).append('\n');
    }
}
