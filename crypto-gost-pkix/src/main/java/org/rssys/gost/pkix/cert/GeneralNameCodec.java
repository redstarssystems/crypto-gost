package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.DerCodec;

/**
 * Кодек GeneralName (RFC 5280 §4.2.1.6) — DNS, IP, rfc822Name, URI, directoryName, otherName.
 *
 * <p>Переиспользуется в {@link GostCertificateBuilder} (SAN) и {@link GostCrlBuilder}
 * (certificateIssuer в indirect CRL).</p>
 */
public final class GeneralNameCodec {

    private GeneralNameCodec() {}

    /** GeneralName tag: dNSName [2] */
    private static final int TAG_DNS_NAME = 0x82;

    /** GeneralName tag: iPAddress [7] */
    private static final int TAG_IP_ADDRESS = 0x87;

    /** GeneralName tag: rfc822Name [1] */
    private static final int TAG_RFC822_NAME = 0x81;

    /** GeneralName tag: uniformResourceIdentifier [6] */
    private static final int TAG_URI = 0x86;

    /** GeneralName tag: directoryName [4] */
    private static final int TAG_DIRECTORY_NAME = 0xA4;

    /** GeneralName tag: otherName [0] (IMPLICIT, заменяет SEQUENCE OtherName) */
    private static final int TAG_OTHER_NAME = 0xA0;

    /** Начало wildcard-метки dNSName: звёздочка и точка. */
    private static final String WILDCARD_LABEL_PREFIX = "*.";

    /** Наибольший код символа US-ASCII. */
    private static final int MAX_ASCII = 0x7F;

    private static final int IPV4_LENGTH = 4;

    /** Длина префикса ::ffff:0:0/96, за которым в IPv4-mapped адресе идут 32 бита IPv4. */
    private static final int IPV4_MAPPED_PREFIX_BITS = 96;

    /**
     * Кодирует GeneralName типа dNSName (RFC 5280 §4.2.1.6).
     *
     * <p>Имя приводится к lowercase A-label через {@link GostDnsName#toAsciiHostname}: имя в
     * Unicode кодируется как punycode, а не искажается заменой символов на {@code ?}. Крайняя
     * левая метка {@code *} допустима (wildcard-сертификат, RFC 6125 §6.4.3).</p>
     *
     * @param dnsName DNS-имя (например, {@code "example.com"} или {@code "*.example.com"})
     * @return DER-encoded GeneralName
     * @throws IllegalArgumentException если имя пустое или не приводится к допустимому имени
     */
    public static byte[] encodeDnsName(String dnsName) {
        String name = dnsName.strip();
        String ascii =
                name.startsWith(WILDCARD_LABEL_PREFIX)
                        ? WILDCARD_LABEL_PREFIX
                                + GostDnsName.toAsciiHostname(
                                        name.substring(WILDCARD_LABEL_PREFIX.length()))
                        : GostDnsName.toAsciiHostname(name);
        return DerCodec.encodeTlv(TAG_DNS_NAME, ascii.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Кодирует GeneralName типа iPAddress (RFC 5280 §4.2.1.6).
     *
     * <p>Адрес разбирается только как литерал ({@link GostDnsName#parseIpAddress}), без обращения
     * к DNS: строка, не являющаяся адресом, - ошибка, а не повод для сетевого запроса. IPv4-mapped
     * IPv6 ({@code ::ffff:a.b.c.d}) кодируется как IPv4 (4 байта): так же адрес читает собственный
     * валидатор, и сертификат нашего построителя проходит {@code permitted}-ограничение IPv4.</p>
     *
     * @param ipAddress IP-литерал: IPv4, IPv6 или IPv6 в квадратных скобках (без зоны)
     * @return DER-encoded GeneralName
     * @throws IllegalArgumentException если строка не является IP-литералом
     */
    public static byte[] encodeIpAddress(String ipAddress) {
        return DerCodec.encodeTlv(TAG_IP_ADDRESS, parseIpLiteral(ipAddress));
    }

    /** Разбирает IP-литерал без DNS; зона ({@code %eth0}) в сертификате не имеет смысла. */
    private static byte[] parseIpLiteral(String literal) {
        byte[] address = literal.indexOf('%') >= 0 ? null : GostDnsName.parseIpAddress(literal);
        if (address == null) {
            throw new IllegalArgumentException("Invalid IP address literal: " + literal);
        }
        return address;
    }

    /** Значение для IA5String: символы US-ASCII, остальное - ошибка, а не молчаливая замена. */
    private static byte[] ascii(String value, String what) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > MAX_ASCII) {
                throw new IllegalArgumentException(what + " must be US-ASCII (IA5String)");
            }
        }
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Кодирует GeneralName типа rfc822Name (RFC 5280 §4.2.1.6).
     * Значение — IA5String (US-ASCII).
     *
     * @param email email-адрес (например, {@code "user@example.com"})
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeRfc822Name(String email) {
        return DerCodec.encodeTlv(TAG_RFC822_NAME, ascii(email, "rfc822Name"));
    }

    /**
     * Кодирует GeneralName типа uniformResourceIdentifier (RFC 5280 §4.2.1.6).
     * Значение — IA5String (US-ASCII).
     *
     * @param uri URI (например, {@code "https://example.com"})
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeUri(String uri) {
        return DerCodec.encodeTlv(TAG_URI, ascii(uri, "uniformResourceIdentifier"));
    }

    /**
     * Кодирует GeneralName типа otherName (RFC 5280 §4.2.1.6).
     *
     * <p>Структура (тег [0] IMPLICIT заменяет SEQUENCE OtherName):
     * <pre>
     * A0 &lt;len&gt;               -- IMPLICIT [0], без вложенного тега SEQUENCE
     *   06 &lt;len&gt; &lt;oid&gt;      -- type-id
     *   A0 &lt;len&gt;              -- [0] EXPLICIT
     *     &lt;valueDer&gt;          -- значение, уже DER-кодированное со своим тегом
     * </pre>
     *
     * @param oid      OID типа (например, {@code "1.3.6.1.4.1.311.20.2.3"} для UPN)
     * @param valueDer DER-кодированное значение со своим тегом (будет обёрнуто в [0] EXPLICIT)
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeOtherName(String oid, byte[] valueDer) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        try {
            content.write(DerCodec.encodeOid(oid));
            content.write(DerCodec.encodeContextConstructed(0, valueDer));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return DerCodec.encodeTlv(TAG_OTHER_NAME, content.toByteArray());
    }

    /**
     * Кодирует otherName с UPN (User Principal Name).
     * Значение — UTF8String.
     *
     * @param upn User Principal Name (например, {@code "user@domain.ru"})
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeOtherNameUpn(String upn) {
        byte[] upnValue = DerCodec.encodeUTF8String(upn);
        return encodeOtherName(GostOids.ID_MS_UPN, upnValue);
    }

    /**
     * Кодирует GeneralName типа directoryName (RFC 5280 §4.2.1.6).
     * Обёртка над DER-кодированным Distinguished Name.
     *
     * @param dnDer DER-кодированный DN (SEQUENCE OF RDN)
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeDirectoryName(byte[] dnDer) {
        return DerCodec.encodeTlv(TAG_DIRECTORY_NAME, dnDer);
    }

    /**
     * Кодирует SEQUENCE OF GeneralName для SAN или certificateIssuer.
     *
     * @param generalNames массив DER-кодированных GeneralName (результаты
     *                     {@link #encodeDnsName}, {@link #encodeIpAddress},
     *                     {@link #encodeDirectoryName}, {@link #encodeRfc822Name},
     *                     {@link #encodeUri}, {@link #encodeOtherName})
     * @return DER-encoded SEQUENCE OF GeneralName
     */
    public static byte[] encodeGeneralNames(byte[]... generalNames) {
        ByteArrayOutputStream gn = new ByteArrayOutputStream();
        try {
            for (byte[] name : generalNames) {
                gn.write(name);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return DerCodec.encodeSequence(gn.toByteArray());
    }

    /**
     * Кодирует SEQUENCE OF GeneralName из строковых DNS и IP имён.
     *
     * @param dnsNames    DNS-имена (может быть {@code null})
     * @param ipAddresses IP-адреса (может быть {@code null})
     * @return DER-encoded SEQUENCE OF GeneralName
     */
    public static byte[] encodeGeneralNames(String[] dnsNames, String[] ipAddresses) {
        List<byte[]> names = new ArrayList<>();
        if (dnsNames != null) {
            for (String name : dnsNames) {
                names.add(encodeDnsName(name));
            }
        }
        if (ipAddresses != null) {
            for (String ip : ipAddresses) {
                names.add(encodeIpAddress(ip));
            }
        }
        return encodeGeneralNames(names.toArray(new byte[0][]));
    }

    /**
     * Кодирует GeneralName типа iPAddress для NameConstraints (RFC 5280 §4.2.1.10).
     *
     * <p>Отличается от {@link #encodeIpAddress(String)}: NameConstraints требует
     * адрес+маску (8 байт для IPv4, 32 байта для IPv6), а не только адрес.</p>
     *
     * @param cidr CIDR-нотация: {@code "192.168.1.0/28"} или {@code "2001:db8::/32"}
     * @return DER-encoded GeneralName (tag 0x87, 8 или 32 байта значения)
     * @throws IllegalArgumentException если строка не в CIDR-формате или адрес некорректен
     */
    public static byte[] encodeIpConstraint(String cidr) {
        int slash = cidr.indexOf('/');
        if (slash < 0) {
            throw new IllegalArgumentException("CIDR notation required: " + cidr);
        }
        String addrStr = cidr.substring(0, slash);
        int prefixLen;
        try {
            prefixLen = Integer.parseInt(cidr.substring(slash + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR: " + cidr);
        }
        byte[] addr = parseIpLiteral(addrStr);
        // IPv4-mapped литерал кодируется как IPv4 (см. encodeIpAddress): префикс /96../128 IPv6
        // становится префиксом /0../32 IPv4, а более короткий не выразим 4 байтами
        if (addr.length == IPV4_LENGTH && addrStr.indexOf(':') >= 0) {
            if (prefixLen < IPV4_MAPPED_PREFIX_BITS) {
                throw new IllegalArgumentException(
                        "IPv4-mapped CIDR needs prefix length of at least "
                                + IPV4_MAPPED_PREFIX_BITS
                                + ": "
                                + cidr);
            }
            prefixLen -= IPV4_MAPPED_PREFIX_BITS;
        }
        int addrLen = addr.length;
        if (addrLen != 4 && addrLen != 16) {
            throw new IllegalArgumentException("Unsupported address family: " + cidr);
        }
        if (prefixLen < 0 || prefixLen > addrLen * 8) {
            throw new IllegalArgumentException(
                    "Prefix length out of range: " + prefixLen + " for address length " + addrLen);
        }
        byte[] mask = new byte[addrLen];
        for (int i = 0; i < addrLen; i++) {
            int bitsInByte = Math.max(0, Math.min(8, prefixLen - i * 8));
            mask[i] = (byte) (0xFF00 >> bitsInByte);
        }
        byte[] netAddr = new byte[addrLen];
        for (int i = 0; i < addrLen; i++) {
            netAddr[i] = (byte) (addr[i] & mask[i]);
        }
        byte[] constraint = new byte[addrLen * 2];
        System.arraycopy(netAddr, 0, constraint, 0, addrLen);
        System.arraycopy(mask, 0, constraint, addrLen, addrLen);
        return DerCodec.encodeTlv(TAG_IP_ADDRESS, constraint);
    }
}
