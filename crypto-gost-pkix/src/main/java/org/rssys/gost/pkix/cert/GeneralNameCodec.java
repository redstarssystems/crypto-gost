package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.util.DerCodec;

/**
 * Кодек GeneralName (RFC 5280 §4.2.1.6) — DNS, IP, directoryName.
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

    /** GeneralName tag: directoryName [4] */
    private static final int TAG_DIRECTORY_NAME = 0xA4;

    /**
     * Кодирует GeneralName типа dNSName (RFC 5280 §4.2.1.6).
     *
     * @param dnsName DNS-имя (например, {@code "example.com"})
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeDnsName(String dnsName) {
        return DerCodec.encodeTlv(TAG_DNS_NAME, dnsName.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Кодирует GeneralName типа iPAddress (RFC 5280 §4.2.1.6).
     *
     * @param ipAddress IP-адрес в строковом представлении
     * @return DER-encoded GeneralName
     */
    public static byte[] encodeIpAddress(String ipAddress) {
        try {
            byte[] ipBytes = java.net.InetAddress.getByName(ipAddress).getAddress();
            return DerCodec.encodeTlv(TAG_IP_ADDRESS, ipBytes);
        } catch (java.net.UnknownHostException e) {
            throw new RuntimeException("Invalid IP address: " + ipAddress, e);
        }
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
     *                     {@link #encodeDirectoryName})
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
        byte[] addr;
        try {
            addr = java.net.InetAddress.getByName(addrStr).getAddress();
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address in CIDR: " + cidr);
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
