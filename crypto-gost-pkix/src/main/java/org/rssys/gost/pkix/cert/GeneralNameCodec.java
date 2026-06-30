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
}
