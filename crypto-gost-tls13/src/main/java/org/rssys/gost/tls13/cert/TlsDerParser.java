package org.rssys.gost.tls13.cert;

import org.rssys.gost.util.DerCodec;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Утилиты парсинга DER (ASN.1) для X.509 сертификатов и OCSP-ответов.
 *
 * <p>Содержит низкоуровневые TLV-парсеры, константы тегов, OID и вспомогательные
 * методы для разбора DER-структур. Вынесен из {@link TlsCertificate} для
 * разделения ответственности.</p>
 */
public final class TlsDerParser {

    // Константы ASN.1 тегов DER (общие теги — forwarding на DerCodec)
    public static final int TAG_BOOLEAN          = DerCodec.TAG_BOOLEAN;
    public static final int TAG_INTEGER          = DerCodec.TAG_INTEGER;
    public static final int TAG_BIT_STRING       = DerCodec.TAG_BIT_STRING;
    public static final int TAG_OCTET_STRING     = DerCodec.TAG_OCTET_STRING;
    public static final int TAG_OID              = DerCodec.TAG_OID;
    public static final int TAG_UTC_TIME         = DerCodec.TAG_UTC_TIME;
    public static final int TAG_GENERALIZED_TIME = DerCodec.TAG_GENERALIZED_TIME;
    public static final int TAG_SEQUENCE         = DerCodec.TAG_SEQUENCE;
    // Контекстно-зависимые теги X.509 структур — не DER-примитивы, держим локально
    public static final int TAG_CTX_0            = 0xA0;
    public static final int TAG_CTX_1            = 0xA1;
    public static final int TAG_CTX_2            = 0xA2;
    public static final int TAG_CTX_3            = 0xA3;
    public static final int TAG_DNS_NAME         = 0x82;
    public static final int TAG_IP_ADDRESS       = 0x87;

    // OID: SubjectAltName 2.5.29.17
    public static final byte[] SAN_OID_BYTES     = {0x55, 0x1D, 0x11};
    // OID: KeyUsage 2.5.29.15
    public static final byte[] KU_OID_BYTES      = {0x55, 0x1D, 0x0F};
    // OID: ExtendedKeyUsage 2.5.29.37
    public static final byte[] EKU_OID_BYTES     = {0x55, 0x1D, 0x25};
    // OID: BasicConstraints 2.5.29.19
    public static final byte[] BC_OID_BYTES      = {0x55, 0x1D, 0x13};
    // OID: id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
    public static final byte[] OCSP_BASIC_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01};

    // OID: SubjectKeyIdentifier 2.5.29.14
    public static final byte[] SKI_OID_BYTES = {0x55, 0x1D, 0x0E};
    // OID: AuthorityKeyIdentifier 2.5.29.35
    public static final byte[] AKI_OID_BYTES = {0x55, 0x1D, 0x23};
    // OID: AuthorityInfoAccess 1.3.6.1.5.5.7.1.1
    public static final byte[] AIA_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};

    // OID access method: id-ad-ocsp 1.3.6.1.5.5.7.48.1
    public static final byte[] AD_OCSP_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};
    // OID access method: id-ad-caIssuers 1.3.6.1.5.5.7.48.2
    public static final byte[] AD_CA_ISSUERS_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};

    // OID: CRLDistributionPoints 2.5.29.31
    public static final byte[] CDP_OID_BYTES = {0x55, 0x1D, 0x1F};
    // OID: IssuingDistributionPoint 2.5.29.28
    public static final byte[] IDP_OID_BYTES = {0x55, 0x1D, 0x1C};
    // OID: CertificatePolicies 2.5.29.32
    public static final byte[] CP_OID_BYTES = {0x55, 0x1D, 0x20};

    // ========================================================================
    // OID Extended Key Usage (RFC 5280 §4.2.1.12)
    // ========================================================================

    // OID: id-kp-serverAuth 1.3.6.1.5.5.7.3.1
    public static final byte[] SERVER_AUTH_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    // OID: id-kp-clientAuth 1.3.6.1.5.5.7.3.2
    public static final byte[] CLIENT_AUTH_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
    // OID: id-kp-OCSPSigning 1.3.6.1.5.5.7.3.9
    public static final byte[] OCSP_SIGNING_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09};
    // OID: anyExtendedKeyUsage 2.5.29.37.0
    public static final byte[] ANY_EKU_OID_BYTES = {0x55, 0x1D, 0x25, 0x00};
    // OID: УКЭП 1.2.643.100.113.1 (усиленная квалифицированная электронная подпись)
    public static final byte[] UKEP_OID_BYTES    = {0x2A, (byte)0x85, 0x03, 0x64, 0x71, 0x01};
    // OID: УНЭП 1.2.643.100.113.2 (усиленная неквалифицированная электронная подпись)
    public static final byte[] UNEP_OID_BYTES    = {0x2A, (byte)0x85, 0x03, 0x64, 0x71, 0x02};
    // ========================================================================
    // OID Distinguished Name атрибутов (RFC 4519, ГОСТ Р 34.10)
    // ========================================================================

    // OID: id-at-commonName 2.5.4.3
    public static final byte[] CN_OID_BYTES    = {0x55, 0x04, 0x03};
    // OID: id-at-countryName 2.5.4.6
    public static final byte[] C_OID_BYTES     = {0x55, 0x04, 0x06};
    // OID: id-at-localityName 2.5.4.7
    public static final byte[] L_OID_BYTES     = {0x55, 0x04, 0x07};
    // OID: id-at-stateOrProvinceName 2.5.4.8
    public static final byte[] ST_OID_BYTES    = {0x55, 0x04, 0x08};
    // OID: id-at-streetAddress 2.5.4.9
    public static final byte[] STREET_OID_BYTES = {0x55, 0x04, 0x09};
    // OID: id-at-organizationName 2.5.4.10
    public static final byte[] O_OID_BYTES     = {0x55, 0x04, 0x0A};
    // OID: id-at-organizationalUnitName 2.5.4.11
    public static final byte[] OU_OID_BYTES    = {0x55, 0x04, 0x0B};
    // OID: id-at-title 2.5.4.12
    public static final byte[] T_OID_BYTES     = {0x55, 0x04, 0x0C};
    // OID: id-at-serialNumber 2.5.4.5
    public static final byte[] SERIALNUM_OID_BYTES = {0x55, 0x04, 0x05};
    // OID: id-at-surname 2.5.4.4
    public static final byte[] SN_OID_BYTES    = {0x55, 0x04, 0x04};
    // OID: id-at-givenName 2.5.4.42
    public static final byte[] GN_OID_BYTES    = {0x55, 0x04, 0x2A};
    // OID: id-at-postalCode 2.5.4.17
    public static final byte[] POSTAL_CODE_OID_BYTES = {0x55, 0x04, 0x11};
    // OID: id-at-uniqueIdentifier 2.5.4.45
    public static final byte[] UNIQUE_ID_OID_BYTES = {0x55, 0x04, 0x2D};
    // OID: id-at-pseudonym 2.5.4.65
    public static final byte[] PSEUDONYM_OID_BYTES  = {0x55, 0x04, 0x41};
    // OID: emailAddress 1.2.840.113549.1.9.1
    public static final byte[] EMAIL_OID_BYTES = {(byte)0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x09, 0x01};
    // OID: uid 0.9.2342.19200300.100.1.1
    public static final byte[] UID_OID_BYTES   = {0x09, (byte)0x92, 0x26, (byte)0x89, (byte)0x93, (byte)0xF2, 0x2C, 0x64, 0x01, 0x01};
    // OID: INN 1.2.643.3.131.1.1
    public static final byte[] INN_OID_BYTES   = {0x2A, (byte)0x85, 0x03, 0x03, (byte)0x83, 0x01, 0x01};
    // OID: OGRNIP 1.2.643.3.131.1.2
    public static final byte[] OGRNIP_OID_BYTES = {0x2A, (byte)0x85, 0x03, 0x03, (byte)0x83, 0x01, 0x02};
    // OID: INNLE 1.2.643.100.1
    public static final byte[] INNLE_OID_BYTES = {0x2A, (byte)0x85, 0x03, 0x64, 0x01};
    // OID: OGRN 1.2.643.100.3
    public static final byte[] OGRN_OID_BYTES  = {0x2A, (byte)0x85, 0x03, 0x64, 0x03};
    // OID: SNILS 1.2.643.100.5
    public static final byte[] SNILS_OID_BYTES = {0x2A, (byte)0x85, 0x03, 0x64, 0x05};
    // OID: organizationIdentifier 2.5.4.97
    public static final byte[] ORG_ID_OID_BYTES = {0x55, 0x04, 0x61};

    // ========================================================================
    // OID OCSP (RFC 6960)
    // ========================================================================

    // OID: id-tc26-gost-3411-12-256 (Streebog-256) 1.2.643.7.1.1.2.2
    public static final byte[] STREEBOG256_OID_BYTES = {
            (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02
    };
    // OID: id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
    public static final byte[] OCSP_NONCE_OID_BYTES = {
            (byte) 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
    };

    private TlsDerParser() {
    }

    /**
     * Парсит SEQUENCE: ищет tag=0x30 и возвращает [dataStart, dataEnd].
     * Поскольку DER-структура начинается с SEQUENCE, этот метод является
     * обёрткой над {@link #readTlv(byte[], int)}.
     *
     * @param der    DER-поток
     * @param offset смещение начала
     * @return [valueStart, valueEnd]
     */
    public static int[] parseSequence(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        if ((der[offset] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Expected SEQUENCE at offset " + offset);
        }
        return readTlv(der, offset);
    }

    /**
     * Читает TLV (Tag + Length + Value) из DER-потока начиная с offset.
     *
     * @param der    DER-поток
     * @param offset смещение на tag текущего TLV
     * @return int[2] {valueStart, valueEnd}, где valueStart — смещение первого байта Value,
     *         valueEnd — смещение за последний байт Value (т.е. начало следующего TLV).
     */
    public static int[] readTlv(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int tag = der[offset] & 0xFF;
        int[] lenResult = parseLength(der, offset + 1);
        int lenBytes = lenResult[0];
        int contentLen = lenResult[1];
        int valueStart = offset + 1 + lenBytes;
        int valueEnd = valueStart + contentLen;
        if (valueEnd > der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        return new int[]{valueStart, valueEnd};
    }

    /**
     * Парсит DER-длину (Length) в формате BER/DER.
     *
     * @param der    DER-поток
     * @param offset смещение на первый байт Length
     * @return int[2] {bytesUsedForLength, contentLength}
     */
    public static int[] parseLength(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int first = der[offset] & 0xFF;
        if (first < 0x80) {
            return new int[]{1, first};
        }
        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 3) {
            throw new IllegalArgumentException("Unsupported DER length encoding at offset " + offset);
        }
        if (offset + numBytes >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int len = 0;
        for (int i = 1; i <= numBytes; i++) {
            len = (len << 8) | (der[offset + i] & 0xFF);
        }
        return new int[]{1 + numBytes, len};
    }

    /**
     * Сравнивает два диапазона byte[] без копирования.
     *
     * @param a    первый массив
     * @param aOff смещение в первом массиве
     * @param aLen длина в первом массиве
     * @param b    второй массив
     * @param bOff смещение во втором массиве
     * @param bLen длина во втором массиве
     * @return true если диапазоны равны
     */
    public static boolean arrayRangeEquals(byte[] a, int aOff, int aLen,
                                            byte[] b, int bOff, int bLen) {
        if (aLen != bLen) return false;
        for (int i = 0; i < aLen; i++) {
            if (a[aOff + i] != b[bOff + i]) return false;
        }
        return true;
    }

    /**
     * Сравнивает байты DER-потока с эталонным OID.
     *
     * @param der      DER-поток
     * @param start    смещение на начало OID в DER
     * @param len      длина OID в DER
     * @param oidBytes эталонный OID
     * @return true если совпадает
     */
    public static boolean matchesOid(byte[] der, int start, int len, byte[] oidBytes) {
        return arrayRangeEquals(der, start, len, oidBytes, 0, oidBytes.length);
    }

    /**
     * Парсит Time (UTCTime или GeneralizedTime) из DER.
     *
     * @param der    DER-поток
     * @param offset смещение на tag времени
     * @return распарсенная дата
     */
    public static Date parseTime(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int tag = der[offset] & 0xFF;
        int[] lenRes = parseLength(der, offset + 1);
        int contentStart = offset + 1 + lenRes[0];
        String s = new String(der, contentStart, lenRes[1], java.nio.charset.StandardCharsets.US_ASCII);
        if (!s.endsWith("Z")) {
            throw new IllegalArgumentException("Only UTC (Z) timezone supported: " + s);
        }
        if (tag == TAG_UTC_TIME) {
            String raw = s.substring(0, s.length() - 1);
            int yy = Integer.parseInt(raw.substring(0, 2));
            int yyyy = yy < 50 ? 2000 + yy : 1900 + yy;
            return parseDateStr(yyyy + raw.substring(2), "yyyyMMddHHmmss");
        } else if (tag == TAG_GENERALIZED_TIME) {
            return parseDateStr(s.substring(0, s.length() - 1), "yyyyMMddHHmmss");
        }
        throw new IllegalArgumentException("Unknown time tag: 0x" + Integer.toHexString(tag));
    }

    /**
     * Парсит строку даты по SimpleDateFormat-паттерну (UTC).
     *
     * @param s       строка с датой (например "20240501120000Z")
     * @param pattern паттерн SimpleDateFormat (например "yyyyMMddHHmmss")
     * @return распарсенная дата
     */
    static Date parseDateStr(String s, String pattern) {
        try {
            SimpleDateFormat fmt = new SimpleDateFormat(pattern);
            fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
            return fmt.parse(s);
        } catch (java.text.ParseException e) {
            throw new IllegalArgumentException("Failed to parse date: " + s, e);
        }
    }
}
