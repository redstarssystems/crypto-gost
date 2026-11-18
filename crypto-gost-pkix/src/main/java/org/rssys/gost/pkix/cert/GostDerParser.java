package org.rssys.gost.pkix.cert;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.util.DerCodec;

/**
 * Утилиты парсинга DER (ASN.1) для X.509 сертификатов и OCSP-ответов.
 *
 * <p>Содержит низкоуровневые TLV-парсеры, константы тегов, OID и вспомогательные
 * методы для разбора DER-структур. Вынесен из {@link GostCertificate} для
 * разделения ответственности.</p>
 */
public final class GostDerParser {

    // Константы ASN.1 тегов DER (общие теги — forwarding на DerCodec)
    public static final int TAG_BOOLEAN = DerCodec.TAG_BOOLEAN;
    public static final int TAG_INTEGER = DerCodec.TAG_INTEGER;
    public static final int TAG_BIT_STRING = DerCodec.TAG_BIT_STRING;
    public static final int TAG_OCTET_STRING = DerCodec.TAG_OCTET_STRING;
    public static final int TAG_OID = DerCodec.TAG_OID;
    public static final int TAG_ENUMERATED = DerCodec.TAG_ENUMERATED;
    public static final int TAG_UTC_TIME = DerCodec.TAG_UTC_TIME;
    public static final int TAG_GENERALIZED_TIME = DerCodec.TAG_GENERALIZED_TIME;

    // Разбор ASN.1-времени (RFC 5280 §4.1.2.5)
    private static final int UTC_TIME_DIGITS = 12;
    private static final int GENERALIZED_TIME_DIGITS = 14;

    /** UTCTime: годы 00..49 - 2000..2049, 50..99 - 1950..1999. */
    private static final int UTC_TIME_PIVOT_YEAR = 50;

    private static final int MAX_HOUR = 23;
    private static final int MAX_MINUTE = 59;
    private static final int MAX_SECOND = 59;
    private static final long SECONDS_PER_MINUTE = 60L;
    private static final long SECONDS_PER_HOUR = 3600L;
    private static final long SECONDS_PER_DAY = 86400L;
    private static final int MAX_TIME_TEXT = 32;
    private static final int[] DAYS_IN_MONTH = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    /** Суток от 0000-03-01 до 1970-01-01 (опора алгоритма «дни от гражданской даты»). */
    private static final long DAYS_FROM_0000_03_01_TO_EPOCH = 719468L;

    public static final int TAG_SEQUENCE = DerCodec.TAG_SEQUENCE;
    public static final int TAG_SET = DerCodec.TAG_SET;
    // Контекстно-зависимые теги X.509 структур — не DER-примитивы, держим локально
    public static final int TAG_CTX_0 = DerCodec.TAG_CTX_BASE;

    /** Кодировка DER для BOOLEAN FALSE (X.690 §11.1). */
    public static final int DER_BOOLEAN_FALSE = 0x00;

    /** Кодировка DER для BOOLEAN TRUE (X.690 §11.1). */
    public static final int DER_BOOLEAN_TRUE = 0xFF;

    /** Старший бит октета INTEGER: знак (X.690 §8.3.3). */
    private static final int DER_INTEGER_SIGN_BIT = 0x80;

    /** Наибольшая длина INTEGER, которую читает {@link #readStrictNonNegativeInt}. */
    private static final int MAX_STRICT_INT_OCTETS = 4;

    /** Индекс использованных байт в результате {@link #parseLength}. */
    public static final int LEN_BYTES_USED = 0;

    /** Индекс длины содержимого в результате {@link #parseLength}. */
    public static final int LEN_CONTENT = 1;

    public static final int TAG_CTX_1 = 0xA1;
    public static final int TAG_CTX_2 = 0xA2;
    public static final int TAG_CTX_3 = 0xA3;

    /**
     * issuerUniqueID [1] и subjectUniqueID [2] в TBSCertificate: IMPLICIT BIT STRING, то есть
     * примитивные теги (RFC 5280 §4.1.2.8). Не путать с {@link #TAG_CTX_1}/{@link #TAG_CTX_2}:
     * те — constructed-теги, нужные другим структурам (например, NameConstraints).
     */
    public static final int TAG_ISSUER_UNIQUE_ID = 0x81;

    public static final int TAG_SUBJECT_UNIQUE_ID = 0x82;
    public static final int TAG_DNS_NAME = 0x82;
    public static final int TAG_IP_ADDRESS = 0x87;
    // GeneralName: rfc822Name [1] -- не поддерживается в Name Constraints, reject
    public static final int TAG_RFC822_NAME = 0x81;
    // GeneralName: directoryName [4] EXPLICIT -- не поддерживается в Name Constraints, reject
    public static final int TAG_DIRECTORY_NAME = 0xA4;
    // GeneralName: uniformResourceIdentifier [6] -- не поддерживается в Name Constraints, reject
    public static final int TAG_URI = 0x86;

    // OID: SubjectAltName 2.5.29.17
    static final byte[] SAN_OID_BYTES = {0x55, 0x1D, 0x11};
    // OID: IssuerAltName 2.5.29.18
    static final byte[] IAN_OID_BYTES = {0x55, 0x1D, 0x12};
    // OID: KeyUsage 2.5.29.15
    static final byte[] KU_OID_BYTES = {0x55, 0x1D, 0x0F};
    // Key Usage bit masks (RFC 5280 §4.2.1.3) — единственное место, где заданы значения;
    // enum GostCertificateBuilder.KeyUsage ссылается на них.
    // decipherOnly (бит 8, 0x8000) не регистрируется: keyUsageFlags() кодирует маску
    // в один байт, и этот бит там потерялся бы.
    public static final int KU_DIGITAL_SIGNATURE = 0x80;
    public static final int KU_NON_REPUDIATION = 0x40;
    public static final int KU_KEY_ENCIPHERMENT = 0x20;
    public static final int KU_DATA_ENCIPHERMENT = 0x10;
    public static final int KU_KEY_AGREEMENT = 0x08;
    public static final int KU_KEY_CERT_SIGN = 0x04;
    public static final int KU_CRL_SIGN = 0x02;
    public static final int KU_ENCIPHER_ONLY = 0x01;
    // OID: ExtendedKeyUsage 2.5.29.37
    static final byte[] EKU_OID_BYTES = {0x55, 0x1D, 0x25};
    // OID: BasicConstraints 2.5.29.19
    static final byte[] BC_OID_BYTES = {0x55, 0x1D, 0x13};
    // OID: id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
    static final byte[] OCSP_BASIC_OID_BYTES = {
        0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
    };

    // OID: SubjectKeyIdentifier 2.5.29.14
    static final byte[] SKI_OID_BYTES = {0x55, 0x1D, 0x0E};
    // OID: AuthorityKeyIdentifier 2.5.29.35
    static final byte[] AKI_OID_BYTES = {0x55, 0x1D, 0x23};
    // OID: AuthorityInfoAccess 1.3.6.1.5.5.7.1.1
    static final byte[] AIA_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};

    // OID access method: id-ad-ocsp 1.3.6.1.5.5.7.48.1
    static final byte[] AD_OCSP_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};
    // OID access method: id-ad-caIssuers 1.3.6.1.5.5.7.48.2
    static final byte[] AD_CA_ISSUERS_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};

    // OID: cRLNumber 2.5.29.20
    static final byte[] CRL_NUMBER_OID_BYTES = {0x55, 0x1D, 0x14};
    // OID: cRLReason 2.5.29.21
    static final byte[] CRL_REASON_OID_BYTES = {0x55, 0x1D, 0x15};
    // OID: DeltaCRLIndicator 2.5.29.27
    static final byte[] DELTA_CRL_INDICATOR_OID_BYTES = {0x55, 0x1D, 0x1B};
    // OID: IssuingDistributionPoint 2.5.29.28
    static final byte[] IDP_OID_BYTES = {0x55, 0x1D, 0x1C};

    /** certificateIssuer (2.5.29.29): расширение записи indirect CRL (RFC 5280 §5.3.3). */
    static final byte[] CERTIFICATE_ISSUER_OID_BYTES = {0x55, 0x1D, 0x1D};

    // OID: CRLDistributionPoints 2.5.29.31
    static final byte[] CDP_OID_BYTES = {0x55, 0x1D, 0x1F};
    // OID: FreshestCRL 2.5.29.46
    static final byte[] FRESHEST_CRL_OID_BYTES = {0x55, 0x1D, 0x2E};
    // OID: CertificatePolicies 2.5.29.32
    static final byte[] CP_OID_BYTES = {0x55, 0x1D, 0x20};
    // OID: NameConstraints 2.5.29.30
    static final byte[] NC_OID_BYTES = {0x55, 0x1D, 0x1E};

    // ========================================================================
    // OID Extended Key Usage (RFC 5280 §4.2.1.12)
    // ========================================================================

    // OID: id-kp-serverAuth 1.3.6.1.5.5.7.3.1
    static final byte[] SERVER_AUTH_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    // OID: id-kp-clientAuth 1.3.6.1.5.5.7.3.2
    static final byte[] CLIENT_AUTH_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};
    // OID: id-kp-OCSPSigning 1.3.6.1.5.5.7.3.9
    static final byte[] OCSP_SIGNING_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09};
    // OID: id-kp-timeStamping 1.3.6.1.5.5.7.3.8
    static final byte[] TIME_STAMPING_OID_BYTES = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08};
    // OID: anyExtendedKeyUsage 2.5.29.37.0
    static final byte[] ANY_EKU_OID_BYTES = {0x55, 0x1D, 0x25, 0x00};

    // ========================================================================
    // OID классов криптосредств ГОСТ (RFC 9215 §5.2, Приказ ФСБ №795 п.28)
    // Размещаются в CertificatePolicies (2.5.29.32), НЕ в ExtendedKeyUsage.
    // KC1-KC3 — классы криптосредств для формирования подписи (KC=Key class),
    // KB1-KB2 — классы для ведения ключей, KA1 — класс для согласования ключей.
    // ========================================================================

    /** 1.2.643.100.113.1 — id-class-kc1 (RFC 9215 §5.2) */
    static final byte[] KC1_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x71, 0x01};

    /** 1.2.643.100.113.2 — id-class-kc2 (RFC 9215 §5.2) */
    static final byte[] KC2_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x71, 0x02};

    // ========================================================================
    // OID Distinguished Name атрибутов (RFC 4519, ГОСТ Р 34.10)
    // ========================================================================

    // OID: id-at-commonName 2.5.4.3
    static final byte[] CN_OID_BYTES = {0x55, 0x04, 0x03};
    // OID: id-at-countryName 2.5.4.6
    static final byte[] C_OID_BYTES = {0x55, 0x04, 0x06};
    // OID: id-at-localityName 2.5.4.7
    static final byte[] L_OID_BYTES = {0x55, 0x04, 0x07};
    // OID: id-at-stateOrProvinceName 2.5.4.8
    static final byte[] ST_OID_BYTES = {0x55, 0x04, 0x08};
    // OID: id-at-streetAddress 2.5.4.9
    static final byte[] STREET_OID_BYTES = {0x55, 0x04, 0x09};
    // OID: id-at-organizationName 2.5.4.10
    static final byte[] O_OID_BYTES = {0x55, 0x04, 0x0A};
    // OID: id-at-organizationalUnitName 2.5.4.11
    static final byte[] OU_OID_BYTES = {0x55, 0x04, 0x0B};
    // OID: id-at-title 2.5.4.12
    static final byte[] T_OID_BYTES = {0x55, 0x04, 0x0C};
    // OID: id-at-serialNumber 2.5.4.5
    static final byte[] SERIALNUM_OID_BYTES = {0x55, 0x04, 0x05};
    // OID: id-at-surname 2.5.4.4
    static final byte[] SN_OID_BYTES = {0x55, 0x04, 0x04};
    // OID: id-at-givenName 2.5.4.42
    static final byte[] GN_OID_BYTES = {0x55, 0x04, 0x2A};
    // OID: id-at-postalCode 2.5.4.17
    static final byte[] POSTAL_CODE_OID_BYTES = {0x55, 0x04, 0x11};
    // OID: id-at-uniqueIdentifier 2.5.4.45
    static final byte[] UNIQUE_ID_OID_BYTES = {0x55, 0x04, 0x2D};
    // OID: id-at-pseudonym 2.5.4.65
    static final byte[] PSEUDONYM_OID_BYTES = {0x55, 0x04, 0x41};
    // OID: emailAddress 1.2.840.113549.1.9.1
    static final byte[] EMAIL_OID_BYTES = {
        (byte) 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x01
    };
    // OID: uid 0.9.2342.19200300.100.1.1
    static final byte[] UID_OID_BYTES = {
        0x09, (byte) 0x92, 0x26, (byte) 0x89, (byte) 0x93, (byte) 0xF2, 0x2C, 0x64, 0x01, 0x01
    };
    // OID: INN 1.2.643.3.131.1.1 (RFC 9215 §5.1)
    static final byte[] INN_OID_BYTES = {
        0x2A, (byte) 0x85, 0x03, 0x03, (byte) 0x81, 0x03, 0x01, 0x01
    };
    // OID: ОГРНИП 1.2.643.100.5 (RFC 9215 §5.1)
    static final byte[] OGRNIP_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x05};
    // OID: ОГРН 1.2.643.100.1 (RFC 9215 §5.1)
    static final byte[] OGRN_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x01};
    // OID: СНИЛС 1.2.643.100.3 (RFC 9215 §5.1)
    static final byte[] SNILS_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x03};
    // OID: INNLE 1.2.643.100.4 (RFC 9215 §5.1)
    static final byte[] INNLE_OID_BYTES = {0x2A, (byte) 0x85, 0x03, 0x64, 0x04};
    // OID: organizationIdentifier 2.5.4.97
    static final byte[] ORG_ID_OID_BYTES = {0x55, 0x04, 0x61};

    // ========================================================================
    // OID PKCS#9 (RFC 2985)
    // ========================================================================

    // OID: extensionRequest 1.2.840.113549.1.9.14
    static final byte[] EXTENSION_REQUEST_OID_BYTES = {
        (byte) 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x0E
    };

    // OID: challengePassword 1.2.840.113549.1.9.7
    static final byte[] CHALLENGE_PASSWORD_OID_BYTES = {
        (byte) 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x09, 0x07
    };

    // ========================================================================
    // Строковые типы ASN.1 (X.680) и алфавит PrintableString
    // ========================================================================

    static final int TAG_T61_STRING = 0x14;
    static final int TAG_UNIVERSAL_STRING = 0x1C;
    static final int TAG_BMP_STRING = 0x1E;

    /** Допустимый алфавит PrintableString по X.680 §41. */
    private static final String PRINTABLE_STRING_CHARS =
            " '()+,-./:=?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /** @return true, если code point входит в алфавит PrintableString */
    static boolean isPrintableStringChar(int codePoint) {
        return PRINTABLE_STRING_CHARS.indexOf(codePoint) >= 0;
    }

    /**
     * Проверяет, что строка целиком состоит из знаков алфавита PrintableString.
     *
     * @throws IllegalArgumentException если встретился знак вне алфавита
     */
    static void requirePrintableString(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isPrintableStringChar(value.charAt(i))) {
                throw new IllegalArgumentException(
                        "PrintableString contains a character outside its alphabet");
            }
        }
    }

    // ========================================================================
    // OID OCSP (RFC 6960)
    // ========================================================================

    // OID: id-tc26-gost-3411-12-256 (Streebog-256) 1.2.643.7.1.1.2.2
    static final byte[] STREEBOG256_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02
    };
    // OID: id-tc26-gost-3411-12-512 (Streebog-512) 1.2.643.7.1.1.2.3
    static final byte[] STREEBOG512_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03
    };

    // ========================================================================
    // OID сигнатурных алгоритмов ГОСТ Р 34.10-2012 (whitelist для verifySignature)
    // ========================================================================

    // OID: 1.2.643.7.1.1.1.1 (ГОСТ Р 34.10-2012, 256 бит)
    static final byte[] GOST_SIGN_256_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01
    };
    // OID: 1.2.643.7.1.1.1.2 (ГОСТ Р 34.10-2012, 512 бит)
    static final byte[] GOST_SIGN_512_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02
    };
    // OID: 1.2.643.7.1.1.3.2 (ГОСТ Р 34.10-2012 + Стрибог-256)
    static final byte[] GOST_SIGN_DIGEST_256_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02
    };
    // OID: 1.2.643.7.1.1.3.3 (ГОСТ Р 34.10-2012 + Стрибог-512)
    static final byte[] GOST_SIGN_DIGEST_512_OID_BYTES = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03
    };
    // OID: id-pkix-ocsp-nonce 1.3.6.1.5.5.7.48.1.2
    static final byte[] OCSP_NONCE_OID_BYTES = {
        (byte) 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
    };

    /**
     * Максимальное количество base-128 байт одного subidentifier OID.
     * Потолок для 63-битного long: 9 байт × 7 бит = 63 бита.
     * Превышение — некорректный (malformed) OID, fail-closed.
     */
    private static final int MAX_OID_SUBIDENTIFIER_BYTES = 9;

    /**
     * Максимальное общее число арок в одном OID.
     * {@link #MAX_OID_SUBIDENTIFIER_BYTES} ограничивает размер каждой отдельной арки,
     * но не их количество: OID из тысяч однобайтовых арок распарсился бы легитимно
     * и раздул бы StringBuilder пропорционально числу арок (defense-in-depth против
     * амплификации в пределах MAX_CERT_SIZE). Реальные OID редко превышают 10-15 арок;
     * 128 даёт запас на порядок. Первый суб-идентификатор даёт две арки, поэтому предел
     * достигается на 127 суб-идентификаторах. Превышение — malformed OID, fail-closed.
     */
    private static final int MAX_OID_ARCS = 128;

    private GostDerParser() {}

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
     * Пропускает необязательное поле {@code version [0] EXPLICIT Version DEFAULT v1} структур
     * OCSP ({@code TBSRequest} и {@code ResponseData}), проверяя, что версия — v1.
     *
     * <p>По RFC 6960 §4.1.1 и §4.2.2.3 допустима только версия v1 (значение 0), поэтому поле либо
     * отсутствует, либо содержит ровно один {@code INTEGER} длиной 1 байт со значением 0 и ничего
     * больше. Явная версия 0 нарушает правило DER про значения по умолчанию, но присутствует в
     * примерах Р 1323565.1.059-2024 (В.2 и В.3), поэтому принимается. Содержимое {@code [0]}
     * должно быть израсходовано целиком: иначе лишний элемент после версии остался бы
     * незамеченным.</p>
     *
     * @param der DER-поток
     * @param pos смещение на возможное поле версии
     * @param end смещение за концом охватывающей структуры
     * @return смещение за полем версии (или {@code pos}, если версии нет)
     * @throws PkixException если версия не v1 или поле устроено неверно
     * @throws IllegalArgumentException если TLV выходит за {@code end}
     */
    static int skipOcspVersionV1(byte[] der, int pos, int end) throws PkixException {
        if (pos >= end || (der[pos] & 0xFF) != TAG_CTX_0) {
            return pos;
        }
        int[] versionField = readTlv(der, pos, end);
        int valueStart = versionField[0];
        int valueEnd = versionField[1];
        if (valueStart >= valueEnd || (der[valueStart] & 0xFF) != TAG_INTEGER) {
            throw new PkixException("OCSP: version must be an INTEGER");
        }
        int[] integer = readTlv(der, valueStart, valueEnd);
        if (integer[1] != valueEnd) {
            throw new PkixException("OCSP: unexpected data after version INTEGER");
        }
        if (integer[1] - integer[0] != 1 || der[integer[0]] != 0) {
            throw new PkixException("OCSP: unsupported version, only v1 (0) is allowed");
        }
        return valueEnd;
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
        return readTlv(der, offset, der.length);
    }

    /**
     * Читает TLV, требуя, чтобы он целиком лежал в {@code [offset, limit)}.
     *
     * <p>Предел нужен вложенным разборщикам: проверки только по {@code der.length}
     * позволяют дочерней структуре «съесть» байты за границей родителя, включая
     * неподписанные поля сертификата.</p>
     *
     * @param der    DER-поток
     * @param offset смещение на tag текущего TLV
     * @param limit  смещение за последним допустимым байтом (не больше {@code der.length})
     * @return int[2] {valueStart, valueEnd}
     * @throws IllegalArgumentException если TLV выходит за {@code limit}
     */
    public static int[] readTlv(byte[] der, int offset, int limit) {
        if (limit > der.length || limit < 0) {
            throw new IllegalArgumentException("DER limit out of range: " + limit);
        }
        if (offset < 0 || offset >= limit) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int[] lenResult = parseLength(der, offset + 1);
        int valueStart = offset + 1 + lenResult[LEN_BYTES_USED];
        int contentLen = lenResult[LEN_CONTENT];
        if (contentLen < 0) {
            throw new IllegalArgumentException(
                    "DER length overflow (negative) at offset " + offset);
        }
        int valueEnd = valueStart + contentLen;
        if (valueStart > limit || valueEnd < valueStart || valueEnd > limit) {
            throw new IllegalArgumentException(
                    "DER length exceeds available data at offset " + offset);
        }
        return new int[] {valueStart, valueEnd};
    }

    /**
     * Читает DER BOOLEAN (X.690 §11.1): ровно один октет 0x00 или 0xFF.
     *
     * <p>Нестрогое чтение «первый байт != 0» превращает пустое или усечённое значение
     * в FALSE, и неизвестное critical-расширение молча игнорируется.</p>
     *
     * @param der    DER-поток
     * @param offset смещение на tag BOOLEAN
     * @param limit  смещение за последним допустимым байтом
     * @return значение BOOLEAN
     * @throws IllegalArgumentException если тег не BOOLEAN, длина не 1 или значение не 0x00/0xFF
     */
    public static boolean readBoolean(byte[] der, int offset, int limit) {
        int[] tlv = readTlv(der, offset, limit);
        if ((der[offset] & 0xFF) != TAG_BOOLEAN) {
            throw new IllegalArgumentException("Expected BOOLEAN at offset " + offset);
        }
        if (tlv[1] - tlv[0] != 1) {
            throw new IllegalArgumentException("Invalid BOOLEAN length at offset " + offset);
        }
        int value = der[tlv[0]] & 0xFF;
        if (value == DER_BOOLEAN_TRUE) {
            return true;
        }
        if (value == DER_BOOLEAN_FALSE) {
            return false;
        }
        throw new IllegalArgumentException("Non-DER BOOLEAN value at offset " + offset);
    }

    /**
     * Проверяет, что constructed-элемент {@code [0]} не пуст: ни {@code A0 00}, ни {@code A0 80 00 00}.
     * Пустой {@code [0] EXPLICIT} не содержит значения, и сборка сегментов дала бы пустой результат,
     * неотличимый от пустого OCTET STRING.
     *
     * @param tlv элемент целиком
     * @return true если содержимого нет
     */
    public static boolean isEmptyConstructed(byte[] tlv) {
        int[] length = DerCodec.decodeLength(tlv, 1);
        int start = 1 + length[1];
        if (length[0] == 0) {
            return true;
        }
        // неопределённая длина: пусто, если сразу за заголовком маркер конца 00 00
        return length[0] < 0 && start + 1 < tlv.length && tlv[start] == 0 && tlv[start + 1] == 0;
    }

    /**
     * Снимает один TLV-слой: проверяет тег и что длина точно покрывает весь элемент.
     *
     * <p>Копирование диапазона по недостоверной длине молча дополнило бы результат нулями или дало
     * бы выход за границу массива, а не отказ; хвост за элементом означал бы неканоничное
     * кодирование. Неопределённая длина BER ({@code 0x80}) отвергается. Предназначен для полей,
     * где обёртка стоит в массиве целиком ({@code [0] EXPLICIT}, {@code OCTET STRING}).</p>
     *
     * @param tlv         элемент целиком: тег, длина, содержимое
     * @param expectedTag ожидаемый тег
     * @param what        имя поля для сообщения об ошибке
     * @return содержимое элемента
     * @throws IllegalArgumentException если тег иной, элемент усечён, длина не совпадает с
     *                                  размером или есть хвост
     */
    public static byte[] exactTlvContent(byte[] tlv, int expectedTag, String what) {
        if (tlv.length < 2 || (tlv[0] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(what + ": unexpected tag or truncated element");
        }
        int[] length = DerCodec.decodeLength(tlv, 1);
        int start = 1 + length[1];
        if (length[0] < 0 || (long) start + length[0] != tlv.length) {
            throw new IllegalArgumentException(what + ": length does not match element size");
        }
        return Arrays.copyOfRange(tlv, start, tlv.length);
    }

    /**
     * Читает DER INTEGER как неотрицательное {@code int} (X.690 §8.3, §11).
     *
     * <p>Для полей, где значение небольшое и по смыслу не отрицательное: {@code pathLenConstraint},
     * {@code version}. Отвергаются пустое значение, знак (старший бит первого октета), неминимальная
     * запись (лишний ведущий {@code 00}) и значение, не помещающееся в {@code int}. Нестрогое чтение
     * «как есть» превращает {@code 02 01 FF} (минус один) в 255 и ослабляет ограничение длины цепочки.</p>
     *
     * @param der    DER-поток
     * @param offset смещение на tag INTEGER
     * @param limit  смещение за последним допустимым байтом
     * @return {@code {значение, смещение за элементом}}
     * @throws IllegalArgumentException если элемент не INTEGER, пуст, отрицателен, записан неминимально
     *                                  или длиннее четырёх октетов
     */
    public static int[] readStrictNonNegativeInt(byte[] der, int offset, int limit) {
        int[] tlv = readTlv(der, offset, limit);
        if ((der[offset] & 0xFF) != TAG_INTEGER) {
            throw new IllegalArgumentException("Expected INTEGER at offset " + offset);
        }
        int length = tlv[1] - tlv[0];
        if (length == 0 || length > MAX_STRICT_INT_OCTETS) {
            throw new IllegalArgumentException(
                    "INTEGER has invalid length " + length + " at offset " + offset);
        }
        int first = der[tlv[0]] & 0xFF;
        if ((first & DER_INTEGER_SIGN_BIT) != 0) {
            throw new IllegalArgumentException("INTEGER is negative at offset " + offset);
        }
        // Ведущий 00 допустим только перед октетом со старшим битом (иначе значение
        // записано неминимально, X.690 §8.3.2); при длине до четырёх октетов и первом
        // октете без знакового бита значение всегда помещается в int
        if (length > 1 && first == 0 && (der[tlv[0] + 1] & DER_INTEGER_SIGN_BIT) == 0) {
            throw new IllegalArgumentException(
                    "INTEGER is not minimally encoded at offset " + offset);
        }
        int value = 0;
        for (int i = tlv[0]; i < tlv[1]; i++) {
            value = (value << Byte.SIZE) | (der[i] & 0xFF);
        }
        return new int[] {value, tlv[1]};
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
            return new int[] {1, first};
        }
        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 4) {
            throw new IllegalArgumentException(
                    "Unsupported DER length encoding at offset " + offset);
        }
        if (offset + numBytes >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int len = 0;
        for (int i = 1; i <= numBytes; i++) {
            len = (len << 8) | (der[offset + i] & 0xFF);
        }
        // Минимальность кодирования (X.690 §10.1): long-form не должен применяться
        // для значений, помещающихся в меньшее число байт (неканоническая malleability).
        // Минимально допустимое значение при numBytes: >= 0x80 для 1 байта,
        // >= 0x100 для 2 байт и т.д. Проверяем через минимальную границу.
        int minAllowed = (numBytes == 1) ? 0x80 : (1 << (8 * (numBytes - 1)));
        if (len < minAllowed) {
            throw new IllegalArgumentException(
                    "Non-minimal DER length encoding at offset " + offset);
        }
        return new int[] {1 + numBytes, len};
    }

    /**
     * Сравнивает два диапазона byte[] без копирования.
     *
     * <p>Намеренно НЕ constant-time: используется для сравнения публичных данных
     * (Subject/Issuer DN, OID алгоритма подписи), где временного оракула на секрет нет.
     * Сравнение секретов и хэшей выполняется через {@code MessageDigest.isEqual}.</p>
     *
     * @param a    первый массив
     * @param aOff смещение в первом массиве
     * @param aLen длина в первом массиве
     * @param b    второй массив
     * @param bOff смещение во втором массиве
     * @param bLen длина во втором массиве
     * @return true если диапазоны равны
     */
    public static boolean arrayRangeEquals(
            byte[] a, int aOff, int aLen, byte[] b, int bOff, int bLen) {
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
     * @return распарсенная дата как Instant (UTC)
     */
    public static Instant parseTime(byte[] der, int offset) {
        if (offset >= der.length) {
            throw new IllegalArgumentException("Truncated DER encoding at offset " + offset);
        }
        int tag = der[offset] & 0xFF;
        int[] lenRes = parseLength(der, offset + 1);
        int contentStart = offset + 1 + lenRes[LEN_BYTES_USED];
        int contentLen = lenRes[LEN_CONTENT];
        int contentEnd = contentStart + contentLen;
        if (contentLen < 0 || contentEnd < contentStart || contentEnd > der.length) {
            throw new IllegalArgumentException(
                    "Truncated DER: time content length exceeds available data at offset "
                            + offset);
        }
        if (tag != TAG_UTC_TIME && tag != TAG_GENERALIZED_TIME) {
            throw new IllegalArgumentException("Unknown time tag: 0x" + Integer.toHexString(tag));
        }
        return Instant.ofEpochSecond(
                parseTimeSeconds(der, contentStart, contentLen, tag == TAG_GENERALIZED_TIME));
    }

    /**
     * Строго разбирает содержимое UTCTime или GeneralizedTime (RFC 5280 §4.1.2.5) в секунды Unix
     * epoch.
     *
     * <p>Формат ровно {@code YYMMDDHHMMSSZ} (UTCTime) или {@code YYYYMMDDHHMMSSZ}
     * (GeneralizedTime): только цифры ASCII, без дробных секунд и смещений. Недействительная
     * дата (30 февраля, 29 февраля невисокосного года, час 24, секунда 60, нулевой день)
     * отвергается, а не нормализуется: срок и время обновления не должны превращаться в другую
     * дату. Разбор не выделяет память (ни строки, ни форматтера): он стоит на каждой записи
     * отозванных сертификатов.</p>
     *
     * @param der         буфер с содержимым времени
     * @param start       смещение первой цифры
     * @param len         длина содержимого
     * @param generalized true - GeneralizedTime (год из четырёх цифр), false - UTCTime
     * @return секунды от 1970-01-01T00:00:00Z
     * @throws IllegalArgumentException при неверной длине, нецифре, отсутствии {@code Z} или
     *                                  несуществующей дате
     */
    static long parseTimeSeconds(byte[] der, int start, int len, boolean generalized) {
        if (start < 0 || len < 0 || start > der.length - len) {
            throw new IllegalArgumentException("Time content is out of buffer bounds");
        }
        int digitCount = generalized ? GENERALIZED_TIME_DIGITS : UTC_TIME_DIGITS;
        if (len != digitCount + 1) {
            throw new IllegalArgumentException(
                    (generalized ? "GeneralizedTime" : "UTCTime")
                            + " must be "
                            + (digitCount + 1)
                            + " chars, got "
                            + len
                            + ": "
                            + timeText(der, start, len));
        }
        if (der[start + digitCount] != 'Z') {
            throw new IllegalArgumentException(
                    "Only UTC (Z) timezone supported: " + timeText(der, start, len));
        }
        int pos = start;
        int year;
        if (generalized) {
            year =
                    timeDigits(der, pos, 2, start, len) * 100
                            + timeDigits(der, pos + 2, 2, start, len);
            pos += 4;
        } else {
            int shortYear = timeDigits(der, pos, 2, start, len);
            year = shortYear < UTC_TIME_PIVOT_YEAR ? 2000 + shortYear : 1900 + shortYear;
            pos += 2;
        }
        int month = timeDigits(der, pos, 2, start, len);
        int day = timeDigits(der, pos + 2, 2, start, len);
        int hour = timeDigits(der, pos + 4, 2, start, len);
        int minute = timeDigits(der, pos + 6, 2, start, len);
        int second = timeDigits(der, pos + 8, 2, start, len);
        if (year < 1
                || month < 1
                || month > 12
                || day < 1
                || day > daysInMonth(year, month)
                || hour > MAX_HOUR
                || minute > MAX_MINUTE
                || second > MAX_SECOND) {
            throw new IllegalArgumentException(
                    "Invalid date or time value: " + timeText(der, start, len));
        }
        return daysFromCivil(year, month, day) * SECONDS_PER_DAY
                + hour * SECONDS_PER_HOUR
                + minute * SECONDS_PER_MINUTE
                + second;
    }

    /**
     * Возвращает время в виде строки GeneralizedTime {@code YYYYMMDDHHMMSSZ}.
     *
     * <p>Предусловие: содержимое уже проверено {@link #parseTimeSeconds}. Для UTCTime век
     * достраивается по правилу RFC 5280 (00..49 - 20xx, 50..99 - 19xx).</p>
     */
    static String generalizedTimeString(byte[] der, int start, boolean generalized) {
        byte[] out = new byte[GENERALIZED_TIME_DIGITS + 1];
        int outPos = 0;
        int digits = GENERALIZED_TIME_DIGITS;
        if (!generalized) {
            int shortYear = (der[start] - '0') * 10 + (der[start + 1] - '0');
            out[0] = shortYear < UTC_TIME_PIVOT_YEAR ? (byte) '2' : (byte) '1';
            out[1] = shortYear < UTC_TIME_PIVOT_YEAR ? (byte) '0' : (byte) '9';
            outPos = 2;
            digits = UTC_TIME_DIGITS;
        }
        System.arraycopy(der, start, out, outPos, digits);
        out[GENERALIZED_TIME_DIGITS] = 'Z';
        return new String(out, java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static int timeDigits(byte[] der, int pos, int count, int start, int len) {
        int value = 0;
        for (int i = 0; i < count; i++) {
            int digit = der[pos + i] - '0';
            if (digit < 0 || digit > 9) {
                throw new IllegalArgumentException(
                        "Non-digit character in time: " + timeText(der, start, len));
            }
            value = value * 10 + digit;
        }
        return value;
    }

    private static int daysInMonth(int year, int month) {
        if (month == 2 && isLeapYear(year)) {
            return 29;
        }
        return DAYS_IN_MONTH[month - 1];
    }

    private static boolean isLeapYear(int year) {
        return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    }

    /** Число суток от 1970-01-01 до даты (григорианский календарь, год не меньше 1). */
    private static long daysFromCivil(int year, int month, int day) {
        int shiftedYear = month <= 2 ? year - 1 : year;
        int era = shiftedYear / 400;
        int yearOfEra = shiftedYear - era * 400;
        int dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
        int dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
        return era * 146097L + dayOfEra - DAYS_FROM_0000_03_01_TO_EPOCH;
    }

    /**
     * Текст времени для сообщения об ошибке: длина ограничена, управляющие символы и байты вне
     * ASCII заменяются на {@code ?}, чтобы недоверенные данные не попали в сообщение как есть.
     */
    private static String timeText(byte[] der, int start, int len) {
        int shown = Math.min(len, MAX_TIME_TEXT);
        char[] text = new char[shown];
        for (int i = 0; i < shown; i++) {
            int b = der[start + i] & 0xFF;
            text[i] = b >= ' ' && b < 0x7F ? (char) b : '?';
        }
        return new String(text);
    }

    /**
     * Преобразует DER-закодированный OID в точечную нотацию.
     *
     * <p>Схема: первые два компонента (arc1, arc2) кодируются одним байтом
     * как 40*arc1 + arc2. Остальные — base-128 variable-length encoding
     * с битом продолжения (MSB=1).</p>
     *
     * @param der   DER-поток
     * @param start смещение на начало OID
     * @param len   длина OID в байтах (не меньше 1: однобайтовый OID, например {@code 1.2},
     *              допустим по X.690)
     * @return OID в точечной нотации (например {@code "1.2.643.7.1.1.2.2"})
     * @throws NullPointerException     если {@code der} равен null
     * @throws IllegalArgumentException если диапазон выходит за массив, OID закодирован
     *                                  не в минимальной форме, оборван или превышает лимиты
     */
    public static String oidBytesToDottedString(byte[] der, int start, int len) {
        Objects.requireNonNull(der, "der");
        // Сравнение через вычитание: start + len переполнило бы int и пропустило
        // выход за границы массива.
        if (start < 0 || len < 1 || len > der.length - start) {
            throw new IllegalArgumentException(
                    "OID range is invalid: start=" + start + ", len=" + len);
        }
        StringBuilder sb = new StringBuilder();
        int pos = start;
        int end = start + len;
        // Первый subidentifier кодирует две первые арки (40*arc1 + arc2).
        // Он тоже может быть multi-byte, поэтому разбирается общим циклом.
        int arcCount = 0;
        boolean firstSubId = true;
        while (pos < end) {
            arcCount += firstSubId ? 2 : 1;
            if (arcCount > MAX_OID_ARCS) {
                throw new IllegalArgumentException("OID arc count exceeds " + MAX_OID_ARCS);
            }
            long val = 0;
            int subIdBytes = 0;
            boolean lastHadContinuation = false;
            while (pos < end) {
                int b = der[pos++] & 0xFF;
                // Ведущий 0x80 означает нулевые старшие группы: значение можно
                // закодировать короче. DER требует минимальную форму, иначе два
                // разных DER дают один OID и сравнение NameConstraints обходится.
                if (subIdBytes == 0 && b == 0x80) {
                    throw new IllegalArgumentException(
                            "OID subidentifier is not minimally encoded");
                }
                val = (val << 7) | (b & 0x7F);
                subIdBytes++;
                lastHadContinuation = (b & 0x80) != 0;
                if (subIdBytes > MAX_OID_SUBIDENTIFIER_BYTES) {
                    throw new IllegalArgumentException(
                            "OID subidentifier exceeds " + MAX_OID_SUBIDENTIFIER_BYTES + " bytes");
                }
                if (!lastHadContinuation) break;
            }
            if (lastHadContinuation) {
                throw new IllegalArgumentException("OID ends with continuation bit set");
            }
            if (firstSubId) {
                if (val < 40) {
                    sb.append("0.").append(val);
                } else if (val < 80) {
                    sb.append("1.").append(val - 40);
                } else {
                    sb.append("2.").append(val - 80);
                }
                firstSubId = false;
            } else {
                sb.append('.').append(val);
            }
        }
        return sb.toString();
    }
}
