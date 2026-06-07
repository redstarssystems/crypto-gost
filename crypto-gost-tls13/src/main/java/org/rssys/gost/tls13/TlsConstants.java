package org.rssys.gost.tls13;

/**
 * Константы протокола TLS 1.3 (RFC 8446) для ГОСТ-криптографии
 * по RFC 9367 (TLS 1.3 GOST Cipher Suites).
 * Содержит типы записей, handshake-сообщений, cipher suite ID,
 * схемы подписи, именованные группы, метки KDF и контекстные строки.
 */
public final class TlsConstants {

    // типы содержимого TLS-записей (RFC 8446 раздел 5)
    public static final byte CT_ALERT = 21;
    public static final byte CT_HANDSHAKE = 22;
    public static final byte CT_APPLICATION_DATA = 23;
    public static final byte CT_CHANGE_CIPHER_SPEC = 20;

    // типы handshake-сообщений (RFC 8446 раздел 4)
    public static final byte HT_CLIENT_HELLO = 1;
    public static final byte HT_SERVER_HELLO = 2;
    public static final byte HT_ENCRYPTED_EXTENSIONS = 8;
    public static final byte HT_CERTIFICATE = 11;
    public static final byte HT_CERTIFICATE_VERIFY = 15;
    public static final byte HT_CERTIFICATE_REQUEST = 13;
    public static final byte HT_NEW_SESSION_TICKET = 4;
    public static final byte HT_FINISHED = 20;
    public static final byte HT_KEY_UPDATE = 24;

    // версии протокола
    public static final int PROTOCOL_TLS_1_2 = 0x0303;
    public static final int PROTOCOL_TLS_1_3 = 0x0304;
    public static final byte LEGACY_VERSION_MAJOR = 0x03;
    public static final byte LEGACY_VERSION_MINOR = 0x03;

    // ГОСТ cipher suites (RFC 9367 §3.1.2)
    public static final int TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L = 0xC103; // Loop ре-кейинг
    public static final int TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S = 0xC105; // Seal (TLSTREE, SNMAX=2^42-1)

    // IANA-имена cipher suites (RFC 9367 §3.1.2)
    public static final String IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L =
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    public static final String IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S =
            "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";

    // схемы подписи ГОСТ (RFC 9367 §3.2 + RFC 8446)
    // 256-бит
    public static final int SIG_GOST_TC26_A_256    = 0x0709; // id_tc26_gost_3410_2012_256_paramSetA
    public static final int SIG_GOST_CRYPTOPRO_A   = 0x070A; // id_GostR3410_2001_CryptoPro_A_ParamSet
    public static final int SIG_GOST_CRYPTOPRO_B   = 0x070B; // id_GostR3410_2001_CryptoPro_B_ParamSet
    public static final int SIG_GOST_CRYPTOPRO_C   = 0x070C; // id_GostR3410_2001_CryptoPro_C_ParamSet
    // 512-бит
    public static final int SIG_GOST_TC26_512_A = 0x070D; // id_tc26_gost_3410_12_512_paramSetA
    public static final int SIG_GOST_TC26_512_B = 0x070E; // id_tc26_gost_3410_12_512_paramSetB
    public static final int SIG_GOST_TC26_512_C = 0x070F; // id_tc26_gost_3410_2012_512_paramSetC

    // IANA-имена схем подписи (RFC 9367 §3.2)
    public static final String IANA_SIG_GOST_TC26_A_256 = "gostr34102012_256a";
    public static final String IANA_SIG_GOST_CRYPTOPRO_A  = "gostr34102012_256b";
    public static final String IANA_SIG_GOST_CRYPTOPRO_B  = "gostr34102012_256c";
    public static final String IANA_SIG_GOST_CRYPTOPRO_C  = "gostr34102012_256d";
    public static final String IANA_SIG_GOST_TC26_512_A   = "gostr34102012_512a";
    public static final String IANA_SIG_GOST_TC26_512_B   = "gostr34102012_512b";
    public static final String IANA_SIG_GOST_TC26_512_C   = "gostr34102012_512c";

    // именованные группы/кривые ГОСТ (RFC 9367 §3.1)
    // 256-бит
    public static final int GRP_GC256A       = 0x0022; // id_tc26_gost_3410_2012_256_paramSetA
    public static final int GRP_GC256B       = 0x0023; // id_GostR3410_2001_CryptoPro_A_ParamSet
    public static final int GRP_GC256C       = 0x0024; // id_GostR3410_2001_CryptoPro_B_ParamSet
    public static final int GRP_GC256D       = 0x0025; // id_GostR3410_2001_CryptoPro_C_ParamSet
    // 512-бит
    public static final int GRP_GC512A       = 0x0026; // id_tc26_gost_3410_12_512_paramSetA
    public static final int GRP_GC512B       = 0x0027; // id_tc26_gost_3410_12_512_paramSetB
    public static final int GRP_GC512C       = 0x0028; // id_tc26_gost_3410_2012_512_paramSetC

    // IANA-имена именованных групп (RFC 9367 §3.1)
    public static final String IANA_GC256A = "GC256A";
    public static final String IANA_GC256B = "GC256B";
    public static final String IANA_GC256C = "GC256C";
    public static final String IANA_GC256D = "GC256D";
    public static final String IANA_GC512A = "GC512A";
    public static final String IANA_GC512B = "GC512B";
    public static final String IANA_GC512C = "GC512C";

    // размеры хешей Streebog
    public static final int STREEBOG_256_HASH_LEN = 32;
    public static final int STREEBOG_512_HASH_LEN = 64;

    // размер случайного поля в ClientHello/ServerHello (RFC 8446 §4.1.2)
    public static final int RANDOM_LENGTH = 32;

    // TLSInnerPlaintext.length ≤ 2^14 (RFC 8446 §5.2)
    // fragment(N) || inner_type(1) + padding
    public static final int MAX_PLAINTEXT_LENGTH = 16384;
    public static final int RECORD_HEADER_SIZE = 5;
    public static final int HANDSHAKE_HEADER_SIZE = 4;
    public static final int MGM_TAG_SIZE = 16;
    public static final int KUZNYECHIK_KEY_SIZE = 32;
    public static final int MGM_IV_SIZE = 16;
    public static final int MAX_CERT_CHAIN_LENGTH = 10;
    /** Максимальный размер одного сертификата в DER (256 КБ).
     *  Типичный ГОСТ-сертификат — 1–10 КБ, 256 КБ даёт 25x запас. */
    public static final int MAX_CERT_SIZE = 262_144;
    /** Максимум delegated OCSP-responder сертификатов в BasicOCSPResponse certs [0]
     *  (RFC 6960 §4.2.2.1). Практически всегда 0–1, 10 — щедрый запас. */
    public static final int MAX_DELEGATED_CERTS = 10;

    // максимальный размер ciphertext в TLS-записи (RFC 8446 §5.1)
    // 2^14 + 1 (inner_type) + 16 (max padding) + 16 (MGM tag) = 16401
    // округляем до 16640 для запаса на padding
    public static final int MAX_CIPHERTEXT_LENGTH = 16640;

    // метки уровней TLSTREE (RFC 9367 §4.2)
    public static final String LABEL_TLSTREE_LEVEL1 = "level1";
    public static final String LABEL_TLSTREE_LEVEL2 = "level2";
    public static final String LABEL_TLSTREE_LEVEL3 = "level3";

    // коды TLS-алертов (RFC 8446 раздел 6)
    public static final byte ALERT_WARNING = 1;
    public static final byte ALERT_FATAL = 2;
    public static final byte CLOSE_NOTIFY = 0;
    public static final byte ALERT_UNEXPECTED_MESSAGE = 10;
    public static final byte ALERT_BAD_CERTIFICATE = 42;
    public static final byte ALERT_HANDSHAKE_FAILURE = 40;
    public static final byte ALERT_ILLEGAL_PARAMETER = 47;
    public static final byte ALERT_UNKNOWN_CA = 48;
    public static final byte ALERT_DECODE_ERROR = 50;
    public static final byte ALERT_DECRYPT_ERROR = 51;
    public static final byte ALERT_MISSING_EXTENSION = 109;
    public static final byte ALERT_RECORD_OVERFLOW = 22;
    public static final byte ALERT_CERTIFICATE_EXPIRED = 45;
    public static final byte ALERT_CERTIFICATE_REVOKED = 44;
    public static final byte ALERT_CERTIFICATE_REQUIRED = 116;
    public static final byte ALERT_INTERNAL_ERROR = 80;

    // идентификаторы TLS-расширений (RFC 8446 раздел 4.2)
    public static final int EXT_SERVER_NAME = 0;
    public static final int EXT_SIGNATURE_ALGORITHMS = 13;
    public static final int EXT_SUPPORTED_GROUPS = 10;
    public static final int EXT_SUPPORTED_VERSIONS = 43;
    public static final int EXT_KEY_SHARE = 51;
    public static final int EXT_STATUS_REQUEST = 5;
    public static final int EXT_PRE_SHARED_KEY = 41;
    public static final int EXT_PSK_KEY_EXCHANGE_MODES = 45;
    public static final int EXT_CERTIFICATE_AUTHORITIES = 47;
    public static final int EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16; // RFC 7301
    public static final int EXT_COOKIE = 44;

    // коды алертов
    /** no_application_protocol (RFC 7301 §3.2): сервер не выбрал протокол ALPN */
    public static final byte ALERT_NO_APPLICATION_PROTOCOL = 120;

    // режимы PSK (RFC 8446 раздел 4.2.9)
    public static final byte PSK_DHE_KE = 1;

    // метки HKDF-Expand-Label (RFC 8446 раздел 7.1)
    public static final String LABEL_DERIVED = "derived";
    public static final String LABEL_SERVER_HANDSHAKE_TRAFFIC = "s hs traffic";
    public static final String LABEL_CLIENT_HANDSHAKE_TRAFFIC = "c hs traffic";
    public static final String LABEL_SERVER_APPLICATION_TRAFFIC = "s ap traffic";
    public static final String LABEL_CLIENT_APPLICATION_TRAFFIC = "c ap traffic";
    public static final String LABEL_KEY = "key";
    public static final String LABEL_IV = "iv";
    public static final String LABEL_FINISHED = "finished";
    public static final String LABEL_RES_BINDER = "res binder";
    public static final String LABEL_RES_MASTER = "res master";
    public static final String LABEL_RESUMPTION = "resumption";

    // метка KeyUpdate (RFC 8446 §7.2)
    public static final String LABEL_TRAFFIC_UPD = "traffic upd";

    // контекстные строки CertificateVerify (RFC 8446 раздел 4.4.3)
    public static final String SERVER_CERTIFICATE_VERIFY_CTX = "TLS 1.3, server CertificateVerify";
    public static final String CLIENT_CERTIFICATE_VERIFY_CTX = "TLS 1.3, client CertificateVerify";

    // HelloRetryRequest random (RFC 8446 §4.1.3)
    public static final byte[] HRR_RANDOM = new byte[]{
            (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A, (byte) 0x61, (byte) 0x11,
            (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91,
            (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
            (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, (byte) 0x33, (byte) 0x9C
    };

    private TlsConstants() {}
}
