package org.rssys.gost.pkix;

import org.rssys.gost.jca.spec.GostCurves;

/**
 * Центральный реестр OID-констант для ГОСТ-криптографии.
 *
 * <p>Содержит OID'ы алгоритмов подписи, параметров эллиптических кривых,
 * дайджестов, расширений X.509v3, атрибутов DN, OCSP, CMS, PKCS#12
 * и других стандартов, используемых в модулях pkix, tls, jsse.</p>
 */
public final class GostOids {

    // ========================================================================
    // Алгоритмы подписи ГОСТ (id_tc26_signwithdigest_gost3410_2012)
    // RFC 4357, RFC 7836, ГОСТ Р 34.10-2012
    // ========================================================================

    /** id_tc26_signwithdigest_gost3410_2012_256 */
    public static final String SIG_WITH_DIGEST_256 = GostCurves.OID_SIGN_256;

    /** id_tc26_signwithdigest_gost3410_2012_512 */
    public static final String SIG_WITH_DIGEST_512 = GostCurves.OID_SIGN_512;

    /** id_tc26_gost3410_2012_256 — алгоритм подписи (без дайджеста) */
    public static final String SIGN_ALG_256 = "1.2.643.7.1.1.3.2";

    /** id_tc26_gost3410_2012_512 — алгоритм подписи 512 (без дайджеста) */
    public static final String SIGN_ALG_512 = "1.2.643.7.1.1.3.3";

    // ========================================================================
    // Параметры эллиптических кривых (ГОСТ Р 34.10-2012)
    // ========================================================================

    /** id_tc26_gost_3410_2012_256_paramSetA */
    public static final String CURVE_256A = GostCurves.OID_TC26_A_256;

    /** id_GostR3410_2001_CryptoPro_A_ParamSet */
    public static final String CURVE_CP_A = GostCurves.OID_CRYPTOPRO_A;

    /** id_GostR3410_2001_CryptoPro_B_ParamSet */
    public static final String CURVE_CP_B = GostCurves.OID_CRYPTOPRO_B;

    /** id_tc26_gost_3410_12_512_paramSetA */
    public static final String CURVE_512A = GostCurves.OID_TC26_A_512;

    /** id_tc26_gost_3410_12_512_paramSetB */
    public static final String CURVE_512B = GostCurves.OID_TC26_B_512;

    /** id_tc26_gost_3410_2012_512_paramSetC */
    public static final String CURVE_512C = GostCurves.OID_TC26_C_512;

    // ========================================================================
    // Дайджесты (ГОСТ Р 34.11-2012)
    // ========================================================================

    /** id_tc26_gost_3411_2012_256 (Streebog-256) */
    public static final String DIGEST_256 = "1.2.643.7.1.1.2.2";

    /** id_tc26_gost_3411_2012_512 (Streebog-512) */
    public static final String DIGEST_512 = "1.2.643.7.1.1.2.3";

    // ========================================================================
    // Расширения X.509v3 (RFC 5280)
    // ========================================================================

    /** id-ce-subjectKeyIdentifier */
    public static final String EXT_SKI = "2.5.29.14";

    /** id-ce-keyUsage */
    public static final String EXT_KU = "2.5.29.15";

    /** id-ce-subjectAltName */
    public static final String EXT_SAN = "2.5.29.17";

    /** id-ce-basicConstraints */
    public static final String EXT_BC = "2.5.29.19";

    /** id-ce-cRLReason (RFC 5280 §5.3.1) */
    public static final String EXT_CRL_REASON = "2.5.29.21";

    /** id-ce-invalidityDate (RFC 5280 §5.3.2) */
    public static final String EXT_INVALIDITY_DATE = "2.5.29.24";

    /** id-ce-issuingDistributionPoint */
    public static final String EXT_IDP = "2.5.29.28";

    /** id-ce-certificateIssuer (RFC 5280 §5.3.3) */
    public static final String EXT_CERTIFICATE_ISSUER = "2.5.29.29";

    /** id-ce-cRLNumber */
    public static final String EXT_CRL_NUMBER = "2.5.29.20";

    /** id-ce-deltaCRLIndicator */
    public static final String EXT_DELTA_CRL_INDICATOR = "2.5.29.27";

    /** id-ce-freshestCRL */
    public static final String EXT_FRESHEST_CRL = "2.5.29.46";

    /** id-ce-cRLDistributionPoints */
    public static final String EXT_CDP = "2.5.29.31";

    /** id-ce-certificatePolicies */
    public static final String EXT_CP = "2.5.29.32";

    /** id-ce-authorityKeyIdentifier */
    public static final String EXT_AKI = "2.5.29.35";

    /** id-ce-extKeyUsage */
    public static final String EXT_EKU = "2.5.29.37";

    /** id-pe-authorityInfoAccess (RFC 5280 §4.2.2.1) */
    public static final String EXT_AIA = "1.3.6.1.5.5.7.1.1";

    /** id-kp-serverAuth (RFC 5280 §4.2.1.12) */
    public static final String EXT_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

    /** id-kp-clientAuth (RFC 5280 §4.2.1.12) */
    public static final String EXT_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    /** id-kp-codeSigning (RFC 5280 §4.2.1.12) */
    public static final String EXT_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";

    /** id-kp-emailProtection (RFC 5280 §4.2.1.12) */
    public static final String EXT_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";

    /** id-kp-timeStamping (RFC 3161 §2.3) */
    public static final String EXT_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

    /** id-kp-OCSPSigning (RFC 6960 §4.2.2.2) */
    public static final String EXT_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    // ========================================================================
    // ГОСТ CertificatePolicies: классы криптосредств (RFC 9215 §5.2, Приказ ФСБ №795 п.28)
    // Размещаются в CertificatePolicies (2.5.29.32).
    // ========================================================================

    /** 1.2.643.100.113.1 — id-class-kc1 (RFC 9215 §5.2) */
    public static final String POLICY_KC1 = "1.2.643.100.113.1";

    /** 1.2.643.100.113.2 — id-class-kc2 (RFC 9215 §5.2) */
    public static final String POLICY_KC2 = "1.2.643.100.113.2";

    // ========================================================================
    // Атрибуты Distinguished Name (RFC 4519)
    // ========================================================================

    /** id-at-commonName */
    public static final String ATTR_CN = "2.5.4.3";

    /** id-at-organizationName */
    public static final String ATTR_O = "2.5.4.10";

    /** id-at-organizationalUnitName */
    public static final String ATTR_OU = "2.5.4.11";

    /** id-at-localityName */
    public static final String ATTR_L = "2.5.4.7";

    /** id-at-stateOrProvinceName */
    public static final String ATTR_ST = "2.5.4.8";

    /** id-at-countryName */
    public static final String ATTR_C = "2.5.4.6";

    /** id-at-streetAddress (RFC 4519) */
    public static final String ATTR_STREET = "2.5.4.9";

    /** id-at-title (RFC 4519) */
    public static final String ATTR_T = "2.5.4.12";

    /** id-at-surname (RFC 4519) */
    public static final String ATTR_SN = "2.5.4.4";

    /** id-at-givenName (RFC 4519) */
    public static final String ATTR_GN = "2.5.4.42";

    /** id-at-serialNumber (RFC 4519) */
    public static final String ATTR_SERIALNUMBER = "2.5.4.5";

    /** id-at-postalCode (RFC 4519) */
    public static final String ATTR_POSTAL_CODE = "2.5.4.17";

    /** id-at-uniqueIdentifier (RFC 4519) */
    public static final String ATTR_UNIQUE_ID = "2.5.4.45";

    /** id-at-pseudonym (RFC 4519) */
    public static final String ATTR_PSEUDONYM = "2.5.4.65";

    /** emailAddress (RFC 2985) */
    public static final String ATTR_EMAIL = "1.2.840.113549.1.9.1";

    /** uid (RFC 4519) */
    public static final String ATTR_UID = "0.9.2342.19200300.100.1.1";

    /** organizationIdentifier (RFC 5280) */
    public static final String ATTR_ORG_ID = "2.5.4.97";

    /** ИНН (RFC 9215 §5.1) */
    public static final String ATTR_INN = "1.2.643.3.131.1.1";

    /** ОГРНИП (RFC 9215 §5.1) */
    public static final String ATTR_OGRNIP = "1.2.643.100.5";

    /** ОГРН (RFC 9215 §5.1) */
    public static final String ATTR_OGRN = "1.2.643.100.1";

    /** СНИЛС (RFC 9215 §5.1) */
    public static final String ATTR_SNILS = "1.2.643.100.3";

    /** ИНН ЮЛ (RFC 9215 §5.1) */
    public static final String ATTR_INNLE = "1.2.643.100.4";

    // ========================================================================
    // OCSP (RFC 6960)
    // ========================================================================

    /** id-ad-ocsp */
    public static final String OCSP_AD = "1.3.6.1.5.5.7.48.1";

    /** id-pkix-ocsp-basic */
    public static final String OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

    /** id-pkix-ocsp-nonce (RFC 8954) */
    public static final String OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

    // ========================================================================
    // TSP (RFC 3161) — Time-Stamp Protocol
    // ========================================================================

    /** id-ad-time-stamping — 1.3.6.1.5.5.7.48.3 */
    public static final String AD_TIME_STAMPING = "1.3.6.1.5.5.7.48.3";

    // PKIStatus (RFC 4210 §3.2.3)

    /** PKIStatus: granted */
    public static final int PKI_STATUS_GRANTED = 0;

    /** PKIStatus: granted with modifications (RFC 4210 §3.2.3) */
    public static final int PKI_STATUS_GRANTED_WITH_MODS = 1;

    /** PKIStatus: rejection */
    public static final int PKI_STATUS_REJECTED = 2;

    // PKIFailureInfo (RFC 4210 §D.2) — битовые маски для failInfo в PKIStatusInfo
    // Маска Java: (1 << N) где N — номер бита в ASN.1 BIT STRING (MSB первого байта = бит 0)

    /** PKIFailureInfo: неизвестный или неподдерживаемый алгоритм */
    public static final int PKI_FAIL_BAD_ALG = 1 << 0;
    /** PKIFailureInfo: некорректный запрос */
    public static final int PKI_FAIL_BAD_REQUEST = 1 << 2;
    /** PKIFailureInfo: неверный формат данных (включая длину хэша) */
    public static final int PKI_FAIL_BAD_DATA_FORMAT = 1 << 5;
    /** PKIFailureInfo: время TSA недоступно */
    public static final int PKI_FAIL_TIME_NOT_AVAILABLE = 1 << 14;
    /** PKIFailureInfo: неподдерживаемая политика */
    public static final int PKI_FAIL_UNACCEPTED_POLICY = 1 << 15;
    /** PKIFailureInfo: неподдерживаемое расширение */
    public static final int PKI_FAIL_UNACCEPTED_EXTENSION = 1 << 16;
    /** PKIFailureInfo: дополнительная информация недоступна */
    public static final int PKI_FAIL_ADD_INFO_NOT_AVAILABLE = 1 << 17;
    /** PKIFailureInfo: внутренняя ошибка TSA */
    public static final int PKI_FAIL_SYSTEM_FAILURE = 1 << 25;

    // ========================================================================
    // PKCS#5 (RFC 8018) — Password-Based Cryptography
    // ========================================================================

    /** id-PBES2 — 1.2.840.113549.1.5.13 */
    public static final String PBES2 = "1.2.840.113549.1.5.13";

    /** id-PBKDF2 — 1.2.840.113549.1.5.12 */
    public static final String PBKDF2 = "1.2.840.113549.1.5.12";

    // ========================================================================
    // TC26 HMAC (PRF для PBKDF2)
    // ========================================================================

    /** id-tc26-hmac-gost-3411-12-256 — HMAC-Streebog-256 */
    public static final String HMAC_STREEBOG_256 = "1.2.643.7.1.1.4.1";

    /** id-tc26-hmac-gost-3411-12-512 — HMAC-Streebog-512 */
    public static final String HMAC_STREEBOG_512 = "1.2.643.7.1.1.4.2";

    // ========================================================================
    // TC26 Cipher CTR-ACPKM (RFC 9337 §7.3)
    // ========================================================================

    /** id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm — Кузнечик CTR-ACPKM */
    public static final String KUZ_CTR_ACPKM = "1.2.643.7.1.1.5.2.1";

    /** id-tc26-cipher-gostr3412-2015-kuznyechik-ctracpkm-omac — Кузнечик CTR-ACPKM-OMAC */
    public static final String KUZ_CTR_ACPKM_OMAC = "1.2.643.7.1.1.5.2.2";

    // ========================================================================
    // TC26 Key Agreement (VKO) для CMS
    // ========================================================================

    /** id-tc26-agreement-gost-3410-2012-256 — VKO ГОСТ Р 34.10-2012 256 */
    public static final String AGREEMENT_VKO_256 = "1.2.643.7.1.1.6.1";

    // ========================================================================
    // TC26 Key Wrap на Кузнечике (id-tc26-wrap)
    // ========================================================================

    /** id-tc26-wrap-gostr3412-2015-kuznyechik (семейство) */
    public static final String WRAP_KUZNYECHIK = "1.2.643.7.1.1.7.2";

    /** id-tc26-wrap-gostr3412-2015-kuznyechik-kexp15 */
    public static final String WRAP_KUZNYECHIK_KEXP15 = "1.2.643.7.1.1.7.2.1";

    // ========================================================================
    // PKCS#7 (RFC 2315) — Content types
    // ========================================================================

    /** id-data — 1.2.840.113549.1.7.1 */
    public static final String PKCS7_DATA = "1.2.840.113549.1.7.1";

    /** id-encryptedData — 1.2.840.113549.1.7.6 */
    public static final String PKCS7_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";

    // ========================================================================
    // CMS (RFC 5652 §4) — Типы содержимого
    // ========================================================================

    /** id-signedData — 1.2.840.113549.1.7.2 */
    public static final String CMS_SIGNED_DATA = "1.2.840.113549.1.7.2";

    /** id-envelopedData — 1.2.840.113549.1.7.3 */
    public static final String CMS_ENVELOPED_DATA = "1.2.840.113549.1.7.3";

    /** id-digestedData — 1.2.840.113549.1.7.5 */
    public static final String CMS_DIGESTED_DATA = "1.2.840.113549.1.7.5";

    // ========================================================================
    // CAdES (ETSI EN 319 122) — ETS-архивные атрибуты
    // ========================================================================

    /** id-ct-TSTInfo — 1.2.840.113549.1.9.16.1.4 */
    public static final String TST_INFO = "1.2.840.113549.1.9.16.1.4";

    /** id-aa-signingCertificateV2 — 1.2.840.113549.1.9.16.2.47 (ESS, RFC 5035) */
    public static final String SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";

    /** id-aa-signaturePolicyIdentifier — 1.2.840.113549.1.9.16.2.15 */
    public static final String SIGNATURE_POLICY_ID = "1.2.840.113549.1.9.16.2.15";

    /** id-aa-signatureTimeStampToken — 1.2.840.113549.1.9.16.2.14 */
    public static final String SIGNATURE_TIME_STAMP = "1.2.840.113549.1.9.16.2.14";

    // ========================================================================
    // PKCS#9 (RFC 2985) — Атрибуты подписи (signed attributes)
    // ========================================================================

    /** id-contentType — 1.2.840.113549.1.9.3 */
    public static final String ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";

    /** id-messageDigest — 1.2.840.113549.1.9.4 */
    public static final String ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

    /** id-signingTime — 1.2.840.113549.1.9.5 */
    public static final String ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5";

    // ========================================================================
    // PKCS#9 (RFC 2985) — Attribute types
    // ========================================================================

    /** id-mime-type-x509Certificate — 1.2.840.113549.1.9.22.1 */
    public static final String PKCS9_X509_CERT = "1.2.840.113549.1.9.22.1";

    // ========================================================================
    // PKCS#12 (RFC 7292) — Bag types
    // ========================================================================

    /** pkcs-12pkcs-8ShroudedKeyBag — 1.2.840.113549.1.12.10.1.2 */
    public static final String BAG_PKCS8_SHROUDED_KEY = "1.2.840.113549.1.12.10.1.2";

    /** pkcs-12-certBag — 1.2.840.113549.1.12.10.1.3 */
    public static final String BAG_CERT = "1.2.840.113549.1.12.10.1.3";

    // ========================================================================
    // PKCS#9 (RFC 2985) — Attributes
    // ========================================================================

    /** id-friendlyName — 1.2.840.113549.1.9.20 */
    public static final String ATTR_FRIENDLY_NAME = "1.2.840.113549.1.9.20";

    /** id-localKeyId — 1.2.840.113549.1.9.21 */
    public static final String ATTR_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";

    // ========================================================================
    // Константы
    // ========================================================================

    /** Итерации PBKDF2 по умолчанию (OpenSSL gost-engine, RFC 9337 §5) */
    public static final int PBE_DEFAULT_ITERATIONS = 2_000;

    /** Длина хеша Стрибог-256 в байтах */
    public static final int STREEBOG_256_HASH_LEN = 32;

    /** Длина хеша Стрибог-512 в байтах */
    public static final int STREEBOG_512_HASH_LEN = 64;

    /** Допуск расхождения часов при проверке thisUpdate/nextUpdate/genTime (5 минут) */
    public static final long CLOCK_SKEW_MS = 5 * 60 * 1000L;

    /** Длина соли PBES2 в байтах (RFC 9337 §5) */
    public static final int PBES2_SALT_LEN = 16;

    /** Длина UKM (вектора) PBES2 в байтах (RFC 9337 §5) */
    public static final int PBES2_UKM_LEN = 16;

    /** Длина ключа шифрования Кузнечик в байтах (ГОСТ Р 34.12-2018) */
    public static final int KUZNYECHIK_KEY_LEN = 32;

    /** Максимальная длина серийного номера сертификата в октетах (RFC 5280 §4.1.2.2) */
    public static final int MAX_SERIAL_OCTETS = 20;

    private GostOids() {}
}
