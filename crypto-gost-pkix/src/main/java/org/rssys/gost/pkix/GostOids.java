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
    // OID алгоритма открытого ключа ГОСТ Р 34.10-2012 (id-tc26-gost3410-2012)
    // RFC 9215 §2, RFC 4491
    //
    // Значение id-tc26-gost3410-2012-256/512 (1.2.643.7.1.1.1.1 / .1.2). Несётся
    // в SubjectPublicKeyInfo и в CMS SignerInfo.signatureAlgorithm (RFC 4490 §3.2,
    // RFC 9215) — именно OID открытого ключа, а НЕ комбинированный signWithDigest,
    // как в поле signatureAlgorithm X.509-сертификата. Так делают эталонные
    // реализации (КриптоПро, openssl gost-engine, BouncyCastle принимает).
    // ========================================================================

    /** id-tc26-gost3410-2012-256 — OID открытого ключа (SPKI, CMS SignerInfo.signatureAlgorithm) */
    public static final String PUBLIC_KEY_256 = GostCurves.OID_SIGN_256;

    /** id-tc26-gost3410-2012-512 — OID открытого ключа (SPKI, CMS SignerInfo.signatureAlgorithm) */
    public static final String PUBLIC_KEY_512 = GostCurves.OID_SIGN_512;

    // ========================================================================
    // OID «подпись с дайджестом» ГОСТ (id-tc26-signwithdigest-gost3410-2012)
    // RFC 9215 §2, ГОСТ Р 34.10-2012
    //
    // Комбинированный OID подпись+Стрибог (1.2.643.7.1.1.3.2 / .3.3). Несётся
    // в поле signatureAlgorithm X.509-сертификата (и tbsCertificate.signature).
    // ========================================================================

    /** id-tc26-signwithdigest-gost3410-2012-256 — X.509 signatureAlgorithm (подпись+Стрибог-256) */
    public static final String SIGN_WITH_DIGEST_256 = "1.2.643.7.1.1.3.2";

    /** id-tc26-signwithdigest-gost3410-2012-512 — X.509 signatureAlgorithm (подпись+Стрибог-512) */
    public static final String SIGN_WITH_DIGEST_512 = "1.2.643.7.1.1.3.3";

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

    /** id-ce-issuerAltName */
    public static final String EXT_IAN = "2.5.29.18";

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

    /** id-ce-nameConstraints (RFC 5280 §4.2.1.10) */
    public static final String EXT_NAME_CONSTRAINTS = "2.5.29.30";

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

    /** anyExtendedKeyUsage (RFC 5280 §4.2.1.12) */
    public static final String EXT_ANY_EKU = "2.5.29.37.0";

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

    /** anyPolicy (RFC 5280 §4.2.1.4) — 2.5.29.32.0; семантически подходит под любую политику */
    public static final String ANY_POLICY = "2.5.29.32.0";

    /** id-qt-cps (RFC 5280 §4.2.1.4) — CPS pointer qualifier */
    public static final String POLICY_QT_CPS = "1.3.6.1.5.5.7.2.1";

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
    // OID для otherName type-id
    // ========================================================================

    /** id-ms-upn — 1.3.6.1.4.1.311.20.2.3 (User Principal Name) */
    public static final String ID_MS_UPN = "1.3.6.1.4.1.311.20.2.3";

    // ========================================================================
    // OCSP (RFC 6960)
    // ========================================================================

    /** id-ad-ocsp */
    public static final String OCSP_AD = "1.3.6.1.5.5.7.48.1";

    /** id-ad-caIssuers */
    public static final String CA_ISSUERS_AD = "1.3.6.1.5.5.7.48.2";

    /** id-pkix-ocsp-basic */
    public static final String OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

    /** id-pkix-ocsp-nonce (RFC 8954) */
    public static final String OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

    /** id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1) */
    public static final String EXT_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";

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

    /** id-tc26-agreement-gost-3410-2012-512 — VKO ГОСТ Р 34.10-2012 512 */
    public static final String AGREEMENT_VKO_512 = "1.2.643.7.1.1.6.2";

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

    /** id-aa-ets-certificateRefs — 1.2.840.113549.1.9.16.2.21 (RFC 5126 §6.2.1) */
    public static final String COMPLETE_CERTIFICATE_REFS = "1.2.840.113549.1.9.16.2.21";

    /** id-aa-ets-revocationRefs — 1.2.840.113549.1.9.16.2.22 (RFC 5126 §6.2.2) */
    public static final String COMPLETE_REVOCATION_REFS = "1.2.840.113549.1.9.16.2.22";

    /** id-aa-ets-certValues — 1.2.840.113549.1.9.16.2.23 (RFC 5126 §6.3.3) */
    public static final String CERTIFICATE_VALUES = "1.2.840.113549.1.9.16.2.23";

    /** id-aa-ets-revocationValues — 1.2.840.113549.1.9.16.2.24 (RFC 5126 §6.3.3) */
    public static final String REVOCATION_VALUES = "1.2.840.113549.1.9.16.2.24";

    /** id-aa-ets-contentTimestamp — 1.2.840.113549.1.9.16.2.20 (RFC 5126 §5.11.1) */
    public static final String CONTENT_TIME_STAMP = "1.2.840.113549.1.9.16.2.20";

    /** id-aa-ets-escTimeStamp — 1.2.840.113549.1.9.16.2.25 (RFC 5126 §6.3.5) */
    public static final String ESC_TIME_STAMP = "1.2.840.113549.1.9.16.2.25";

    // ========================================================================
    // PKCS#9 (RFC 2985) — Атрибуты подписи (signed attributes)
    // ========================================================================

    /** id-contentType — 1.2.840.113549.1.9.3 */
    public static final String ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";

    /** id-messageDigest — 1.2.840.113549.1.9.4 */
    public static final String ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

    /** id-signingTime — 1.2.840.113549.1.9.5 */
    public static final String ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5";

    /** id-countersignature — 1.2.840.113549.1.9.6 (RFC 5652 §11.4) */
    public static final String ATTR_COUNTERSIGNATURE = "1.2.840.113549.1.9.6";

    // ========================================================================
    // ГОСТ CMS unprotected-атрибуты (Р 1323565.1.025-2019 §13.4)
    // ========================================================================

    /** id-cms-mac-attr — 1.2.643.7.1.0.6.1.1 (content-mac в unprotectedAttrs) */
    public static final String ID_CMS_MAC_ATTR = "1.2.643.7.1.0.6.1.1";

    /** id-extensionRequest — 1.2.840.113549.1.9.14 (PKCS#9 §5.4.1) */
    public static final String ATTR_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

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

    /** pkcs-9-at-challengePassword — 1.2.840.113549.1.9.7 (RFC 2985 §5.4.1) */
    public static final String ATTR_CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7";

    /** id-friendlyName — 1.2.840.113549.1.9.20 */
    public static final String ATTR_FRIENDLY_NAME = "1.2.840.113549.1.9.20";

    /** id-localKeyId — 1.2.840.113549.1.9.21 */
    public static final String ATTR_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";

    // ========================================================================
    // Константы
    // ========================================================================

    /** Итерации PBKDF2 по умолчанию (OpenSSL gost-engine, RFC 9337 §5) */
    public static final int PBE_DEFAULT_ITERATIONS = 2_000;

    /** Минимальное число итераций PBKDF2 при импорте untrusted PFX. */
    public static final int MIN_PBKDF2_ITERATIONS_PFX = 1_000;

    /** Длина хеша Стрибог-256 в байтах */
    public static final int STREEBOG_256_HASH_LEN = 32;

    /** Длина хеша Стрибог-512 в байтах */
    public static final int STREEBOG_512_HASH_LEN = 64;

    /**
     * Длина SHA-1 в байтах: ResponderID byKey в ответах сторонних служб (Р 1323565.1.059-2024,
     * п. 7.3.3.3). Библиотека SHA-1 не вычисляет, константа нужна только для распознавания длины.
     */
    public static final int SHA1_HASH_LEN = 20;

    /** Допуск расхождения часов при проверке thisUpdate/nextUpdate/genTime (5 минут) */
    public static final long CLOCK_SKEW_MS = 5 * 60 * 1000L;

    /**
     * Оценка удерживаемой памяти разобранным CRL на одну отозванную запись (без учёта копии DER),
     * в байтах. Получена замером: 224 МиБ на 800 000 записей при 49 байтах DER на запись.
     * Нужна кэшу проверенных CRL для бюджета памяти.
     */
    public static final int CRL_RETAINED_BYTES_PER_ENTRY = 245;

    /** Максимальный возраст OCSP-ответа без nextUpdate (RFC 6960 §2.4 — локальная политика) */
    public static final long MAX_OCSP_AGE_MS = 24 * 60 * 60 * 1000L;

    /** Предел числа уникальных доказательств отзыва на один сертификат в X-Long */
    public static final int MAX_REVOCATION_EVIDENCE_PER_CERT = 8;

    /**
     * Предел числа недоверенных кандидатов в сертификаты делегированных OCSP-ответчиков
     * (из certificate-values). Каждый кандидат стоит проверки ГОСТ-подписи.
     */
    public static final int MAX_OCSP_RESPONDER_CANDIDATES = 8;

    /**
     * Предел числа элементов списка кандидатов в OCSP-ответчики до дедупликации.
     * Нужен, чтобы сама дедупликация по DER (попарное сравнение) не стала вектором DoS.
     */
    public static final int MAX_RAW_OCSP_RESPONDER_CANDIDATES = 4 * MAX_OCSP_RESPONDER_CANDIDATES;

    /**
     * Длина соли PBKDF2 при записи (PBES2 и MacData PFX), в байтах. RFC 9337 и RFC 9548 §8
     * рекомендуют не менее 32 октетов, чтобы снизить вероятность совпадения ключей из одного пароля.
     */
    public static final int PBKDF2_SALT_LEN = 32;

    /** Минимальная длина соли PBKDF2 при чтении (RFC 9337: от 8 октетов; RFC 9548 §7). */
    public static final int MIN_PBKDF2_SALT_LEN = 8;

    /** Максимальная длина соли PBKDF2 при чтении (RFC 9337: до 32 октетов; RFC 9548 §7). */
    public static final int MAX_PBKDF2_SALT_LEN = 32;

    /** Длина UKM (вектора) PBES2 в байтах (RFC 9337 §5) */
    public static final int PBES2_UKM_LEN = 16;

    /**
     * Длина content-UKM шифра CTR-ACPKM(-OMAC) в CMS EnvelopedData: IV[0..8) ‖ seed[8..16).
     * Укороченное значение молча дополнялось бы нулями в seed KDF_TREE и ослабляло
     * защиту от коллизий, поэтому длина проверяется строго.
     */
    public static final int CMS_CONTENT_UKM_LEN = 16;

    /** Длина ключа шифрования Кузнечик в байтах (ГОСТ Р 34.12-2018) */
    public static final int KUZNYECHIK_KEY_LEN = 32;

    /** Максимальная длина серийного номера сертификата в октетах (RFC 5280 §4.1.2.2) */
    public static final int MAX_SERIAL_OCTETS = 20;

    /**
     * Максимальная длина cRLNumber и BaseCRLNumber в октетах по величине без ведущего нуля знака
     * (RFC 5280 §5.2.3: проверяющий обязан принимать номера до 20 октетов).
     */
    public static final int MAX_CRL_NUMBER_OCTETS = 20;

    /**
     * Предел числа расширений на уровне CRL. Поиск дубликатов квадратичен, поэтому число
     * расширений ограничено; настоящий CRL содержит единицы расширений.
     */
    public static final int MAX_CRL_EXTENSIONS = 32;

    /** Предел числа расширений одной записи об отзыве (по тем же причинам, что и на уровне CRL). */
    public static final int MAX_CRL_ENTRY_EXTENSIONS = 16;

    // ========================================================================
    // Отображаемые имена OID для человекочитаемого вывода
    // ========================================================================

    private static final java.util.Map<String, String> OID_TO_DISPLAY_NAME;

    static {
        var m = new java.util.LinkedHashMap<String, String>();

        // Алгоритмы подписи
        m.put(PUBLIC_KEY_256, "GOST R 34.10-2012 (256)");
        m.put(PUBLIC_KEY_512, "GOST R 34.10-2012 (512)");
        m.put(SIGN_WITH_DIGEST_256, "GOST R 34.10-2012 (256) + Streebog-256");
        m.put(SIGN_WITH_DIGEST_512, "GOST R 34.10-2012 (512) + Streebog-512");

        // Параметры эллиптических кривых
        m.put(CURVE_256A, "id-tc26-gost-3410-2012-256-paramSetA");
        m.put(CURVE_CP_A, "id-GostR3410-2001-CryptoPro-A-ParamSet");
        m.put(CURVE_CP_B, "id-GostR3410-2001-CryptoPro-B-ParamSet");
        m.put(CURVE_512A, "id-tc26-gost-3410-12-512-paramSetA");
        m.put(CURVE_512B, "id-tc26-gost-3410-12-512-paramSetB");
        m.put(CURVE_512C, "id-tc26-gost-3410-2012-512-paramSetC");

        // Дайджесты
        m.put(DIGEST_256, "Streebog-256");
        m.put(DIGEST_512, "Streebog-512");

        // Расширения X.509v3
        m.put(EXT_SKI, "Subject Key Identifier (id-ce 2.5.29.14)");
        m.put(EXT_KU, "Key Usage (id-ce 2.5.29.15)");
        m.put(EXT_SAN, "Subject Alternative Name (id-ce 2.5.29.17)");
        m.put(EXT_IAN, "Issuer Alternative Name (id-ce 2.5.29.18)");
        m.put(EXT_BC, "Basic Constraints (id-ce 2.5.29.19)");
        m.put(EXT_CRL_REASON, "CRL Reason Code (id-ce 2.5.29.21)");
        m.put(EXT_INVALIDITY_DATE, "Invalidity Date (id-ce 2.5.29.24)");
        m.put(EXT_IDP, "Issuing Distribution Point (id-ce 2.5.29.28)");
        m.put(EXT_CERTIFICATE_ISSUER, "Certificate Issuer (id-ce 2.5.29.29)");
        m.put(EXT_CRL_NUMBER, "CRL Number (id-ce 2.5.29.20)");
        m.put(EXT_DELTA_CRL_INDICATOR, "Delta CRL Indicator (id-ce 2.5.29.27)");
        m.put(EXT_FRESHEST_CRL, "Freshest CRL (id-ce 2.5.29.46)");
        m.put(EXT_CDP, "CRL Distribution Points (id-ce 2.5.29.31)");
        m.put(EXT_CP, "Certificate Policies (id-ce 2.5.29.32)");
        m.put(POLICY_QT_CPS, "CPS Pointer Qualifier (id-qt-cps 1.3.6.1.5.5.7.2.1)");
        m.put(EXT_AKI, "Authority Key Identifier (id-ce 2.5.29.35)");
        m.put(EXT_EKU, "Extended Key Usage (id-ce 2.5.29.37)");
        m.put(EXT_NAME_CONSTRAINTS, "Name Constraints (id-ce 2.5.29.30)");
        m.put(EXT_AIA, "Authority Info Access (id-pe 1.3.6.1.5.5.7.1.1)");

        // Extended Key Usage
        m.put(EXT_ANY_EKU, "anyExtendedKeyUsage");
        m.put(EXT_SERVER_AUTH, "serverAuth");
        m.put(EXT_CLIENT_AUTH, "clientAuth");
        m.put(EXT_CODE_SIGNING, "codeSigning");
        m.put(EXT_EMAIL_PROTECTION, "emailProtection");
        m.put(EXT_TIME_STAMPING, "timeStamping");
        m.put(EXT_OCSP_SIGNING, "OCSPSigning");
        m.put(EXT_OCSP_NOCHECK, "OCSP No Check");

        // Certificate Policies
        m.put(POLICY_KC1, "class-kc1");
        m.put(POLICY_KC2, "class-kc2");
        m.put(ANY_POLICY, "anyPolicy");

        // Атрибуты DN
        m.put(ATTR_CN, "commonName");
        m.put(ATTR_O, "organizationName");
        m.put(ATTR_OU, "organizationalUnitName");
        m.put(ATTR_L, "localityName");
        m.put(ATTR_ST, "stateOrProvinceName");
        m.put(ATTR_C, "countryName");
        m.put(ATTR_STREET, "streetAddress");
        m.put(ATTR_T, "title");
        m.put(ATTR_SN, "surname");
        m.put(ATTR_GN, "givenName");
        m.put(ATTR_SERIALNUMBER, "serialNumber");
        m.put(ATTR_POSTAL_CODE, "postalCode");
        m.put(ATTR_UNIQUE_ID, "uniqueIdentifier");
        m.put(ATTR_PSEUDONYM, "pseudonym");
        m.put(ATTR_EMAIL, "emailAddress");
        m.put(ATTR_UID, "uid");
        m.put(ATTR_ORG_ID, "organizationIdentifier");
        m.put(ATTR_INN, "ИНН");
        m.put(ATTR_OGRNIP, "ОГРНИП");
        m.put(ATTR_OGRN, "ОГРН");
        m.put(ATTR_SNILS, "СНИЛС");
        m.put(ATTR_INNLE, "ИНН ЮЛ");

        // otherName type-id
        m.put(ID_MS_UPN, "User Principal Name (id-ms-upn 1.3.6.1.4.1.311.20.2.3)");

        // OCSP
        m.put(OCSP_AD, "OCSP (id-ad 1.3.6.1.5.5.7.48.1)");
        m.put(CA_ISSUERS_AD, "caIssuers (id-ad 1.3.6.1.5.5.7.48.2)");
        m.put(OCSP_BASIC, "OCSP Basic Response");
        m.put(OCSP_NONCE, "OCSP Nonce");

        // TSP
        m.put(AD_TIME_STAMPING, "Time-Stamping (id-ad 1.3.6.1.5.5.7.48.3)");
        m.put(TST_INFO, "TSTInfo (id-ct 1.2.840.113549.1.9.16.1.4)");

        // CMS
        m.put(CMS_SIGNED_DATA, "SignedData (id-signedData)");
        m.put(CMS_ENVELOPED_DATA, "EnvelopedData (id-envelopedData)");
        m.put(CMS_DIGESTED_DATA, "DigestedData (id-digestedData)");
        m.put(PKCS7_DATA, "Data (id-data)");
        m.put(PKCS7_ENCRYPTED_DATA, "EncryptedData (id-encryptedData)");

        // CAdES
        m.put(SIGNING_CERTIFICATE_V2, "Signing Certificate V2 (ESS)");
        m.put(SIGNATURE_POLICY_ID, "Signature Policy Identifier");
        m.put(SIGNATURE_TIME_STAMP, "Signature Time-Stamp Token");
        m.put(COMPLETE_CERTIFICATE_REFS, "Complete Certificate References (CAdES-C)");
        m.put(COMPLETE_REVOCATION_REFS, "Complete Revocation References (CAdES-C)");
        m.put(CERTIFICATE_VALUES, "Certificate Values (CAdES-X Long)");
        m.put(REVOCATION_VALUES, "Revocation Values (CAdES-X Long)");
        m.put(CONTENT_TIME_STAMP, "Content Time-Stamp (ES-C)");
        m.put(ESC_TIME_STAMP, "CAdES-C Time-Stamp (CAdES-X Type 1)");

        // PKCS#9 signed attributes
        m.put(ATTR_CONTENT_TYPE, "Content Type");
        m.put(ATTR_MESSAGE_DIGEST, "Message Digest");
        m.put(ATTR_SIGNING_TIME, "Signing Time");
        m.put(ATTR_COUNTERSIGNATURE, "Countersignature");
        m.put(ATTR_EXTENSION_REQUEST, "Extension Request");
        m.put(ID_CMS_MAC_ATTR, "CMS Content MAC Attribute (1.2.643.7.1.0.6.1.1)");

        // Key agreement / key wrap
        m.put(AGREEMENT_VKO_256, "VKO GOST R 34.10-2012 (256)");
        m.put(AGREEMENT_VKO_512, "VKO GOST R 34.10-2012 (512)");
        m.put(WRAP_KUZNYECHIK, "Kuznyechik Key Wrap");
        m.put(WRAP_KUZNYECHIK_KEXP15, "Kuznyechik KExp15 Key Wrap");
        m.put(KUZ_CTR_ACPKM, "Kuznyechik CTR-ACPKM");
        m.put(KUZ_CTR_ACPKM_OMAC, "Kuznyechik CTR-ACPKM-OMAC");

        // HMAC
        m.put(HMAC_STREEBOG_256, "HMAC-Streebog-256");
        m.put(HMAC_STREEBOG_512, "HMAC-Streebog-512");

        // PKCS#12
        m.put(BAG_PKCS8_SHROUDED_KEY, "PKCS#8 Shrouded Key Bag");
        m.put(BAG_CERT, "Certificate Bag");
        m.put(ATTR_CHALLENGE_PASSWORD, "Challenge Password");
        m.put(ATTR_FRIENDLY_NAME, "Friendly Name");
        m.put(ATTR_LOCAL_KEY_ID, "Local Key ID");
        m.put(PBES2, "PBES2");
        m.put(PBKDF2, "PBKDF2");
        m.put(PKCS9_X509_CERT, "X.509 Certificate");

        OID_TO_DISPLAY_NAME = java.util.Collections.unmodifiableMap(m);
    }

    /**
     * Возвращает человекочитаемое имя для OID, или сам OID если имя неизвестно.
     *
     * @param oid идентификатор OID в точечной нотации (например "1.2.643.7.1.1.3.2")
     * @return отображаемое имя или исходная строка OID
     */
    public static String displayName(String oid) {
        if (oid == null) {
            return "null";
        }
        String name = OID_TO_DISPLAY_NAME.get(oid);
        return name != null ? name : oid;
    }

    private GostOids() {}
}
