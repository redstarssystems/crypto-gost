package org.rssys.gost.tls13;

import org.rssys.gost.jca.spec.GostCurves;

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

    /** id-ce-basicConstraints */
    public static final String EXT_BC  = "2.5.29.19";
    /** id-ce-keyUsage */
    public static final String EXT_KU  = "2.5.29.15";
    /** id-ce-subjectAltName */
    public static final String EXT_SAN = "2.5.29.17";
    /** id-ce-extKeyUsage */
    public static final String EXT_EKU = "2.5.29.37";
    /** id-pe-authorityInfoAccess (RFC 5280 §4.2.2.1) */
    public static final String EXT_AIA = "1.3.6.1.5.5.7.1.1";
    /** id-kp-serverAuth (RFC 5280 §4.2.1.12) */
    public static final String EXT_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    /** id-kp-clientAuth (RFC 5280 §4.2.1.12) */
    public static final String EXT_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    // ========================================================================
    // Атрибуты Distinguished Name (RFC 4519)
    // ========================================================================

    /** id-at-commonName */
    public static final String ATTR_CN = "2.5.4.3";

    // ========================================================================
    // OCSP (RFC 6960)
    // ========================================================================

    /** id-ad-ocsp */
    public static final String OCSP_AD    = "1.3.6.1.5.5.7.48.1";
    /** id-pkix-ocsp-basic */
    public static final String OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

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
    // PKCS#7 (RFC 2315) — Content types
    // ========================================================================

    /** id-data — 1.2.840.113549.1.7.1 */
    public static final String PKCS7_DATA = "1.2.840.113549.1.7.1";
    /** id-encryptedData — 1.2.840.113549.1.7.6 */
    public static final String PKCS7_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";

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

    private GostOids() {}
}
