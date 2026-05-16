package org.rssys.gost.tls13;

public final class GostOids {

    // ========================================================================
    // Алгоритмы подписи ГОСТ (id_tc26_signwithdigest_gost3410_2012)
    // RFC 4357, RFC 7836, ГОСТ Р 34.10-2012
    // ========================================================================

    /** id_tc26_signwithdigest_gost3410_2012_256 */
    public static final String SIG_WITH_DIGEST_256 = "1.2.643.7.1.1.1.1";
    /** id_tc26_signwithdigest_gost3410_2012_512 */
    public static final String SIG_WITH_DIGEST_512 = "1.2.643.7.1.1.1.2";
    /** id_tc26_gost3410_2012_256 — алгоритм подписи (без дайджеста) */
    public static final String SIGN_ALG_256 = "1.2.643.7.1.1.3.2";
    /** id_tc26_gost3410_2012_512 — алгоритм подписи 512 (без дайджеста) */
    public static final String SIGN_ALG_512 = "1.2.643.7.1.1.3.3";

    // ========================================================================
    // Параметры эллиптических кривых (ГОСТ Р 34.10-2012)
    // ========================================================================

    /** id_tc26_gost_3410_2012_256_paramSetA */
    public static final String CURVE_256A = "1.2.643.7.1.2.1.2.1";
    /** id_GostR3410_2001_CryptoPro_A_ParamSet */
    public static final String CURVE_CP_A = "1.2.643.2.2.35.1";
    /** id_GostR3410_2001_CryptoPro_B_ParamSet */
    public static final String CURVE_CP_B = "1.2.643.2.2.35.2";
    /** id_tc26_gost_3410_12_512_paramSetA */
    public static final String CURVE_512A = "1.2.643.7.1.2.1.1.1";
    /** id_tc26_gost_3410_12_512_paramSetB */
    public static final String CURVE_512B = "1.2.643.7.1.2.1.1.2";
    /** id_tc26_gost_3410_2012_512_paramSetC */
    public static final String CURVE_512C = "1.2.643.7.1.2.1.1.3";

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

    private GostOids() {}
}
