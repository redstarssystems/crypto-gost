package org.rssys.gost.jsse.crl;

/**
 * Политика проверки CRL (Certificate Revocation List, RFC 5280 §5).
 * <p>
 * Определяет, требуется ли CRL и как реагировать на отсутствие CRLDistributionPoints.
 */
public enum CrlPolicy {

    /** CRL не проверять */
    DISABLED,

    /** Проверить CRL если у сертификата есть CDP; нет CDP — OK */
    IF_CDP_PRESENT,

    /** CRL обязателен при наличии CDP; нет CDP при REQUIRE — reject */
    REQUIRE
}
