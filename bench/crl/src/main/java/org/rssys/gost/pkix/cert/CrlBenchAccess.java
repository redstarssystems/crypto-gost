package org.rssys.gost.pkix.cert;

import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Доступ замерщика к пакетному {@code GostCrl.verifySignatureAndParse}.
 *
 * <p>Лежит в пакете библиотеки только ради замера: публичный {@code GostCrl.verify} проверяет срок
 * CRL, а у настоящего CRL чужого УЦ он истекает. Второй параметр
 * {@code verifySignatureAndParse(caKey, allowDelta)} - это {@code allowDelta}, а не признак срока;
 * срок этот метод не проверяет вовсе.</p>
 */
public final class CrlBenchAccess {

    private CrlBenchAccess() {}

    /** Подпись, затем строгий разбор записей, без проверки срока и без delta-CRL. */
    public static GostCrl verifyAndParse(
            byte[] crlDer, PublicKeyParameters caKey, CrlLimits limits) throws PkixException {
        GostCrl crl = new GostCrl(crlDer, limits);
        crl.verifySignatureAndParse(caKey, false);
        return crl;
    }
}
