package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Верификация CRL (Certificate Revocation List, RFC 5280 §5).
 * <p>
 * Предполагается direct CRL (issuer CRL == issuer сертификата, RFC 5280 §5.2.5).
 * Indirect CRL (issuingDistributionPoint с indirectCRL) не поддерживается.
 * Partial CRL (issuingDistributionPoint с onlyContains...) не поддерживается.
 * Delta CRL (deltaCRLIndicator) — изолированно не поддерживается,
 * но поддерживается в паре base+delta через {@link #verify(byte[], byte[], byte[], PublicKeyParameters)}.
 * <p>
 * Порядок проверки (fail-closed):
 * <ol>
 *   <li>Сверка issuer DN CRL с issuer DN сертификата (RFC 5280 §6.3.3(c))</li>
 *   <li>Подпись CRL — до сканирования revoked-списка</li>
 *   <li>Срок действия (thisUpdate/nextUpdate)</li>
 *   <li>Отклонение issuingDistributionPoint (partial/indirect CRL)</li>
 *   <li>Сканирование revokedCertificates</li>
 * </ol>
 * <p>
 * Делегирует парсинг и верификацию подписи в {@link GostCrl}.
 */
public final class CrlVerifier {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.CrlVerifier");

    private CrlVerifier() {}

    /**
     * Проверяет CRL: подпись, срок, отсутствие indirect/partial, и отзыв сертификата.
     *
     * @param crlDer       DER-encoded CertificateList (RFC 5280 §5.1)
     * @param certSerial   серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey        открытый ключ CA, подписавшего CRL (должен совпадать с issuer сертификата)
     * @throws PkixException если CRL невалиден (подпись, срок, indirect) или сертификат отозван
     */
    public static void verify(byte[] crlDer, byte[] certSerial, PublicKeyParameters caKey)
            throws PkixException {
        verify(crlDer, certSerial, caKey, null);
    }

    /**
     * Проверяет CRL: подпись, срок, issuer DN, отсутствие indirect/partial, и отзыв сертификата.
     *
     * @param crlDer        DER-encoded CertificateList (RFC 5280 §5.1)
     * @param certSerial    серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey         открытый ключ CA, подписавшего CRL
     * @param certIssuerDn  DER-encoded issuer DN сертификата (полный SEQUENCE TLV) или null
     * @throws PkixException если CRL невалиден или сертификат отозван
     */
    public static void verify(
            byte[] crlDer, byte[] certSerial, PublicKeyParameters caKey, byte[] certIssuerDn)
            throws PkixException {
        if (crlDer == null) {
            throw new PkixException("CRL is null");
        }
        if (certSerial == null) {
            throw new PkixException("certSerial must not be null");
        }
        LOG.log(
                Level.INFO,
                "Verifying CRL for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));

        GostCrl crl;
        try {
            crl = new GostCrl(crlDer);
        } catch (RuntimeException e) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "Failed to parse CRL DER", e);
        }

        // Сверка issuer DN CRL с issuer DN сертификата (RFC 5280 §6.3.3(c))
        if (certIssuerDn != null) {
            byte[] crlIssuerDn = crl.getIssuerDnBytes();
            if (!GostDerParser.arrayRangeEquals(
                    crlIssuerDn, 0, crlIssuerDn.length, certIssuerDn, 0, certIssuerDn.length)) {
                throw new PkixException("CRL: issuer DN does not match certificate issuer DN");
            }
        }

        // Верификация подписи + парсинг revoked-списка (fail-closed порядок внутри GostCrl)
        crl.verify(caKey);

        // Проверка отзыва конкретного сертификата
        if (crl.isRevoked(certSerial)) {
            throw new PkixException(PkixException.Reason.REVOKED, "Certificate is revoked per CRL");
        }

        LOG.log(
                Level.INFO,
                "CRL verification passed for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));
    }

    /**
     * Проверяет пару base CRL + delta CRL с merge-логикой (RFC 5280 §5.2.4).
     *
     * <p>Порядок (fail-closed):
     * <ol>
     *   <li>Верификация обоих CRL по отдельности</li>
     *   <li>delta.isDelta()</li>
     *   <li>delta.baseCrlNumber == base.crlNumber</li>
     *   <li>delta.thisUpdate >= base.thisUpdate</li>
     *   <li>Сверка issuer DN (base == delta)</li>
     *   <li>Merge: delta перекрывает base; REMOVE_FROM_CRL в delta удаляет из base</li>
     *   <li>Проверка certSerial в merged-наборе</li>
     * </ol>
     *
     * @param baseCrlDer  DER-encoded base CRL
     * @param deltaCrlDer DER-encoded delta CRL
     * @param certSerial  серийный номер проверяемого сертификата (raw DER INTEGER)
     * @param caKey       открытый ключ CA
     * @throws PkixException если любой CRL невалиден, несовместим или сертификат отозван
     */
    public static void verify(
            byte[] baseCrlDer, byte[] deltaCrlDer,
            byte[] certSerial, PublicKeyParameters caKey) throws PkixException {
        if (baseCrlDer == null || deltaCrlDer == null) {
            throw new PkixException("CRL must not be null");
        }
        if (certSerial == null) {
            throw new PkixException("certSerial must not be null");
        }

        LOG.log(Level.INFO, "Verifying base+delta CRL for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));

        GostCrl base;
        GostCrl delta;
        try {
            base = new GostCrl(baseCrlDer);
            delta = new GostCrl(deltaCrlDer);
        } catch (RuntimeException e) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR,
                    "Failed to parse CRL DER", e);
        }

        // Верификация: base без delta-допуска, delta с допуском
        base.verify(caKey, false);
        delta.verify(caKey, true);

        // delta.isDelta()
        if (!delta.isDelta()) {
            throw new PkixException("CRL: not a delta CRL (no deltaCRLIndicator)");
        }

        // delta.baseCrlNumber == base.crlNumber
        BigInteger baseNum = base.getCrlNumber();
        BigInteger deltaBaseNum = delta.getBaseCrlNumber();
        if (baseNum == null) {
            throw new PkixException("CRL: base CRL missing cRLNumber extension");
        }
        if (!deltaBaseNum.equals(baseNum)) {
            throw new PkixException(
                    "CRL: delta baseCrlNumber does not match base cRLNumber");
        }

        // delta.thisUpdate >= base.thisUpdate (с допуском)
        if (delta.getThisUpdate().isBefore(
                base.getThisUpdate().minusMillis(GostOids.CLOCK_SKEW_MS))) {
            throw new PkixException(
                    "CRL: delta thisUpdate is before base thisUpdate");
        }

        // Сверка issuer DN
        if (!GostDerParser.arrayRangeEquals(
                base.getIssuerDnBytes(), 0, base.getIssuerDnBytes().length,
                delta.getIssuerDnBytes(), 0, delta.getIssuerDnBytes().length)) {
            throw new PkixException(
                    "CRL: delta issuer DN does not match base issuer DN");
        }

        // Merge и проверка отзыва
        if (delta.isRevoked(certSerial)) {
            ReasonCode reason = delta.getReason(certSerial);
            if (reason == ReasonCode.REMOVE_FROM_CRL) {
                LOG.log(Level.INFO,
                        "Certificate removed from CRL via delta (REMOVE_FROM_CRL)");
                return;
            }
            throw new PkixException(PkixException.Reason.REVOKED,
                    "Certificate is revoked per delta CRL");
        }

        if (base.isRevoked(certSerial)) {
            throw new PkixException(PkixException.Reason.REVOKED,
                    "Certificate is revoked per base CRL");
        }

        LOG.log(Level.INFO, "CRL verification passed for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));
    }

    /**
     * Парсит nextUpdate из CRL без полной верификации (для кэша).
     * <p>
     * В отличие от {@link #verify(byte[], byte[], PublicKeyParameters)}, этот метод
     * не проверяет подпись и не сканирует revoked-список — только извлекает дату
     * истечения срока действия CRL. Нужен {@code org.rssys.gost.jsse.crl.CrlCache}
     * чтобы определить момент инвалидации кэша.
     * <p>
     * Не создаёт объект {@link GostCrl} — использует облегчённый путь для производительности.
     *
     * @param crlDer DER-encoded CertificateList
     * @return nextUpdate Instant или null если поле отсутствует
     */
    public static Instant extractNextUpdate(byte[] crlDer) {
        if (crlDer == null) {
            return null;
        }
        try {
            int[] clSeq = GostDerParser.parseSequence(crlDer, 0);
            int[] tbsSeq = GostDerParser.parseSequence(crlDer, clSeq[0]);
            int tbPos = tbsSeq[0];
            int tbEnd = tbsSeq[1];

            // Пропускаем поля TBSCertList header до nextUpdate: чтобы не парсить
            // весь сертификат и не верифицировать подпись
            tbPos = skipCrlVersion(crlDer, tbPos, tbEnd);
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd) return null;
            int tag = crlDer[tbPos] & 0xFF;
            if (tag != GostDerParser.TAG_UTC_TIME && tag != GostDerParser.TAG_GENERALIZED_TIME)
                return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd) return null;
            tag = crlDer[tbPos] & 0xFF;
            if (tag != GostDerParser.TAG_UTC_TIME && tag != GostDerParser.TAG_GENERALIZED_TIME)
                return null;
            int tagPos = tbPos;
            GostDerParser.readTlv(crlDer, tbPos);
            return GostDerParser.parseTime(crlDer, tagPos);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Пропускает опциональное поле version в TBSCertList.
     */
    private static int skipCrlVersion(byte[] crlDer, int pos, int end) {
        if (pos < end && (crlDer[pos] & 0xFF) == GostDerParser.TAG_INTEGER) {
            return GostDerParser.readTlv(crlDer, pos)[1];
        }
        if (pos < end && (crlDer[pos] & 0xFF) == 0xA0) {
            return GostDerParser.readTlv(crlDer, pos)[1];
        }
        return pos;
    }
}
