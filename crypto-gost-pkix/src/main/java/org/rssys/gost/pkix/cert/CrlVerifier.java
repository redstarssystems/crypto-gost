package org.rssys.gost.pkix.cert;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Верификация CRL (Certificate Revocation List, RFC 5280 §5).
 * <p>
 * Предполагается direct CRL (issuer CRL == issuer сертификата, RFC 5280 §5.2.5).
 * Indirect CRL (issuingDistributionPoint с indirectCRL) не поддерживается.
 * Partial CRL (issuingDistributionPoint с onlyContains...) не поддерживается.
 * Delta CRL (deltaCRLIndicator) — изолированно не поддерживается,
 * но поддерживается в паре base+delta через {@link #verify(byte[], byte[], byte[], PublicKeyParameters, byte[])}.
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
     * Проверяет CRL: подпись, срок, issuer DN, отсутствие indirect/partial, и отзыв сертификата.
     * Использует лимиты по умолчанию ({@link GostCrl#DEFAULT_MAX_CRL_SIZE},
     * {@link GostCrl#DEFAULT_MAX_REVOKED_ENTRIES}).
     *
     * @param crlDer        DER-encoded CertificateList (RFC 5280 §5.1)
     * @param certSerial    серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey         открытый ключ CA, подписавшего CRL
     * @param certIssuerDn  DER-encoded issuer DN сертификата (полный SEQUENCE TLV)
     * @throws PkixException если CRL невалиден или сертификат отозван
     */
    public static void verify(
            byte[] crlDer, byte[] certSerial, PublicKeyParameters caKey, byte[] certIssuerDn)
            throws PkixException {
        verify(
                crlDer,
                certSerial,
                caKey,
                certIssuerDn,
                null,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Проверяет CRL с проверкой монотонности cRLNumber (защита от CRL rollback, RFC 5280 §5.2.3).
     * Использует лимиты по умолчанию.
     *
     * @param crlDer         DER-encoded CertificateList
     * @param certSerial     серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey          открытый ключ CA
     * @param certIssuerDn   DER-encoded issuer DN сертификата
     * @param minCrlNumber   минимально допустимый cRLNumber (inclusive) или null — пропустить проверку
     * @throws PkixException если CRL невалиден, cRLNumber меньше minCrlNumber, или сертификат отозван
     */
    public static void verify(
            byte[] crlDer,
            byte[] certSerial,
            PublicKeyParameters caKey,
            byte[] certIssuerDn,
            BigInteger minCrlNumber)
            throws PkixException {
        verify(
                crlDer,
                certSerial,
                caKey,
                certIssuerDn,
                minCrlNumber,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Проверяет CRL с настраиваемыми лимитами размера и числа записей.
     *
     * @param crlDer             DER-encoded CertificateList
     * @param certSerial         серийный номер проверяемого сертификата (raw DER INTEGER value)
     * @param caKey              открытый ключ CA
     * @param certIssuerDn       DER-encoded issuer DN сертификата
     * @param minCrlNumber       минимально допустимый cRLNumber или null
     * @param maxCrlSize         максимальный размер CRL в байтах
     * @param maxRevokedEntries  максимальное число отозванных записей
     * @throws PkixException если CRL невалиден, cRLNumber меньше minCrlNumber, или сертификат отозван
     */
    public static void verify(
            byte[] crlDer,
            byte[] certSerial,
            PublicKeyParameters caKey,
            byte[] certIssuerDn,
            BigInteger minCrlNumber,
            int maxCrlSize,
            int maxRevokedEntries)
            throws PkixException {
        if (crlDer == null) {
            throw new PkixException("CRL is null");
        }
        if (certSerial == null) {
            throw new PkixException("certSerial must not be null");
        }
        if (certIssuerDn == null) {
            throw new PkixException("certIssuerDn must not be null");
        }
        LOG.log(
                Level.DEBUG,
                "Verifying CRL for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));

        GostCrl crl;
        try {
            crl = new GostCrl(crlDer, maxCrlSize, maxRevokedEntries);
        } catch (RuntimeException e) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "Failed to parse CRL DER", e);
        }

        // Сверка issuer DN CRL с issuer DN сертификата (RFC 5280 §6.3.3(c))
        byte[] crlIssuerDn = crl.getIssuerDnBytes();
        if (!GostDerParser.arrayRangeEquals(
                crlIssuerDn, 0, crlIssuerDn.length, certIssuerDn, 0, certIssuerDn.length)) {
            throw new PkixException("CRL: issuer DN does not match certificate issuer DN");
        }

        // Верификация подписи + парсинг revoked-списка (fail-closed порядок внутри GostCrl)
        crl.verify(caKey);

        // Проверка cRLNumber монотонности (RFC 5280 §5.2.3)
        if (minCrlNumber != null) {
            BigInteger actual = crl.getCrlNumber();
            if (actual == null) {
                throw new PkixException(
                        "CRL: no cRLNumber extension, but minCrlNumber was provided");
            }
            if (actual.compareTo(minCrlNumber) < 0) {
                throw new PkixException(
                        "CRL: cRLNumber downgrade — got "
                                + actual
                                + ", min expected "
                                + minCrlNumber);
            }
        }

        // Проверка отзыва конкретного сертификата
        if (crl.isRevoked(certSerial)) {
            throw new PkixException(PkixException.Reason.REVOKED, "Certificate is revoked per CRL");
        }

        LOG.log(
                Level.DEBUG,
                "CRL verification passed for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));
    }

    /**
     * Проверяет пару base CRL + delta CRL с merge-логикой (RFC 5280 §5.2.4).
     * Использует лимиты по умолчанию.
     *
     * <p>Порядок (fail-closed):
     * <ol>
     *   <li>Верификация обоих CRL по отдельности</li>
     *   <li>delta.isDelta()</li>
     *   <li>delta.baseCrlNumber == base.crlNumber</li>
     *   <li>delta.thisUpdate >= base.thisUpdate</li>
     *   <li>Сверка issuer DN (base == certIssuerDn)</li>
     *   <li>Сверка issuer DN (base == delta)</li>
     *   <li>Merge: delta перекрывает base; REMOVE_FROM_CRL в delta удаляет из base</li>
     *   <li>Проверка certSerial в merged-наборе</li>
     * </ol>
     *
     * @param baseCrlDer   DER-encoded base CRL
     * @param deltaCrlDer  DER-encoded delta CRL
     * @param certSerial   серийный номер проверяемого сертификата (raw DER INTEGER)
     * @param caKey        открытый ключ CA
     * @param certIssuerDn DER-encoded issuer DN сертификата (полный SEQUENCE TLV)
     * @throws PkixException если любой CRL невалиден, несовместим или сертификат отозван
     */
    public static void verify(
            byte[] baseCrlDer,
            byte[] deltaCrlDer,
            byte[] certSerial,
            PublicKeyParameters caKey,
            byte[] certIssuerDn)
            throws PkixException {
        verify(
                baseCrlDer,
                deltaCrlDer,
                certSerial,
                caKey,
                certIssuerDn,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Проверяет пару base CRL + delta CRL с настраиваемыми лимитами.
     *
     * @param baseCrlDer         DER-encoded base CRL
     * @param deltaCrlDer        DER-encoded delta CRL
     * @param certSerial         серийный номер проверяемого сертификата (raw DER INTEGER)
     * @param caKey              открытый ключ CA
     * @param certIssuerDn       DER-encoded issuer DN сертификата
     * @param maxCrlSize         максимальный размер CRL в байтах
     * @param maxRevokedEntries  максимальное число отозванных записей
     * @throws PkixException если любой CRL невалиден, несовместим или сертификат отозван
     */
    public static void verify(
            byte[] baseCrlDer,
            byte[] deltaCrlDer,
            byte[] certSerial,
            PublicKeyParameters caKey,
            byte[] certIssuerDn,
            int maxCrlSize,
            int maxRevokedEntries)
            throws PkixException {
        if (baseCrlDer == null || deltaCrlDer == null) {
            throw new PkixException("CRL must not be null");
        }
        if (certSerial == null) {
            throw new PkixException("certSerial must not be null");
        }
        if (certIssuerDn == null) {
            throw new PkixException("certIssuerDn must not be null");
        }

        LOG.log(
                Level.DEBUG,
                "Verifying base+delta CRL for certificate serial 0x{0}",
                new BigInteger(1, certSerial).toString(16));

        GostCrl base;
        GostCrl delta;
        try {
            base = new GostCrl(baseCrlDer, maxCrlSize, maxRevokedEntries);
            delta = new GostCrl(deltaCrlDer, maxCrlSize, maxRevokedEntries);
        } catch (RuntimeException e) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "Failed to parse CRL DER", e);
        }

        // Верификация: base без delta-допуска, delta с допуском
        base.verify(caKey, false);
        delta.verify(caKey, true);

        // Сверка issuer DN base CRL с issuer DN сертификата (RFC 5280 §6.3.3(c))
        byte[] baseIssuerDn = base.getIssuerDnBytes();
        if (!GostDerParser.arrayRangeEquals(
                baseIssuerDn, 0, baseIssuerDn.length, certIssuerDn, 0, certIssuerDn.length)) {
            throw new PkixException("CRL: base issuer DN does not match certificate issuer DN");
        }

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
            throw new PkixException("CRL: delta baseCrlNumber does not match base cRLNumber");
        }

        // delta.thisUpdate >= base.thisUpdate (с допуском)
        if (delta.getThisUpdate()
                .isBefore(base.getThisUpdate().minusMillis(GostOids.CLOCK_SKEW_MS))) {
            throw new PkixException("CRL: delta thisUpdate is before base thisUpdate");
        }

        // Сверка issuer DN
        if (!GostDerParser.arrayRangeEquals(
                base.getIssuerDnBytes(),
                0,
                base.getIssuerDnBytes().length,
                delta.getIssuerDnBytes(),
                0,
                delta.getIssuerDnBytes().length)) {
            throw new PkixException("CRL: delta issuer DN does not match base issuer DN");
        }

        // Merge и проверка отзыва
        if (delta.isRevoked(certSerial)) {
            ReasonCode reason = delta.getReason(certSerial);
            if (reason == ReasonCode.REMOVE_FROM_CRL) {
                LOG.log(Level.DEBUG, "Certificate removed from CRL via delta (REMOVE_FROM_CRL)");
                return;
            }
            throw new PkixException(
                    PkixException.Reason.REVOKED, "Certificate is revoked per delta CRL");
        }

        if (base.isRevoked(certSerial)) {
            throw new PkixException(
                    PkixException.Reason.REVOKED, "Certificate is revoked per base CRL");
        }

        LOG.log(
                Level.DEBUG,
                "CRL verification passed for certificate serial 0x{0}",
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
     * <p>
     * <b>Security:</b> результат получен из <b>неверифицированных</b> байт. Использовать
     * только для метаданных кэша (TTL/инвалидация), никогда — для acceptance-решения.
     * Решение об отзыве всегда проходит через полный
     * {@link #verify(byte[], byte[], PublicKeyParameters)} с проверкой подписи, поэтому
     * подделка nextUpdate влияет лишь на эффективность кэша, не на корректность проверки.
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

    /**
     * Извлекает cRLNumber из CRL без полной верификации.
     * <p>
     * cRLNumber (OID 2.5.29.20) находится в CRL-level extensions после revokedCertificates
     * переменной длины. Возвращает {@code null} если расширение отсутствует или CRL повреждён.
     * <p>
     * <b>Security:</b> результат получен из <b>неверифицированных</b> байт. Использовать
     * только для метаданных кэша (rollback-baseline), никогда — для acceptance-решения.
     * Подделка cRLNumber влияет лишь на rollback-трекинг кэша, не на корректность проверки
     * отзыва, которая всегда идёт через полный {@link #verify(byte[], byte[], PublicKeyParameters)}.
     *
     * @param crlDer DER-encoded CertificateList
     * @return cRLNumber или null
     */
    public static BigInteger extractCrlNumber(byte[] crlDer) {
        if (crlDer == null) {
            return null;
        }
        try {
            int[] clSeq = GostDerParser.parseSequence(crlDer, 0);
            int[] tbsSeq = GostDerParser.parseSequence(crlDer, clSeq[0]);
            int tbPos = tbsSeq[0];
            int tbEnd = tbsSeq[1];

            // Пропускаем header TBSCertList
            tbPos = skipCrlVersion(crlDer, tbPos, tbEnd);
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1]; // algorithm
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1]; // issuer
            if (tbPos >= tbEnd) return null;
            // thisUpdate
            int tag = crlDer[tbPos] & 0xFF;
            if (tag != GostDerParser.TAG_UTC_TIME && tag != GostDerParser.TAG_GENERALIZED_TIME)
                return null;
            tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
            if (tbPos >= tbEnd) return null;
            // nextUpdate OPTIONAL
            tag = crlDer[tbPos] & 0xFF;
            if (tag == GostDerParser.TAG_UTC_TIME || tag == GostDerParser.TAG_GENERALIZED_TIME) {
                tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
                if (tbPos >= tbEnd) return null;
            }
            // Пропускаем revokedCertificates SEQUENCE
            if (tbPos < tbEnd && (crlDer[tbPos] & 0xFF) == GostDerParser.TAG_SEQUENCE) {
                tbPos = GostDerParser.readTlv(crlDer, tbPos)[1];
            }
            // crlExtensions [0] EXPLICIT
            if (tbPos >= tbEnd || (crlDer[tbPos] & 0xFF) != 0xA0) {
                return null;
            }
            int[] extExplTlv = GostDerParser.readTlv(crlDer, tbPos);
            int extPos = extExplTlv[0];
            int extEnd = extExplTlv[1];
            if (extPos >= extEnd || (crlDer[extPos] & 0xFF) != GostDerParser.TAG_SEQUENCE)
                return null;
            int[] extSeq = GostDerParser.readTlv(crlDer, extPos);
            int p = extSeq[0];
            int pe = extSeq[1];

            // Ищем cRLNumber в расширениях
            while (p < pe) {
                int[] extTlv = GostDerParser.parseSequence(crlDer, p);
                int oc = extTlv[0];
                int oce = extTlv[1];
                if (oc < oce && (crlDer[oc] & 0xFF) == GostDerParser.TAG_OID) {
                    int[] oidTlv = GostDerParser.readTlv(crlDer, oc);
                    if (GostDerParser.matchesOid(
                            crlDer,
                            oidTlv[0],
                            oidTlv[1] - oidTlv[0],
                            GostDerParser.CRL_NUMBER_OID_BYTES)) {
                        int afterOid = oidTlv[1];
                        if (afterOid < oce
                                && (crlDer[afterOid] & 0xFF) == GostDerParser.TAG_OCTET_STRING) {
                            int[] octTlv = GostDerParser.readTlv(crlDer, afterOid);
                            if (octTlv[0] < octTlv[1]
                                    && (crlDer[octTlv[0]] & 0xFF) == GostDerParser.TAG_INTEGER) {
                                int[] intTlv = GostDerParser.readTlv(crlDer, octTlv[0]);
                                return new BigInteger(
                                        Arrays.copyOfRange(crlDer, intTlv[0], intTlv[1]));
                            }
                        }
                        return null;
                    }
                }
                p = extTlv[1];
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
