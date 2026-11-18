package org.rssys.gost.pkix.cert;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Верификация CRL (Certificate Revocation List, RFC 5280 §5).
 * <p>
 * Поддерживает прямой CRL (issuer CRL == issuer сертификата) и
 * делегированных CRL-подписантов (RFC 5280 §6.3.3(c)) через
 * {@link #verifyDelegated(byte[], GostCertificate, GostCertificate, List)}.
 * Indirect CRL (issuingDistributionPoint с indirectCRL, certificateIssuer в записях)
 * не поддерживается.
 * <p>
 * Область действия CRL (IssuingDistributionPoint, RFC 5280 §5.2.5) проверяется на всех путях
 * приёмки: прямом, делегированном, в паре base+delta и для X-Long. Для этого методы принимают
 * сам {@link GostCertificate}, а не пару «серийный номер + issuer DN»: область зависит от
 * признака CA и от CDP сертификата. onlyContainsUserCerts допустим только для не-CA,
 * onlyContainsCACerts только для CA, distributionPoint обязан совпасть с CDP сертификата;
 * onlySomeReasons, onlyContainsAttributeCerts и nameRelativeToCRLIssuer отклоняются
 * ({@code IDP_NOT_SUPPORTED}). CRL, не покрывающий сертификат, не доказывает «не отозван».
 * <p>
 * Delta CRL (deltaCRLIndicator) — изолированно не поддерживается,
 * но поддерживается в паре base+delta через
 * {@link #verify(byte[], byte[], GostCertificate, GostCertificate)}.
 * <p>
 * Порядок проверки (fail-closed):
 * <ol>
 *   <li>Сверка issuer DN CRL с issuer DN сертификата (RFC 5280 §6.3.3(c))</li>
 *   <li>Подпись CRL — до разбора revoked-списка и расширений</li>
 *   <li>Срок действия (thisUpdate/nextUpdate)</li>
 *   <li>Строгий разбор расширений и записей (неизвестное critical-расширение, indirect CRL)</li>
 *   <li>cRLNumber не ниже минимального (если задан)</li>
 *   <li>Запись об отзыве сертификата: отзыв в подписанном CRL не зависит от его области</li>
 *   <li>Область CRL: покрывает ли он этот сертификат</li>
 * </ol>
 * <p>
 * Делегирует парсинг и верификацию подписи в {@link GostCrl}.
 */
public final class CrlVerifier {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.CrlVerifier");

    private CrlVerifier() {}

    /**
     * Проверяет CRL: подпись, срок, issuer DN, отзыв сертификата и область действия CRL.
     * Использует пределы по умолчанию ({@link CrlLimits#DEFAULT}).
     *
     * @param crlDer DER-encoded CertificateList (RFC 5280 §5.1)
     * @param cert   проверяемый сертификат: из него берутся серийный номер, issuer DN,
     *               признак CA и CDP
     * @param issuerCa сертификат CA, подписавшего CRL: из него берутся ключ проверки подписи и
     *                 право подписывать CRL (KeyUsage {@code cRLSign}, если KeyUsage задан)
     * @throws PkixException если CRL невалиден, не покрывает сертификат
     *         ({@code IDP_NOT_SUPPORTED}), сертификат отозван или у издателя нет права подписывать
     *         CRL ({@code MISSING_CRL_SIGN})
     */
    public static void verify(byte[] crlDer, GostCertificate cert, GostCertificate issuerCa)
            throws PkixException {
        verify(crlDer, cert, issuerCa, null, CrlLimits.DEFAULT);
    }

    /**
     * Проверяет CRL с проверкой монотонности cRLNumber (защита от CRL rollback, RFC 5280 §5.2.3).
     * Использует лимиты по умолчанию.
     *
     * @param crlDer       DER-encoded CertificateList
     * @param cert         проверяемый сертификат
     * @param issuerCa     сертификат CA, подписавшего CRL
     * @param minCrlNumber минимально допустимый cRLNumber (inclusive) или null — пропустить проверку
     * @throws PkixException если CRL невалиден, cRLNumber меньше minCrlNumber, CRL не покрывает
     *         сертификат, сертификат отозван или у издателя нет права подписывать CRL
     */
    public static void verify(
            byte[] crlDer, GostCertificate cert, GostCertificate issuerCa, BigInteger minCrlNumber)
            throws PkixException {
        verify(crlDer, cert, issuerCa, minCrlNumber, CrlLimits.DEFAULT);
    }

    /**
     * Проверяет CRL с настраиваемыми лимитами размера и числа записей.
     *
     * @param crlDer            DER-encoded CertificateList
     * @param cert              проверяемый сертификат
     * @param issuerCa          сертификат CA, подписавшего CRL
     * @param minCrlNumber      минимально допустимый cRLNumber или null
     * @param limits            пределы размера и числа записей CRL
     * @throws PkixException если CRL невалиден, cRLNumber меньше minCrlNumber, CRL не покрывает
     *         сертификат, сертификат отозван или у издателя нет права подписывать CRL
     */
    public static void verify(
            byte[] crlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            BigInteger minCrlNumber,
            CrlLimits limits)
            throws PkixException {
        requireInputs(crlDer, cert);
        requireIssuerCa(issuerCa);
        logVerifying(cert);

        GostCrl crl = parseCrl(crlDer, limits);
        requireIssuerDnMatch(crl, cert.getIssuerDnBytes());
        // Право подписывать CRL проверяется до хэша и подписи: отказ дешёвый
        requireCrlSign(issuerCa);

        // Верификация подписи + строгий разбор (fail-closed порядок внутри GostCrl)
        crl.verify(issuerCa.getPublicKey());

        requireCrlNumberNotBelow(crl, minCrlNumber);
        requireNotRevokedInScope(crl, cert);

        LOG.log(
                Level.DEBUG,
                "CRL verification passed for certificate serial 0x{0}",
                serialHex(cert));
    }

    /**
     * Проверяет подпись CRL один раз и разбирает записи, не привязывая результат к сертификату.
     *
     * <p>Порядок: ограничения размера и числа записей, дешёвая проверка сроков (до хэша большого
     * CRL), подпись и строгий разбор. Применять результат к сертификату - через
     * {@link VerifiedCrl#verifyFor}. Делегированные и delta CRL не принимаются.</p>
     *
     * @param crlDer            DER-encoded CertificateList
     * @param issuerCa          сертификат издателя CRL
     * @param limits            пределы размера и числа записей CRL
     * @return проверенный CRL, привязанный к ключу издателя
     * @throws PkixException если CRL невалиден (подпись, срок, структура, неподдерживаемое
     *                       расширение, delta CRL) или у издателя нет права подписывать CRL
     *                       ({@code MISSING_CRL_SIGN})
     */
    public static VerifiedCrl authenticate(
            byte[] crlDer, GostCertificate issuerCa, CrlLimits limits) throws PkixException {
        if (crlDer == null) {
            throw new PkixException("CRL is null");
        }
        requireIssuerCa(issuerCa);
        // Дешёвые проверки издателя идут до дорогих действий: непригодный ключ или сертификат без
        // права подписывать CRL не должен стоить хэша CRL
        byte[] issuerKeySpki = encodeIssuerKey(issuerCa.getPublicKey());
        requireCrlSign(issuerCa);
        GostCrl crl = parseCrl(crlDer, limits);
        crl.verify(issuerCa.getPublicKey());
        return new VerifiedCrl(crl, issuerKeySpki);
    }

    /**
     * Издатель CRL вправе подписывать CRL: если у его сертификата есть KeyUsage, в нём обязан быть
     * {@code cRLSign}. Отсутствие KeyUsage разрешением считается (RFC 5280 §4.2.1.3, §6.3.3 f), а
     * KeyUsage без {@code cRLSign} - запретом. Для делегированных подписантов правило строже, см.
     * {@link GostCertificate#hasCrlSignKeyUsage()}.
     *
     * @throws PkixException {@code MISSING_CRL_SIGN}, если KeyUsage задан без {@code cRLSign}
     */
    static void requireCrlSign(GostCertificate issuerCa) throws PkixException {
        if (!issuerCa.isCrlSigner()) {
            throw new PkixException(
                    PkixException.Reason.MISSING_CRL_SIGN,
                    "CRL issuer certificate has KeyUsage without cRLSign");
        }
    }

    private static void requireIssuerCa(GostCertificate issuerCa) throws PkixException {
        if (issuerCa == null) {
            throw new PkixException("issuerCa must not be null");
        }
    }

    /** Канонический вид ключа издателя для сравнения (SubjectPublicKeyInfo). */
    static byte[] encodeIssuerKey(PublicKeyParameters issuerKey) throws PkixException {
        try {
            return VerifiedCrl.encodeKey(issuerKey);
        } catch (RuntimeException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Cannot encode issuer public key", e);
        }
    }

    /**
     * Проверки сертификата по уже проверенному CRL: issuer DN, монотонность {@code cRLNumber},
     * отзыв и область. Сроки и подпись проверены раньше.
     */
    static void checkAuthenticated(GostCrl crl, GostCertificate cert, BigInteger minCrlNumber)
            throws PkixException {
        requireIssuerDnMatch(crl, cert.getIssuerDnBytes());
        requireCrlNumberNotBelow(crl, minCrlNumber);
        requireNotRevokedInScope(crl, cert);
    }

    private static void requireInputs(byte[] crlDer, GostCertificate cert) throws PkixException {
        if (crlDer == null) {
            throw new PkixException("CRL is null");
        }
        if (cert == null) {
            throw new PkixException("cert must not be null");
        }
    }

    private static void logVerifying(GostCertificate cert) {
        LOG.log(Level.DEBUG, "Verifying CRL for certificate serial 0x{0}", serialHex(cert));
    }

    private static String serialHex(GostCertificate cert) {
        return new BigInteger(1, cert.getSerialNumber()).toString(16);
    }

    /**
     * Разбирает CRL с проверкой пределов. Размер проверяется до создания {@link GostCrl}, поэтому
     * превышение даёт причину {@code CRL_LIMIT_EXCEEDED}, а не ошибку разбора.
     */
    private static GostCrl parseCrl(byte[] crlDer, CrlLimits limits) throws PkixException {
        requireLimits(limits);
        limits.requireSize(crlDer);
        try {
            return new GostCrl(crlDer, limits);
        } catch (RuntimeException e) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "Failed to parse CRL DER", e);
        }
    }

    private static void requireLimits(CrlLimits limits) {
        if (limits == null) {
            throw new IllegalArgumentException("limits must not be null");
        }
    }

    /** Сверка issuer DN CRL с issuer DN сертификата (RFC 5280 §6.3.3(c)). */
    private static void requireIssuerDnMatch(GostCrl crl, byte[] certIssuerDn)
            throws PkixException {
        byte[] crlIssuerDn = crl.getIssuerDnBytes();
        if (!GostDerParser.arrayRangeEquals(
                crlIssuerDn, 0, crlIssuerDn.length, certIssuerDn, 0, certIssuerDn.length)) {
            throw new PkixException("CRL: issuer DN does not match certificate issuer DN");
        }
    }

    /** Проверка cRLNumber монотонности (RFC 5280 §5.2.3). */
    private static void requireCrlNumberNotBelow(GostCrl crl, BigInteger minCrlNumber)
            throws PkixException {
        if (minCrlNumber == null) {
            return;
        }
        BigInteger actual = crl.getCrlNumber();
        if (actual == null) {
            throw new PkixException("CRL: no cRLNumber extension, but minCrlNumber was provided");
        }
        if (actual.compareTo(minCrlNumber) < 0) {
            throw new PkixException(
                    "CRL: cRLNumber downgrade — got " + actual + ", min expected " + minCrlNumber);
        }
    }

    /**
     * Запись об отзыве определяет REVOKED раньше проверки области: отзыв в подписанном CRL не
     * должен зависеть от того, какие сертификаты CRL «обязан» покрывать. Иначе подлинный CRL
     * другого сегмента с этим номером превратился бы из REVOKED в «неподдерживаемый», и CMS без
     * required пропустила бы его. Область проверяется только для вывода «не отозван».
     */
    private static void requireNotRevokedInScope(GostCrl crl, GostCertificate cert)
            throws PkixException {
        if (crl.isRevoked(cert.getSerialNumber())) {
            throw new PkixException(PkixException.Reason.REVOKED, "Certificate is revoked per CRL");
        }
        requirePartialScope(crl, cert);
    }

    /**
     * Проверяет одно CRL-доказательство для CAdES-X Long.
     *
     * <p>Порядок: структура и подпись, принадлежность издателю, область CRL, статус,
     * затем окно выпуска. Область здесь проверяется до статуса (в отличие от
     * {@link #verify(byte[], GostCertificate, GostCertificate)}): для долгосрочной
     * проверки не покрывающее доказательство — ошибка, а не «пропустить и взять другое».
     * {@code revoked} отклоняется до оценки окна, поэтому устаревшее доказательство не может
     * «не участвовать» и скрыть отзыв.</p>
     *
     * @param crlDer DER-кодированный CRL
     * @param cert   проверяемый сертификат (серийный номер, issuer DN, признак CA и CDP)
     * @param issuerCa сертификат издателя CRL
     * @param window окно подписи/сбора
     * @param policy политика свежести
     * @param limits пределы размера и числа записей CRL
     * @return {@link EvidenceFreshness#IN_WINDOW} или
     *         {@link EvidenceFreshness#OUT_OF_WINDOW} для good-доказательства
     * @throws PkixException при структурной ошибке, неверной подписи, чужом
     *         издателе, delta/indirect CRL, не покрывающем сертификат CRL,
     *         отсутствии nextUpdate или отзыве
     */
    static EvidenceFreshness verifyEvidence(
            byte[] crlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            CrlLimits limits)
            throws PkixException {
        if (crlDer == null) {
            throw new PkixException("CRL is null");
        }
        if (cert == null) {
            throw new PkixException("cert must not be null");
        }
        requireIssuerCa(issuerCa);
        if (window == null) {
            throw new IllegalArgumentException("window must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }

        GostCrl crl = parseCrl(crlDer, limits);

        byte[] certIssuerDn = cert.getIssuerDnBytes();
        byte[] crlIssuerDn = crl.getIssuerDnBytes();
        if (!GostDerParser.arrayRangeEquals(
                crlIssuerDn, 0, crlIssuerDn.length, certIssuerDn, 0, certIssuerDn.length)) {
            throw new PkixException("CRL: issuer DN does not match certificate issuer DN");
        }

        requireCrlSign(issuerCa);

        // Signature-first: structural parse/extensions happen here; delta/indirect reject.
        crl.verifySignatureAndParse(issuerCa.getPublicKey(), false);

        // Область проверяем до статуса: неподходящая область не даёт "good".
        requirePartialScope(crl, cert);

        // Статус проверяем до окна: revoked в устаревшем доказательстве всё равно отклоняет.
        if (crl.isRevoked(cert.getSerialNumber())) {
            throw new PkixException(PkixException.Reason.REVOKED, "Certificate is revoked per CRL");
        }

        Instant thisUpdate = crl.getThisUpdate();
        Instant nextUpdate = crl.getNextUpdate();
        if (nextUpdate == null) {
            throw new PkixException(
                    PkixException.Reason.NEXT_UPDATE_MISSING,
                    "CRL without nextUpdate is not accepted for long-term validation");
        }
        if (nextUpdate.isBefore(thisUpdate)) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "CRL: nextUpdate is before thisUpdate");
        }

        Instant collection = window.collectionTime();
        Instant signing = window.signingTime();

        boolean issuedNotAfterCollection =
                !thisUpdate.isAfter(collection.plusMillis(GostOids.CLOCK_SKEW_MS));
        boolean freshAtCollection =
                !collection.isAfter(nextUpdate.plusMillis(GostOids.CLOCK_SKEW_MS));
        boolean issuedNotBeforeSigning =
                policy != RevocationFreshnessPolicy.STRICT
                        || !thisUpdate.isBefore(signing.minusMillis(GostOids.CLOCK_SKEW_MS));

        boolean inWindow = issuedNotAfterCollection && freshAtCollection && issuedNotBeforeSigning;
        return inWindow ? EvidenceFreshness.IN_WINDOW : EvidenceFreshness.OUT_OF_WINDOW;
    }

    /**
     * Нарушение области CRL для сертификата: текст нарушения или {@code null}, если CRL
     * покрывает сертификат.
     *
     * <p>onlyContainsUserCerts допустим только для не-CA, onlyContainsCACerts —
     * только для CA. onlySomeReasons, onlyContainsAttributeCerts,
     * nameRelativeToCRLIssuer и несовпадающий distributionPoint отклоняются:
     * библиотека не умеет безопасно комбинировать partial-покрытие.</p>
     *
     * <p>Единственный источник условий: на нём построены и предикат
     * {@link #isPartialScopeCovered}, и {@link #requirePartialScope}, поэтому тексты и
     * условия не расходятся.</p>
     */
    static String partialScopeViolation(GostCrl crl, GostCertificate cert) {
        if (!crl.isIdp()) {
            return null;
        }
        if (crl.isOnlySomeReasons()) {
            return "CRL: onlySomeReasons is not supported";
        }
        if (crl.isOnlyContainsAttributeCerts()) {
            return "CRL: onlyContainsAttributeCerts is not applicable to X.509 certificates";
        }
        if (crl.isOnlyContainsUserCerts() && crl.isOnlyContainsCACerts()) {
            return "CRL: onlyContainsUserCerts and onlyContainsCACerts are both set";
        }
        if (crl.isOnlyContainsUserCerts() && cert.isCA()) {
            return "CRL: onlyContainsUserCerts does not cover a CA certificate";
        }
        if (crl.isOnlyContainsCACerts() && !cert.isCA()) {
            return "CRL: onlyContainsCACerts does not cover an end-entity certificate";
        }
        if (crl.isIdpNameRelativeToCrlIssuer()) {
            return "CRL: nameRelativeToCRLIssuer cannot be matched to certificate CDP";
        }
        if (crl.isIdpDistributionPointPresent()) {
            String[] idpUris = crl.getIdpDistributionPointUris();
            String[] cdpUris = cert.getCdpUris();
            if (idpUris == null || cdpUris == null || !intersects(idpUris, cdpUris)) {
                return "CRL: distributionPoint does not match certificate CDP";
            }
        }
        return null;
    }

    /** Покрывает ли CRL сертификат; без исключений, для логики, где область не прерывает проверку. */
    private static boolean isPartialScopeCovered(GostCrl crl, GostCertificate cert) {
        return partialScopeViolation(crl, cert) == null;
    }

    /** Применяет область CRL к сертификату; нарушение — {@code IDP_NOT_SUPPORTED}. */
    private static void requirePartialScope(GostCrl crl, GostCertificate cert)
            throws PkixException {
        String violation = partialScopeViolation(crl, cert);
        if (violation != null) {
            throw new PkixException(PkixException.Reason.IDP_NOT_SUPPORTED, violation);
        }
    }

    private static boolean intersects(String[] left, String[] right) {
        for (String a : left) {
            for (String b : right) {
                if (a != null && a.equals(b)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Проверяет пару base CRL + delta CRL с merge-логикой (RFC 5280 §5.2.4).
     * Использует лимиты по умолчанию.
     *
     * <p>Порядок (fail-closed):
     * <ol>
     *   <li>Верификация обоих CRL по отдельности</li>
     *   <li>Сверка issuer DN (base == сертификат, base == delta)</li>
     *   <li>delta.isDelta(), delta.baseCrlNumber == base.crlNumber, delta.thisUpdate >= base.thisUpdate</li>
     *   <li>Область: base и delta покрывают сертификат, IDP base и delta совпадают, AKI не
     *       противоречат (RFC 5280 §6.3.3(c))</li>
     *   <li>Отзыв: запись в delta или base определяет REVOKED независимо от области;
     *       {@code REMOVE_FROM_CRL} в delta снимает отзыв только если область согласована</li>
     *   <li>Область не согласована -> {@code IDP_NOT_SUPPORTED}</li>
     * </ol>
     *
     * @param baseCrlDer  DER-encoded base CRL
     * @param deltaCrlDer DER-encoded delta CRL
     * @param cert        проверяемый сертификат
     * @param issuerCa    сертификат CA, подписавшего оба CRL
     * @throws PkixException если любой CRL невалиден, несовместим, не покрывает сертификат,
     *         сертификат отозван или у издателя нет права подписывать CRL
     */
    public static void verify(
            byte[] baseCrlDer, byte[] deltaCrlDer, GostCertificate cert, GostCertificate issuerCa)
            throws PkixException {
        verify(baseCrlDer, deltaCrlDer, cert, issuerCa, CrlLimits.DEFAULT);
    }

    /**
     * Проверяет пару base CRL + delta CRL с настраиваемыми лимитами.
     *
     * @param baseCrlDer        DER-encoded base CRL
     * @param deltaCrlDer       DER-encoded delta CRL
     * @param cert              проверяемый сертификат
     * @param issuerCa          сертификат CA, подписавшего оба CRL
     * @param limits            пределы размера и числа записей CRL
     * @throws PkixException если любой CRL невалиден, несовместим, не покрывает сертификат,
     *         сертификат отозван или у издателя нет права подписывать CRL
     */
    public static void verify(
            byte[] baseCrlDer,
            byte[] deltaCrlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            CrlLimits limits)
            throws PkixException {
        if (baseCrlDer == null || deltaCrlDer == null) {
            throw new PkixException("CRL must not be null");
        }
        if (cert == null) {
            throw new PkixException("cert must not be null");
        }
        requireIssuerCa(issuerCa);
        requireCrlSign(issuerCa);
        byte[] certSerial = cert.getSerialNumber();
        byte[] certIssuerDn = cert.getIssuerDnBytes();

        LOG.log(
                Level.DEBUG,
                "Verifying base+delta CRL for certificate serial 0x{0}",
                serialHex(cert));

        GostCrl base = parseCrl(baseCrlDer, limits);
        GostCrl delta = parseCrl(deltaCrlDer, limits);

        // Верификация: base без delta-допуска, delta с допуском
        base.verify(issuerCa.getPublicKey(), false);
        delta.verify(issuerCa.getPublicKey(), true);

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

        // Область (RFC 5280 §6.3.3(c)): предикаты без исключений, иначе чужой CRL с номером дал бы
        // IDP_NOT_SUPPORTED вместо REVOKED. AKI: оба keyIdentifier есть и различаются -> конфликт;
        // у одного нет -> предупреждение (оба CRL проверены ключом одного издателя, подпись уже
        // связывает их).
        boolean akiConflict = akiConflict(base, delta);
        boolean covered =
                isPartialScopeCovered(base, cert)
                        && isPartialScopeCovered(delta, cert)
                        && idpMatches(base, delta)
                        && !akiConflict;

        // Запись в delta (кроме REMOVE_FROM_CRL) определяет отзыв независимо от области
        boolean removedByDelta = false;
        if (delta.isRevoked(certSerial)) {
            if (delta.getReason(certSerial) != ReasonCode.REMOVE_FROM_CRL) {
                throw new PkixException(
                        PkixException.Reason.REVOKED, "Certificate is revoked per delta CRL");
            }
            // REMOVE_FROM_CRL снимает отзыв только при согласованной области: иначе чужой delta
            // снял бы отзыв, записанный в base
            removedByDelta = covered;
        }

        if (base.isRevoked(certSerial) && !removedByDelta) {
            throw new PkixException(
                    PkixException.Reason.REVOKED, "Certificate is revoked per base CRL");
        }

        if (!covered) {
            if (akiConflict) {
                throw new PkixException("CRL: delta AKI does not match base AKI");
            }
            String violation = partialScopeViolation(base, cert);
            if (violation == null) {
                violation = partialScopeViolation(delta, cert);
            }
            throw new PkixException(
                    PkixException.Reason.IDP_NOT_SUPPORTED,
                    violation != null
                            ? violation
                            : "CRL: base and delta IssuingDistributionPoint differ");
        }

        if (removedByDelta) {
            LOG.log(Level.DEBUG, "Certificate removed from CRL via delta (REMOVE_FROM_CRL)");
            return;
        }

        LOG.log(
                Level.DEBUG,
                "CRL verification passed for certificate serial 0x{0}",
                serialHex(cert));
    }

    /**
     * IDP base и delta совпадают побайтно по extnValue (RFC 5280 §6.3.3(c)): отдельные поля не
     * дают полного сравнения, например для onlySomeReasons хранится лишь признак. Флаг critical в
     * сравнении не участвует (библиотека принимает оба варианта). Оба без IDP тоже совпадают.
     * Разный порядок URI даёт расхождение, это допустимо.
     */
    private static boolean idpMatches(GostCrl base, GostCrl delta) {
        return Arrays.equals(base.getIdpExtnValue(), delta.getIdpExtnValue());
    }

    /**
     * Конфликт AKI base и delta: оба keyIdentifier есть и различаются. Если у одного его нет,
     * это предупреждение, а не конфликт: оба CRL проверены одним ключом, и подпись уже связывает
     * их с ним. Оба без keyIdentifier совпадают.
     */
    private static boolean akiConflict(GostCrl base, GostCrl delta) {
        byte[] baseAki = base.getAuthorityKeyIdentifier();
        byte[] deltaAki = delta.getAuthorityKeyIdentifier();
        if (baseAki == null || deltaAki == null) {
            if (baseAki != deltaAki) {
                // Данные издателя CRL, отказа нет: оператору нечего исправить, на DEBUG
                LOG.log(
                        Level.DEBUG,
                        "CRL: AKI keyIdentifier is present in only one of base/delta CRL");
            }
            return false;
        }
        return !Arrays.equals(baseAki, deltaAki);
    }

    /**
     * Парсит nextUpdate из CRL без полной верификации (для кэша).
     * <p>
     * В отличие от {@link #verify(byte[], GostCertificate, GostCertificate)}, этот метод
     * не проверяет подпись и не сканирует revoked-список — только извлекает дату
     * истечения срока действия CRL. Нужен {@code org.rssys.gost.jsse.crl.CrlCache}
     * чтобы определить момент инвалидации кэша.
     * <p>
     * Не создаёт объект {@link GostCrl} — использует облегчённый путь для производительности.
     * <p>
     * <b>Security:</b> результат получен из <b>неверифицированных</b> байт. Использовать
     * только для метаданных кэша (TTL/инвалидация), никогда — для acceptance-решения.
     * Решение об отзыве всегда проходит через полный
     * {@link #verify(byte[], GostCertificate, GostCertificate)} с проверкой подписи, поэтому
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
     * отзыва, которая всегда идёт через полный {@link #verify(byte[], GostCertificate, GostCertificate)}.
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
                        // critical разбор cRLNumber принимает: без пропуска BOOLEAN метаданные
                        // кэша (baseline защиты от отката) для такого CRL терялись бы
                        if (afterOid < oce
                                && (crlDer[afterOid] & 0xFF) == GostDerParser.TAG_BOOLEAN) {
                            afterOid = GostDerParser.readTlv(crlDer, afterOid)[1];
                        }
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

    // ========================================================================
    // Делегированная CRL-верификация (RFC 5280 §6.3.3(c))
    // ========================================================================

    /**
     * Проверяет CRL с поддержкой делегированных CRL-подписантов.
     * Использует лимиты по умолчанию.
     *
     * <p>Порядок: issuer DN match -> попытка ключом CA -> перебор CRL-подписантов.
     * Сертификаты подписантов валидируются: срок действия, обязательный KeyUsage с cRLSign
     * (отсутствие KeyUsage не принимается), отсутствие неизвестных critical-расширений,
     * подпись УЦ на сертификате подписанта.
     *
     * <p>Список подписантов должен быть доверенным: метод не связывает subject подписанта с
     * издателем CRL и не проверяет отзыв самого подписанта (для этого нужен CRL того же УЦ,
     * то есть рекурсия), это остаётся на вызывающем. Модель «подписант под другим DN» не
     * совпадает с indirect CRL по RFC 5280 §5.1.2.3, соответствие RFC вынесено отдельно.
     *
     * @param crlDer            DER-encoded CertificateList
     * @param cert              проверяемый сертификат (не путать с {@code issuerCa})
     * @param issuerCa          сертификат CA: его ключ проверяет подпись CRL и сертификаты
     *                          подписантов; если CRL подписан самим CA, у CA должен быть
     *                          {@code cRLSign} (при заданном KeyUsage)
     * @param crlSignerCertDers DER-encoded сертификаты CRL-подписантов (может быть null или пустой)
     * @throws PkixException если CRL невалиден, не покрывает сертификат, сертификат отозван или
     *         CRL подписан самим CA без права подписывать CRL ({@code MISSING_CRL_SIGN})
     */
    public static void verifyDelegated(
            byte[] crlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            List<byte[]> crlSignerCertDers)
            throws PkixException {
        verifyDelegated(crlDer, cert, issuerCa, crlSignerCertDers, null, CrlLimits.DEFAULT);
    }

    /**
     * Проверяет CRL с поддержкой делегированных CRL-подписантов
     * и проверкой монотонности cRLNumber.
     *
     * @param minCrlNumber минимально допустимый cRLNumber или null
     */
    public static void verifyDelegated(
            byte[] crlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            List<byte[]> crlSignerCertDers,
            BigInteger minCrlNumber)
            throws PkixException {
        verifyDelegated(crlDer, cert, issuerCa, crlSignerCertDers, minCrlNumber, CrlLimits.DEFAULT);
    }

    /**
     * Проверяет CRL с поддержкой делегированных CRL-подписантов и
     * настраиваемыми лимитами.
     *
     * <p>Порядок проверки (fail-closed):
     * <ol>
     *   <li>Парсинг CRL</li>
     *   <li>Сверка issuer DN CRL == issuer DN сертификата (прямой CRL)</li>
     *   <li>Попытка верификации ключом CA ({@code crl.verify(issuerCa ключ)}).
     *       indirectCRL -> IDP_NOT_SUPPORTED. При успехе у CA обязан быть cRLSign (если задан
     *       KeyUsage), иначе {@code MISSING_CRL_SIGN}</li>
     *   <li>Если CA-ключ не подошёл (SIGNATURE_INVALID) — перебор crlSignerCertDers:
     *       срок -> hasCrlSignKeyUsage() -> без неизвестных critical -> verifySignature(ключ CA)
     *       (цепочка) -> crl.verify(signerKey)</li>
     *   <li>cRLNumber монотонность (если задан minCrlNumber)</li>
     *   <li>Запись об отзыве сертификата, затем область CRL</li>
     * </ol>
     *
     * @param crlDer             DER-encoded CertificateList
     * @param cert               проверяемый сертификат (не путать с {@code issuerCa})
     * @param issuerCa           сертификат CA
     * @param crlSignerCertDers  DER-encoded сертификаты CRL-подписантов (может быть null или пустой)
     * @param minCrlNumber       минимально допустимый cRLNumber или null
     * @param limits             пределы размера и числа записей CRL
     * @throws PkixException если CRL невалиден, не покрывает сертификат или сертификат отозван
     */
    public static void verifyDelegated(
            byte[] crlDer,
            GostCertificate cert,
            GostCertificate issuerCa,
            List<byte[]> crlSignerCertDers,
            BigInteger minCrlNumber,
            CrlLimits limits)
            throws PkixException {
        requireInputs(crlDer, cert);
        requireIssuerCa(issuerCa);
        LOG.log(
                Level.DEBUG,
                "Verifying CRL (delegated) for certificate serial 0x{0}",
                serialHex(cert));

        GostCrl crl = parseCrl(crlDer, limits);
        requireIssuerDnMatch(crl, cert.getIssuerDnBytes());

        // Попытка 1: ключ CA
        boolean verified = false;
        try {
            crl.verify(issuerCa.getPublicKey());
            verified = true;
        } catch (PkixException e) {
            if (e.reason() != PkixException.Reason.SIGNATURE_INVALID) {
                throw e;
            }
            LOG.log(Level.DEBUG, "CA key verification failed, trying delegated signers");
        }
        // CRL подписан ключом самого CA: право подписывать CRL у CA обязано быть. Проверка стоит
        // после подписи, а не до неё: при чужой подписи CA без cRLSign не должен закрывать путь
        // делегированных подписантов
        if (verified) {
            requireCrlSign(issuerCa);
        }

        // Попытка 2: делегированные подписанты
        if (!verified && crlSignerCertDers != null) {
            for (byte[] signerDer : crlSignerCertDers) {
                GostCertificate signer;
                try {
                    signer = new GostCertificate(signerDer);
                } catch (RuntimeException e) {
                    LOG.log(Level.DEBUG, "Failed to parse CRL signer certificate", e);
                    continue;
                }

                if (signer.isExpired()) continue;
                // Строгий cRLSign: у делегированного подписанта нет иной границы полномочий
                // (связи с издателем CRL по имени нет), поэтому отсутствие KeyUsage не разрешение.
                if (!signer.hasCrlSignKeyUsage()) continue;
                // Подписант с непонятым critical-расширением не вправе подписывать CRL
                // (RFC 5280 §4.2: такой сертификат использовать нельзя).
                if (signer.hasUnknownCriticalExtension()) continue;

                // Цепочка: сертификат подписанта должен быть подписан CA
                if (!signer.verifySignature(issuerCa.getPublicKey())) continue;

                try {
                    crl.verify(signer.getPublicKey());
                    verified = true;
                    LOG.log(
                            Level.DEBUG,
                            "CRL verified with delegated signer: {0}",
                            signer.getSubjectDnForLog(GostCertificate.DN_LOG_MAX_CHARS));
                    break;
                } catch (PkixException e) {
                    if (e.reason() != PkixException.Reason.SIGNATURE_INVALID) {
                        throw e;
                    }
                }
            }
        }

        if (!verified) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID,
                    "CRL: no valid signer found (tried CA key"
                            + (crlSignerCertDers != null
                                    ? " + " + crlSignerCertDers.size() + " delegated"
                                    : "")
                            + ")");
        }

        requireCrlNumberNotBelow(crl, minCrlNumber);
        requireNotRevokedInScope(crl, cert);

        LOG.log(
                Level.DEBUG,
                "CRL verification (delegated) passed for certificate serial 0x{0}",
                serialHex(cert));
    }
}
