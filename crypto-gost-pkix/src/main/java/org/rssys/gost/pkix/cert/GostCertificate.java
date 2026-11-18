package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.CheckReturnValue;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Минимальный парсер X.509 сертификата для GOST R 34.10-2012.
 * Извлекает открытый ключ, подпись и верифицирует подпись сертификата.
 */
public final class GostCertificate {

    /** Максимальный размер одного сертификата в DER (256 КБ).
     *  Совпадает с {@code TlsConstants.MAX_CERT_SIZE} в tls13-модуле
     *  (модуль pkix не зависит от tls13, поэтому константа продублирована). */
    private static final int MAX_CERT_SIZE = 262_144;

    /**
     * Длина DN в записях журнала и диагностических строках по умолчанию. DN несёт персональные
     * данные, поэтому в журнал он попадает только усечённым и только на уровне DEBUG; в строках
     * {@code toString()} усечение защищает от слишком длинного вывода.
     */
    public static final int DN_LOG_MAX_CHARS = 128;

    // Индексы SEQUENCE в TBSCertificate для навигации (RFC 5280 §4.1)
    // SPKI — 5-я, Validity — 3-я SEQUENCE
    private static final int TBS_VALIDITY_SEQUENCE_INDEX = 3;
    private static final int TBS_SPKI_SEQUENCE_INDEX = 5;
    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.GostCertificate");

    /** Наибольшее значение поля version: 2 - v3 (RFC 5280 §4.1.2.1). */
    private static final int MAX_VERSION_VALUE = 2;

    // Версия X.509 v3 (в поле version хранится значение 2): с неё допустимы extensions
    private static final int CERT_VERSION_V2 = 2;
    private static final int CERT_VERSION_V3 = 3;
    private static final int ISSUER_DN_SKIP = 0;
    private static final int SUBJECT_DN_SKIP = 2;

    // OID известных X.509v3 расширений (dot-notation) для oid_filters matching.
    // Если сервер запросил фильтр с таким OID, а в сертификате расширения нет,
    private final byte[] certData;
    private final int tbsCertOff;
    private final int tbsCertLen;
    private final PublicKeyParameters publicKey;
    private final int sigOff;
    private final int sigLen;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String[] sanDnsNames;
    private final byte[][] sanIpAddresses;
    private final String[] sanRfc822Names;
    private final String[] sanUris;
    private final byte[][] sanDirectoryNames;
    private final OtherNameEntry[] sanOtherNames;
    private final Set<UnsupportedGeneralNameForm> sanUnsupportedNameForms;
    private final String[] ianDnsNames;
    private final byte[][] ianIpAddresses;
    private final String[] ianRfc822Names;
    private final String[] ianUris;
    private final byte[][] ianDirectoryNames;
    private final OtherNameEntry[] ianOtherNames;
    private final boolean keyUsageValid;
    private final boolean crlSignValid;
    private final boolean ekuValid;
    private final boolean ekuClientAuth;
    private final boolean ekuOcspSigning;
    private final boolean ekuTimeStamping;
    private final boolean isCA;
    private final int pathLen;
    private final boolean keyCertSign;
    private final boolean hasUnknownCritical;
    private final boolean algConsistent;
    private volatile byte[] ocspResponse;
    private volatile byte[] ocspNonce;
    private final int version;
    private final String subjectDnStr;
    private final String issuerDnStr;
    private final GostDnParser.DnField[] subjectDnFields;
    private final GostDnParser.DnField[] issuerDnFields;
    private final int serialOff;
    private final int serialLen;
    private final int issuerDnOff;
    private final int issuerDnLen;
    private final int subjectDnOff;
    private final int subjectDnLen;
    private final int spkiKeyValueOff;
    private final int spkiKeyValueLen;
    private final int spkiAlgIdOff;
    private final int spkiAlgIdLen;

    // OID алгоритма подписи (из signatureAlgorithm SEQUENCE) — для getSignatureAlgorithmOid()
    private final byte[] sigAlgOidBytes;
    // SubjectKeyIdentifier (2.5.29.14) — идентификатор ключа субъекта
    private final byte[] skiBytes;
    // AuthorityKeyIdentifier (2.5.29.35) — идентификатор ключа издателя
    private final byte[] akiBytes;
    // URI из AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) — OCSP и caIssuers
    private final String[] aiaUris;
    // id-ad-ocsp URI (1.3.6.1.5.5.7.48.1) — отдельно для OCSP-запросов
    private final String[] ocspUris;
    // id-ad-caIssuers URI (1.3.6.1.5.5.7.48.2) — промежуточные сертификаты
    private final String[] caIssuersUris;
    // URI из CRLDistributionPoints (2.5.29.31) — точки распространения CRL
    private final String[] cdpUris;
    // URI из FreshestCRL (2.5.29.46) — точки распространения delta CRL
    private final String[] freshestCrlUris;
    // OID политик сертификата (2.5.29.32) — идентификаторы политик
    private final String[] certPolicyOids;
    // Маска KeyUsage (2.5.29.15): 16-bit raw битовая маска
    private final int keyUsageBits;
    // Все OID ExtendedKeyUsage (2.5.29.37) в DER-байтах — для oid_filters matching
    private final byte[][] ekuOids;
    // OID политик CertificatePolicies (2.5.29.32) в DER-байтах — для oid_filters matching
    private final byte[][] cpOids;
    // Политики сертификата с опциональными CPS-квалификаторами (2.5.29.32)
    private final CertificatePolicy[] certPolicyInfos;
    // Множество всех OID расширений, присутствующих в сертификате (dot-нотация)
    private final Set<String> presentExtensionOids;
    private final Map<String, byte[]> extensionValues;
    // Name Constraints (RFC 5280 §4.2.1.10)
    private final NameConstraintsData nameConstraints;
    // Результат парсинга расширений — для bulk-доступа через getExtensions()
    private final GostExtensionParser.ExtensionsResult extResult;

    /**
     * Парсит DER-закодированный X.509 сертификат.
     *
     * <p><b>Безопасность:</b> конструктор НЕ валидирует границы DER-массива.
     * На повреждённом или обрезанном DER может выбросить любое непроверяемое исключение
     * ({@link ArrayIndexOutOfBoundsException}, {@link IllegalArgumentException},
     * {@link NullPointerException}). Вызывающий код, обрабатывающий недоверенный DER
     * (например, из сети, файла, пользовательского ввода), ОБЯЗАН оборачивать
     * вызов в {@code try { ... } catch (RuntimeException e)} и трактовать любое
     * исключение как «невалидный сертификат».</p>
     *
     * <p>Внутри TLS-handshake такая обёртка уже есть в вызывающем коде.</p>
     *
     * @param derEncoded полный сертификат в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null}
     *         или явно обнаружен невалидный синтаксис (например, неожиданный тег)
     * @throws RuntimeException на повреждённом DER — конкретный подкласс не специфицирован
     */
    public GostCertificate(byte[] derEncoded) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("Certificate DER must not be null");
        }
        if (derEncoded.length > MAX_CERT_SIZE) {
            throw new IllegalArgumentException(
                    "Certificate DER exceeds maximum size "
                            + MAX_CERT_SIZE
                            + ", got "
                            + derEncoded.length);
        }
        this.certData = derEncoded.clone();

        int[] outer = parseSequence(derEncoded, 0);
        // Сертификат - ровно один DER-элемент: хвост за ним не читается и не подписан, но
        // остался бы в certData и уходил дальше вместе с сертификатом
        if (outer[1] != derEncoded.length) {
            throw new IllegalArgumentException(
                    "Unexpected trailing data after certificate: "
                            + (derEncoded.length - outer[1])
                            + " byte(s)");
        }
        int certContentStart = outer[0];
        if (certContentStart >= outer[1]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: empty certificate SEQUENCE");
        }

        // Три потомка верхнего уровня: TBSCertificate, SignatureAlgorithm, SignatureValue
        int[] tbsTlv = readTlv(derEncoded, certContentStart, outer[1]);
        this.tbsCertOff = certContentStart;
        this.tbsCertLen = tbsTlv[1] - certContentStart;

        // Version: [0] EXPLICIT { INTEGER } (OPTIONAL, default v1)
        // Парсим до validity, чтобы не менять существующий parseValidity
        int v = 1;
        {
            int vPos = tbsTlv[0];
            if (vPos < tbsTlv[1] && (derEncoded[vPos] & 0xFF) == TAG_CTX_0) {
                int[] verTagTlv = readTlv(derEncoded, vPos, tbsTlv[1]);
                // verTagTlv[0] — начало INTEGER внутри [0] EXPLICIT; [0] расходуется целиком:
                // лишние байты после INTEGER - повреждённая структура, а не пропускаемые данные
                int[] versionAndEnd =
                        readStrictNonNegativeInt(derEncoded, verTagTlv[0], verTagTlv[1]);
                if (versionAndEnd[1] != verTagTlv[1]) {
                    throw new IllegalArgumentException("Unexpected trailing data in version field");
                }
                if (versionAndEnd[0] > MAX_VERSION_VALUE) {
                    throw new IllegalArgumentException(
                            "Unsupported certificate version value " + versionAndEnd[0]);
                }
                if (versionAndEnd[0] == 0) {
                    // v1 - значение DEFAULT, и DER (X.690 §11.5) требует его опустить. Явная
                    // запись встречается у старых издателей и безвредна: допускаем и помечаем
                    LOG.log(Level.DEBUG, "Certificate has explicit default version v1");
                }
                v = versionAndEnd[0] + 1;
            }
        }
        this.version = v;

        // Validity (notBefore, notAfter)
        Instant[] validity = parseValidity(derEncoded, tbsTlv);
        this.notBefore = validity[0];
        this.notAfter = validity[1];

        // Issuer DN (4-я SEQUENCE в TBS)
        int[] issuerOffLen = parseDnByIndex(derEncoded, tbsTlv, ISSUER_DN_SKIP);
        this.issuerDnOff = issuerOffLen[0];
        this.issuerDnLen = issuerOffLen[1];
        // Subject DN (6-я SEQUENCE в TBS)
        int[] subjectOffLen = parseDnByIndex(derEncoded, tbsTlv, SUBJECT_DN_SKIP);
        this.subjectDnOff = subjectOffLen[0];
        this.subjectDnLen = subjectOffLen[1];

        // DN строки: парсим в человеко-читаемый формат.
        // try-catch — если DER повреждён, возвращаем null вместо падения.
        GostDnParser.DnParseResult subjectDnR =
                GostDnParser.parseDnString(derEncoded, this.subjectDnOff, this.subjectDnLen);
        this.subjectDnStr = subjectDnR.dnString;
        this.subjectDnFields =
                subjectDnR.fields.isEmpty()
                        ? null
                        : subjectDnR.fields.toArray(new GostDnParser.DnField[0]);
        GostDnParser.DnParseResult issuerDnR =
                GostDnParser.parseDnString(derEncoded, this.issuerDnOff, this.issuerDnLen);
        this.issuerDnStr = issuerDnR.dnString;
        this.issuerDnFields =
                issuerDnR.fields.isEmpty()
                        ? null
                        : issuerDnR.fields.toArray(new GostDnParser.DnField[0]);

        // SignatureAlgorithm (SEQUENCE of OID + params) — извлекаем OID
        int[] sigAlgTlv = readTlv(derEncoded, tbsTlv[1], outer[1]);
        if (sigAlgTlv[0] < sigAlgTlv[1] && (derEncoded[sigAlgTlv[0]] & 0xFF) == TAG_OID) {
            int[] oidTlv = readTlv(derEncoded, sigAlgTlv[0], sigAlgTlv[1]);
            this.sigAlgOidBytes = Arrays.copyOfRange(derEncoded, oidTlv[0], oidTlv[1]);
        } else {
            this.sigAlgOidBytes = new byte[0];
        }

        // SignatureValue (BIT STRING)
        int sigTagOffset = sigAlgTlv[1];
        if (sigTagOffset >= outer[1]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: missing signature at offset " + sigTagOffset);
        }
        // Тег сверяется целиком: маска 0x1F пропускала бы 0x23 (constructed), 0x43 и 0x83
        // (другие классы), то есть другое DER-кодирование того же сертификата
        if ((derEncoded[sigTagOffset] & 0xFF) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("Expected BIT STRING for signature");
        }
        int[] sigValTlv = readTlv(derEncoded, sigTagOffset, outer[1]);
        if (sigValTlv[1] <= sigValTlv[0]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: empty BIT STRING for signature at offset "
                            + sigTagOffset);
        }
        // Подпись - последний элемент сертификата: байты за ней внутри внешней SEQUENCE не
        // покрыты подписью (она считается только по TBS) и меняли бы отпечаток
        if (sigValTlv[1] != outer[1]) {
            throw new IllegalArgumentException(
                    "Unexpected trailing data after signature value in certificate");
        }
        int unusedBits = derEncoded[sigValTlv[0]] & 0xFF;
        if (unusedBits != 0) {
            throw new IllegalArgumentException("Unsupported BIT STRING with unused bits");
        }
        this.sigOff = sigValTlv[0] + 1;
        this.sigLen = sigValTlv[1] - sigValTlv[0] - 1;

        // Извлекаем SubjectPublicKeyInfo и BIT STRING value из TBSCertificate
        SpkiExtractResult spki = extractPublicKeyAndKeyValue(derEncoded, tbsTlv);
        this.publicKey = spki.publicKey;
        this.spkiKeyValueOff = spki.spkiKeyValueOff;
        this.spkiKeyValueLen = spki.spkiKeyValueLen;
        this.spkiAlgIdOff = spki.spkiAlgIdOff;
        this.spkiAlgIdLen = spki.spkiAlgIdLen;

        // Парсим SubjectAltName, KeyUsage, ExtendedKeyUsage, BasicConstraints из extensions
        this.extResult = parseExtensions(derEncoded, tbsTlv, v);
        this.sanDnsNames = extResult.sanDnsNames;
        this.sanIpAddresses = extResult.sanIpAddresses;
        this.sanRfc822Names = extResult.sanRfc822Names;
        this.sanUris = extResult.sanUris;
        this.sanDirectoryNames = extResult.sanDirectoryNames;
        this.sanOtherNames = extResult.sanOtherNames;
        this.sanUnsupportedNameForms = extResult.sanUnsupportedNameForms;
        this.ianDnsNames = extResult.ianDnsNames;
        this.ianIpAddresses = extResult.ianIpAddresses;
        this.ianRfc822Names = extResult.ianRfc822Names;
        this.ianUris = extResult.ianUris;
        this.ianDirectoryNames = extResult.ianDirectoryNames;
        this.ianOtherNames = extResult.ianOtherNames;
        this.keyUsageValid = extResult.keyUsageValid;
        this.crlSignValid = extResult.crlSignValid;
        this.ekuValid = extResult.ekuValid;
        this.ekuClientAuth = extResult.ekuClientAuth;
        this.ekuOcspSigning = extResult.ekuOcspSigning;
        this.ekuTimeStamping = extResult.ekuTimeStamping;
        this.isCA = extResult.isCA;
        this.pathLen = extResult.pathLen;
        this.keyCertSign = extResult.keyCertSign;
        this.hasUnknownCritical = extResult.hasUnknownCritical;
        this.skiBytes = extResult.skiBytes;
        this.akiBytes = extResult.akiBytes;
        this.aiaUris = extResult.aiaUris;
        this.ocspUris = extResult.ocspUris;
        this.caIssuersUris = extResult.caIssuersUris;
        this.cdpUris = extResult.cdpUris;
        this.freshestCrlUris = extResult.freshestCrlUris;
        this.certPolicyOids = extResult.certPolicyOids;
        this.keyUsageBits = extResult.keyUsageBits;
        this.ekuOids = extResult.ekuOids;
        this.cpOids = extResult.cpOids;
        this.certPolicyInfos = extResult.certPolicies;
        this.presentExtensionOids = extResult.presentExtensionOids;
        this.extensionValues = extResult.extensionValues;
        this.nameConstraints = extResult.nameConstraints;

        // Проверка согласованности алгоритма (RFC 5280 §4.1.1.2):
        // signatureAlgorithm (вне TBS) должен совпадать с TBSCertificate.signature
        // signatureAlgorithm = SEQUENCE в derEncoded между tbsTlv[1] и sigAlgTlv[1]
        int outerSigOff = tbsTlv[1];
        int outerSigLen = sigAlgTlv[1] - tbsTlv[1];
        // TBSCertificate.signature — вторая SEQUENCE внутри TBS (после version, serial)
        int tbsPos = tbsTlv[0];
        if (tbsPos < tbsTlv[1] && (derEncoded[tbsPos] & 0xFF) == 0xA0) {
            tbsPos = readTlv(derEncoded, tbsPos, tbsTlv[1])[1];
        }
        int[] serialTlv = readTlv(derEncoded, tbsPos, tbsTlv[1]);
        this.serialOff = serialTlv[0];
        this.serialLen = serialTlv[1] - serialTlv[0];
        tbsPos = serialTlv[1];
        // signature — SEQUENCE внутри TBS
        if (tbsPos < tbsTlv[1] && (derEncoded[tbsPos] & 0xFF) == TAG_SEQUENCE) {
            int[] tbsSigTlv = readTlv(derEncoded, tbsPos, tbsTlv[1]);
            this.algConsistent =
                    outerSigLen == tbsSigTlv[1] - tbsPos
                            && arrayRangeEquals(
                                    derEncoded,
                                    outerSigOff,
                                    outerSigLen,
                                    derEncoded,
                                    tbsPos,
                                    tbsSigTlv[1] - tbsPos);
        } else {
            this.algConsistent = false;
        }
    }

    /**
     * @return открытый ключ, извлечённый из сертификата
     */
    public PublicKeyParameters getPublicKey() {
        return publicKey;
    }

    /**
     * Верифицирует подпись сертификата с использованием ключа удостоверяющего центра.
     * Проверяет только криптографическую подпись (не сроки, не статус отзыва).
     *
     * @param caPublicKey открытый ключ издателя сертификата
     * @return true если подпись действительна
     */
    @CheckReturnValue
    public boolean verifySignature(PublicKeyParameters caPublicKey) {
        // Whitelist допустимых OID алгоритма подписи (defense-in-depth)
        if (!matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_256_OID_BYTES)
                && !matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_512_OID_BYTES)
                && !matchesOid(
                        sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_DIGEST_256_OID_BYTES)
                && !matchesOid(
                        sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_DIGEST_512_OID_BYTES)) {
            return false;
        }
        int hlen = caPublicKey.getParams().hlen;
        Digest.Algorithm hashAlg = GostSignatureHelper.digestAlgByHlen(hlen);
        Digest digest = new Digest(hashAlg);
        digest.update(certData, tbsCertOff, tbsCertLen);
        byte[] hash = digest.digest();

        byte[] sigCopy = new byte[sigLen];
        System.arraycopy(certData, sigOff, sigCopy, 0, sigLen);
        // Подпись неверной длины - не валидная подпись: verifyHash возвращает false
        return Signature.verifyHash(hash, sigCopy, caPublicKey);
    }

    /**
     * @return true если срок действия сертификата истёк (с учётом clock skew)
     */
    @CheckReturnValue
    public boolean isExpired() {
        Instant now = Instant.now();
        return now.isBefore(notBefore.minusMillis(GostOids.CLOCK_SKEW_MS))
                || now.isAfter(notAfter.plusMillis(GostOids.CLOCK_SKEW_MS));
    }

    /**
     * Проверяет hostname сервера против SubjectAltName/dNSName по RFC 6125.
     * <p>
     * Поддерживаются только dNSName entries; CN из Subject не используется
     * (RFC 6125 §6.4.4, deprecated в современных TLS-стеках). Если SAN
     * отсутствует — проверка не проходит.
     * <p>
     * IssuerAltName (IAN) <b>не участвует</b> в проверке: IAN описывает
     * identity издателя, а не субъекта (RFC 5280 §4.2.1.7). Подключение
     * IAN к hostname-верификации — дыра: CA-сертификат может нести
     * произвольные dNSName в IssuerAltName, и они не должны влиять
     * на аутентификацию хоста.
     * <p>
     * Wildcard (*.example.com) матчит ровно одну метку слева.
     * Частичные wildcard (f*.example.com) запрещены. IDN-домены допускаются
     * в A-label; Unicode-имя преобразуется в A-label перед сравнением.
     *
     * @param hostname DNS-имя сервера; {@code null} и пустая строка дают
     *                 {@code false}. Если проверка имени не нужна, вызывающий
     *                 обязан явно её не вызывать, а не передавать {@code null}
     * @return {@code true} только если hostname соответствует сертификату;
     *         {@code false} в остальных случаях
     */
    @CheckReturnValue
    public boolean verifyHostname(String hostname) {
        if (hostname == null) return false;
        if (hostname.isEmpty()) return false;

        // Вся нормализация (края, регистр, завершающая точка, IDN) - в GostDnsName: второй
        // собственный разбор здесь расходился бы с ним в границах случаев (например, по числу
        // срезаемых точек). Ошибка преобразования - это несовпадение, а не исключение.
        String normalized;
        try {
            normalized = GostDnsName.toAsciiHostname(hostname);
        } catch (IllegalArgumentException e) {
            return false;
        }

        // IP-адрес -> проверка против iPAddress SAN (tag 0x87). Квадратные скобки - синтаксис
        // URI-хоста, не часть адреса; их снимает разбор литерала.
        byte[] rawAddress = GostDnsName.parseIpAddress(normalized);
        if (rawAddress != null) {
            return verifyAddress(rawAddress);
        }

        // DNS-проверка требует хотя бы одного dNSName в SAN
        if (sanDnsNames == null) return false;

        for (String san : sanDnsNames) {
            if (matchDnsName(normalized, san)) return true;
        }
        return false;
    }

    /**
     * Атомарное сопоставление нормализованного hostname с одним dNSName из SAN.
     * <p>
     * Поддерживает точное совпадение и wildcard {@code *.example.com}.
     * Частичные wildcard ({@code f*.example.com}) запрещены. IDN-зоны
     * в A-label допустимы ({@code *.example.xn--p1ai}), но wildcard не может
     * покрывать всю публичную зону ({@code *.xn--p1ai}).
     *
     * @param normalizedHostname нормализованный hostname (trim, lowercase, без trailing dot)
     * @param sanDnsName         одно dNSName значение из SAN (не нормализовано)
     * @return {@code true} если hostname соответствует dNSName
     */
    static boolean matchDnsName(String normalizedHostname, String sanDnsName) {
        String sanLower = sanDnsName.toLowerCase(Locale.ROOT);

        // Точное совпадение
        if (normalizedHostname.equals(sanLower)) return true;

        // Wildcard: должен начинаться с "*."
        if (!sanLower.startsWith("*.")) return false;

        String suffix = sanLower.substring(2); // всё после "*."

        // Wildcard не должен быть "*." + apex (напр. *.com)
        if (suffix.isEmpty() || suffix.indexOf('.') < 0) return false;

        // Частичный wildcard (f*.example.com) запрещён
        if (sanLower.indexOf('*', 1) >= 0) return false;

        // Первая метка hostname не должна быть пустой и не должна содержать точек
        int firstDot = normalizedHostname.indexOf('.');
        if (firstDot <= 0) return false;

        String firstLabel = normalizedHostname.substring(0, firstDot);
        if (firstLabel.isEmpty()) return false;

        // Оставшаяся часть hostname должна совпадать с suffix
        String rest = normalizedHostname.substring(firstDot + 1);
        return rest.equals(suffix);
    }

    /**
     * Проверяет IP-адрес против iPAddress SAN (RFC 5280 §4.2.1.6).
     *
     * <p>Принимаются только IP-литералы (IPv4, IPv6, IPv6 в квадратных скобках, IPv6 с зоной):
     * имя хоста не резолвится, обращений к DNS нет. IPv4-mapped IPv6 сопоставляется как IPv4.</p>
     *
     * @param ipAddress IP-литерал; не IP-литерал даёт {@code false}
     * @return true если адрес найден в SAN iPAddress entries
     */
    @CheckReturnValue
    public boolean verifyAddress(String ipAddress) {
        byte[] rawAddress = GostDnsName.parseIpAddress(ipAddress);
        return rawAddress != null && verifyAddress(rawAddress);
    }

    /**
     * Проверяет raw IP-адрес (4 или 16 байт) против iPAddress SAN.
     *
     * @param rawAddress raw IP-адрес (4 или 16 байт)
     * @return true если адрес найден в SAN iPAddress entries
     */
    @CheckReturnValue
    public boolean verifyAddress(byte[] rawAddress) {
        if (sanIpAddresses == null || rawAddress == null) return false;
        for (byte[] ip : sanIpAddresses) {
            if (Arrays.equals(ip, rawAddress)) return true;
        }
        return false;
    }

    /**
     * @return массив raw IP-адресов из SAN iPAddress entries или null
     *         Возвращает defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public byte[][] getSanIpAddresses() {
        if (sanIpAddresses == null) return null;
        byte[][] copy = new byte[sanIpAddresses.length][];
        for (int i = 0; i < sanIpAddresses.length; i++) {
            copy[i] = sanIpAddresses[i].clone();
        }
        return copy;
    }

    /**
     * @return массив raw IP-адресов из IssuerAltName iPAddress entries или null.
     *         Возвращает defensive copy — caller не может модифицировать внутреннее состояние.
     *         <p>
     *         Информационное расширение (RFC 5280 §4.2.1.7): identity издателя,
     *         не субъекта. Не участвует в hostname-верификации (RFC 6125)
     *         и в построении/валидации цепочек (RFC 5280 §6.1).
     */
    public byte[][] getIssuerAltNameIpAddresses() {
        if (ianIpAddresses == null) return null;
        byte[][] copy = new byte[ianIpAddresses.length][];
        for (int i = 0; i < ianIpAddresses.length; i++) {
            copy[i] = ianIpAddresses[i].clone();
        }
        return copy;
    }

    /**
     * @return true если KeyUsage не задан или содержит digitalSignature (RFC 8446 §4.4.2.2)
     */
    public boolean isKeyUsageValid() {
        return keyUsageValid;
    }

    /**
     * Проверяет, разрешён ли сертификат для подписи CMS.
     * <p>
     * В отличие от TLS, где требуется {@code digitalSignature}, CMS допускает
     * также {@code nonRepudiation} (RFC 5280 §4.2.1.3). Отсутствие KeyUsage
     * означает отсутствие ограничений по ключу.
     *
     * @return true если KeyUsage не задан или содержит digitalSignature/nonRepudiation
     */
    public boolean isKeyUsageValidForSigning() {
        if (!presentExtensionOids.contains(GostOids.EXT_KU)) {
            return true;
        }
        return (keyUsageBits
                        & (GostDerParser.KU_DIGITAL_SIGNATURE | GostDerParser.KU_NON_REPUDIATION))
                != 0;
    }

    /**
     * Проверяет, предназначен ли ключ сертификата для шифрования, то есть может ли сертификат
     * быть получателем CMS EnvelopedData (ktri и kari). Парно {@link #isKeyUsageValidForSigning()}.
     *
     * <p>Если KeyUsage не задан, ограничений нет. Если задан, нужен хотя бы один из битов
     * {@code keyEncipherment}, {@code keyAgreement}, {@code dataEncipherment}, в обоих режимах
     * одинаково. Критичность расширения не влияет. {@code encipherOnly} и {@code decipherOnly}
     * не учитываются: для получателя в VKO их смысл неоднозначен.
     *
     * <p>Это сознательное отступление от RFC 5652 §6.2.1 и §6.2.2, где бит привязан к типу
     * RecipientInfo (ktri - {@code keyEncipherment}, kari - {@code keyAgreement}), и от буквы
     * RFC 9215 §4.4. В ГОСТ оба режима строятся на VKO (RFC 4490 §4.1.1, §4.2.1), а RFC 9215 §6
     * (информационный профиль ключей ГОСТ Р 34.10-2012 в PKIX) указывает, что
     * {@code keyEncipherment} и {@code dataEncipherment} для таких ключей определены не
     * полностью. Строгая привязка бита к режиму отвергла бы выпускаемые удостоверяющими центрами
     * сертификаты без {@code keyAgreement}, на которые контейнер при этом расшифровывается.
     * Набор битов совпадает с поведением КриптоПро CSP 5.0 (cryptcp -encr отвергает сертификаты
     * только для подписи и для УЦ и принимает сертификат с любым из этих трёх битов).
     * Сертификат только для подписи отвергается (RFC 4491 §3).
     *
     * @return true если KeyUsage не задан или содержит keyEncipherment, keyAgreement либо
     *         dataEncipherment
     */
    public boolean isKeyUsageValidForEncryption() {
        if (!presentExtensionOids.contains(GostOids.EXT_KU)) {
            return true;
        }
        return (keyUsageBits
                        & (GostDerParser.KU_KEY_ENCIPHERMENT
                                | GostDerParser.KU_KEY_AGREEMENT
                                | GostDerParser.KU_DATA_ENCIPHERMENT))
                != 0;
    }

    /**
     * Мягкая проверка права подписывать CRL <b>для прямого пути</b>, где CRL подписан ключом
     * самого УЦ: отсутствие KeyUsage трактуется как «без ограничений» (RFC 5280 §4.2.1.3).
     * Для делегированных подписантов не подходит, см. {@link #hasCrlSignKeyUsage()}.
     *
     * @return true если KeyUsage не задан или содержит cRLSign
     */
    public boolean isCrlSigner() {
        return crlSignValid;
    }

    /**
     * Строгая проверка права подписывать CRL <b>для делегированного подписанта</b>: KeyUsage
     * обязан присутствовать и содержать cRLSign. Отсутствие KeyUsage здесь не разрешение:
     * у делегированного подписанта нет иной границы полномочий (связи по имени с издателем
     * CRL нет), поэтому любой сертификат УЦ без KeyUsage иначе подписал бы CRL от его имени.
     *
     * @return true только если KeyUsage задан и содержит cRLSign
     */
    public boolean hasCrlSignKeyUsage() {
        return presentExtensionOids.contains(GostOids.EXT_KU)
                && (keyUsageBits & GostDerParser.KU_CRL_SIGN) != 0;
    }

    /** @return true если EKU не задан или содержит serverAuth */
    public boolean isEkuValidForServer() {
        return ekuValid;
    }

    /** @return true если EKU не задан или содержит clientAuth */
    public boolean isEkuValidForClient() {
        return ekuClientAuth;
    }

    /**
     * @return true если EKU содержит id-kp-OCSPSigning; сертификат без EKU
     *     подписантом OCSP-ответа не считается (RFC 6960 §4.2.2.2 требует явного EKU)
     */
    public boolean isOcspSigning() {
        return ekuOcspSigning;
    }

    /**
     * @return true если сертификат несёт расширение id-pkix-ocsp-nocheck
     *     (RFC 6960 §4.2.2.2.1). Значение расширения пустое (DER NULL), поэтому важен
     *     только факт присутствия.
     */
    public boolean hasOcspNoCheck() {
        return presentExtensionOids.contains(GostOids.EXT_OCSP_NOCHECK);
    }

    /** @return true если сертификат имеет EKU id-kp-timeStamping (RFC 3161 §2.3) */
    public boolean isTimeStamping() {
        return ekuTimeStamping;
    }

    /** @return true если сертификат является CA (BasicConstraints.cA=TRUE) */
    public boolean isCA() {
        return isCA;
    }

    /** @return pathLenConstraint, или -1 если не задан */
    public int getPathLen() {
        return pathLen;
    }

    /** @return true если KU.keyCertSign задан или KU отсутствует */
    public boolean isKeyCertSignSet() {
        return keyCertSign;
    }

    /** @return true если найдено unknown critical extension (RFC 5280 §4.2) */
    public boolean hasUnknownCriticalExtension() {
        return hasUnknownCritical;
    }

    /**
     * Возвращает данные расширения Name Constraints (RFC 5280 §4.2.1.10).
     *
     * <p>Результат - независимая копия: правка его массивов не влияет на проверку цепочки.</p>
     *
     * @return распарсенные ограничения имён или {@link NameConstraintsData#EMPTY} если расширение отсутствует
     */
    public NameConstraintsData getNameConstraints() {
        return GostExtensionParser.ExtensionsResult.copyNameConstraints(nameConstraintsInternal());
    }

    /**
     * Ограничения имён без копирования - для проверки цепочки внутри пакета. Наружу не отдаются:
     * поля объекта - публичные изменяемые массивы, и их правка меняла бы результат проверки.
     */
    NameConstraintsData nameConstraintsInternal() {
        NameConstraintsData nc = nameConstraints;
        return nc != null ? nc : NameConstraintsData.EMPTY;
    }

    /** @return true если SignatureAlgorithm внутри и вне TBS совпадает (RFC 5280 §4.1.1.2) */
    public boolean isAlgConsistent() {
        return algConsistent;
    }

    /** @return дата начала действия сертификата */
    public Instant getNotBefore() {
        return notBefore;
    }

    /** @return дата окончания действия сертификата */
    public Instant getNotAfter() {
        return notAfter;
    }

    /**
     * @return массив dNSName из SubjectAltName или null.
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public String[] getSanDnsNames() {
        return sanDnsNames == null ? null : sanDnsNames.clone();
    }

    /**
     * @return массив dNSName из IssuerAltName или null.
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     *         <p>
     *         Информационное расширение (RFC 5280 §4.2.1.7): identity издателя,
     *         не субъекта. Не участвует в hostname-верификации (RFC 6125)
     *         и в построении/валидации цепочек (RFC 5280 §6.1).
     */
    public String[] getIssuerAltNameDnsNames() {
        return ianDnsNames == null ? null : ianDnsNames.clone();
    }

    /** @return массив rfc822Name из SubjectAltName или null. Defensive copy. */
    public String[] getSanRfc822Names() {
        return sanRfc822Names == null ? null : sanRfc822Names.clone();
    }

    /** @return массив rfc822Name из IssuerAltName или null. Defensive copy. */
    public String[] getIssuerAltNameRfc822Names() {
        return ianRfc822Names == null ? null : ianRfc822Names.clone();
    }

    /** @return массив URI из SubjectAltName или null. Defensive copy. */
    public String[] getSanUris() {
        return sanUris == null ? null : sanUris.clone();
    }

    /** @return массив URI из IssuerAltName или null. Defensive copy. */
    public String[] getIssuerAltNameUris() {
        return ianUris == null ? null : ianUris.clone();
    }

    /** @return массив raw DER DN из SAN directoryName или null. Defensive copy. */
    public byte[][] getSanDirectoryNames() {
        if (sanDirectoryNames == null) return null;
        byte[][] copy = new byte[sanDirectoryNames.length][];
        for (int i = 0; i < sanDirectoryNames.length; i++) {
            copy[i] = sanDirectoryNames[i].clone();
        }
        return copy;
    }

    /** @return массив raw DER DN из IAN directoryName или null. Defensive copy. */
    public byte[][] getIssuerAltNameDirectoryNames() {
        if (ianDirectoryNames == null) return null;
        byte[][] copy = new byte[ianDirectoryNames.length][];
        for (int i = 0; i < ianDirectoryNames.length; i++) {
            copy[i] = ianDirectoryNames[i].clone();
        }
        return copy;
    }

    /** @return массив otherName из SubjectAltName или null. Defensive copy. */
    public OtherNameEntry[] getSanOtherNames() {
        return sanOtherNames == null ? null : sanOtherNames.clone();
    }

    /**
     * Неподдерживаемые формы GeneralName в SubjectAltName: otherName, x400Address,
     * ediPartyName, registeredID. Нужны для NameConstraints: ограничение на такую форму
     * проверить нельзя, поэтому при пересечении с формами в NameConstraints цепочка
     * отклоняется.
     *
     * @return неизменяемое множество; пустое, если таких имён в SAN нет
     */
    public Set<UnsupportedGeneralNameForm> getSanUnsupportedNameForms() {
        return sanUnsupportedNameForms;
    }

    /** @return массив otherName из IssuerAltName или null. Defensive copy. */
    public OtherNameEntry[] getIssuerAltNameOtherNames() {
        return ianOtherNames == null ? null : ianOtherNames.clone();
    }

    /**
     * @return raw OCSP-ответ из CertificateEntry (null если нет status_request).
     *         Defensive copy — caller не может модифицировать внутренний OCSP-ответ.
     */
    public byte[] getOcspResponse() {
        byte[] resp = ocspResponse;
        return resp == null ? null : resp.clone();
    }

    /**
     * TLS-internal. Устанавливает OCSP-ответ, полученный при TLS-рукопожатии
     * (RFC 8446 §4.4.2.1, status_request). Не предназначен для вызова
     * пользовательским кодом.
     *
     * @param data OCSP-ответ из CertificateEntry status_request.
     *             Defensive copy — caller не может модифицировать внутренний OCSP-ответ.
     */
    public void setOcspResponse(byte[] data) {
        this.ocspResponse = data == null ? null : data.clone();
    }

    /**
     * @return true если в сертификате есть OCSP-ответ (status_request).
     *         Полезен для быстрой проверки без клонирования массива.
     */
    public boolean hasOcspResponse() {
        return ocspResponse != null;
    }

    /** @return серийный номер сертификата в DER INTEGER */
    public byte[] getSerialNumber() {
        byte[] result = new byte[serialLen];
        System.arraycopy(certData, serialOff, result, 0, serialLen);
        return result;
    }

    /** @return полный DER-encoded сертификат (defensive copy) */
    public byte[] getEncoded() {
        return certData.clone();
    }

    /**
     * Кодирует сертификат в PEM-формат (Base64 с заголовками).
     * <p>Симметричный аналог {@link #fromPemOrDer(byte[])}.
     * <p>Строка содержит ровно один блок {@code -----BEGIN CERTIFICATE-----}.
     * Для записи в файл: {@code Files.write(path, cert.toPem().getBytes())}.
     *
     * @return PEM-строка (включая заголовки и переводы строк)
     */
    public String toPem() {
        return GostPemUtils.toPem(getEncoded());
    }

    /**
     * Кодирует цепочку сертификатов в PEM-формат.
     * <p>Симметричный аналог {@link #listFromPem(byte[])}.
     * <p>Порядок сертификатов сохраняется: от leaf до root.
     * Результат можно записать в файл для nginx / trust store.
     *
     * @param chain цепочка сертификатов
     * @return PEM-строка с несколькими блоками {@code -----BEGIN CERTIFICATE-----}
     */
    public static String chainToPem(List<GostCertificate> chain) {
        if (chain == null) {
            throw new IllegalArgumentException("chain must not be null");
        }
        StringBuilder sb = new StringBuilder();
        for (GostCertificate cert : chain) {
            sb.append(cert.toPem());
        }
        return sb.toString();
    }

    /** @return raw DER Issuer Distinguished Name */
    public byte[] getIssuerDnBytes() {
        byte[] result = new byte[issuerDnLen];
        System.arraycopy(certData, issuerDnOff, result, 0, issuerDnLen);
        return result;
    }

    /** @return raw DER Subject Distinguished Name */
    public byte[] getSubjectDnBytes() {
        byte[] result = new byte[subjectDnLen];
        System.arraycopy(certData, subjectDnOff, result, 0, subjectDnLen);
        return result;
    }

    /**
     * @return BIT STRING value из SubjectPublicKeyInfo, включая ведущий октет unused-bits.
     *         Для issuerKeyHash и ResponderID.byKey (RFC 6960 §4.1.1) не подходит:
     *         используйте {@link #getSpkiKeyBits()}
     */
    public byte[] getSpkiKeyValue() {
        byte[] result = new byte[spkiKeyValueLen];
        System.arraycopy(certData, spkiKeyValueOff, result, 0, spkiKeyValueLen);
        return result;
    }

    /**
     * Возвращает биты открытого ключа из SubjectPublicKeyInfo без тега, длины и октета
     * unused-bits: именно от них RFC 6960 §4.1.1 требует считать issuerKeyHash и
     * ResponderID.byKey. Для ГОСТ-ключа это DER {@code OCTET STRING(x_LE || y_LE)}.
     *
     * @return байты ключа без unused-bits (защитная копия)
     * @throws IllegalStateException если октет unused-bits не равен нулю (fail-closed:
     *         ГОСТ-ключ всегда кратен восьми битам)
     */
    public byte[] getSpkiKeyBits() {
        if (spkiKeyValueLen < 2 || certData[spkiKeyValueOff] != 0) {
            throw new IllegalStateException("SubjectPublicKey BIT STRING has non-zero unused bits");
        }
        return java.util.Arrays.copyOfRange(
                certData, spkiKeyValueOff + 1, spkiKeyValueOff + spkiKeyValueLen);
    }

    /**
     * Возвращает AlgorithmIdentifier из SubjectPublicKeyInfo сертификата — DER-элемент
     * SEQUENCE с OID открытого ключа и параметрами (включая {@code publicKeyParamSet}
     * и {@code digestParamSet}).
     * <p>
     * Нужен для точного воспроизведения представления ключа получателя в эфемерном
     * ключе CMS EnvelopedData: Р 1323565.1.025-2019 §8.4.2.2 требует, чтобы ASN.1-идентификаторы
     * и параметры эфемерного ключа в точности совпадали с представлением в сертификате.
     *
     * @return DER AlgorithmIdentifier из SPKI
     */
    public byte[] getSpkiAlgorithmId() {
        byte[] result = new byte[spkiAlgIdLen];
        System.arraycopy(certData, spkiAlgIdOff, result, 0, spkiAlgIdLen);
        return result;
    }

    /**
     * Побайтовое сравнение subjectDN двух сертификатов без копирования — security-grade.
     * <p>
     * В отличие от {@link #isSelfIssued()} (помечен «НЕ security check», сравнивает issuer==subject
     * внутри одного сертификата), этот метод сравнивает subjectDN двух разных сертификатов
     * напрямую из certData через {@link GostDerParser#arrayRangeEquals} — без копирования,
     * детерминированно и пригоден для security-решений.
     * Используется в {@code ChainValidator} для подсчёта self-issued сертификатов в pathLen.
     * <p>
     * <b>Осознанный трейд-офф:</b> сравнение побайтовое, а не семантическое
     * (через X500Name). RFC 5280 §4.1.2.4 требует DER (каноническая кодировка) —
     * два семантически эквивалентных DN обязаны иметь идентичное DER-представление.
     * Единственное реалистичное последствие — false positive: легитимный self-issued
     * сертификат с неканоничным DER-кодированием DN посчитается как не-self-issued
     * -> более строгий pathLen (fail-closed, не security bypass). Обратная ситуация
     * (обход pathLen) нереалистична — DN контролируется CA.
     * Исторически «умная» нормализация DN (X500Name, LdapName) сама была источником
     * реальных уязвимостей в PKI-реализациях: Unicode confusables, whitespace-нормализация.
     *
     * @param a первый сертификат
     * @param b второй сертификат
     * @return true если subjectDN побайтово совпадает
     */
    static boolean subjectDnEquals(GostCertificate a, GostCertificate b) {
        return GostDerParser.arrayRangeEquals(
                a.certData,
                a.subjectDnOff,
                a.subjectDnLen,
                b.certData,
                b.subjectDnOff,
                b.subjectDnLen);
    }

    /**
     * TLS-internal. Возвращает nonce, установленный через {@link #setOcspNonce(byte[])}
     * при TLS-рукопожатии (RFC 8446 §4.4.2.1, status_request).
     *
     * @return значение nonce OCSP-запроса или {@code null} если не был установлен
     */
    public byte[] getOcspNonce() {
        byte[] nonce = ocspNonce;
        return nonce == null ? null : nonce.clone();
    }

    /**
     * TLS-internal. Устанавливает nonce, полученный при TLS-рукопожатии
     * (RFC 8446 §4.4.2.1, status_request). Не предназначен для вызова
     * пользовательским кодом.
     *
     * @param nonce значение nonce из OCSP-запроса (defensive copy)
     */
    public void setOcspNonce(byte[] nonce) {
        this.ocspNonce = nonce == null ? null : nonce.clone();
    }

    // ========================================================================
    // Identity (equals, hashCode, toString)
    // ========================================================================

    /**
     * Сравнивает сертификаты побайтово по DER-кодировке.
     *
     * <p><b>Ограничение:</b> byte-exact сравнение. Два семантически идентичных
     * сертификата с разной DER-сериализацией (например, из PKCS#12 с
     * re-encoding) могут быть признаны неравными. Если ваш загрузчик
     * нормализует DER, этот метод может давать false negative через
     * разные пути загрузки — это архитектурная проблема загрузчика,
     * не equals().</p>
     *
     * @param o объект для сравнения
     * @return true если DER-представление совпадает побайтово
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GostCertificate that = (GostCertificate) o;
        // byte-exact сравнение — единственный надёжный способ для X.509
        return Arrays.equals(certData, that.certData);
    }

    /**
     * @return хеш-код по DER-байтам (совместим с equals)
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(certData);
    }

    /**
     * @return человеко-читаемое представление сертификата.
     *         DN усечены до 256 символов — защита от log-inflation через
     *         длинные DN. Полный DN доступен через {@link #getSubjectDn()}.
     *         OCSP намеренно исключён — может быть большим, не для логов.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(256);
        sb.append("GostCertificate{serial=0x").append(getSerialNumberBigInt().toString(16));
        sb.append(", subject=").append(getSubjectDnForLog(256));
        sb.append(", issuer=").append(getIssuerDnForLog(256));
        DateTimeFormatter fmt = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);
        sb.append(", validity=[")
                .append(fmt.format(notBefore))
                .append(" -> ")
                .append(fmt.format(notAfter))
                .append(']');
        sb.append(", algorithm=")
                .append(publicKey.getParams().hlen * 8)
                .append("bit GOST R 34.10-2012");
        sb.append('}');
        return sb.toString();
    }

    // ========================================================================
    // Версия и серийный номер
    // ========================================================================

    /**
     * @return версия сертификата (1, 2 или 3). По RFC 5280 §4.1.2.1.
     */
    public int getVersion() {
        return version;
    }

    /**
     * @return серийный номер как BigInteger (беззнаковый).
     *         В отличие от getSerialNumber() (сырой DER INTEGER),
     *         этот метод возвращает чистое числовое значение.
     */
    public BigInteger getSerialNumberBigInt() {
        byte[] raw = getSerialNumber();
        return new BigInteger(1, raw);
    }

    // ========================================================================
    // Self-signed / self-issued
    // ========================================================================

    /**
     * Проверяет, является ли сертификат самоподписанным.
     *
     * <p>Криптографическая проверка: пытается верифицировать подпись
     * собственным публичным ключом. Единственный надёжный способ —
     * криптография, а не сравнение DN (см. {@link #isSelfIssued()}).</p>
     *
     * @return true если сертификат можно верифицировать своим же ключом
     */
    public boolean isSelfSigned() {
        try {
            return verifySignature(publicKey);
        } catch (Exception e) {
            // Любая ошибка (битый ключ, неподдерживаемый алгоритм) -> false
            return false;
        }
    }

    /**
     * Проверяет, является ли сертификат self-issued (издатель = субъект).
     *
     * <p><b>НЕ security check!</b> Сравнивает DER-байты issuer и subject
     * побайтово. Два семантически одинаковых DN с разной DER-сериализацией
     * могут быть признаны неравными. Используйте для логирования,
     * НЕ для security-решений.</p>
     *
     * @return true если issuer и subject совпадают побайтово
     */
    public boolean isSelfIssued() {
        return arrayRangeEquals(
                certData, issuerDnOff, issuerDnLen, certData, subjectDnOff, subjectDnLen);
    }

    // ========================================================================
    // Validity
    // ========================================================================

    /**
     * Проверяет, действителен ли сертификат на указанную дату.
     *
     * @param instant дата проверки (не null)
     * @return true если notBefore <= instant <= notAfter
     */
    public boolean isValidAt(Instant instant) {
        return !instant.isBefore(notBefore) && !instant.isAfter(notAfter);
    }

    // ========================================================================
    // DN (Distinguished Name) — человеко-читаемые строки
    // ========================================================================

    /**
     * @return Subject DN в формате "CN=..., O=..., C=..."
     *         или null если парсинг DN не удался.
     */
    public String getSubjectDn() {
        return subjectDnStr;
    }

    /**
     * @return Issuer DN в формате "CN=..., O=..., C=..."
     *         или null если парсинг DN не удался.
     */
    public String getIssuerDn() {
        return issuerDnStr;
    }

    /**
     * Возвращает все значения указанного OID-атрибута из Subject DN.
     *
     * <p>В DN может быть несколько одинаковых атрибутов (RFC 5280 §4.1.2.4),
     * поэтому возвращается массив. Если атрибут не найден — пустой массив.</p>
     *
     * @param oidDot OID в точечной нотации, например "2.5.4.3" для CN
     * @return массив значений (может быть пустым, но не null)
     */
    public String[] getSubjectDnField(String oidDot) {
        return GostDnParser.getDnField(subjectDnFields, oidDot);
    }

    /**
     * Возвращает все значения указанного OID-атрибута из Issuer DN.
     *
     * @param oidDot OID в точечной нотации, например "2.5.4.3" для CN
     * @return массив значений (может быть пустым, но не null)
     */
    public String[] getIssuerDnField(String oidDot) {
        return GostDnParser.getDnField(issuerDnFields, oidDot);
    }

    /**
     * @param maxLen максимальная длина строки
     * @return Subject DN для логирования, обрезанный до maxLen символов.
     *         Если DN длиннее — добавляет "...[truncated]".
     */
    public String getSubjectDnForLog(int maxLen) {
        return GostDnParser.truncateForLog(subjectDnStr, maxLen);
    }

    /**
     * @param maxLen максимальная длина строки
     * @return Issuer DN для логирования, обрезанный до maxLen символов.
     *         Если DN длиннее — добавляет "...[truncated]".
     */
    public String getIssuerDnForLog(int maxLen) {
        return GostDnParser.truncateForLog(issuerDnStr, maxLen);
    }

    // ========================================================================
    // SignatureAlgorithm OID, SKI/AKI — алгоритм и идентификаторы
    // ========================================================================

    /**
     * @return OID алгоритма подписи в точечной нотации, или null если OID не удалось распарсить
     */
    public String getSignatureAlgorithmOid() {
        if (sigAlgOidBytes.length == 0) return null;
        return oidBytesToDottedString(sigAlgOidBytes, 0, sigAlgOidBytes.length);
    }

    /**
     * Размер ключа в битах, определённый по кривой (hlen × 8).
     *
     * <p>GOST Р 34.10-2012 поддерживает ровно два размера: 256 и 512 бит.
     * Определяется по {@link org.rssys.gost.signature.ECParameters#hlen}.</p>
     *
     * @return 256 или 512
     */
    public int getKeySize() {
        return publicKey.getParams().hlen * 8;
    }

    /**
     * SubjectKeyIdentifier (RFC 5280 §4.2.1.2): идентификатор ключа субъекта.
     *
     * <p>Хэш открытого ключа сертификата. Используется для построения
     * цепочек сертификатов: AKI в дочернем сертификате ссылается на SKI
     * родительского.</p>
     *
     * @return идентификатор ключа субъекта, или null если расширение отсутствует
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public byte[] getSubjectKeyIdentifier() {
        return skiBytes == null ? null : skiBytes.clone();
    }

    /**
     * AuthorityKeyIdentifier (RFC 5280 §4.2.1.1): идентификатор ключа издателя.
     *
     * <p>Ссылается на SKI сертификата CA, выпустившего этот сертификат.
     * Позволяет построить цепочку: ищем CA-сертификат с SKI == этот AKI.</p>
     *
     * @return keyIdentifier издателя, или null если расширение отсутствует
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public byte[] getAuthorityKeyIdentifier() {
        return akiBytes == null ? null : akiBytes.clone();
    }

    /**
     * AuthorityInfoAccess (RFC 5280 §4.2.2.1): URI для OCSP-ответов и caIssuers.
     *
     * <p>Нужен caller'у для проверки статуса сертификата через OCSP
     * или для скачивания цепочки CA. Без этих URI клиент не знает,
     * где получить OCSP-ответ или промежуточный сертификат.</p>
     *
     * <p><b>⚠ Безопасность (SSRF):</b> возвращаемые URI извлечены из недоверенного
     * сертификата. Атакующий, контролирующий выпуск сертификата, может вписать
     * любой URI: внутренние адреса (192.168.x.x, 127.0.0.1), file://, ldap://,
     * gopher://, и т.д. Использование этих URI для HTTP-запросов БЕЗ строгой
     * валидации — прямой SSRF-вектор.</p>
     *
     * <p>Перед фетчингом вызывающий код ОБЯЗАН: проверить схему (только https/http),
     * проверить хост против списка разрешённых, заблокировать приватные
     * IP-диапазоны после DNS-разрешения, ограничить таймаут и размер ответа.</p>
     *
     * @return URI из AuthorityInfoAccess (OCSP и caIssuers), или null если расширение отсутствует
     */
    public String[] getAiaUris() {
        return aiaUris == null ? null : aiaUris.clone();
    }

    /**
     * URI для OCSP-запросов (id-ad-ocsp) из AuthorityInfoAccess.
     * <p>В отличие от {@link #getAiaUris()}, возвращает только URI OCSP-responder'ов,
     * без caIssuers. Если расширение AIA отсутствует или не содержит OCSP — null.</p>
     *
     * @return URI OCSP-responder'ов или null
     */
    public String[] getOcspUris() {
        return ocspUris == null ? null : ocspUris.clone();
    }

    /**
     * URI для caIssuers (id-ad-caIssuers) из AuthorityInfoAccess.
     * <p>Только URI точек получения промежуточных сертификатов, без OCSP.</p>
     *
     * @return URI caIssuers или null
     */
    public String[] getCaIssuersUris() {
        return caIssuersUris == null ? null : caIssuersUris.clone();
    }

    /**
     * CRLDistributionPoints (RFC 5280 §4.2.1.13): URI к CRL (certificate revocation lists).
     *
     * <p>Нужен caller'у для проверки статуса сертификата через CRL.
     * Храним отдельно от AIA, потому что CDP и AIA — разные механизмы
     * проверки статуса (CRL vs OCSP) с разными протоколами.</p>
     *
     * <p><b>⚠ Безопасность (SSRF):</b> возвращаемые URI извлечены из недоверенного
     * сертификата. Атакующий, контролирующий выпуск сертификата, может вписать
     * любой URI: внутренние адреса (192.168.x.x, 127.0.0.1), file://, ldap://,
     * gopher://, и т.д.</p>
     *
     * <p>При использовании штатного CRL-фетчера библиотеки
     * ({@code org.rssys.gost.jsse.crl.JdkHttpCrlFetcher}) защиты реализованы
     * автоматически: проверка схемы (только http/https), блокировка приватных
     * IP-адресов после DNS-разрешения (через {@link org.rssys.gost.pkix.util.SsrfGuard}),
     * ограничение таймаута и размера ответа. Если разработчик реализует собственный
     * фетчер — те же проверки обязательны. Allowlist доверенных хостов всегда
     * остаётся на уровне приложения (зависит от PKI-политики).</p>
     *
     * @return URI из CRLDistributionPoints, или null если расширение отсутствует
     */
    public String[] getCdpUris() {
        return cdpUris == null ? null : cdpUris.clone();
    }

    /**
     * FreshestCRL (RFC 5280 §5.2.6): URI для получения delta CRL.
     * Структура DistributionPoint идентична CDP (RFC 5280 §4.2.1.13),
     * отличается только OID (2.5.29.46).
     *
     * <p>Нужен caller'у для получения delta CRL с целью инкрементального
     * обновления CRL-статуса сертификата.</p>
     *
     * <p><b>⚠ Безопасность (SSRF):</b> возвращаемые URI извлечены из недоверенного
     * сертификата. Атакующий, контролирующий выпуск сертификата, может вписать
     * любой URI: внутренние адреса (192.168.x.x, 127.0.0.1), file://, ldap://,
     * gopher://, и т.д.</p>
     *
     * <p>В отличие от {@link #getCdpUris()}, {@code GostX509TrustManager} не
     * передаёт FreshestCRL URI в CRL-фетчер автоматически — разработчику
     * необходимо явно вызвать {@code getFreshestCrlUris()} и передать URI
     * в {@code JdkHttpCrlFetcher.fetch()}, который принимает любой CRL-URI
     * и уже реализует защиты: проверка схемы (http/https), блокировка приватных
     * IP ({@link org.rssys.gost.pkix.util.SsrfGuard}), лимит таймаута и размера.
     * Allowlist хостов остаётся на уровне приложения (зависит от PKI-политики).</p>
     *
     * @return URI из FreshestCRL, или null если расширение отсутствует
     */
    public String[] getFreshestCrlUris() {
        return freshestCrlUris == null ? null : freshestCrlUris.clone();
    }

    /**
     * CertificatePolicies (RFC 5280 §4.2.1.4): OID политик сертификата.
     *
     * <p>Политики описывают, для каких целей выпущен сертификат
     * (например, \"аутентификация клиента\", \"ЭП для госуслуг\").
     * Caller может проверить, соответствует ли сертификат требуемой политике.</p>
     *
     * @return OID политик в точечной нотации, или null если расширение отсутствует
     */
    public String[] getCertificatePolicies() {
        return certPolicyOids == null ? null : certPolicyOids.clone();
    }

    /**
     * Проверяет, соответствует ли закрытый ключ открытому ключу сертификата.
     *
     * <p>Генерирует 32 случайных байта, подписывает их закрытым ключом
     * и верифицирует подпись открытым ключом сертификата.
     * Использует {@link org.rssys.gost.util.CryptoRandom#INSTANCE}.</p>
     *
     * <p>try-catch: любая ошибка (неподдерживаемая кривая, битый ключ) -> false.</p>
     *
     * @param privKey закрытый ключ для проверки
     * @return true если ключи образуют пару
     */
    public boolean matchesPrivateKey(org.rssys.gost.signature.PrivateKeyParameters privKey) {
        if (privKey == null || privKey.isDestroyed()) return false;
        try {
            byte[] challenge = new byte[32];
            org.rssys.gost.util.CryptoRandom.INSTANCE.nextBytes(challenge);
            byte[] sig = org.rssys.gost.api.Signature.sign(challenge, privKey);
            return org.rssys.gost.api.Signature.verify(challenge, sig, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    // ========================================================================
    // SignatureValue и TBSCertificate — доступ к сырым DER-байтам
    // ========================================================================

    /**
     * Возвращает сырое значение подписи (SignatureValue) без BIT STRING обёртки.
     *
     * <p>Нужен caller'у для проверки подписи внешними средствами (HSM,
     * кастомный валидатор цепочек). Хранить готовую подпись на случай,
     * если верификация через {@link #verifySignature(PublicKeyParameters)} не подходит.</p>
     *
     * @return значение подписи (64 или 128 байт для 256/512-битных кривых)
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public byte[] getSignatureValue() {
        byte[] result = new byte[sigLen];
        System.arraycopy(certData, sigOff, result, 0, sigLen);
        return result;
    }

    /**
     * Возвращает DER-кодированный TBSCertificate.
     *
     * <p>Всё, что внутри Certificate SEQUENCE до signatureAlgorithm.
     * Нужен для расчёта хэша при проверке подписи или для экспорта
     * в форматы CMS/PKCS#7, где нужен оригинальный TBS.</p>
     *
     * @return TBSCertificate DER-байты
     *         Defensive copy — caller не может модифицировать внутреннее состояние.
     */
    public byte[] getTBSCertificateBytes() {
        byte[] result = new byte[tbsCertLen];
        System.arraycopy(certData, tbsCertOff, result, 0, tbsCertLen);
        return result;
    }

    /**
     * @return raw битовая маска KeyUsage (16 бит) для oid_filters matching.
     *         Внутренний API.
     */
    public int getKeyUsageBits() {
        return keyUsageBits;
    }

    /**
     * @return все OID ExtendedKeyUsage в DER-байтах. Defensive copy.
     */
    public byte[][] getEkuOids() {
        if (ekuOids == null) return null;
        byte[][] copy = new byte[ekuOids.length][];
        for (int i = 0; i < ekuOids.length; i++) {
            copy[i] = ekuOids[i].clone();
        }
        return copy;
    }

    /**
     * @return все OID CertificatePolicies (2.5.29.32) в DER-байтах — для oid_filters matching.
     *         Defensive copy.
     */
    public byte[][] getCpOids() {
        if (cpOids == null) return null;
        byte[][] copy = new byte[cpOids.length][];
        for (int i = 0; i < cpOids.length; i++) {
            copy[i] = cpOids[i].clone();
        }
        return copy;
    }

    /**
     * @return политики сертификата с опциональными CPS-квалификаторами,
     *         или {@code null} если расширение отсутствует. Defensive copy.
     */
    public CertificatePolicy[] getCertificatePolicyInfos() {
        if (certPolicyInfos == null) return null;
        return certPolicyInfos.clone();
    }

    /**
     * @return множество OID всех присутствующих расширений (dot-notation). Defensive copy.
     */
    public Set<String> getPresentExtensionOids() {
        return new HashSet<>(presentExtensionOids);
    }

    /**
     * Возвращает значение расширения: содержимое OCTET STRING {@code extnValue}, то есть DER
     * значения расширения (RFC 5280 §4.1), без обёртки Extension, OID и флага критичности.
     * Значение берётся из того же строгого разбора, что и остальные свойства сертификата;
     * повторяющихся расширений в сертификате быть не может (такой сертификат не создаётся).
     *
     * @param oid OID расширения в dot-notation, например {@code "2.5.29.15"}
     * @return копия значения или {@code null}, если расширения в сертификате нет
     * @throws IllegalArgumentException если {@code oid} равен {@code null}
     */
    public byte[] getExtensionValue(String oid) {
        if (oid == null) {
            throw new IllegalArgumentException("oid must not be null");
        }
        byte[] value = extensionValues.get(oid);
        return value == null ? null : value.clone();
    }

    /**
     * Возвращает результат парсинга расширений X.509v3.
     *
     * <p><b>Граница доверия:</b> расширения в сертификате подтверждены УЦ,
     * но это не освобождает оператора от обязанности валидировать их
     * при перевыпуске. Автоматическое копирование расширений
     * в {@link GostCertificateBuilder} без проверки актуальности
     * (владение доменом для SAN, полномочия на EKU, статус CA для
     * BasicConstraints) небезопасно — короткий срок действия
     * сертификатов в CA/Browser Forum введён для принудительной
     * периодической переаттестации.</p>
     *
     * <p>Результат - независимая копия: изменение возвращённых массивов не влияет на разобранный
     * объект и на проверку цепочки.</p>
     *
     * @return структурированный результат парсинга расширений.
     *         {@link GostExtensionParser.ExtensionsResult#empty()} если расширения отсутствуют.
     */
    public GostExtensionParser.ExtensionsResult getExtensions() {
        return extResult.copy();
    }

    /** @return true если сертификат содержит хотя бы одно распознанное расширение */
    public boolean hasExtensions() {
        return !extResult.presentExtensionOids.isEmpty();
    }

    /**
     * Результат извлечения открытого ключа и позиции BIT STRING value из SPKI.
     */
    private static class SpkiExtractResult {
        final PublicKeyParameters publicKey;
        final int spkiKeyValueOff;
        final int spkiKeyValueLen;
        final int spkiAlgIdOff;
        final int spkiAlgIdLen;

        SpkiExtractResult(
                PublicKeyParameters publicKey,
                int spkiKeyValueOff,
                int spkiKeyValueLen,
                int spkiAlgIdOff,
                int spkiAlgIdLen) {
            this.publicKey = publicKey;
            this.spkiKeyValueOff = spkiKeyValueOff;
            this.spkiKeyValueLen = spkiKeyValueLen;
            this.spkiAlgIdOff = spkiAlgIdOff;
            this.spkiAlgIdLen = spkiAlgIdLen;
        }
    }

    /**
     * Извлекает SubjectPublicKeyInfo и BIT STRING value из TBSCertificate.
     * SubjectPublicKeyInfo — 5-я SEQUENCE в TBSCertificate после
     * version [0] (если есть) и serialNumber (INTEGER).
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return результат с открытым ключом и позицией BIT STRING value в der
     */
    private static SpkiExtractResult extractPublicKeyAndKeyValue(byte[] der, int[] tbsTlv) {
        int pos = tbsTlv[0];
        int end = tbsTlv[1];

        // version [0] EXPLICIT (OPTIONAL, default v1)
        if (pos < end && (der[pos] & 0xFF) == 0xA0) {
            pos = readTlv(der, pos, end)[1];
        }
        // serialNumber (INTEGER)
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos, end)[1];

        // Из оставшихся полей SPKI — 5-я SEQUENCE
        // (1=signature, 2=issuer, 3=validity, 4=subject, 5=SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos, end);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == 5) {
                    // tlv = [spkiValueStart, spkiValueEnd] — содержимое SPKI SEQUENCE
                    int spkiValueStart = tlv[0];
                    byte[] spkiDer = Arrays.copyOfRange(der, pos, tlv[1]);
                    PublicKeyParameters key = GostDerCodec.decodePublicKey(spkiDer);

                    // Извлекаем позицию BIT STRING value внутри SPKI:
                    // SEQUENCE -> AlgorithmIdentifier -> BIT STRING -> value
                    int[] algTlv = readTlv(der, spkiValueStart, tlv[1]);
                    int bsPos = algTlv[1];
                    int[] bsTlv = readTlv(der, bsPos, tlv[1]);
                    // bsTlv[0] — начало BIT STRING value (включая unused-bits байт)
                    // bsTlv[1] — конец BIT STRING value
                    int keyValueOff = bsTlv[0];
                    int keyValueLen = bsTlv[1] - bsTlv[0];
                    // AlgorithmIdentifier-элемент целиком: от тега SEQUENCE (spkiValueStart)
                    // до начала BIT STRING (bsPos). Нужен для точного воспроизведения
                    // paramSet получателя в эфемерном ключе CMS (Р 1323565.1.025-2019 §8.4.2.2).
                    int algIdOff = spkiValueStart;
                    int algIdLen = bsPos - spkiValueStart;
                    return new SpkiExtractResult(key, keyValueOff, keyValueLen, algIdOff, algIdLen);
                }
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("No SubjectPublicKeyInfo found in TBSCertificate");
    }

    // ========================================================================
    // Extensions (SubjectAltName, KeyUsage, ExtendedKeyUsage)
    // ========================================================================

    /**
     * Пропускает version [0] EXPLICIT и serialNumber INTEGER в начале TBSCertificate.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return позиция после serialNumber или -1 при некорректной структуре
     */
    private static int skipVersionAndSerial(byte[] der, int[] tbsTlv) {
        int pos = tbsTlv[0];
        int end = tbsTlv[1];
        if (pos < end && (der[pos] & 0xFF) == TAG_CTX_0) {
            pos = readTlv(der, pos, end)[1];
        }
        if (pos >= end) return -1;
        return readTlv(der, pos, end)[1];
    }

    /**
     * Парсит extensions [3] из TBSCertificate — обход до пятой SEQUENCE (SPKI),
     * затем пропуск uniqueID [1]/[2] и разбор блока [3].
     * Извлекает SubjectAltName (dNSName), KeyUsage, ExtendedKeyUsage, BasicConstraints.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @param certVersion версия сертификата (1..3)
     * @return результат парсинга расширений
     */
    private static GostExtensionParser.ExtensionsResult parseExtensions(
            byte[] der, int[] tbsTlv, int certVersion) {
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(der, tbsTlv);
        if (pos < 0) {
            throw new IllegalArgumentException("TBSCertificate too short");
        }
        // Сканируем до 5-й SEQUENCE (SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos, end);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == TBS_SPKI_SEQUENCE_INDEX) {
                    pos = tlv[1];
                    break;
                }
            }
            pos = tlv[1];
        }
        if (seqCount < TBS_SPKI_SEQUENCE_INDEX) {
            throw new IllegalArgumentException("No SubjectPublicKeyInfo found in TBSCertificate");
        }

        // issuerUniqueID [1], subjectUniqueID [2], затем extensions [3].
        // Расширения опциональны (v1/v2): пустой результат допустим только если [3]
        // отсутствует. Любой другой хвост — повреждённая структура, а не «нет расширений».
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            // Канонический uniqueID — IMPLICIT BIT STRING (0x81/0x82); constructed-вариант
            // (0xA1/0xA2) оставлен как раньше.
            if (tag == TAG_ISSUER_UNIQUE_ID
                    || tag == TAG_SUBJECT_UNIQUE_ID
                    || tag == TAG_CTX_1
                    || tag == TAG_CTX_2) {
                // RFC 5280 §4.1.2.8: uniqueID допустимы только в сертификатах v2 и v3
                if (certVersion < CERT_VERSION_V2) {
                    throw new IllegalArgumentException(
                            "Unique IDs are not allowed in a v1 certificate");
                }
                pos = readTlv(der, pos, end)[1];
                continue;
            }
            if (tag == TAG_CTX_3) {
                // RFC 5280 §4.1.2.9: extensions допустимы только в сертификате v3. Для v1/v2
                // блок [3] - несогласованная структура, а не набор действующих расширений.
                if (certVersion < CERT_VERSION_V3) {
                    throw new IllegalArgumentException(
                            "Extensions are only allowed in a v3 certificate, got v" + certVersion);
                }
                return GostExtensionParser.parseFromExtensionsBlock(der, pos, end);
            }
            throw new IllegalArgumentException(
                    "Unexpected field in TBSCertificate at offset " + pos);
        }
        return GostExtensionParser.ExtensionsResult.empty();
    }

    // ========================================================================
    // DN parsing (Issuer = 4-я SEQUENCE, Subject = 6-я SEQUENCE в TBS)
    // DN matching: byte-exact DER сравнение;
    // семантическая нормализация согласно RFC 5280 §7.1 не реализована.
    // ========================================================================

    /**
     * Парсит DN по индексу пропуска SEQUENCE после signature.
     * Для issuer (4-я SEQUENCE) skipSeqs = 0, для subject (6-я SEQUENCE) skipSeqs = 2.
     *
     * @param der      DER-поток сертификата
     * @param tbsTlv   [valueStart, valueEnd] TBSCertificate
     * @param skipSeqs количество SEQUENCE для пропуска после signature
     * @return [offset, length] DN
     */
    private static int[] parseDnByIndex(byte[] der, int[] tbsTlv, int skipSeqs) {
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(der, tbsTlv);
        if (pos < 0) throw new IllegalArgumentException("TBSCertificate too short");
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos, end)[1]; // signature SEQUENCE
        for (int i = 0; i < skipSeqs; i++) {
            if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
            pos = readTlv(der, pos, end)[1];
        }
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos, end);
            if (tag == TAG_SEQUENCE) {
                return new int[] {pos, tlv[1] - pos};
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException(
                "DN not found in TBSCertificate (skipSeqs=" + skipSeqs + ")");
    }

    // ========================================================================
    // Validity (X.509 Validity SEQUENCE)
    // ========================================================================

    /**
     * Парсит Validity SEQUENCE из TBSCertificate.
     * Validity — третья SEQUENCE в содержании TBS.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return [notBefore, notAfter]
     */
    private static Instant[] parseValidity(byte[] der, int[] tbsTlv) {
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(der, tbsTlv);
        if (pos < 0) throw new IllegalArgumentException("TBSCertificate too short");

        // validity — 3-я SEQUENCE (1=signature, 2=issuer, 3=validity)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos, end);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == TBS_VALIDITY_SEQUENCE_INDEX) {
                    // Оба времени лежат целиком внутри Validity и заполняют её без хвоста:
                    // parseTime проверяет только der.length, а не границы родителя.
                    int[] notBeforeTlv = readTlv(der, tlv[0], tlv[1]);
                    int[] notAfterTlv = readTlv(der, notBeforeTlv[1], tlv[1]);
                    if (notAfterTlv[1] != tlv[1]) {
                        throw new IllegalArgumentException(
                                "Trailing bytes after notAfter in Validity");
                    }
                    Instant notBefore = parseTime(der, tlv[0]);
                    Instant notAfter = parseTime(der, notBeforeTlv[1]);
                    return new Instant[] {notBefore, notAfter};
                }
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("Validity not found in TBSCertificate");
    }

    /**
     * Создаёт сертификат из DER-байтов.
     *
     * @param der DER-encoded X.509 сертификат
     * @return сертификат
     * @throws IllegalArgumentException если DER невалиден
     */
    public static GostCertificate fromDer(byte[] der) {
        return new GostCertificate(der);
    }

    /**
     * Создаёт сертификат из PEM- или DER-байтов с автоопределением формата.
     *
     * <p>Определяет формат по первому байту: {@code 0x30} = DER,
     * {@code 0x2D} = PEM (строка начинается с '-'). PEM-блок должен содержать
     * ровно один сертификат.
     *
     * @param data PEM- или DER-байты сертификата
     * @return сертификат
     * @throws IllegalArgumentException если данные не являются валидным сертификатом
     */
    public static GostCertificate fromPemOrDer(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Certificate data must not be null or empty");
        }
        if ((data[0] & 0xFF) == 0x30) {
            return new GostCertificate(data);
        }
        if (data[0] == (byte) 0x2D) {
            return new GostCertificate(GostPemUtils.pemToDer(data));
        }
        throw new IllegalArgumentException(
                "Unrecognized certificate format: first byte 0x"
                        + Integer.toHexString(data[0] & 0xFF)
                        + " (expected 0x30 for DER or 0x2D for PEM)");
    }

    /**
     * Проверяет, являются ли данные PEM-форматом.
     *
     * <p>Дискриминатор: первый байт 0x2D (ASCII '-') — начало PEM-заголовка.
     *
     * @param data проверяемые байты
     * @return true если данные начинаются с PEM-заголовка
     */
    public static boolean isPem(byte[] data) {
        return GostPemUtils.isPem(data);
    }

    /**
     * Проверяет, являются ли данные PFX-контейнером (PKCS12).
     *
     * <p>Дискриминатор: внешний SEQUENCE, первый вложенный элемент — INTEGER 3
     * (версия PFX). Это надёжнее полного разбора — без лишних аллокаций.
     *
     * @param data проверяемые байты
     * @return true если данные имеют структуру PFX
     */
    public static boolean isPkcs12(byte[] data) {
        return GostPemUtils.isPkcs12(data);
    }

    /**
     * Разбирает PEM-файл, содержащий один или несколько сертификатов (цепочку),
     * и возвращает список {@link GostCertificate}.
     *
     * <p>Обрабатывает файлы с несколькими блоками {@code -----BEGIN CERTIFICATE-----},
     * включая цепочки из PEM-файлов УЦ Минцифры.
     *
     * @param pem PEM-байты, содержащие один или несколько сертификатов
     * @return список сертификатов (порядок из файла)
     * @throws IllegalArgumentException если ни один сертификат не распознан
     */
    public static List<GostCertificate> listFromPem(byte[] pem) {
        List<byte[]> ders = GostPemUtils.decodePemBlocks(pem);
        List<GostCertificate> result = new ArrayList<>();
        for (byte[] der : ders) {
            result.add(new GostCertificate(der));
        }
        return result;
    }

    /**
     * Декодирует один PEM-блок (Base64 между заголовками) в DER-байты.
     * <p>Вырезает заголовки {@code -----BEGIN ...-----} / {@code -----END ...-----} и пробельные
     * символы, декодирует оставшийся Base64. Блок должен быть ровно один; файл с цепочкой
     * сертификатов читается через {@link #listFromPem(byte[])}.
     *
     * @param pem байты PEM-данных (сертификат, ключ или любой PEM-блок)
     * @return DER-байты
     * @throws IllegalArgumentException если блоков не один или структура заголовков нарушена
     */
    public static byte[] pemToDer(byte[] pem) {
        return GostPemUtils.pemToDer(pem);
    }
}
