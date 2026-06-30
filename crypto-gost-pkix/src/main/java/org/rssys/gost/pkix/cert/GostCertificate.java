package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Минимальный парсер X.509 сертификата для GOST R 34.10-2012.
 * Извлекает открытый ключ, подпись и верифицирует подпись сертификата.
 */
public final class GostCertificate {

    // Индексы SEQUENCE в TBSCertificate для навигации (RFC 5280 §4.1)
    // SPKI — 5-я, Validity — 3-я SEQUENCE
    private static final int TBS_VALIDITY_SEQUENCE_INDEX = 3;
    private static final int TBS_SPKI_SEQUENCE_INDEX = 5;
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
    private final boolean keyUsageValid;
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
    // OID политик сертификата (2.5.29.32) — идентификаторы политик
    private final String[] certPolicyOids;
    // Маска KeyUsage (2.5.29.15): 16-bit raw битовая маска
    private final int keyUsageBits;
    // Все OID ExtendedKeyUsage (2.5.29.37) в DER-байтах — для oid_filters matching
    private final byte[][] ekuOids;
    // OID политик CertificatePolicies (2.5.29.32) в DER-байтах — для oid_filters matching
    private final byte[][] cpOids;
    // Множество всех OID расширений, присутствующих в сертификате (dot-нотация)
    private final Set<String> presentExtensionOids;

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
        this.certData = derEncoded.clone();

        int[] outer = parseSequence(derEncoded, 0);
        int certContentStart = outer[0];
        if (certContentStart >= outer[1]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: empty certificate SEQUENCE");
        }

        // Три потомка верхнего уровня: TBSCertificate, SignatureAlgorithm, SignatureValue
        int[] tbsTlv = readTlv(derEncoded, certContentStart);
        this.tbsCertOff = certContentStart;
        this.tbsCertLen = tbsTlv[1] - certContentStart;

        // Version: [0] EXPLICIT { INTEGER } (OPTIONAL, default v1)
        // Парсим до validity, чтобы не менять существующий parseValidity
        int v = 1;
        {
            int vPos = tbsTlv[0];
            if (vPos < tbsTlv[1] && (derEncoded[vPos] & 0xFF) == TAG_CTX_0) {
                int[] verTagTlv = readTlv(derEncoded, vPos);
                // verTagTlv[0] — начало INTEGER внутри [0] EXPLICIT
                if (verTagTlv[0] < verTagTlv[1]
                        && (derEncoded[verTagTlv[0]] & 0xFF) == TAG_INTEGER) {
                    int[] verIntTlv = readTlv(derEncoded, verTagTlv[0]);
                    if (verIntTlv[0] >= verIntTlv[1]) {
                        throw new IllegalArgumentException(
                                "Truncated DER encoding: empty INTEGER in version field");
                    }
                    v = (derEncoded[verIntTlv[0]] & 0xFF) + 1;
                }
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
        int[] sigAlgTlv = readTlv(derEncoded, tbsTlv[1]);
        if (sigAlgTlv[0] < sigAlgTlv[1] && (derEncoded[sigAlgTlv[0]] & 0xFF) == TAG_OID) {
            int[] oidTlv = readTlv(derEncoded, sigAlgTlv[0]);
            this.sigAlgOidBytes = Arrays.copyOfRange(derEncoded, oidTlv[0], oidTlv[1]);
        } else {
            this.sigAlgOidBytes = new byte[0];
        }

        // SignatureValue (BIT STRING)
        int sigTagOffset = sigAlgTlv[1];
        if (sigTagOffset >= derEncoded.length) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: missing signature at offset " + sigTagOffset);
        }
        if ((derEncoded[sigTagOffset] & 0x1F) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("Expected BIT STRING for signature");
        }
        int[] sigValTlv = readTlv(derEncoded, sigTagOffset);
        if (sigValTlv[1] <= sigValTlv[0]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: empty BIT STRING for signature at offset "
                            + sigTagOffset);
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

        // Парсим SubjectAltName, KeyUsage, ExtendedKeyUsage, BasicConstraints из extensions
        GostExtensionParser.ExtensionsResult ext = parseExtensions(derEncoded, tbsTlv);
        this.sanDnsNames = ext.sanDnsNames;
        this.sanIpAddresses = ext.sanIpAddresses;
        this.keyUsageValid = ext.keyUsageValid;
        this.ekuValid = ext.ekuValid;
        this.ekuClientAuth = ext.ekuClientAuth;
        this.ekuOcspSigning = ext.ekuOcspSigning;
        this.ekuTimeStamping = ext.ekuTimeStamping;
        this.isCA = ext.isCA;
        this.pathLen = ext.pathLen;
        this.keyCertSign = ext.keyCertSign;
        this.hasUnknownCritical = ext.hasUnknownCritical;
        this.skiBytes = ext.skiBytes;
        this.akiBytes = ext.akiBytes;
        this.aiaUris = ext.aiaUris;
        this.ocspUris = ext.ocspUris;
        this.caIssuersUris = ext.caIssuersUris;
        this.cdpUris = ext.cdpUris;
        this.certPolicyOids = ext.certPolicyOids;
        this.keyUsageBits = ext.keyUsageBits;
        this.ekuOids = ext.ekuOids;
        this.cpOids = ext.cpOids;
        this.presentExtensionOids = ext.presentExtensionOids;

        // Проверка согласованности алгоритма (RFC 5280 §4.1.1.2):
        // signatureAlgorithm (вне TBS) должен совпадать с TBSCertificate.signature
        // signatureAlgorithm = SEQUENCE в derEncoded между tbsTlv[1] и sigAlgTlv[1]
        int outerSigOff = tbsTlv[1];
        int outerSigLen = sigAlgTlv[1] - tbsTlv[1];
        // TBSCertificate.signature — вторая SEQUENCE внутри TBS (после version, serial)
        int tbsPos = tbsTlv[0];
        if (tbsPos < tbsTlv[1] && (derEncoded[tbsPos] & 0xFF) == 0xA0) {
            tbsPos = readTlv(derEncoded, tbsPos)[1];
        }
        int[] serialTlv = readTlv(derEncoded, tbsPos);
        this.serialOff = serialTlv[0];
        this.serialLen = serialTlv[1] - serialTlv[0];
        tbsPos = serialTlv[1];
        // signature — SEQUENCE внутри TBS
        if (tbsPos < tbsTlv[1] && (derEncoded[tbsPos] & 0xFF) == TAG_SEQUENCE) {
            int[] tbsSigTlv = readTlv(derEncoded, tbsPos);
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
    public boolean verifySignature(PublicKeyParameters caPublicKey) {
        // Whitelist допустимых OID алгоритма подписи (defense-in-depth)
        if (!matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_256_OID_BYTES)
                && !matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length, GOST_SIGN_512_OID_BYTES)
                && !matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length,
                        GOST_SIGN_DIGEST_256_OID_BYTES)
                && !matchesOid(sigAlgOidBytes, 0, sigAlgOidBytes.length,
                        GOST_SIGN_DIGEST_512_OID_BYTES)) {
            return false;
        }
        int hlen = caPublicKey.getParams().hlen;
        Digest.Algorithm hashAlg =
                hlen == GostOids.STREEBOG_512_HASH_LEN
                        ? Digest.Algorithm.STREEBOG_512
                        : Digest.Algorithm.STREEBOG_256;
        Digest digest = new Digest(hashAlg);
        digest.update(certData, tbsCertOff, tbsCertLen);
        byte[] hash = digest.digest();

        byte[] sigCopy = new byte[sigLen];
        System.arraycopy(certData, sigOff, sigCopy, 0, sigLen);
        return Signature.verifyHash(hash, sigCopy, caPublicKey);
    }

    /**
     * @return true если срок действия сертификата истёк (с учётом clock skew)
     */
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
     * Wildcard (*.example.com) матчит ровно одну метку слева.
     * Частичные wildcard (f*.example.com) запрещены.
     * IDN A-label wildcard (xn--*) запрещён.
     *
     * @param hostname DNS-имя сервера; {@code null} — проверка пропускается
     *                 (IP-соединение, см. RFC 6125 §1.7.2);
     *                 пустая строка — {@code false}
     * @return {@code true} если hostname соответствует сертификату,
     *         или hostname == {@code null} (проверка пропущена);
     *         {@code false} в остальных случаях
     */
    public boolean verifyHostname(String hostname) {
        if (hostname == null) return true;
        if (hostname.isEmpty()) return false;

        // Нормализация: trim, lowercase, удаляем trailing dot
        String normalized = hostname.trim().toLowerCase();
        if (normalized.isEmpty()) return false;
        if (normalized.charAt(normalized.length() - 1) == '.') {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        // IP-адрес -> проверка против iPAddress SAN (tag 0x87)
        if (isIpAddress(normalized)) return verifyAddress(normalized);

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
     * Частичные wildcard ({@code f*.example.com}) и IDN A-label
     * ({@code *.xn--...}) запрещены по RFC 6125 §6.4.3.
     * <p>
     * Метод public, поскольку используется также в
     * {@code GostX509KeyManager} из модуля JSSE.
     *
     * @param normalizedHostname нормализованный hostname (trim, lowercase, без trailing dot)
     * @param sanDnsName         одно dNSName значение из SAN (не нормализовано)
     * @return {@code true} если hostname соответствует dNSName
     */
    public static boolean matchDnsName(String normalizedHostname, String sanDnsName) {
        String sanLower = sanDnsName.toLowerCase();

        // Точное совпадение
        if (normalizedHostname.equals(sanLower)) return true;

        // Wildcard: должен начинаться с "*."
        if (!sanLower.startsWith("*.")) return false;

        String suffix = sanLower.substring(2); // всё после "*."

        // Wildcard не должен быть "*." + apex (напр. *.com)
        if (suffix.isEmpty() || suffix.indexOf('.') < 0) return false;

        // Частичный wildcard (f*.example.com) запрещён
        if (sanLower.indexOf('*', 1) >= 0) return false;

        // IDN A-label wildcard запрещён
        if (suffix.startsWith("xn--") || suffix.contains(".xn--")) return false;

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
     * Проверяет, является ли строка IP-адресом (IPv4 или IPv6).
     * IPv6 детектится по наличию двоеточия, IPv4 — 4 десятичных октета.
     *
     * @param hostname строка для проверки
     * @return true если строка является IP-адресом
     */
    private static boolean isIpAddress(String hostname) {
        if (hostname.indexOf(':') >= 0) return true;
        // Проверка на IPv4: 4 числа, разделённых точками
        String[] parts = hostname.split("\\.");
        if (parts.length != 4) return false;
        for (String p : parts) {
            try {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Проверяет IP-адрес против iPAddress SAN (RFC 5280 §4.2.1.6).
     *
     * @param ipAddress IP-адрес (IPv4 или IPv6)
     * @return true если адрес найден в SAN iPAddress entries
     */
    public boolean verifyAddress(String ipAddress) {
        if (sanIpAddresses == null) return false;
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            byte[] raw = addr.getAddress();
            return verifyAddress(raw);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Проверяет raw IP-адрес (4 или 16 байт) против iPAddress SAN.
     *
     * @param rawAddress raw IP-адрес (4 или 16 байт)
     * @return true если адрес найден в SAN iPAddress entries
     */
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
     * @return true если KeyUsage не задан или содержит digitalSignature (RFC 8446 §4.4.2.2)
     */
    public boolean isKeyUsageValid() {
        return keyUsageValid;
    }

    /** @return true если EKU не задан или содержит serverAuth */
    public boolean isEkuValidForServer() {
        return ekuValid;
    }

    /** @return true если EKU не задан или содержит clientAuth */
    public boolean isEkuValidForClient() {
        return ekuClientAuth;
    }

    /** @return true если сертификат разрешён для подписи OCSP-ответов */
    public boolean isOcspSigning() {
        // EKU не задан -> без ограничений (RFC 5280 §4.2.1.12)
        return ekuOcspSigning;
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
     * @return BIT STRING value из SubjectPublicKeyInfo (включая unused-bits байт),
     *         для вычисления issuerKeyHash в CertID (RFC 6960 §4.1.1)
     */
    public byte[] getSpkiKeyValue() {
        byte[] result = new byte[spkiKeyValueLen];
        System.arraycopy(certData, spkiKeyValueOff, result, 0, spkiKeyValueLen);
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
     * gopher://, и т.д. Использование этих URI для HTTP-запросов БЕЗ строгой
     * валидации — прямой SSRF-вектор.</p>
     *
     * <p>Перед фетчингом вызывающий код ОБЯЗАН: проверить схему (только https/http),
     * проверить хост против списка разрешённых, заблокировать приватные
     * IP-диапазоны после DNS-разрешения, ограничить таймаут и размер ответа.</p>
     *
     * @return URI из CRLDistributionPoints, или null если расширение отсутствует
     */
    public String[] getCdpUris() {
        return cdpUris == null ? null : cdpUris.clone();
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
     * @return множество OID всех присутствующих расширений (dot-notation). Defensive copy.
     */
    public Set<String> getPresentExtensionOids() {
        return new HashSet<>(presentExtensionOids);
    }

    /**
     * Результат извлечения открытого ключа и позиции BIT STRING value из SPKI.
     */
    private static class SpkiExtractResult {
        final PublicKeyParameters publicKey;
        final int spkiKeyValueOff;
        final int spkiKeyValueLen;

        SpkiExtractResult(PublicKeyParameters publicKey, int spkiKeyValueOff, int spkiKeyValueLen) {
            this.publicKey = publicKey;
            this.spkiKeyValueOff = spkiKeyValueOff;
            this.spkiKeyValueLen = spkiKeyValueLen;
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
            pos = readTlv(der, pos)[1];
        }
        // serialNumber (INTEGER)
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1];

        // Из оставшихся полей SPKI — 5-я SEQUENCE
        // (1=signature, 2=issuer, 3=validity, 4=subject, 5=SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == 5) {
                    // tlv = [spkiValueStart, spkiValueEnd] — содержимое SPKI SEQUENCE
                    int spkiValueStart = tlv[0];
                    byte[] spkiDer = Arrays.copyOfRange(der, pos, tlv[1]);
                    PublicKeyParameters key = GostDerCodec.decodePublicKey(spkiDer);

                    // Извлекаем позицию BIT STRING value внутри SPKI:
                    // SEQUENCE -> AlgorithmIdentifier -> BIT STRING -> value
                    int[] algTlv = readTlv(der, spkiValueStart);
                    int bsPos = algTlv[1];
                    int[] bsTlv = readTlv(der, bsPos);
                    // bsTlv[0] — начало BIT STRING value (включая unused-bits байт)
                    // bsTlv[1] — конец BIT STRING value
                    int keyValueOff = bsTlv[0];
                    int keyValueLen = bsTlv[1] - bsTlv[0];
                    return new SpkiExtractResult(key, keyValueOff, keyValueLen);
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
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end) return -1;
        return readTlv(der, pos)[1];
    }

    /**
     * Парсит extensions [3] из TBSCertificate — обход до пятой SEQUENCE (SPKI),
     * затем пропуск uniqueID [1]/[2] и разбор блока [3].
     * Извлекает SubjectAltName (dNSName), KeyUsage, ExtendedKeyUsage, BasicConstraints.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return результат парсинга расширений
     */
    private static GostExtensionParser.ExtensionsResult parseExtensions(byte[] der, int[] tbsTlv) {
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(der, tbsTlv);
        if (pos < 0) return GostExtensionParser.ExtensionsResult.empty();
        // Сканируем до 5-й SEQUENCE (SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == TBS_SPKI_SEQUENCE_INDEX) {
                    pos = tlv[1];
                    break;
                }
            }
            pos = tlv[1];
        }
        if (seqCount < TBS_SPKI_SEQUENCE_INDEX) return GostExtensionParser.ExtensionsResult.empty();

        // issuerUniqueID [1], subjectUniqueID [2], затем extensions [3]
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            if (tag == TAG_CTX_1 || tag == TAG_CTX_2) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            if (tag == TAG_CTX_3) {
                return GostExtensionParser.parseFromExtensionsBlock(der, pos);
            }
            break;
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
        pos = readTlv(der, pos)[1]; // signature SEQUENCE
        for (int i = 0; i < skipSeqs; i++) {
            if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
            pos = readTlv(der, pos)[1];
        }
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
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
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == TBS_VALIDITY_SEQUENCE_INDEX) {
                    Instant notBefore = parseTime(der, tlv[0]);
                    Instant notAfter = parseTime(der, readTlv(der, tlv[0])[1]);
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
     * Декодирует PEM-формат (Base64 между заголовками) в DER-байты.
     * <p>Вырезает любые PEM-заголовки {@code -----BEGIN ...-----} / {@code -----END ...-----}
     * и пробельные символы, декодирует оставшийся Base64.
     *
     * @param pem байты PEM-данных (сертификат, ключ или любой PEM-блок)
     * @return DER-байты
     */
    public static byte[] pemToDer(byte[] pem) {
        return GostPemUtils.pemToDer(pem);
    }
}
