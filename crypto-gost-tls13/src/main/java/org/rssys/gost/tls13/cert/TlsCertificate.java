package org.rssys.gost.tls13.cert;

import static org.rssys.gost.tls13.cert.TlsDerParser.*;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.OIDFilter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Base64;

/**
 * Минимальный парсер X.509 сертификата для GOST R 34.10-2012.
 * Извлекает открытый ключ, подпись и верифицирует подпись сертификата.
 */
public final class TlsCertificate {

    // Индексы SEQUENCE в TBSCertificate для навигации (RFC 5280 §4.1)
    // SPKI — 5-я, Validity — 3-я SEQUENCE
    private static final int TBS_VALIDITY_SEQUENCE_INDEX = 3;
    private static final int TBS_SPKI_SEQUENCE_INDEX = 5;
    private static final int ISSUER_DN_SKIP = 0;
    private static final int SUBJECT_DN_SKIP = 2;

    // OID известных X.509v3 расширений (dot-notation) для oid_filters matching.
    // Если сервер запросил фильтр с таким OID, а в сертификате расширения нет,
    // фильтр НЕ проходит (return false), даже если values пусты.
    private static final Set<String> KNOWN_EXTENSION_OIDS = Set.of(
            "2.5.29.14",  // SubjectKeyIdentifier
            "2.5.29.15",  // KeyUsage
            "2.5.29.17",  // SubjectAltName
            "2.5.29.19",  // BasicConstraints
            "2.5.29.31",  // CRLDistributionPoints
            "2.5.29.32",  // CertificatePolicies
            "2.5.29.35",  // AuthorityKeyIdentifier
            "2.5.29.37",  // ExtendedKeyUsage
            "1.3.6.1.5.5.7.1.1"   // AuthorityInfoAccess
    );

    private final byte[] certData;
    private final int tbsCertOff;
    private final int tbsCertLen;
    private final PublicKeyParameters publicKey;
    private final int sigOff;
    private final int sigLen;
    private final Date notBefore;
    private final Date notAfter;
    private final String[] sanDnsNames;
    private final byte[][] sanIpAddresses;
    private final boolean keyUsageValid;
    private final boolean ekuValid;
    private final boolean ekuClientAuth;
    private final boolean ekuOcspSigning;
    private final boolean isCA;
    private final int pathLen;
    private final boolean keyCertSign;
    private final boolean hasUnknownCritical;
    private final boolean algConsistent;
    private byte[] ocspResponse;
    private byte[] ocspNonce;
    private final int version;
    private final String subjectDnStr;
    private final String issuerDnStr;
    private final DnField[] subjectDnFields;
    private final DnField[] issuerDnFields;
    private final int serialOff;
    private final int serialLen;
    private final int issuerDnOff;
    private final int issuerDnLen;
    private final int subjectDnOff;
    private final int subjectDnLen;

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
    // Все OID ExtendedKeyUsage (2.5.29.37) — не только известные, но и УКЭП/УНЭП
    private final byte[][] ekuOids;
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
     * <p>Внутри TLS-handshake такая обёртка уже есть — см.
     * {@code TlsHandshakeEngine.receiveCertificate}.</p>
     *
     * @param derEncoded полный сертификат в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null}
     *         или явно обнаружен невалидный синтаксис (например, неожиданный тег)
     * @throws RuntimeException на повреждённом DER — конкретный подкласс не специфицирован
     */
    public TlsCertificate(byte[] derEncoded) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("Certificate DER must not be null");
        }
        this.certData = derEncoded.clone();

        int[] outer = parseSequence(derEncoded, 0);
        int certContentStart = outer[0];
        if (certContentStart >= outer[1]) {
            throw new IllegalArgumentException("Truncated DER encoding: empty certificate SEQUENCE");
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
                if (verTagTlv[0] < verTagTlv[1] && (derEncoded[verTagTlv[0]] & 0xFF) == TAG_INTEGER) {
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
        Date[] validity = parseValidity(derEncoded, tbsTlv);
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
        DnParseResult subjectDnR = parseDnString(derEncoded, this.subjectDnOff, this.subjectDnLen);
        this.subjectDnStr = subjectDnR.dnString;
        this.subjectDnFields = subjectDnR.fields.isEmpty() ? null : subjectDnR.fields.toArray(new DnField[0]);
        DnParseResult issuerDnR = parseDnString(derEncoded, this.issuerDnOff, this.issuerDnLen);
        this.issuerDnStr = issuerDnR.dnString;
        this.issuerDnFields = issuerDnR.fields.isEmpty() ? null : issuerDnR.fields.toArray(new DnField[0]);

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
                    "Truncated DER encoding: empty BIT STRING for signature at offset " + sigTagOffset);
        }
        int unusedBits = derEncoded[sigValTlv[0]] & 0xFF;
        if (unusedBits != 0) {
            throw new IllegalArgumentException("Unsupported BIT STRING with unused bits");
        }
        this.sigOff = sigValTlv[0] + 1;
        this.sigLen = sigValTlv[1] - sigValTlv[0] - 1;

        // Извлекаем SubjectPublicKeyInfo из TBSCertificate
        this.publicKey = extractPublicKey(derEncoded, tbsTlv);

        // Парсим SubjectAltName, KeyUsage, ExtendedKeyUsage, BasicConstraints из extensions
        ExtensionsResult ext = parseExtensions(derEncoded, tbsTlv);
        this.sanDnsNames = ext.sanDnsNames;
        this.sanIpAddresses = ext.sanIpAddresses;
        this.keyUsageValid = ext.keyUsageValid;
        this.ekuValid = ext.ekuValid;
        this.ekuClientAuth = ext.ekuClientAuth;
        this.ekuOcspSigning = ext.ekuOcspSigning;
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
            this.algConsistent = outerSigLen == tbsSigTlv[1] - tbsPos
                && arrayRangeEquals(derEncoded, outerSigOff, outerSigLen,
                                    derEncoded, tbsPos, tbsSigTlv[1] - tbsPos);
        } else {
            this.algConsistent = false;
        }
    }

    /**
     * @return сырые DER-байты сертификата
     */
    public byte[] getCertData() {
        return certData.clone();
    }

    /**
     * @return открытый ключ, извлечённый из сертификата
     */
    public PublicKeyParameters getPublicKey() {
        return publicKey;
    }

    /**
     * Верифицирует подпись сертификата с использованием ключа удостоверяющего центра.
     *
     * @param caPublicKey открытый ключ издателя сертификата
     * @return true если подпись действительна
     */
    public boolean verify(PublicKeyParameters caPublicKey) {
        int hlen = caPublicKey.getParams().hlen;
        Digest.Algorithm hashAlg = hlen == TlsConstants.STREEBOG_512_HASH_LEN
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
     * @return true если срок действия сертификата истёк
     */
    public boolean isExpired() {
        Date now = new Date();
        return now.before(notBefore) || now.after(notAfter);
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
     * @param hostname DNS-имя сервера (null или пустой → true)
     * @return true если hostname соответствует сертификату
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

        // IP-адрес → проверка против iPAddress SAN (tag 0x87)
        if (isIpAddress(normalized)) return verifyAddress(normalized);

        // DNS-проверка требует хотя бы одного dNSName в SAN
        if (sanDnsNames == null) return false;

        for (String san : sanDnsNames) {
            String sanLower = san.toLowerCase();

            // Точное совпадение
            if (normalized.equals(sanLower)) return true;

            // Wildcard: должен начинаться с "*."
            if (sanLower.startsWith("*.")) {
                String suffix = sanLower.substring(2); // всё после "*."

                // Wildcard не должен быть "*." + apex (напр. *.com)
                if (suffix.isEmpty() || suffix.indexOf('.') < 0) continue;

                // Частичный wildcard (f*.example.com) запрещён — sanLower уже проверили startsWith("*.")
                // Но проверяем что других * нет
                if (sanLower.indexOf('*', 1) >= 0) continue;

                // IDN A-label wildcard запрещён
                if (suffix.startsWith("xn--") || suffix.contains(".xn--")) continue;

                // Первая метка hostname не должна содержать точек
                int firstDot = normalized.indexOf('.');
                if (firstDot < 0) continue;

                // Первая метка не пустая
                String firstLabel = normalized.substring(0, firstDot);
                if (firstLabel.isEmpty()) continue;

                // Оставшаяся часть hostname должна совпадать с suffix
                String rest = normalized.substring(firstDot + 1);
                if (rest.equals(suffix)) return true;
            }
        }
        return false;
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
        // EKU не задан → без ограничений (RFC 5280 §4.2.1.12)
        return ekuOcspSigning;
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
    public Date getNotBefore() {
        return notBefore;
    }

    /** @return дата окончания действия сертификата */
    public Date getNotAfter() {
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
        return ocspResponse == null ? null : ocspResponse.clone();
    }

    /**
     * @param data OCSP-ответ из CertificateEntry status_request
     *              Defensive copy — caller не может модифицировать внутренний OCSP-ответ.
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
     * Возвращает DER-encoded сертификат.
     * <p>Симметричный аналог {@link #fromDer(byte[])}.
     *
     * @return DER-encoded сертификат
     */
    public byte[] toDer() {
        return getEncoded();
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
        byte[] der = getEncoded();
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END CERTIFICATE-----\n");
        return sb.toString();
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
    public static String chainToPem(List<TlsCertificate> chain) {
        if (chain == null) {
            throw new IllegalArgumentException("chain must not be null");
        }
        StringBuilder sb = new StringBuilder();
        for (TlsCertificate cert : chain) {
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

    public byte[] getOcspNonce() {
        return ocspNonce == null ? null : ocspNonce.clone();
    }

    /**
     * @param nonce значение nonce из OCSP-запроса (defensive copy)
     */
    public void setOcspNonce(byte[] nonce) {
        this.ocspNonce = nonce == null ? null : nonce.clone();
    }

    /**
     * Верифицирует OCSP-ответ (RFC 6960) для этого сертификата.
     *
     * <p><b>Ограничения:</b></p>
     * <ul>
     *   <li>Поддерживается только OCSP от непосредственного issuer'а сертификата.</li>
     *   <li>Delegated OCSP responders (RFC 6960 §2.6) не поддерживаются.</li>
     *   <li>responderID не валидируется — authenticity гарантируется проверкой подписи переданным caKey.</li>
     * </ul>
     *
     * @param caKey открытый ключ CA, выпустившего сертификат
     * @throws TlsException при ошибке верификации OCSP
     */
    public void verifyOcspResponse(PublicKeyParameters caKey) throws TlsException {
        verifyOcspResponse(caKey, null);
    }

    /**
     * Верифицирует OCSP-ответ с дополнительной проверкой CertID (issuerNameHash/issuerKeyHash).
     *
     * @param caKey  открытый ключ CA
     * @param issuer сертификат издателя (может быть null — тогда CertID не проверяется)
     * @throws TlsException при ошибке верификации
     */
    public void verifyOcspResponse(PublicKeyParameters caKey, TlsCertificate issuer) throws TlsException {
        byte[] serialCopy = new byte[serialLen];
        System.arraycopy(certData, serialOff, serialCopy, 0, serialLen);
        if (issuer != null) {
            TlsOcspVerifier.verify(ocspResponse, serialCopy, caKey,
                    getIssuerDnBytes(), issuer.getEncoded());
        } else {
            TlsOcspVerifier.verify(ocspResponse, serialCopy, caKey);
        }
        // Проверка nonce если он был установлен
        if (ocspNonce != null) {
            TlsOcspVerifier.verifyNonce(ocspResponse, ocspNonce, false);
        }
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
        TlsCertificate that = (TlsCertificate) o;
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
        sb.append("TlsCertificate{serial=0x").append(getSerialNumberBigInt().toString(16));
        sb.append(", subject=").append(getSubjectDnForLog(256));
        sb.append(", issuer=").append(getIssuerDnForLog(256));
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd");
        sb.append(", validity=[").append(fmt.format(notBefore)).append(" → ").append(fmt.format(notAfter)).append(']');
        sb.append(", algorithm=").append(publicKey.getParams().hlen * 8).append("bit GOST R 34.10-2012");
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
            return verify(publicKey);
        } catch (Exception e) {
            // Любая ошибка (битый ключ, неподдерживаемый алгоритм) → false
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
        return arrayRangeEquals(certData, issuerDnOff, issuerDnLen,
                                certData, subjectDnOff, subjectDnLen);
    }

    // ========================================================================
    // Validity
    // ========================================================================

    /**
     * Проверяет, действителен ли сертификат на указанную дату.
     *
     * @param date дата проверки (не null)
     * @return true если notBefore <= date <= notAfter
     */
    public boolean isValidAt(Date date) {
        return !date.before(notBefore) && !date.after(notAfter);
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
        return getDnField(subjectDnFields, oidDot);
    }

    /**
     * Возвращает все значения указанного OID-атрибута из Issuer DN.
     *
     * @param oidDot OID в точечной нотации, например "2.5.4.3" для CN
     * @return массив значений (может быть пустым, но не null)
     */
    public String[] getIssuerDnField(String oidDot) {
        return getDnField(issuerDnFields, oidDot);
    }

    /**
     * @param maxLen максимальная длина строки
     * @return Subject DN для логирования, обрезанный до maxLen символов.
     *         Если DN длиннее — добавляет "...[truncated]".
     */
    public String getSubjectDnForLog(int maxLen) {
        return truncateForLog(subjectDnStr, maxLen);
    }

    /**
     * @param maxLen максимальная длина строки
     * @return Issuer DN для логирования, обрезанный до maxLen символов.
     *         Если DN длиннее — добавляет "...[truncated]".
     */
    public String getIssuerDnForLog(int maxLen) {
        return truncateForLog(issuerDnStr, maxLen);
    }

    // ========================================================================
    // Внутренние методы
    // ========================================================================

    /**
     * Проверяет, относится ли указанная схема подписи к той же длине ключа,
     * что и сертификат (RFC 9367 §3.2: все схемы одной длины взаимозаменяемы
     * для целей проверки CertificateVerify).
     *
     * @param scheme схема подписи из CertificateVerify
     * @return true если схема совместима с ключом сертификата
     */
    public boolean hasSignatureScheme(int scheme) {
        int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(publicKey.getParams());
        int expectedScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
        return scheme == expectedScheme;
    }

    // ========================================================================
    // SignatureAlgorithm OID, NamedGroup, SKI/AKI — алгоритм и идентификаторы
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
     * TLS named group (RFC 9367 §3.1) по кривой открытого ключа.
     *
     * <p>Используется для согласования кривой в TLS handshake.
     * Мапинг через {@link TlsCiphersuite#paramsToNamedGroup} сравнением
     * {@code params.n} (порядка подгруппы) с эталонными кривыми.</p>
     *
     * @return константа TlsConstants.GRP_GC256A и т.д.
     * @throws IllegalArgumentException если кривая не распознана
     */
    public int getNamedGroup() {
        return TlsCiphersuite.paramsToNamedGroup(publicKey.getParams());
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
     * <p>try-catch: любая ошибка (неподдерживаемая кривая, битый ключ) → false.</p>
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
     * если верификация через {@link #verify(PublicKeyParameters)} не подходит.</p>
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
     * Извлекает SubjectPublicKeyInfo из TBSCertificate.
     * SubjectPublicKeyInfo — 5-я SEQUENCE в TBSCertificate после
     * version [0] (если есть) и serialNumber (INTEGER).
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return открытый ключ
     */
    private static PublicKeyParameters extractPublicKey(
            byte[] der, int[] tbsTlv) {
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
                    byte[] spkiDer = Arrays.copyOfRange(der, pos, tlv[1]);
                    return GostDerCodec.decodePublicKey(spkiDer);
                }
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("No SubjectPublicKeyInfo found in TBSCertificate");
    }

    // ========================================================================
    // Extensions (SubjectAltName, KeyUsage, ExtendedKeyUsage)
    // ========================================================================

    private static final class ExtensionsResult {
        final String[] sanDnsNames;
        final byte[][] sanIpAddresses;
        final boolean keyUsageValid;
        final boolean ekuValid;
        final boolean ekuClientAuth;
        final boolean ekuOcspSigning;
        final boolean isCA;
        final int pathLen;
        final boolean keyCertSign;
        final boolean hasUnknownCritical;
        final byte[] skiBytes;
        final byte[] akiBytes;
        final String[] aiaUris;
        final String[] ocspUris;
        final String[] caIssuersUris;
        final String[] cdpUris;
        final String[] certPolicyOids;
        final int keyUsageBits;
        final byte[][] ekuOids;
        final Set<String> presentExtensionOids;
        ExtensionsResult(String[] sanDnsNames, byte[][] sanIpAddresses, boolean keyUsageValid, boolean ekuValid, boolean ekuClientAuth,
                          boolean ekuOcspSigning, boolean isCA, int pathLen, boolean keyCertSign, boolean hasUnknownCritical,
                          byte[] skiBytes, byte[] akiBytes, String[] aiaUris,
                          String[] ocspUris, String[] caIssuersUris,
                          String[] cdpUris, String[] certPolicyOids,
                          int keyUsageBits, byte[][] ekuOids, Set<String> presentExtensionOids) {
            this.sanDnsNames = sanDnsNames;
            this.sanIpAddresses = sanIpAddresses;
            this.keyUsageValid = keyUsageValid;
            this.ekuValid = ekuValid;
            this.ekuClientAuth = ekuClientAuth;
            this.ekuOcspSigning = ekuOcspSigning;
            this.isCA = isCA;
            this.pathLen = pathLen;
            this.keyCertSign = keyCertSign;
            this.hasUnknownCritical = hasUnknownCritical;
            this.skiBytes = skiBytes;
            this.akiBytes = akiBytes;
            this.aiaUris = aiaUris;
            this.ocspUris = ocspUris;
            this.caIssuersUris = caIssuersUris;
            this.cdpUris = cdpUris;
            this.certPolicyOids = certPolicyOids;
            this.keyUsageBits = keyUsageBits;
            this.ekuOids = ekuOids;
            this.presentExtensionOids = presentExtensionOids;
        }

        /** @return пустой результат — расширения не найдены или не распарсены.
         *         По RFC 5280 отсутствие расширений не является ошибкой: ключ
         *         считается валидным для всех целей (permissive default). */
        static ExtensionsResult empty() {
            return new ExtensionsResult(
                null,   // sanDnsNames
                null,   // sanIpAddresses
                true,   // keyUsageValid     — KU отсутствует, все uses разрешены (§4.2.1.3)
                true,   // ekuValid          — EKU отсутствует, все purposes разрешены (§4.2.1.12)
                true,   // ekuClientAuth     — следствие absent EKU
                false,  // ekuOcspSigning    — OCSP-подпись не подразумевается
                false,  // isCA              — BC отсутствует, не CA (§4.2.1.9)
                -1,     // pathLen           — BC отсутствует, ограничения нет
                false,  // keyCertSign       — KU отсутствует, keyCertSign не установлен
                false,  // hasUnknownCritical— нечему быть unknown
                null,   // skiBytes
                null,   // akiBytes
                null,   // aiaUris
                null,   // ocspUris
                null,   // caIssuersUris
                null,   // cdpUris
                null,   // certPolicyOids
                0,      // keyUsageBits      — KU отсутствует, маска пуста
                null,   // ekuOids           — EKU отсутствует
                Collections.emptySet()  // presentExtensionOids — ни одного OID
            );
        }
    }

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
    private static ExtensionsResult parseExtensions(byte[] der, int[] tbsTlv) {
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(der, tbsTlv);
        if (pos < 0) return ExtensionsResult.empty();
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
        if (seqCount < TBS_SPKI_SEQUENCE_INDEX) return ExtensionsResult.empty();

        // issuerUniqueID [1], subjectUniqueID [2], затем extensions [3]
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            if (tag == TAG_CTX_1 || tag == TAG_CTX_2) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            if (tag == TAG_CTX_3) {
                return parseFromExtensionsBlock(der, pos);
            }
            break;
        }
        return ExtensionsResult.empty();
    }

    /**
     * Парсит содержимое [3] EXPLICIT — Extensions SEQUENCE с итерацией по каждому Extension.
     * Распознаёт OID: SAN (2.5.29.17), KU (2.5.29.15), EKU (2.5.29.37), BC (2.5.29.19).
     * Unknown critical extension → hasUnknownCritical = true (RFC 5280 §4.2).
     *
     * @param der          DER-поток сертификата
     * @param extTagOffset смещение на tag [3] EXPLICIT
     * @return результат парсинга расширений
     */
    private static ExtensionsResult parseFromExtensionsBlock(byte[] der, int extTagOffset) {
        int[] extTlv = readTlv(der, extTagOffset);
        int pos = extTlv[0];
        int end = extTlv[1];

        if (pos >= end || (der[pos] & 0xFF) != 0x30) {
            return ExtensionsResult.empty();
        }
        int[] seqTlv = readTlv(der, pos);
        pos = seqTlv[0];
        end = seqTlv[1];

        ArrayList<String> sanList = new ArrayList<>();
        ArrayList<byte[]> ipList = new ArrayList<>();
        boolean kuPresent = false;
        boolean kuDigitalSignature = false;
        boolean kuKeyCertSign = false;
        boolean ekuPresent = false;
        boolean ekuServerAuth = false;
        boolean ekuClientAuth = false;
        boolean ekuOcspSigning = false;

        boolean isCA = false;
        int pathLen = -1;
        boolean hasUnknownCritical = false;
        // SubjectKeyIdentifier, AuthorityKeyIdentifier, AuthorityInfoAccess
        byte[] skiBytesLocal = null;
        byte[] akiBytesLocal = null;
        ArrayList<String> aiaList = new ArrayList<>();
        ArrayList<String> ocspList = new ArrayList<>();
        ArrayList<String> caIssuersList = new ArrayList<>();
        // CRLDistributionPoints и CertificatePolicies
        ArrayList<String> cdpList = new ArrayList<>();
        ArrayList<String> certPolicyList = new ArrayList<>();
        // Для oid_filters matching (RFC 8446 §4.2.5)
        Set<String> presentOids = new HashSet<>();
        int keyUsageBitsLocal = 0;
        ArrayList<byte[]> ekuOidList = new ArrayList<>();

        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] extSeqTlv = readTlv(der, pos);
            int extContent = extSeqTlv[0];
            int extContentEnd = extSeqTlv[1];

            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != TAG_OID) {
                pos = extSeqTlv[1];
                continue;
            }
            int[] oidTlv = readTlv(der, extContent);
            int oidStart = oidTlv[0];
            int oidLen = oidTlv[1] - oidTlv[0];

            int afterOid = oidTlv[1];
            // Сохраняем OID в set для oid_filters matching
            String oidDot = oidBytesToDottedString(der, oidStart, oidLen);
            presentOids.add(oidDot);
            // Optional BOOLEAN (critical) — запоминаем значение
            boolean critical = false;
            if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_BOOLEAN) {
                int[] boolTlv = readTlv(der, afterOid);
                critical = boolTlv[0] < boolTlv[1] && der[boolTlv[0]] != 0;
                afterOid = boolTlv[1];
            }

            if (matchesOid(der, oidStart, oidLen, SAN_OID_BYTES)) {
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseSanGeneralNames(der, octTlv[0], octTlv[1], sanList, ipList);
                }
            } else if (matchesOid(der, oidStart, oidLen, KU_OID_BYTES)) {
                kuPresent = true;
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    int bsStart = octTlv[0];
                    if (bsStart < octTlv[1] && (der[bsStart] & 0xFF) == TAG_BIT_STRING) {
                        int[] bitTlv = readTlv(der, bsStart);
                        int unusedBits = der[bitTlv[0]] & 0xFF;
                        int valueStart = bitTlv[0] + 1;
                        int valueLen = bitTlv[1] - valueStart;
                        if (valueStart < bitTlv[1] && valueLen > 0) {
                            kuDigitalSignature = (der[valueStart] & TlsDerParser.KU_DIGITAL_SIGNATURE) != 0;
                            // keyCertSign — бит 5 = 0x04 в первом байте (KU не определяет биты ≥ 9)
                            if (valueLen > 0) kuKeyCertSign = (der[valueStart] & TlsDerParser.KU_KEY_CERT_SIGN) != 0;
                            // Собираем raw KU-маску для oid_filters matching
                            for (int k = 0; k < valueLen && k < 2; k++) {
                                keyUsageBitsLocal |= (der[valueStart + k] & 0xFF) << (8 * k);
                            }
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, EKU_OID_BYTES)) {
                ekuPresent = true;
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    ekuServerAuth = hasEku(der, octTlv[0], octTlv[1], TlsDerParser.SERVER_AUTH_OID_BYTES);
                    ekuClientAuth = hasEku(der, octTlv[0], octTlv[1], TlsDerParser.CLIENT_AUTH_OID_BYTES);
                    // EKU id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
                    if (hasEku(der, octTlv[0], octTlv[1], TlsDerParser.OCSP_SIGNING_OID_BYTES)
                            || hasEku(der, octTlv[0], octTlv[1], TlsDerParser.ANY_EKU_OID_BYTES)) {
                        ekuOcspSigning = true;
                    }
                    // Собираем ВСЕ EKU OID для oid_filters matching (в т.ч. УКЭП/УНЭП)
                    collectAllEkuOids(der, octTlv[0], octTlv[1], ekuOidList);
                }
            } else if (matchesOid(der, oidStart, oidLen, BC_OID_BYTES)) {
                // BasicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    int bcPos = octTlv[0];
                    int bcEnd = octTlv[1];
                    if (bcPos < bcEnd && (der[bcPos] & 0xFF) == TAG_SEQUENCE) {
                        int[] bcSeqTlv = readTlv(der, bcPos);
                        int bcInnerPos = bcSeqTlv[0];
                        int bcInnerEnd = bcSeqTlv[1];
                        // cA BOOLEAN (optional, default FALSE)
                        if (bcInnerPos < bcInnerEnd && (der[bcInnerPos] & 0xFF) == TAG_BOOLEAN) {
                            int[] boolTlv = readTlv(der, bcInnerPos);
                            isCA = boolTlv[0] < boolTlv[1] && der[boolTlv[0]] != 0;
                            bcInnerPos = boolTlv[1];
                        }
                        // pathLen INTEGER (optional)
                        if (bcInnerPos < bcInnerEnd && (der[bcInnerPos] & 0xFF) == TAG_INTEGER) {
                            int[] intTlv = readTlv(der, bcInnerPos);
                            // DER INTEGER: unpack value
                            int val = 0;
                            for (int i = intTlv[0]; i < intTlv[1]; i++) {
                                val = (val << 8) | (der[i] & 0xFF);
                            }
                            pathLen = val;
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, SKI_OID_BYTES)) {
                // SubjectKeyIdentifier — OCTET STRING внутри OCTET STRING (RFC 5280 §4.2.1.2).
                // Внешний OCTET STRING — обёртка X.509 extension value.
                // Внутренний — сам KeyIdentifier (хэш ключа).
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_OCTET_STRING) {
                        int[] innerTlv = readTlv(der, octTlv[0]);
                        skiBytesLocal = Arrays.copyOfRange(der, innerTlv[0], innerTlv[1]);
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, AKI_OID_BYTES)) {
                // AuthorityKeyIdentifier — SEQUENCE с опциональным [0] KeyIdentifier (RFC 5280 §4.2.1.1).
                // Остальные поля ([1] issuer, [2] serial) не парсим — не используются.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_SEQUENCE) {
                        int[] akiSeqTlv = readTlv(der, octTlv[0]);
                        int akiPos = akiSeqTlv[0];
                        int akiEnd = akiSeqTlv[1];
                        // [0] IMPLICIT на OCTET STRING — tag 0x80 (primitive) или 0xA0 (constructed).
                        // Оба варианта встречаются в реальных сертификатах.
                        if (akiPos < akiEnd) {
                            int ctxTag = der[akiPos] & 0xFF;
                            if ((ctxTag & 0xDF) == 0x80) {
                                int[] ctxTlv = readTlv(der, akiPos);
                                akiBytesLocal = Arrays.copyOfRange(der, ctxTlv[0], ctxTlv[1]);
                            }
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, AIA_OID_BYTES)) {
                // AuthorityInfoAccess — SEQUENCE of AccessDescription (RFC 5280 §4.2.2.1).
                // Извлекаем все URI (uniformResourceIdentifier [6]) — и OCSP, и caIssuers.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseAiaDescriptions(der, octTlv[0], octTlv[1], aiaList, ocspList, caIssuersList);
                }
            } else if (matchesOid(der, oidStart, oidLen, CDP_OID_BYTES)) {
                // CRLDistributionPoints (RFC 5280 §4.2.1.13) — точки распространения CRL.
                // Нужен клиенту чтобы найти CRL для проверки статуса сертификата.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCdpUris(der, octTlv[0], octTlv[1], cdpList);
                }
            } else if (matchesOid(der, oidStart, oidLen, CP_OID_BYTES)) {
                // CertificatePolicies (RFC 5280 §4.2.1.4) — OID политик сертификата.
                // Нужен caller'у чтобы проверить соответствие политикам организации.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCertPolicyOids(der, octTlv[0], octTlv[1], certPolicyList);
                }
            } else if (critical) {
                // Неизвестное critical extension: reject согласно RFC 5280 §4.2
                hasUnknownCritical = true;
            }
            pos = extSeqTlv[1];
        }

        // keyCertSign проверка: если KU есть, нужен бит 5; если KU нет — не отклоняем
        boolean keyCertSignOk = !kuPresent || kuKeyCertSign;

        String[] sanResult = sanList.isEmpty() ? null : sanList.toArray(new String[0]);
        byte[][] ipResult = ipList.isEmpty() ? null : ipList.toArray(new byte[0][]);
        boolean kuValid = !kuPresent || kuDigitalSignature;
        boolean ekuValid = !ekuPresent || ekuServerAuth;
        boolean ekuClientAuthValid = !ekuPresent || ekuClientAuth;
        byte[][] ekuOidsResult = ekuOidList.isEmpty() ? null : ekuOidList.toArray(new byte[0][]);
        return new ExtensionsResult(sanResult, ipResult, kuValid, ekuValid, ekuClientAuthValid,
                !ekuPresent || ekuOcspSigning, isCA, pathLen, keyCertSignOk, hasUnknownCritical,
                skiBytesLocal, akiBytesLocal,
                aiaList.isEmpty() ? null : aiaList.toArray(new String[0]),
                ocspList.isEmpty() ? null : ocspList.toArray(new String[0]),
                caIssuersList.isEmpty() ? null : caIssuersList.toArray(new String[0]),
                cdpList.isEmpty() ? null : cdpList.toArray(new String[0]),
                certPolicyList.isEmpty() ? null : certPolicyList.toArray(new String[0]),
                keyUsageBitsLocal, ekuOidsResult, presentOids);
    }

    // ========================================================================
    // SAN, EKU helpers (используют статические импорты из TlsDerParser)
    // ========================================================================

    /**
     * Парсит GeneralNames SEQUENCE из SubjectAltName.
     * Извлекает dNSName (tag 0x82) и iPAddress (tag 0x87) entries.
     *
     * @param der       DER-поток сертификата
     * @param gnOuter   смещение на SEQUENCE GeneralNames
     * @param gnOuterEnd конец outer TLV
     * @param sanList   список для DNS-имён
     * @param ipList    список для IP-адресов
     */
    private static void parseSanGeneralNames(byte[] der, int gnOuter, int gnOuterEnd,
                                              ArrayList<String> sanList, ArrayList<byte[]> ipList) {
        if (gnOuter >= gnOuterEnd || (der[gnOuter] & 0xFF) != TAG_SEQUENCE) return;
        int[] gnSeqTlv = readTlv(der, gnOuter);
        int gnPos = gnSeqTlv[0];
        int gnEnd = gnSeqTlv[1];
        while (gnPos < gnEnd) {
            int gnTag = der[gnPos] & 0xFF;
            if (gnTag == TAG_DNS_NAME) {
                int[] dnsTlv = readTlv(der, gnPos);
                String name = new String(der, dnsTlv[0], dnsTlv[1] - dnsTlv[0],
                        java.nio.charset.StandardCharsets.US_ASCII);
                sanList.add(name);
                gnPos = dnsTlv[1];
            } else if (gnTag == TAG_IP_ADDRESS) {
                int[] ipTlv = readTlv(der, gnPos);
                int len = ipTlv[1] - ipTlv[0];
                if (len == 4 || len == 16) {
                    ipList.add(Arrays.copyOfRange(der, ipTlv[0], ipTlv[1]));
                }
                gnPos = ipTlv[1];
            } else {
                gnPos = readTlv(der, gnPos)[1];
            }
        }
    }

    // id-ad-ocsp = 1.3.6.1.5.5.7.48.1, id-ad-caIssuers = 1.3.6.1.5.5.7.48.2
    // (константы в TlsDerParser.AD_OCSP_OID_BYTES, TlsDerParser.AD_CA_ISSUERS_OID_BYTES)

    /**
     * Проверяет наличие указанного OID в ExtendedKeyUsage SEQUENCE.
     *
     * @param der      DER-поток сертификата
     * @param seqOuter смещение на SEQUENCE EKU
     * @param seqEnd   конец SEQUENCE EKU
     * @param oid      OID для поиска
     * @return true если OID найден
     */
    private static boolean hasEku(byte[] der, int seqOuter, int seqEnd, byte[] oid) {
        int pos = seqOuter;
        if (pos >= seqEnd || (der[pos] & 0xFF) != TAG_SEQUENCE) return false;
        int[] seqTlv = readTlv(der, pos);
        pos = seqTlv[0];
        int end = seqTlv[1];
        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_OID) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] oidTlv = readTlv(der, pos);
            if (matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], oid)) {
                return true;
            }
            pos = oidTlv[1];
        }
        return false;
    }

    /**
     * Собирает все OID из SEQUENCE ExtendedKeyUsage.
     * oid_filters matching для УКЭП/УНЭП (1.2.643.100.113.1/2) требует знать
     * все EKU OID сертификата, а не только три хардкоженных (serverAuth, clientAuth, ocspSigning).
     */
    private static void collectAllEkuOids(byte[] der, int seqOuter, int seqEnd,
                                           ArrayList<byte[]> ekuOidList) {
        int pos = seqOuter;
        if (pos >= seqEnd || (der[pos] & 0xFF) != TAG_SEQUENCE) return;
        int[] seqTlv = readTlv(der, pos);
        pos = seqTlv[0];
        int end = seqTlv[1];
        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_OID) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] oidTlv = readTlv(der, pos);
            ekuOidList.add(Arrays.copyOfRange(der, oidTlv[0], oidTlv[1]));
            pos = oidTlv[1];
        }
    }

    /**
     * Проверяет, удовлетворяет ли сертификат OID-фильтру из oid_filters
     * (RFC 8446 §4.2.5).
     * <p>
     * Правила matching:
     * <ul>
     *   <li>Неизвестный OID → игнорируется (возвращает true)</li>
     *   <li>KU (2.5.29.15): все биты фильтра должны быть установлены в keyUsage</li>
     *   <li>EKU (2.5.29.37): все OID фильтра должны присутствовать; anyExtendedKeyUsage запрещён</li>
     *   <li>Известный OID, пустые values: достаточно присутствия расширения</li>
     *   <li>Известный OID, непустые values: DER-значение должно совпадать</li>
     * </ul>
     *
     * @param filter OID-фильтр из CertificateRequest
     * @return true если сертификат удовлетворяет фильтру
     */
    public boolean matchesOidFilter(OIDFilter filter) {
        byte[] filterOid = filter.extensionOid();
        byte[] filterValues = filter.extensionValues();

        // KU (2.5.29.15)
        if (Arrays.equals(filterOid, KU_OID_BYTES)) {
            int filterBits = 0;
            // DER BIT STRING: первый байт — unused bits, затем собственно биты
            if (filterValues.length > 0) {
                int unused = filterValues[0] & 0xFF;
                for (int i = 1; i < filterValues.length && i - 1 < 2; i++) {
                    filterBits |= (filterValues[i] & 0xFF) << (8 * (i - 1));
                }
                if (unused > 0 && filterValues.length > 1) {
                    filterBits = (filterBits >> unused) << unused;
                }
            }
            return (keyUsageBits & filterBits) == filterBits;
        }

        // EKU (2.5.29.37)
        if (Arrays.equals(filterOid, EKU_OID_BYTES)) {
            if (ekuOids == null && filterValues.length > 0) {
                return false;
            }
            // anyExtendedKeyUsage запрещён (RFC 8446 §4.2.5)
            if (ekuOids != null) {
                for (byte[] ekuOid : ekuOids) {
                    if (matchesOid(ekuOid, 0, ekuOid.length, ANY_EKU_OID_BYTES)) {
                        return false;
                    }
                }
            }
            // Пустые values — достаточно присутствия EKU
            if (filterValues.length == 0) {
                return ekuOids != null;
            }
            // Разбираем filterValues как DER SEQUENCE of OID
            if (filterValues.length < 2 || filterValues[0] != TAG_SEQUENCE) {
                return false;
            }
            int[] seqTlv = readTlv(filterValues, 0);
            int pos = seqTlv[0];
            int end = seqTlv[1];
            while (pos < end) {
                if ((filterValues[pos] & 0xFF) != TAG_OID) {
                    pos = readTlv(filterValues, pos)[1];
                    continue;
                }
                int[] oidTlv = readTlv(filterValues, pos);
                boolean found = false;
                if (ekuOids != null) {
                    for (byte[] ekuOid : ekuOids) {
                        if (matchesOid(ekuOid, 0, ekuOid.length,
                                Arrays.copyOfRange(filterValues, oidTlv[0], oidTlv[1]))) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) return false;
                pos = oidTlv[1];
            }
            return true;
        }

        // Другие известные OID: проверяем наличие по presentExtensionOids
        String oidDot = oidBytesToDottedString(filterOid, 0, filterOid.length);
        if (presentExtensionOids.contains(oidDot)) {
            if (filterValues.length > 0) {
                return matchesExtensionValue(filterOid, filterValues);
            }
            return true;
        }

        // Известное расширение отсутствует в сертификате — фильтр не проходит,
        // даже если values пусты (RFC 5280: absent extension = не удовлетворяет требованию)
        if (KNOWN_EXTENSION_OIDS.contains(oidDot)) {
            return false;
        }

        // Неизвестный OID → игнорируем (RFC 8446 §4.2.5)
        return true;
    }

    /**
     * Сканирует raw DER сертификата для поиска extension с указанным OID
     * и сравнивает его значение с expectedValue побайтово.
     * <p>
     * Почему не через pre-parsed поля: для произвольных OID (не KU/EKU/BC и т.д.)
     * у нас нет отдельного поля в ExtensionsResult. Единственный способ проверить
     * значение — просканировать extensions блок заново. Это O(n) по числу extensions,
     * но вызывается только для oid_filters с непустыми values — редкий случай.
     */
    private boolean matchesExtensionValue(byte[] filterOid, byte[] expectedValue) {
        // Сканируем extensions в raw DER сертификата
        int[] tbsTlv = parseSequence(certData, tbsCertOff);
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(certData, tbsTlv);
        if (pos < 0) return false;
        // Сканируем до 5-й SEQUENCE (SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = certData[pos] & 0xFF;
            int[] tlv = readTlv(certData, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == TBS_SPKI_SEQUENCE_INDEX) {
                    pos = tlv[1];
                    break;
                }
            }
            pos = tlv[1];
        }
        if (seqCount < TBS_SPKI_SEQUENCE_INDEX) return false;
        // issuerUniqueID [1], subjectUniqueID [2], extensions [3]
        while (pos < end) {
            if (pos >= end) return false;
            int tag = certData[pos] & 0xFF;
            if (tag == TAG_CTX_1 || tag == TAG_CTX_2) {
                pos = readTlv(certData, pos)[1];
                continue;
            }
            if (tag == TAG_CTX_3) {
                int[] extTlv = readTlv(certData, pos);
                int epos = extTlv[0];
                int eend = extTlv[1];
                if (epos >= eend || (certData[epos] & 0xFF) != 0x30) return false;
                int[] seqTlv2 = readTlv(certData, epos);
                epos = seqTlv2[0];
                eend = seqTlv2[1];
                while (epos < eend) {
                    if ((certData[epos] & 0xFF) != TAG_SEQUENCE) {
                        epos = readTlv(certData, epos)[1];
                        continue;
                    }
                    int[] extSeqTlv = readTlv(certData, epos);
                    int extContent2 = extSeqTlv[0];
                    int extContentEnd2 = extSeqTlv[1];
                    if (extContent2 >= extContentEnd2 || (certData[extContent2] & 0xFF) != TAG_OID) {
                        epos = extSeqTlv[1];
                        continue;
                    }
                    int[] oidTlv = readTlv(certData, extContent2);
                    if (!matchesOid(certData, oidTlv[0], oidTlv[1] - oidTlv[0], filterOid)) {
                        epos = extSeqTlv[1];
                        continue;
                    }
                    // Нашли extension — извлекаем значение (после OID и optional BOOLEAN)
                    int afterOid = oidTlv[1];
                    if (afterOid < extContentEnd2 && (certData[afterOid] & 0xFF) == TAG_BOOLEAN) {
                        afterOid = readTlv(certData, afterOid)[1];
                    }
                    if (afterOid >= extContentEnd2) return false;
                    if ((certData[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                        int[] octTlv = readTlv(certData, afterOid);
                        return octTlv[1] - octTlv[0] == expectedValue.length
                                && arrayRangeEquals(certData, octTlv[0], octTlv[1],
                                expectedValue, 0, expectedValue.length);
                    }
                    return false;
                }
                return false;
            }
            break;
        }
        return false;
    }

    // ========================================================================
    // AIA парсинг — AuthorityInfoAccess (RFC 5280 §4.2.2.1)
    // ========================================================================

    /**
     * Парсит AccessDescription SEQUENCE из AuthorityInfoAccess.
     * <p>
     * AccessDescription ::= SEQUENCE {
     *   accessMethod   OBJECT IDENTIFIER,
     *   accessLocation GeneralName }
     * <p>
     * Извлекает URI (uniformResourceIdentifier [6]) и раскладывает по трём спискам:
     * uriList — все URI (для backward-compat), ocspList — id-ad-ocsp,
     * caIssuersList — id-ad-caIssuers.
     */
    private static void parseAiaDescriptions(byte[] der, int aiaOuter, int aiaEnd,
                                              ArrayList<String> uriList,
                                              ArrayList<String> ocspList,
                                              ArrayList<String> caIssuersList) {
        if (aiaOuter >= aiaEnd || (der[aiaOuter] & 0xFF) != TAG_SEQUENCE) return;
        int[] aiaSeqTlv = readTlv(der, aiaOuter);
        int pos = aiaSeqTlv[0];
        int end = aiaSeqTlv[1];
        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] adSeqTlv = readTlv(der, pos);
            int adPos = adSeqTlv[0];
            int adEnd = adSeqTlv[1];
            if (adPos >= adEnd || (der[adPos] & 0xFF) != TAG_OID) {
                pos = adSeqTlv[1];
                continue;
            }
            int[] methodOidTlv = readTlv(der, adPos);
            // rawOidTlv — для сравнения OID с AD_OCSP и AD_CA_ISSUERS
            int[] rawOidTlv = readTlv(der, adPos);
            int locPos = methodOidTlv[1];
            if (locPos < adEnd) {
                int locTag = der[locPos] & 0xFF;
                if ((locTag & 0xDF) == 0x86) {
                    int[] uriTlv = readTlv(der, locPos);
                    String uri = new String(der, uriTlv[0], uriTlv[1] - uriTlv[0],
                            java.nio.charset.StandardCharsets.US_ASCII);
                    uriList.add(uri);
                    if (matchesOid(der, rawOidTlv[0], rawOidTlv[1] - rawOidTlv[0], TlsDerParser.AD_OCSP_OID_BYTES)) {
                        ocspList.add(uri);
                    } else if (matchesOid(der, rawOidTlv[0], rawOidTlv[1] - rawOidTlv[0], TlsDerParser.AD_CA_ISSUERS_OID_BYTES)) {
                        caIssuersList.add(uri);
                    }
                }
            }
            pos = adSeqTlv[1];
        }
    }

    // ========================================================================
    // CDP парсинг — CRLDistributionPoints (RFC 5280 §4.2.1.13)
    // ========================================================================

    /**
     * Парсит CRLDistributionPoints: извлекает URI из fullName GeneralNames.
     *
     * <p>DistributionPoint может содержать несколько URI (разные mirror'ы CRL).
     * Извлекаем все — caller выберет доступный. Структура DER:</p>
     * <pre>DistributionPoint ::= SEQUENCE {
     *   distributionPoint [0] DistributionPointName OPTIONAL,
     *   ... }
     * DistributionPointName ::= [0] GeneralNames</pre>
     */
    private static void parseCdpUris(byte[] der, int cdpOuter, int cdpEnd,
                                      ArrayList<String> uriList) {
        if (cdpOuter >= cdpEnd || (der[cdpOuter] & 0xFF) != TAG_SEQUENCE) return;
        int[] seqTlv = readTlv(der, cdpOuter);
        int pos = seqTlv[0];
        int end = seqTlv[1];
        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] dpSeqTlv = readTlv(der, pos);
            int dpPos = dpSeqTlv[0];
            int dpEnd = dpSeqTlv[1];
            // Ищем [0] DistributionPointName
            if (dpPos < dpEnd && (der[dpPos] & 0xFF) == TAG_CTX_0) {
                int[] dpNameTlv = readTlv(der, dpPos);
                int gnPos = dpNameTlv[0];
                int gnEnd = dpNameTlv[1];
                // DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
                // Пропускаем все [0] EXPLICIT обёртки до GeneralNames SEQUENCE
                int maxDepth = 10;
                while (gnPos < gnEnd && (der[gnPos] & 0xFF) == TAG_CTX_0 && --maxDepth > 0) {
                    int[] ctxTlv = readTlv(der, gnPos);
                    gnPos = ctxTlv[0];
                }
                // GeneralNames (SEQUENCE)
                if (gnPos < gnEnd && (der[gnPos] & 0xFF) == TAG_SEQUENCE) {
                    int[] gnSeqTlv = readTlv(der, gnPos);
                    int gnInner = gnSeqTlv[0];
                    int gnInnerEnd = gnSeqTlv[1];
                    while (gnInner < gnInnerEnd) {
                        int gnTag = der[gnInner] & 0xFF;
                        if ((gnTag & 0xDF) == 0x86) {
                            int[] uriTlv = readTlv(der, gnInner);
                            String uri = new String(der, uriTlv[0], uriTlv[1] - uriTlv[0],
                                    java.nio.charset.StandardCharsets.US_ASCII);
                            uriList.add(uri);
                            gnInner = uriTlv[1];
                        } else {
                            gnInner = readTlv(der, gnInner)[1];
                        }
                    }
                }
            }
            pos = dpSeqTlv[1];
        }
    }

    // ========================================================================
    // CertificatePolicies парсинг (RFC 5280 §4.2.1.4)
    // ========================================================================

    /**
     * Парсит CertificatePolicies: извлекает policyIdentifier OID как точечную строку.
     *
     * <p>Каждая PolicyInformation содержит OID политики и опциональные квалификаторы
     * (CPS URI, userNotice). Квалификаторы не парсим — OID достаточно для
     * идентификации политики. Формат DER:</p>
     * <pre>CertificatePolicies ::= SEQUENCE OF PolicyInformation
     * PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }</pre>
     */
    private static void parseCertPolicyOids(byte[] der, int cpOuter, int cpEnd,
                                             ArrayList<String> oidList) {
        if (cpOuter >= cpEnd || (der[cpOuter] & 0xFF) != TAG_SEQUENCE) return;
        int[] seqTlv = readTlv(der, cpOuter);
        int pos = seqTlv[0];
        int end = seqTlv[1];
        while (pos < end) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] piSeqTlv = readTlv(der, pos);
            int piPos = piSeqTlv[0];
            int piEnd = piSeqTlv[1];
            if (piPos < piEnd && (der[piPos] & 0xFF) == TAG_OID) {
                int[] oidTlv = readTlv(der, piPos);
                String oidStr = oidBytesToDottedString(der, oidTlv[0], oidTlv[1] - oidTlv[0]);
                oidList.add(oidStr);
            }
            pos = piSeqTlv[1];
        }
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
                return new int[]{pos, tlv[1] - pos};
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("DN not found in TBSCertificate (skipSeqs=" + skipSeqs + ")");
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
    private static Date[] parseValidity(byte[] der, int[] tbsTlv) {
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
                    Date notBefore = parseTime(der, tlv[0]);
                    Date notAfter = parseTime(der, readTlv(der, tlv[0])[1]);
                    return new Date[]{notBefore, notAfter};
                }
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("Validity not found in TBSCertificate");
    }

    // ========================================================================
    // DN string parsing — человеко-читаемые Distinguished Names
    // ========================================================================

    /**
     * Одна запись DN: OID (точечная нотация) + строковое значение.
     */
    private static final class DnField {
        final String oid;
        final String value;
        DnField(String oid, String value) {
            this.oid = oid;
            this.value = value;
        }
    }

    /**
     * Результат парсинга DN: готовая строка и список полей для lookup.
     */
    private static final class DnParseResult {
        final String dnString;
        final List<DnField> fields;
        DnParseResult(String dnString, List<DnField> fields) {
            this.dnString = dnString;
            this.fields = fields;
        }
    }

    // OID DN-атрибутов — в TlsDerParser (CN_OID_BYTES, C_OID_BYTES и т.д.)

    /**
     * Парсит DN SEQUENCE в человеко-читаемый DN-формат и список полей.
     * Формат строки: "CN=..., O=..., C=..."
     *
     * <p>try-catch: при ошибке парсинга возвращаем DnParseResult с null.
     * Безопасность: непечатные символы экранируются в escapeDnValue.</p>
     *
     * @param der   DER-поток сертификата
     * @param dnOff смещение на DN SEQUENCE
     * @param dnLen длина DN SEQUENCE
     * @return результат парсинга
     */
    private static DnParseResult parseDnString(byte[] der, int dnOff, int dnLen) {
        try {
            // DN = SEQUENCE of SET, каждая SET содержит SEQUENCE { OID, value }
            if (dnOff >= der.length || (der[dnOff] & 0xFF) != TAG_SEQUENCE) {
                return new DnParseResult(null, new ArrayList<DnField>(0));
            }
            int[] dnSeqTlv = readTlv(der, dnOff);
            int pos = dnSeqTlv[0];
            int end = dnSeqTlv[1];

            StringBuilder sb = new StringBuilder();
            List<DnField> fields = new ArrayList<>();
            boolean first = true;

            while (pos < end) {
                int tag = der[pos] & 0xFF;
                if (tag != 0x31) { // SET
                    pos = readTlv(der, pos)[1];
                    continue;
                }
                int[] setTlv = readTlv(der, pos);
                int setPos = setTlv[0];
                int setEnd = setTlv[1];

                while (setPos < setEnd) {
                    if ((der[setPos] & 0xFF) != TAG_SEQUENCE) {
                        setPos = readTlv(der, setPos)[1];
                        continue;
                    }
                    int[] attrTlv = readTlv(der, setPos);
                    int attrPos = attrTlv[0];
                    int attrEnd = attrTlv[1];
                    // OID — первый элемент SEQUENCE
                    if (attrPos >= attrEnd || (der[attrPos] & 0xFF) != TAG_OID) break;
                    int[] oidTlv = readTlv(der, attrPos);
                    String oidStr = oidBytesToDottedString(der, oidTlv[0], oidTlv[1] - oidTlv[0]);

                    // Value — второй элемент SEQUENCE (после OID)
                    int valPos = oidTlv[1];
                    if (valPos >= attrEnd) break;
                    int valTag = der[valPos] & 0xFF;
                    int[] valTlv = readTlv(der, valPos);
                    String value = decodeDnValue(der, valTlv[0], valTlv[1] - valTlv[0], valTag);

                    // В DN-строке используем короткое имя для известных OID
                    if (!first) sb.append(", ");
                    else first = false;
                    sb.append(lookupOidName(der, oidTlv[0], oidTlv[1] - oidTlv[0]));
                    sb.append('=').append(escapeDnValue(value));

                    fields.add(new DnField(oidStr, value));
                    setPos = attrTlv[1];
                }
                pos = setTlv[1];
            }
            return new DnParseResult(sb.toString(), fields);
        } catch (Exception e) {
            // DER повреждён или неизвестный формат → возвращаем null
            return new DnParseResult(null, new ArrayList<DnField>(0));
        }
    }

    /**
     * Преобразует DER-закодированный OID в точечную нотацию.
     *
     * <p>Схема: первые два компонента (arc1, arc2) кодируются одним байтом
     * как 40*arc1 + arc2. Остальные — base-128 variable-length encoding
     * с битом продолжения (MSB=1).</p>
     */
    private static String oidBytesToDottedString(byte[] der, int start, int len) {
        if (len < 1) return "";
        StringBuilder sb = new StringBuilder();
        int first = der[start] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);
        int pos = start + 1;
        int end = start + len;
        while (pos < end) {
            long val = 0;
            while (pos < end) {
                int b = der[pos++] & 0xFF;
                val = (val << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) break;
            }
            sb.append('.').append(val);
        }
        return sb.toString();
    }

    /**
     * Возвращает короткое имя OID для человеко-читаемого вывода.
     * Если OID неизвестен — возвращает точечную нотацию.
     */
    private static String lookupOidName(byte[] der, int start, int len) {
        if (matchesOid(der, start, len, TlsDerParser.CN_OID_BYTES)) return "CN";
        if (matchesOid(der, start, len, TlsDerParser.C_OID_BYTES)) return "C";
        if (matchesOid(der, start, len, TlsDerParser.L_OID_BYTES)) return "L";
        if (matchesOid(der, start, len, TlsDerParser.ST_OID_BYTES)) return "ST";
        if (matchesOid(der, start, len, TlsDerParser.STREET_OID_BYTES)) return "STREET";
        if (matchesOid(der, start, len, TlsDerParser.O_OID_BYTES)) return "O";
        if (matchesOid(der, start, len, TlsDerParser.OU_OID_BYTES)) return "OU";
        if (matchesOid(der, start, len, TlsDerParser.T_OID_BYTES)) return "T";
        if (matchesOid(der, start, len, TlsDerParser.SN_OID_BYTES)) return "SN";
        if (matchesOid(der, start, len, TlsDerParser.GN_OID_BYTES)) return "GN";
        if (matchesOid(der, start, len, TlsDerParser.SERIALNUM_OID_BYTES)) return "SERIALNUMBER";
        if (matchesOid(der, start, len, TlsDerParser.POSTAL_CODE_OID_BYTES)) return "postalCode";
        if (matchesOid(der, start, len, TlsDerParser.UNIQUE_ID_OID_BYTES)) return "UNIQUE_IDENTIFIER";
        if (matchesOid(der, start, len, TlsDerParser.PSEUDONYM_OID_BYTES)) return "pseudonym";
        if (matchesOid(der, start, len, TlsDerParser.EMAIL_OID_BYTES)) return "emailAddress";
        if (matchesOid(der, start, len, TlsDerParser.UID_OID_BYTES)) return "UID";
        if (matchesOid(der, start, len, TlsDerParser.INN_OID_BYTES)) return "INN";
        if (matchesOid(der, start, len, TlsDerParser.OGRNIP_OID_BYTES)) return "OGRNIP";
        if (matchesOid(der, start, len, TlsDerParser.INNLE_OID_BYTES)) return "INN";
        if (matchesOid(der, start, len, TlsDerParser.OGRN_OID_BYTES)) return "OGRN";
        if (matchesOid(der, start, len, TlsDerParser.SNILS_OID_BYTES)) return "SNILS";
        if (matchesOid(der, start, len, TlsDerParser.ORG_ID_OID_BYTES)) return "organizationIdentifier";
        return oidBytesToDottedString(der, start, len);
    }

    /**
     * Декодирует значение DN-атрибута из DER в строку.
     * Поддерживает UTF8String, PrintableString, T61String, IA5String,
     * NumericString, BMPString.
     */
    private static String decodeDnValue(byte[] der, int start, int len, int tag) {
        switch (tag) {
            case 0x0C: // UTF8String
                return new String(der, start, len, java.nio.charset.StandardCharsets.UTF_8);
            case 0x12: // NumericString
            case 0x13: // PrintableString
            case 0x16: // IA5String
                return new String(der, start, len, java.nio.charset.StandardCharsets.US_ASCII);
            case 0x14: // T61String / TeletexString — фактически Latin-1
                return new String(der, start, len, java.nio.charset.StandardCharsets.ISO_8859_1);
            case 0x1E: // BMPString (UCS-2 big-endian)
                return new String(der, start, len, java.nio.charset.StandardCharsets.UTF_16BE);
            default:
                // Неизвестный тип: hex dump (не теряем данные)
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < len && i < 128; i++) {
                    sb.append(String.format("%02X", der[start + i] & 0xFF));
                }
                if (len > 128) sb.append("...");
                return sb.toString();
        }
    }

    /**
     * Экранирует символы в значении DN для безопасного вывода.
     *
     * <p>Зачем: запятые ломают формат CN=a,b (воспринимается как два RDN),
     * равно ломает key=value, управляющие символы опасны в логах.</p>
     */
    private static String escapeDnValue(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ',' || c == '=' || c == '+' || c == '\\') {
                // RFC 4514: , = + \ экранируются обратным слешем.
                // \ критичен — без него не отличить escape от literal.
                sb.append('\\').append(c);
            } else if (c < 0x20 || (c >= 0x7F && c < 0xA0)) {
                // C0 (0x00-0x1F), DEL (0x7F) и C1 controls (0x80-0x9F) непечатны.
                // C1 возможны в T61String-декодированных значениях.
                sb.append('\\').append(String.format("u%04X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Обрезает строку для логирования, если она длиннее maxLen.
     * Добавляет "...[truncated]" при обрезке.
     */
    private static String truncateForLog(String s, int maxLen) {
        if (s == null) return null;
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...[truncated]";
    }

    /**
     * Возвращает массив значений указанного OID из DN-полей.
     *
     * @param fields массив DnField (может быть null)
     * @param oidDot OID в точечной нотации
     * @return массив значений (пустой если не найдено)
     */
    private static String[] getDnField(DnField[] fields, String oidDot) {
        if (fields == null) return new String[0];
        List<String> result = new ArrayList<>();
        for (DnField f : fields) {
            if (f.oid.equals(oidDot)) result.add(f.value);
        }
        return result.toArray(new String[0]);
    }

    /**
     * Создаёт сертификат из DER-байтов.
     *
     * @param der DER-encoded X.509 сертификат
     * @return сертификат
     * @throws IllegalArgumentException если DER невалиден
     */
    public static TlsCertificate fromDer(byte[] der) {
        return new TlsCertificate(der);
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
    public static TlsCertificate fromPemOrDer(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Certificate data must not be null or empty");
        }
        if ((data[0] & 0xFF) == 0x30) {
            return new TlsCertificate(data);
        }
        if (data[0] == (byte) 0x2D) {
            return new TlsCertificate(pemToDer(data));
        }
        throw new IllegalArgumentException(
            "Unrecognized certificate format: first byte 0x" + Integer.toHexString(data[0] & 0xFF)
            + " (expected 0x30 for DER or 0x2D for PEM)");
    }

    /**
     * Разбирает PEM-файл, содержащий один или несколько сертификатов (цепочку),
     * и возвращает список {@link TlsCertificate}.
     *
     * <p>Обрабатывает файлы с несколькими блоками {@code -----BEGIN CERTIFICATE-----},
     * включая цепочки из PEM-файлов УЦ Минцифры.
     *
     * @param pem PEM-байты, содержащие один или несколько сертификатов
     * @return список сертификатов (порядок из файла)
     * @throws IllegalArgumentException если ни один сертификат не распознан
     */
    public static List<TlsCertificate> listFromPem(byte[] pem) {
        String text = new String(pem, java.nio.charset.StandardCharsets.US_ASCII);
        String[] blocks = text.split("-----BEGIN CERTIFICATE-----");
        List<TlsCertificate> result = new ArrayList<>();
        for (String block : blocks) {
            int end = block.indexOf("-----END CERTIFICATE-----");
            if (end < 0) {
                continue;
            }
            String b64 = block.substring(0, end).replaceAll("\\s", "");
            if (b64.isEmpty()) {
                continue;
            }
            byte[] der = Base64.getDecoder().decode(b64);
            result.add(new TlsCertificate(der));
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("No valid PEM certificates found");
        }
        return result;
    }

    /**
     * Декодирует PEM-формат (Base64 между заголовками) в DER-байты.
     *
     * @param pem байты PEM-сертификата
     * @return DER-байты
     */
    private static byte[] pemToDer(byte[] pem) {
        String text = new String(pem, java.nio.charset.StandardCharsets.US_ASCII);
        String b64 = text.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }
}

