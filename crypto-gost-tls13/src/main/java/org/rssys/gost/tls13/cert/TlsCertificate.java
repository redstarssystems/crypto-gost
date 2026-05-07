package org.rssys.gost.tls13.cert;

import static org.rssys.gost.tls13.cert.TlsDerParser.*;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

/**
 * Минимальный парсер X.509 сертификата для GOST R 34.10-2012.
 * Извлекает открытый ключ, подпись и верифицирует подпись сертификата.
 */
public final class TlsCertificate {

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
    private final boolean isCA;
    private final int pathLen;
    private final boolean keyCertSign;
    private final boolean hasUnknownCritical;
    private final boolean algConsistent;
    private byte[] ocspResponse;
    private final int serialOff;
    private final int serialLen;
    private final int issuerDnOff;
    private final int issuerDnLen;
    private final int subjectDnOff;
    private final int subjectDnLen;

    /**
     * Парсит DER-закодированный X.509 сертификат.
     *
     * @param derEncoded полный сертификат в DER
     */
    public TlsCertificate(byte[] derEncoded) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("Certificate DER must not be null");
        }
        this.certData = derEncoded.clone();

        int[] outer = parseSequence(derEncoded, 0);
        int certContentStart = outer[0];

        // Три потомка верхнего уровня: TBSCertificate, SignatureAlgorithm, SignatureValue
        int[] tbsTlv = readTlv(derEncoded, certContentStart);
        this.tbsCertOff = certContentStart;
        this.tbsCertLen = tbsTlv[1] - certContentStart;

        // Validity (notBefore, notAfter)
        Date[] validity = parseValidity(derEncoded, tbsTlv);
        this.notBefore = validity[0];
        this.notAfter = validity[1];

        // Issuer DN (4-я SEQUENCE в TBS)
        int[] issuerOffLen = parseIssuerDn(derEncoded, tbsTlv);
        this.issuerDnOff = issuerOffLen[0];
        this.issuerDnLen = issuerOffLen[1];
        // Subject DN (6-я SEQUENCE в TBS)
        int[] subjectOffLen = parseSubjectDn(derEncoded, tbsTlv);
        this.subjectDnOff = subjectOffLen[0];
        this.subjectDnLen = subjectOffLen[1];

        // SignatureAlgorithm (SEQUENCE of OID + params) — пропускаем
        int[] sigAlgTlv = readTlv(derEncoded, tbsTlv[1]);

        // SignatureValue (BIT STRING)
        int sigTagOffset = sigAlgTlv[1];
        if ((derEncoded[sigTagOffset] & 0x1F) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("Expected BIT STRING for signature");
        }
        int[] sigValTlv = readTlv(derEncoded, sigTagOffset);
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
        this.isCA = ext.isCA;
        this.pathLen = ext.pathLen;
        this.keyCertSign = ext.keyCertSign;
        this.hasUnknownCritical = ext.hasUnknownCritical;

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
        Digest.Algorithm hashAlg = hlen == 64
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

    /** @return массив raw IP-адресов из SAN iPAddress entries или null */
    public byte[][] getSanIpAddresses() {
        return sanIpAddresses;
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

    /** @return raw OCSP-ответ из CertificateEntry (null если нет status_request) */
    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    /** @param data OCSP-ответ из CertificateEntry status_request */
    public void setOcspResponse(byte[] data) {
        this.ocspResponse = data;
    }

    /** @return серийный номер сертификата в DER INTEGER */
    public byte[] getSerialNumber() {
        byte[] result = new byte[serialLen];
        System.arraycopy(certData, serialOff, result, 0, serialLen);
        return result;
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
        byte[] serialCopy = new byte[serialLen];
        System.arraycopy(certData, serialOff, serialCopy, 0, serialLen);
        TlsOcspVerifier.verify(ocspResponse, serialCopy, caKey);
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
        final boolean isCA;
        final int pathLen;
        final boolean keyCertSign;
        final boolean hasUnknownCritical;
        ExtensionsResult(String[] sanDnsNames, byte[][] sanIpAddresses, boolean keyUsageValid, boolean ekuValid, boolean ekuClientAuth,
                          boolean isCA, int pathLen, boolean keyCertSign, boolean hasUnknownCritical) {
            this.sanDnsNames = sanDnsNames;
            this.sanIpAddresses = sanIpAddresses;
            this.keyUsageValid = keyUsageValid;
            this.ekuValid = ekuValid;
            this.ekuClientAuth = ekuClientAuth;
            this.isCA = isCA;
            this.pathLen = pathLen;
            this.keyCertSign = keyCertSign;
            this.hasUnknownCritical = hasUnknownCritical;
        }
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
        int pos = tbsTlv[0];
        int end = tbsTlv[1];

        // version [0] EXPLICIT (OPTIONAL)
        if (pos < end && (der[pos] & 0xFF) == TAG_CTX_0) {
            pos = readTlv(der, pos)[1];
        }
        // serialNumber (INTEGER)
        if (pos >= end) return new ExtensionsResult(null, null, true, true, true, false, -1, false, false);
        pos = readTlv(der, pos)[1];
        // Сканируем до 5-й SEQUENCE (SPKI)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == 5) {
                    pos = tlv[1];
                    break;
                }
            }
            pos = tlv[1];
        }
        if (seqCount < 5) return new ExtensionsResult(null, null, true, true, true, false, -1, false, false);

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
        return new ExtensionsResult(null, null, true, true, true, false, -1, false, false);
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
            return new ExtensionsResult(null, null, true, true, true, false, -1, false, false);
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
        boolean isCA = false;
        int pathLen = -1;
        boolean hasUnknownCritical = false;

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
                            kuDigitalSignature = (der[valueStart] & 0x80) != 0;
                            // keyCertSign — бит 5 = 0x04 в первом байте (KU не определяет биты ≥ 9)
                            if (valueLen > 0) kuKeyCertSign = (der[valueStart] & 0x04) != 0;
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, EKU_OID_BYTES)) {
                ekuPresent = true;
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    ekuServerAuth = hasEku(der, octTlv[0], octTlv[1], SERVER_AUTH_OID);
                    ekuClientAuth = hasEku(der, octTlv[0], octTlv[1], CLIENT_AUTH_OID);
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
        return new ExtensionsResult(sanResult, ipResult, kuValid, ekuValid, ekuClientAuthValid,
                isCA, pathLen, keyCertSignOk, hasUnknownCritical);
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

    private static final byte[] SERVER_AUTH_OID = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    private static final byte[] CLIENT_AUTH_OID = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};

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

    // ========================================================================
    // DN parsing (Issuer = 4-я SEQUENCE, Subject = 6-я SEQUENCE в TBS)
    // DN matching: byte-exact DER сравнение;
    // семантическая нормализация согласно RFC 5280 §7.1 не реализована.
    // ========================================================================

    /**
     * Парсит Issuer DN — 4-я SEQUENCE в TBSCertificate.
     * Пропускает version, serialNumber, signature, затем ищет первую SEQUENCE.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return [offset, length] Issuer DN
     */
    private static int[] parseIssuerDn(byte[] der, int[] tbsTlv) {
        int pos = tbsTlv[0];
        int end = tbsTlv[1];
        if (pos < end && (der[pos] & 0xFF) == 0xA0) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // serialNumber
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // signature SEQUENCE
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                return new int[]{pos, tlv[1] - pos};
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("Issuer DN not found in TBSCertificate");
    }

    /**
     * Парсит Subject DN — 6-я SEQUENCE в TBSCertificate.
     * Пропускает version, serialNumber, signature, issuer, validity, затем ищет первую SEQUENCE.
     *
     * @param der    DER-поток сертификата
     * @param tbsTlv [valueStart, valueEnd] TBSCertificate
     * @return [offset, length] Subject DN
     */
    private static int[] parseSubjectDn(byte[] der, int[] tbsTlv) {
        int pos = tbsTlv[0];
        int end = tbsTlv[1];
        if (pos < end && (der[pos] & 0xFF) == 0xA0) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // serialNumber
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // signature SEQUENCE
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // issuer SEQUENCE
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1]; // validity SEQUENCE
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                return new int[]{pos, tlv[1] - pos};
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("Subject DN not found in TBSCertificate");
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
        int pos = tbsTlv[0];
        int end = tbsTlv[1];

        // version [0] EXPLICIT (OPTIONAL)
        if (pos < end && (der[pos] & 0xFF) == 0xA0) {
            pos = readTlv(der, pos)[1];
        }
        // serialNumber (INTEGER)
        if (pos >= end) throw new IllegalArgumentException("TBSCertificate too short");
        pos = readTlv(der, pos)[1];

        // validity — 3-я SEQUENCE (1=signature, 2=issuer, 3=validity)
        int seqCount = 0;
        while (pos < end) {
            int tag = der[pos] & 0xFF;
            int[] tlv = readTlv(der, pos);
            if (tag == TAG_SEQUENCE) {
                seqCount++;
                if (seqCount == 3) {
                    Date notBefore = parseTime(der, tlv[0]);
                    Date notAfter = parseTime(der, readTlv(der, tlv[0])[1]);
                    return new Date[]{notBefore, notAfter};
                }
            }
            pos = tlv[1];
        }
        throw new IllegalArgumentException("Validity not found in TBSCertificate");
    }
}
