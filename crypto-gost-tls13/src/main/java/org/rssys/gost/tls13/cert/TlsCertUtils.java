package org.rssys.gost.tls13.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.util.Arrays;
import java.util.Set;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.config.OIDFilter;

/**
 * Статические TLS-утилиты для работы с сертификатами ({@link GostCertificate}).
 * <p>
 * TLS-специфичная логика живёт здесь, чистые PKIX-операции — напрямую
 * на {@link GostCertificate}.
 */
public final class TlsCertUtils {

    /** OID известных X.509v3 расширений для oid_filters matching (RFC 8446 §4.2.5). */
    static final Set<String> KNOWN_EXTENSION_OIDS =
            Set.of(
                    GostOids.EXT_SKI,
                    GostOids.EXT_KU,
                    GostOids.EXT_SAN,
                    GostOids.EXT_BC,
                    GostOids.EXT_CDP,
                    GostOids.EXT_CP,
                    GostOids.EXT_AKI,
                    GostOids.EXT_EKU,
                    GostOids.EXT_AIA);

    private static final int TBS_SPKI_SEQUENCE_INDEX = 5;

    private TlsCertUtils() {}

    /**
     * Проверяет, относится ли схема подписи к ключу сертификата (RFC 9367 §3.2).
     *
     * @param pubKey открытый ключ сертификата
     * @param scheme схема подписи из CertificateVerify
     * @return true если схема соответствует длине ключа
     */
    public static boolean hasSignatureScheme(PublicKeyParameters pubKey, int scheme) {
        int certNamedGroup = TlsCiphersuite.paramsToNamedGroup(pubKey.getParams());
        int expectedScheme = TlsCiphersuite.namedGroupToSignatureScheme(certNamedGroup);
        return scheme == expectedScheme;
    }

    /**
     * TLS named group (RFC 9367 §3.1) по параметрам открытого ключа.
     *
     * @param pubKey открытый ключ сертификата
     * @return идентификатор named group
     */
    public static int getNamedGroup(PublicKeyParameters pubKey) {
        return TlsCiphersuite.paramsToNamedGroup(pubKey.getParams());
    }

    /**
     * Верифицирует OCSP-ответ для сертификата (RFC 6960).
     * <p>
     * Оборачивает {@link PkixException} в {@link TlsException} с alert-кодом
     * {@link TlsConstants#ALERT_BAD_CERTIFICATE}.
     *
     * @param cert    сертификат с прикреплённым OCSP-ответом
     * @param caKey   открытый ключ для проверки подписи OCSP-ответа
     * @param issuer  сертификат издателя (null — только базовая проверка без CertID)
     * @throws TlsException при ошибке верификации OCSP
     */
    public static void verifyOcspResponse(
            GostCertificate cert, PublicKeyParameters caKey, GostCertificate issuer)
            throws TlsException {
        byte[] serialCopy = cert.getSerialNumber();
        byte[] ocspResp = cert.getOcspResponse();
        byte[] nonce = cert.getOcspNonce();
        try {
            OcspVerifier.verify(
                    ocspResp,
                    serialCopy,
                    caKey,
                    issuer != null ? cert.getIssuerDnBytes() : null,
                    issuer != null ? issuer.getEncoded() : null,
                    nonce,
                    false);
        } catch (PkixException e) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE, e.getMessage());
        }
    }

    /**
     * Проверяет, удовлетворяет ли сертификат OID-фильтру из {@code oid_filters}
     * расширения CertificateRequest (RFC 8446 §4.2.5).
     * <p>
     * Используется в mTLS для выбора клиентского сертификата по фильтрам сервера.
     *
     * @param cert   сертификат для проверки
     * @param filter OID-фильтр из CertificateRequest
     * @return true если сертификат удовлетворяет фильтру
     */
    public static boolean matchesOidFilter(GostCertificate cert, OIDFilter filter) {
        byte[] filterOid = filter.extensionOid();
        byte[] filterValues = filter.extensionValues();
        int keyUsageBits = cert.getKeyUsageBits();
        byte[][] ekuOids = cert.getEkuOids();
        Set<String> presentExtensionOids = cert.getPresentExtensionOids();

        if (Arrays.equals(filterOid, KU_OID_BYTES)) {
            int filterBits = 0;
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

        if (Arrays.equals(filterOid, EKU_OID_BYTES)) {
            if (ekuOids == null && filterValues.length > 0) {
                return false;
            }
            if (ekuOids != null) {
                for (byte[] ekuOid : ekuOids) {
                    if (matchesOid(ekuOid, 0, ekuOid.length, ANY_EKU_OID_BYTES)) {
                        return false;
                    }
                }
            }
            if (filterValues.length == 0) {
                return ekuOids != null;
            }
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
                        if (matchesOid(
                                ekuOid,
                                0,
                                ekuOid.length,
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

        // anyPolicy (2.5.29.32.0, RFC 5280 §4.2.1.4) — структурный аналог anyExtendedKeyUsage —
        // не обрабатывается отдельно; отсутствие аналогичной логики осознанно, при добавлении
        // anyPolicy-handling синхронизировать с EKU-веткой.
        if (Arrays.equals(filterOid, CP_OID_BYTES)) {
            byte[][] cpOids = cert.getCpOids();
            if (cpOids == null && filterValues.length > 0) {
                return false;
            }
            if (filterValues.length == 0) {
                return cpOids != null;
            }
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
                if (cpOids != null) {
                    for (byte[] cpOid : cpOids) {
                        if (matchesOid(
                                cpOid,
                                0,
                                cpOid.length,
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

        String oidDot = oidBytesToDottedString(filterOid, 0, filterOid.length);
        if (presentExtensionOids.contains(oidDot)) {
            if (filterValues.length > 0) {
                return matchesExtensionValue(filterOid, filterValues, cert);
            }
            return true;
        }

        if (KNOWN_EXTENSION_OIDS.contains(oidDot)) {
            return false;
        }

        return true;
    }

    /**
     * Сканирует raw DER сертификата для поиска extension с указанным OID
     * и сравнивает его значение с expectedValue побайтово.
     */
    private static boolean matchesExtensionValue(
            byte[] filterOid, byte[] expectedValue, GostCertificate cert) {
        byte[] certData = cert.getEncoded();
        int tbsCertOff = parseSequence(certData, 0)[0];
        int[] tbsTlv = readTlv(certData, tbsCertOff);
        int end = tbsTlv[1];
        int pos = skipVersionAndSerial(certData, tbsTlv);
        if (pos < 0) return false;

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
                    if (extContent2 >= extContentEnd2
                            || (certData[extContent2] & 0xFF) != TAG_OID) {
                        epos = extSeqTlv[1];
                        continue;
                    }
                    int[] oidTlv = readTlv(certData, extContent2);
                    if (!matchesOid(certData, oidTlv[0], oidTlv[1] - oidTlv[0], filterOid)) {
                        epos = extSeqTlv[1];
                        continue;
                    }
                    int afterOid = oidTlv[1];
                    if (afterOid < extContentEnd2 && (certData[afterOid] & 0xFF) == TAG_BOOLEAN) {
                        afterOid = readTlv(certData, afterOid)[1];
                    }
                    if (afterOid >= extContentEnd2) return false;
                    if ((certData[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                        int[] octTlv = readTlv(certData, afterOid);
                        return octTlv[1] - octTlv[0] == expectedValue.length
                                && arrayRangeEquals(
                                        certData,
                                        octTlv[0],
                                        octTlv[1],
                                        expectedValue,
                                        0,
                                        expectedValue.length);
                    }
                    return false;
                }
                return false;
            }
            break;
        }
        return false;
    }

    /** Пропускает version [0] EXPLICIT и serial INTEGER в TBSCertificate. */
    private static int skipVersionAndSerial(byte[] der, int[] tbsTlv) {
        int pos = tbsTlv[0];
        int end = tbsTlv[1];
        if (pos < end && (der[pos] & 0xFF) == TAG_CTX_0) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end) return -1;
        return readTlv(der, pos)[1];
    }
}
