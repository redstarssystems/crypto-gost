package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.rssys.gost.util.DerCodec;

/**
 * Парсер X.509v3 расширений из DER-кодированного блока [3] EXPLICIT Extensions.
 *
 * <p>Распознаёт OID расширений: SubjectAltName, KeyUsage, ExtendedKeyUsage,
 * BasicConstraints, SubjectKeyIdentifier, AuthorityKeyIdentifier,
 * AuthorityInfoAccess, CRLDistributionPoints, CertificatePolicies.
 * Неизвестное critical extension -> {@link ExtensionsResult#hasUnknownCritical} = true.</p>
 *
 * <p>Вынесен из {@link GostCertificate} для разделения ответственности.</p>
 *
 * @see GostCertificate
 * @see GostDerParser
 */
public final class GostExtensionParser {

    private GostExtensionParser() {}

    /**
     * Результат парсинга расширений X.509v3.
     */
    public static final class ExtensionsResult {
        public final String[] sanDnsNames;
        public final byte[][] sanIpAddresses;
        public final boolean keyUsageValid;
        public final boolean ekuValid;
        public final boolean ekuClientAuth;
        public final boolean ekuOcspSigning;
        public final boolean ekuTimeStamping;
        public final boolean isCA;
        public final int pathLen;
        public final boolean keyCertSign;
        public final boolean hasUnknownCritical;
        public final byte[] skiBytes;
        public final byte[] akiBytes;
        public final String[] aiaUris;
        public final String[] ocspUris;
        public final String[] caIssuersUris;
        public final String[] cdpUris;
        public final String[] certPolicyOids;

        /** Сырые DER-байты OID политик — для oid_filters matching (RFC 8446 §4.2.5). */
        public final byte[][] cpOids;

        public final int keyUsageBits;
        public final byte[][] ekuOids;
        public final Set<String> presentExtensionOids;

        public ExtensionsResult(
                String[] sanDnsNames,
                byte[][] sanIpAddresses,
                boolean keyUsageValid,
                boolean ekuValid,
                boolean ekuClientAuth,
                boolean ekuOcspSigning,
                boolean ekuTimeStamping,
                boolean isCA,
                int pathLen,
                boolean keyCertSign,
                boolean hasUnknownCritical,
                byte[] skiBytes,
                byte[] akiBytes,
                String[] aiaUris,
                String[] ocspUris,
                String[] caIssuersUris,
                String[] cdpUris,
                String[] certPolicyOids,
                int keyUsageBits,
                byte[][] ekuOids,
                Set<String> presentExtensionOids,
                byte[][] cpOids) {
            this.sanDnsNames = sanDnsNames;
            this.sanIpAddresses = sanIpAddresses;
            this.keyUsageValid = keyUsageValid;
            this.ekuValid = ekuValid;
            this.ekuClientAuth = ekuClientAuth;
            this.ekuOcspSigning = ekuOcspSigning;
            this.ekuTimeStamping = ekuTimeStamping;
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
            this.cpOids = cpOids;
            this.presentExtensionOids = presentExtensionOids;
        }

        /** Канонический пустой результат — гарантирует {@code ==} сравнение. */
        private static final ExtensionsResult EMPTY =
                new ExtensionsResult(
                        null,
                        null,
                        true,
                        true,
                        true,
                        true,
                        true,
                        false,
                        -1,
                        true,
                        false,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        0,
                        null,
                        Collections.emptySet(),
                        null);

        /** @return пустой результат — расширения не найдены или не распарсены.
         *         По RFC 5280 отсутствие расширений не является ошибкой: ключ
         *         считается валидным для всех целей (permissive default).
         *         Возвращает канонический синглтон — можно сравнивать через {@code ==}. */
        public static ExtensionsResult empty() {
            return EMPTY;
        }
    }

    /**
     * Парсит содержимое [3] EXPLICIT — Extensions SEQUENCE с итерацией по каждому Extension.
     * Распознаёт OID: SAN (2.5.29.17), KU (2.5.29.15), EKU (2.5.29.37), BC (2.5.29.19).
     * Unknown critical extension -> hasUnknownCritical = true (RFC 5280 §4.2).
     *
     * @param der          DER-поток сертификата
     * @param extTagOffset смещение на tag [3] EXPLICIT
     * @return результат парсинга расширений
     */
    static ExtensionsResult parseFromExtensionsBlock(byte[] der, int extTagOffset) {
        int[] extTlv = readTlv(der, extTagOffset);
        int pos = extTlv[0];
        int end = extTlv[1];

        if (pos >= end || (der[pos] & 0xFF) != 0x30) {
            return ExtensionsResult.empty();
        }
        return parseExtensionsFromSequence(der, pos);
    }

    /**
     * Парсит Extensions ::= SEQUENCE OF Extension без обёртки [3] EXPLICIT.
     *
     * <p>Используется для CSR (PKCS#10), где расширения из extensionRequest атрибута
     * лежат как {@code SET { Extensions }} без контекстного тега [3], в отличие от
     * TBSCertificate в X.509 сертификате (RFC 5280 §4.1.2.9 vs PKCS#9 §5.4.1).</p>
     *
     * @param der         DER-поток
     * @param seqTagOffset смещение на тег SEQUENCE (0x30) — начало Extensions
     * @return результат парсинга расширений
     */
    public static ExtensionsResult parseExtensionsFromSequence(byte[] der, int seqTagOffset) {
        if (seqTagOffset >= der.length || (der[seqTagOffset] & 0xFF) != 0x30) {
            return ExtensionsResult.empty();
        }
        int[] seqTlv = readTlv(der, seqTagOffset);
        int pos = seqTlv[0];
        int end = seqTlv[1];

        ArrayList<String> sanList = new ArrayList<>();
        ArrayList<byte[]> ipList = new ArrayList<>();
        boolean kuPresent = false;
        boolean kuDigitalSignature = false;
        boolean kuKeyCertSign = false;
        boolean ekuPresent = false;
        boolean ekuServerAuth = false;
        boolean ekuClientAuth = false;
        boolean ekuOcspSigning = false;
        boolean ekuTimeStamping = false;

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
        ArrayList<byte[]> cpOidList = new ArrayList<>();

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
                        if (bitTlv[1] > bitTlv[0]) {
                            int unusedBits = der[bitTlv[0]] & 0xFF;
                            int valueStart = bitTlv[0] + 1;
                            int valueLen = bitTlv[1] - valueStart;
                            if (valueStart < bitTlv[1] && valueLen > 0) {
                                kuDigitalSignature =
                                        (der[valueStart] & GostDerParser.KU_DIGITAL_SIGNATURE) != 0;
                                // keyCertSign — бит 5 = 0x04 в первом байте (KU не определяет биты
                                // ≥ 9)
                                if (valueLen > 0)
                                    kuKeyCertSign =
                                            (der[valueStart] & GostDerParser.KU_KEY_CERT_SIGN) != 0;
                                // Собираем raw KU-маску для oid_filters matching
                                for (int k = 0; k < valueLen && k < 2; k++) {
                                    keyUsageBitsLocal |= (der[valueStart + k] & 0xFF) << (8 * k);
                                }
                            }
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, EKU_OID_BYTES)) {
                ekuPresent = true;
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    ekuServerAuth =
                            hasEku(der, octTlv[0], octTlv[1], GostDerParser.SERVER_AUTH_OID_BYTES);
                    ekuClientAuth =
                            hasEku(der, octTlv[0], octTlv[1], GostDerParser.CLIENT_AUTH_OID_BYTES);
                    // EKU id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
                    if (hasEku(der, octTlv[0], octTlv[1], GostDerParser.OCSP_SIGNING_OID_BYTES)
                            || hasEku(der, octTlv[0], octTlv[1], GostDerParser.ANY_EKU_OID_BYTES)) {
                        ekuOcspSigning = true;
                    }
                    // EKU id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
                    if (hasEku(der, octTlv[0], octTlv[1], GostDerParser.TIME_STAMPING_OID_BYTES)) {
                        ekuTimeStamping = true;
                    }
                    // Собираем ВСЕ EKU OID для oid_filters matching (RFC 8446 §4.2.5)
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
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_OCTET_STRING) {
                        int[] innerTlv = readTlv(der, octTlv[0]);
                        skiBytesLocal = Arrays.copyOfRange(der, innerTlv[0], innerTlv[1]);
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, AKI_OID_BYTES)) {
                // AuthorityKeyIdentifier — SEQUENCE с опциональным [0] KeyIdentifier (RFC 5280
                // §4.2.1.1).
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_SEQUENCE) {
                        int[] akiSeqTlv = readTlv(der, octTlv[0]);
                        int akiPos = akiSeqTlv[0];
                        int akiEnd = akiSeqTlv[1];
                        // [0] IMPLICIT на OCTET STRING — tag 0x80 (primitive) или 0xA0
                        // (constructed).
                        if (akiPos < akiEnd) {
                            int ctxTag = der[akiPos] & 0xFF;
                            if ((ctxTag & 0xDF) == DerCodec.TAG_CTX_PRIMITIVE_0) {
                                int[] ctxTlv = readTlv(der, akiPos);
                                akiBytesLocal = Arrays.copyOfRange(der, ctxTlv[0], ctxTlv[1]);
                            }
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, AIA_OID_BYTES)) {
                // AuthorityInfoAccess — SEQUENCE of AccessDescription (RFC 5280 §4.2.2.1).
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseAiaDescriptions(
                            der, octTlv[0], octTlv[1], aiaList, ocspList, caIssuersList);
                }
            } else if (matchesOid(der, oidStart, oidLen, CDP_OID_BYTES)) {
                // CRLDistributionPoints (RFC 5280 §4.2.1.13) — точки распространения CRL.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCdpUris(der, octTlv[0], octTlv[1], cdpList);
                }
            } else if (matchesOid(der, oidStart, oidLen, CP_OID_BYTES)) {
                // CertificatePolicies (RFC 5280 §4.2.1.4) — OID политик сертификата.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCertPolicyOids(der, octTlv[0], octTlv[1], certPolicyList, cpOidList);
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
        byte[][] cpOidsResult = cpOidList.isEmpty() ? null : cpOidList.toArray(new byte[0][]);
        return new ExtensionsResult(
                sanResult,
                ipResult,
                kuValid,
                ekuValid,
                ekuClientAuthValid,
                !ekuPresent || ekuOcspSigning,
                ekuPresent && ekuTimeStamping,
                isCA,
                pathLen,
                keyCertSignOk,
                hasUnknownCritical,
                skiBytesLocal,
                akiBytesLocal,
                aiaList.isEmpty() ? null : aiaList.toArray(new String[0]),
                ocspList.isEmpty() ? null : ocspList.toArray(new String[0]),
                caIssuersList.isEmpty() ? null : caIssuersList.toArray(new String[0]),
                cdpList.isEmpty() ? null : cdpList.toArray(new String[0]),
                certPolicyList.isEmpty() ? null : certPolicyList.toArray(new String[0]),
                keyUsageBitsLocal,
                ekuOidsResult,
                presentOids,
                cpOidsResult);
    }

    // ====================================================================
    // SAN parser
    // ====================================================================

    /**
     * Парсит GeneralNames SEQUENCE из SubjectAltName.
     * Извлекает dNSName (tag 0x82) и iPAddress (tag 0x87) entries.
     */
    private static void parseSanGeneralNames(
            byte[] der,
            int gnOuter,
            int gnOuterEnd,
            ArrayList<String> sanList,
            ArrayList<byte[]> ipList) {
        if (gnOuter >= gnOuterEnd || (der[gnOuter] & 0xFF) != TAG_SEQUENCE) return;
        int[] gnSeqTlv = readTlv(der, gnOuter);
        int gnPos = gnSeqTlv[0];
        int gnEnd = gnSeqTlv[1];
        while (gnPos < gnEnd) {
            int gnTag = der[gnPos] & 0xFF;
            if (gnTag == TAG_DNS_NAME) {
                int[] dnsTlv = readTlv(der, gnPos);
                String name =
                        new String(
                                der, dnsTlv[0], dnsTlv[1] - dnsTlv[0], StandardCharsets.US_ASCII);
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

    // ====================================================================
    // EKU parsers
    // ====================================================================

    /**
     * Проверяет наличие указанного OID в ExtendedKeyUsage SEQUENCE.
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
     * oid_filters matching (RFC 8446 §4.2.5) требует знать
     * все EKU OID сертификата, а не только три хардкоженных.
     */
    private static void collectAllEkuOids(
            byte[] der, int seqOuter, int seqEnd, ArrayList<byte[]> ekuOidList) {
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

    // ====================================================================
    // AIA parser
    // ====================================================================

    /**
     * Парсит AccessDescription SEQUENCE из AuthorityInfoAccess.
     * AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
     * Извлекает URI (uniformResourceIdentifier [6]).
     */
    private static void parseAiaDescriptions(
            byte[] der,
            int aiaOuter,
            int aiaEnd,
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
            int[] rawOidTlv = methodOidTlv;
            int locPos = methodOidTlv[1];
            if (locPos < adEnd) {
                int locTag = der[locPos] & 0xFF;
                if ((locTag & 0xDF) == 0x86) {
                    int[] uriTlv = readTlv(der, locPos);
                    String uri =
                            new String(
                                    der,
                                    uriTlv[0],
                                    uriTlv[1] - uriTlv[0],
                                    StandardCharsets.US_ASCII);
                    uriList.add(uri);
                    if (matchesOid(
                            der,
                            rawOidTlv[0],
                            rawOidTlv[1] - rawOidTlv[0],
                            GostDerParser.AD_OCSP_OID_BYTES)) {
                        ocspList.add(uri);
                    } else if (matchesOid(
                            der,
                            rawOidTlv[0],
                            rawOidTlv[1] - rawOidTlv[0],
                            GostDerParser.AD_CA_ISSUERS_OID_BYTES)) {
                        caIssuersList.add(uri);
                    }
                }
            }
            pos = adSeqTlv[1];
        }
    }

    // ====================================================================
    // CDP parser
    // ====================================================================

    /**
     * Парсит CRLDistributionPoints: извлекает URI из fullName GeneralNames.
     * DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, ... }
     * DistributionPointName ::= [0] GeneralNames
     */
    private static void parseCdpUris(
            byte[] der, int cdpOuter, int cdpEnd, ArrayList<String> uriList) {
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
                int maxDepth = 10;
                while (gnPos < gnEnd && (der[gnPos] & 0xFF) == TAG_CTX_0 && --maxDepth > 0) {
                    int[] ctxTlv = readTlv(der, gnPos);
                    gnPos = ctxTlv[0];
                }
                // ФНС и другие УЦ могут кодировать GeneralNames c IMPLICIT [0] fullName
                if (gnPos < gnEnd && (der[gnPos] & 0xFF) == TAG_SEQUENCE) {
                    // EXPLICIT: GeneralNames SEQUENCE
                    int[] gnSeqTlv = readTlv(der, gnPos);
                    gnPos = gnSeqTlv[0];
                    gnEnd = gnSeqTlv[1];
                }
                while (gnPos < gnEnd) {
                    int gnTag = der[gnPos] & 0xFF;
                    if ((gnTag & 0xDF) == 0x86) {
                        int[] uriTlv = readTlv(der, gnPos);
                        String uri =
                                new String(
                                        der,
                                        uriTlv[0],
                                        uriTlv[1] - uriTlv[0],
                                        StandardCharsets.US_ASCII);
                        uriList.add(uri);
                        gnPos = uriTlv[1];
                    } else {
                        gnPos = readTlv(der, gnPos)[1];
                    }
                }
            }
            pos = dpSeqTlv[1];
        }
    }

    // ====================================================================
    // CertificatePolicies parser
    // ====================================================================

    /**
     * Парсит CertificatePolicies: извлекает policyIdentifier OID как точечную строку
     * и параллельно собирает сырые DER-байты OID для oid_filters matching (RFC 8446 §4.2.5).
     * CertificatePolicies ::= SEQUENCE OF PolicyInformation
     * PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }
     */
    private static void parseCertPolicyOids(
            byte[] der,
            int cpOuter,
            int cpEnd,
            ArrayList<String> oidList,
            ArrayList<byte[]> cpOidBytes) {
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
                cpOidBytes.add(Arrays.copyOfRange(der, oidTlv[0], oidTlv[1]));
            }
            pos = piSeqTlv[1];
        }
    }
}
