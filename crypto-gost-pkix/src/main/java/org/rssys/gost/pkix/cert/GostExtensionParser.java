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
 * <p>Распознаёт OID расширений: SubjectAltName, IssuerAltName, KeyUsage, ExtendedKeyUsage,
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

    private static final int MAX_EXTENSIONS_PER_CERT = 64;

    // MAX_EXTENSIONS_PER_CERT ограничивает число расширений, но не число записей
    // внутри одного SAN — сертификат в пределах cert-cap может нести десятки тысяч
    // dNSName/iPAddress. Отдельный count-барьер на записи SAN.
    private static final int MAX_SAN_ENTRIES = 512;

    private GostExtensionParser() {}

    /**
     * Результат парсинга расширений X.509v3.
     */
    public static final class ExtensionsResult {
        public final String[] sanDnsNames;
        public final byte[][] sanIpAddresses;
        public final String[] ianDnsNames;
        public final byte[][] ianIpAddresses;
        public final boolean keyUsageValid;
        public final boolean crlSignValid;
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
        public final String[] freshestCrlUris;
        public final String[] certPolicyOids;

        /** Сырые DER-байты OID политик — для oid_filters matching (RFC 8446 §4.2.5). */
        public final byte[][] cpOids;

        /** Name Constraints (RFC 5280 §4.2.1.10) — null если расширение отсутствует. */
        public final NameConstraintsData nameConstraints;

        public final int keyUsageBits;
        public final byte[][] ekuOids;
        public final Set<String> presentExtensionOids;

        public ExtensionsResult(
                String[] sanDnsNames,
                byte[][] sanIpAddresses,
                String[] ianDnsNames,
                byte[][] ianIpAddresses,
                boolean keyUsageValid,
                boolean crlSignValid,
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
                String[] freshestCrlUris,
                String[] certPolicyOids,
                int keyUsageBits,
                byte[][] ekuOids,
                Set<String> presentExtensionOids,
                byte[][] cpOids,
                NameConstraintsData nameConstraints) {
            this.sanDnsNames = sanDnsNames;
            this.sanIpAddresses = sanIpAddresses;
            this.ianDnsNames = ianDnsNames;
            this.ianIpAddresses = ianIpAddresses;
            this.keyUsageValid = keyUsageValid;
            this.crlSignValid = crlSignValid;
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
            this.freshestCrlUris = freshestCrlUris;
            this.certPolicyOids = certPolicyOids;
            this.keyUsageBits = keyUsageBits;
            this.ekuOids = ekuOids;
            this.cpOids = cpOids;
            this.presentExtensionOids = presentExtensionOids;
            this.nameConstraints = nameConstraints;
        }

        /** Канонический пустой результат — гарантирует {@code ==} сравнение. */
        private static final ExtensionsResult EMPTY =
                new ExtensionsResult(
                        null,
                        null,
                        null,
                        null,
                        true,
                        true,
                        true,
                        true,
                        // ekuOcspSigning / ekuTimeStamping = false: «нет extensions»
                        // логически = «EKU absent», а OCSP-делегат (RFC 6960 §4.2.2.2)
                        // и TSA (RFC 3161 §2.3) требуют обязательного EKU. Permissive
                        // здесь ошибочно принимал cert без extensions как responder/TSA.
                        false,
                        false,
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
                        null,
                        0,
                        null,
                        Collections.emptySet(),
                        null,
                        null);

        /** @return пустой результат — расширения не найдены или не распарсены.
         *         По RFC 5280 §4.2.1.12 отсутствие EKU не ограничивает общие цели
         *         (permissive default для ekuValid/ekuClientAuth). Исключение —
         *         OCSP-делегат и TSA: там EKU обязателен (RFC 6960 §4.2.2.2,
         *         RFC 3161 §2.3), поэтому ekuOcspSigning/ekuTimeStamping = false.
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
        ArrayList<String> ianDnsList = new ArrayList<>();
        ArrayList<byte[]> ianIpList = new ArrayList<>();
        boolean kuPresent = false;
        boolean kuDigitalSignature = false;
        boolean kuKeyCertSign = false;
        boolean kuCrlSign = false;
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
        ArrayList<String> freshestCrlList = new ArrayList<>();
        ArrayList<String> certPolicyList = new ArrayList<>();
        // Для oid_filters matching (RFC 8446 §4.2.5)
        Set<String> presentOids = new HashSet<>();
        int keyUsageBitsLocal = 0;
        ArrayList<byte[]> ekuOidList = new ArrayList<>();
        ArrayList<byte[]> cpOidList = new ArrayList<>();
        // Name Constraints (RFC 5280 §4.2.1.10)
        NameConstraintsData ncLocal = null;

        int extCount = 0;
        while (pos < end) {
            if (extCount >= MAX_EXTENSIONS_PER_CERT) {
                throw new IllegalArgumentException(
                        "Too many X.509 extensions in certificate: " + extCount);
            }
            extCount++;
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
            } else if (matchesOid(der, oidStart, oidLen, IAN_OID_BYTES)) {
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseSanGeneralNames(der, octTlv[0], octTlv[1], ianDnsList, ianIpList);
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
                                kuCrlSign = (der[valueStart] & GostDerParser.KU_CRL_SIGN) != 0;
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
                    // EKU id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9).
                    // anyExtendedKeyUsage НЕ принимаем: RFC 6960 §4.2.2.2 требует
                    // делегирование именно через id-kp-OCSPSigning, anyEKU недостаточен.
                    if (hasEku(der, octTlv[0], octTlv[1], GostDerParser.OCSP_SIGNING_OID_BYTES)) {
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
                            int intLen = intTlv[1] - intTlv[0];
                            if (intLen > 4 || intLen == 0) {
                                throw new IllegalArgumentException(
                                        "pathLen INTEGER: invalid length " + intLen);
                            }
                            int val = 0;
                            for (int i = intTlv[0]; i < intTlv[1]; i++) {
                                val = (val << 8) | (der[i] & 0xFF);
                            }
                            // Guard длины (intLen<=4) не ловит знаковое переполнение:
                            // 4-байтовый INTEGER с MSB=1 (напр. 80 00 00 00) даёт val<0,
                            // и в ChainValidator проверка `pl >= 0` молча пропускает
                            // pathLen-ограничение. pathLenConstraint по RFC 5280 §4.2.1.9 —
                            // неотрицательный INTEGER, отрицательное значение невалидно.
                            if (val < 0) {
                                throw new IllegalArgumentException(
                                        "pathLen INTEGER: negative value");
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
            } else if (matchesOid(der, oidStart, oidLen, FRESHEST_CRL_OID_BYTES)) {
                // FreshestCRL (RFC 5280 §5.2.6) — точки распространения delta CRL.
                // Структура DistributionPoint идентична CDP.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCdpUris(der, octTlv[0], octTlv[1], freshestCrlList);
                }
            } else if (matchesOid(der, oidStart, oidLen, CP_OID_BYTES)) {
                // CertificatePolicies (RFC 5280 §4.2.1.4) — OID политик сертификата.
                if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_OCTET_STRING) {
                    int[] octTlv = readTlv(der, afterOid);
                    parseCertPolicyOids(der, octTlv[0], octTlv[1], certPolicyList, cpOidList);
                }
            } else if (matchesOid(der, oidStart, oidLen, NC_OID_BYTES)) {
                // NameConstraints (RFC 5280 §4.2.1.10)
                ncLocal = parseNameConstraints(der, afterOid, extContentEnd, critical);
            } else if (critical) {
                // Неизвестное critical extension: reject согласно RFC 5280 §4.2
                hasUnknownCritical = true;
            }
            pos = extSeqTlv[1];
        }

        // keyCertSign проверка: если KU есть, нужен бит 5; если KU нет — не отклоняем
        boolean keyCertSignOk = !kuPresent || kuKeyCertSign;
        // crlSignValid: если KeyUsage нет — без ограничений; если есть — нужен бит cRLSign
        boolean crlSignValid = !kuPresent || kuCrlSign;

        String[] sanResult = sanList.isEmpty() ? null : sanList.toArray(new String[0]);
        byte[][] ipResult = ipList.isEmpty() ? null : ipList.toArray(new byte[0][]);
        String[] ianDnsResult = ianDnsList.isEmpty() ? null : ianDnsList.toArray(new String[0]);
        byte[][] ianIpResult = ianIpList.isEmpty() ? null : ianIpList.toArray(new byte[0][]);
        boolean kuValid = !kuPresent || kuDigitalSignature;
        boolean ekuValid = !ekuPresent || ekuServerAuth;
        boolean ekuClientAuthValid = !ekuPresent || ekuClientAuth;
        byte[][] ekuOidsResult = ekuOidList.isEmpty() ? null : ekuOidList.toArray(new byte[0][]);
        byte[][] cpOidsResult = cpOidList.isEmpty() ? null : cpOidList.toArray(new byte[0][]);
        return new ExtensionsResult(
                sanResult,
                ipResult,
                ianDnsResult,
                ianIpResult,
                kuValid,
                crlSignValid,
                ekuValid,
                ekuClientAuthValid,
                // OCSP-делегат и TSA требуют обязательного EKU (restrictive):
                // RFC 6960 §4.2.2.2 и RFC 3161 §2.3. В отличие от ekuValid/
                // ekuClientAuth (permissive default RFC 5280 §4.2.1.12 для общего
                // TLS-EKU), здесь отсутствие EKU НЕ даёт назначение — иначе cert
                // без EKU ошибочно принимается как responder/TSA.
                ekuPresent && ekuOcspSigning,
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
                freshestCrlList.isEmpty() ? null : freshestCrlList.toArray(new String[0]),
                certPolicyList.isEmpty() ? null : certPolicyList.toArray(new String[0]),
                keyUsageBitsLocal,
                ekuOidsResult,
                presentOids,
                cpOidsResult,
                ncLocal);
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
        int sanCount = 0;
        while (gnPos < gnEnd) {
            if (sanCount >= MAX_SAN_ENTRIES) {
                throw new IllegalArgumentException("SAN entries exceed maximum " + MAX_SAN_ENTRIES);
            }
            sanCount++;
            int gnTag = der[gnPos] & 0xFF;
            if (gnTag == TAG_DNS_NAME) {
                int[] dnsTlv = readTlv(der, gnPos);
                // dNSName — IA5String (RFC 5280 §4.2.1.6). US_ASCII декодирует lossy:
                // байты >127 заменяются на U+FFFD. Обхода hostname-проверки нет
                // (сравнение идёт по итоговой строке); это лишь data-quality аспект
                // для логирования/отображения.
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
                // uniformResourceIdentifier [6] IMPLICIT IA5String (RFC 5280 §4.2.1.6) —
                // строго primitive 0x86. Точное сравнение (а не маска 0xDF, гасившая
                // constructed-бит) отсекает non-standard constructed 0xA6.
                if (locTag == TAG_URI) {
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
    static void parseCdpUris(byte[] der, int cdpOuter, int cdpEnd, ArrayList<String> uriList) {
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
                    // uniformResourceIdentifier [6] IMPLICIT IA5String (RFC 5280 §4.2.1.6) —
                    // строго primitive 0x86. Точное сравнение отсекает non-standard
                    // constructed 0xA6, который маска 0xDF ошибочно пропускала.
                    if (gnTag == TAG_URI) {
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

    // ====================================================================
    // NameConstraints parser (RFC 5280 §4.2.1.10)
    // ====================================================================

    /**
     * Парсит расширение NameConstraints из extnValue OCTET STRING.
     *
     * <p>Поддерживаемые типы GeneralName: dNSName [2] и iPAddress [7].
     * Неподдерживаемые (rfc822Name, directoryName, URI, otherName) — флаг
     * hasUnsupportedNameType. min != 0 или max присутствует — hasInvalidMinMax.
     * non-critical — отдельный флаг (нарушение RFC 5280 §4.2.1.10).</p>
     *
     * <p>iPAddress в NameConstraints кодируется с маской: 8 байт (IPv4)
     * или 32 байта (IPv6) — в отличие от SAN, где 4/16 байт без маски.</p>
     *
     * @param der           DER-поток сертификата
     * @param extValuePos   позиция начала extnValue OCTET STRING
     * @param extContentEnd конец SEQUENCE Extension
     * @param critical      true если расширение помечено как critical
     * @return распарсенные NameConstraints или EMPTY если OCTET STRING не найден
     */
    private static NameConstraintsData parseNameConstraints(
            byte[] der, int extValuePos, int extContentEnd, boolean critical) {
        if (extValuePos >= extContentEnd || (der[extValuePos] & 0xFF) != TAG_OCTET_STRING) {
            return NameConstraintsData.EMPTY;
        }
        int[] octTlv = readTlv(der, extValuePos);
        int ncStart = octTlv[0];
        int ncEnd = octTlv[1];
        if (ncStart >= ncEnd || (der[ncStart] & 0xFF) != TAG_SEQUENCE) {
            return NameConstraintsData.EMPTY;
        }
        int[] ncSeqTlv = readTlv(der, ncStart);
        int pos = ncSeqTlv[0];
        int end = ncSeqTlv[1];

        ArrayList<String> permDns = null;
        ArrayList<byte[]> permIp = null;
        ArrayList<String> exclDns = null;
        ArrayList<byte[]> exclIp = null;
        boolean hasUnsupported = false;
        boolean hasInvalidMinMax = false;

        while (pos < end) {
            int tag = der[pos] & 0xFF;
            if (tag == TAG_CTX_0 || tag == TAG_CTX_1) {
                boolean isExcluded = (tag == TAG_CTX_1);
                int[] subtreeTlv = readTlv(der, pos);

                ArrayList<String> dnsOut = new ArrayList<>();
                ArrayList<byte[]> ipOut = new ArrayList<>();
                boolean[] flags =
                        parseGeneralSubtrees(der, subtreeTlv[0], subtreeTlv[1], dnsOut, ipOut);

                if (flags[0]) hasUnsupported = true;
                if (flags[1]) hasInvalidMinMax = true;

                if (isExcluded) {
                    if (!dnsOut.isEmpty()) exclDns = addToList(exclDns, dnsOut);
                    if (!ipOut.isEmpty()) exclIp = addToIpList(exclIp, ipOut);
                } else {
                    if (!dnsOut.isEmpty()) permDns = addToList(permDns, dnsOut);
                    if (!ipOut.isEmpty()) permIp = addToIpList(permIp, ipOut);
                }
                pos = subtreeTlv[1];
            } else {
                pos = readTlv(der, pos)[1];
            }
        }

        return new NameConstraintsData(
                permDns == null ? null : permDns.toArray(new String[0]),
                permIp == null ? null : permIp.toArray(new byte[0][]),
                exclDns == null ? null : exclDns.toArray(new String[0]),
                exclIp == null ? null : exclIp.toArray(new byte[0][]),
                hasUnsupported,
                hasInvalidMinMax,
                !critical);
    }

    /**
     * Парсит содержимое [0]/[1] GeneralSubtrees (SEQUENCE OF GeneralSubtree).
     * Заполняет переданные списки dnsOut/ipOut и возвращает флаги ошибок.
     *
     * @return boolean[2]: [0]=hasUnsupported, [1]=hasInvalidMinMax
     */
    private static boolean[] parseGeneralSubtrees(
            byte[] der, int start, int end, ArrayList<String> dnsOut, ArrayList<byte[]> ipOut) {
        boolean hasUnsupported = false;
        boolean hasInvalidMinMax = false;
        int pos = start;

        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            return new boolean[] {hasUnsupported, hasInvalidMinMax};
        }
        int[] seqTlv = readTlv(der, pos);
        pos = seqTlv[0];
        int seqEnd = seqTlv[1];

        while (pos < seqEnd) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                pos = readTlv(der, pos)[1];
                continue;
            }
            int[] subtreeSeqTlv = readTlv(der, pos);
            int sPos = subtreeSeqTlv[0];
            int sEnd = subtreeSeqTlv[1];

            if (sPos >= sEnd) {
                pos = subtreeSeqTlv[1];
                continue;
            }
            int gnTag = der[sPos] & 0xFF;
            int[] gnTlv = readTlv(der, sPos);

            if (gnTag == TAG_DNS_NAME) {
                String name =
                        new String(
                                der,
                                gnTlv[0],
                                gnTlv[1] - gnTlv[0],
                                java.nio.charset.StandardCharsets.US_ASCII);
                dnsOut.add(name.toLowerCase());
            } else if (gnTag == TAG_IP_ADDRESS) {
                int ipLen = gnTlv[1] - gnTlv[0];
                if (ipLen != 8 && ipLen != 32) {
                    throw new IllegalArgumentException(
                            "Invalid iPAddress length in NameConstraints: "
                                    + ipLen
                                    + " (expected 8 or 32)");
                }
                ipOut.add(Arrays.copyOfRange(der, gnTlv[0], gnTlv[1]));
            } else {
                hasUnsupported = true;
            }

            int afterBase = gnTlv[1];
            while (afterBase < sEnd) {
                int ctxTag = der[afterBase] & 0xFF;
                if (ctxTag == TAG_CTX_0) {
                    int[] minTlv = readTlv(der, afterBase);
                    if (minTlv[0] < minTlv[1] && (der[minTlv[0]] & 0xFF) == TAG_INTEGER) {
                        int[] intTlv = readTlv(der, minTlv[0]);
                        int minVal = 0;
                        for (int i = intTlv[0]; i < intTlv[1]; i++) {
                            minVal = (minVal << 8) | (der[i] & 0xFF);
                        }
                        if (minVal != 0) {
                            hasInvalidMinMax = true;
                        }
                    }
                    afterBase = minTlv[1];
                } else if (ctxTag == TAG_CTX_1) {
                    hasInvalidMinMax = true;
                    afterBase = readTlv(der, afterBase)[1];
                } else {
                    break;
                }
            }

            pos = subtreeSeqTlv[1];
        }

        return new boolean[] {hasUnsupported, hasInvalidMinMax};
    }

    private static ArrayList<String> addToList(ArrayList<String> target, ArrayList<String> src) {
        if (target == null) {
            target = new ArrayList<>();
        }
        target.addAll(src);
        return target;
    }

    private static ArrayList<byte[]> addToIpList(ArrayList<byte[]> target, ArrayList<byte[]> src) {
        if (target == null) {
            target = new ArrayList<>();
        }
        target.addAll(src);
        return target;
    }
}
