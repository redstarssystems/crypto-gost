package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.rssys.gost.pkix.GostOids;
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

    private static final int TAG_GENERAL_NAME_OTHER = 0xA0;
    private static final int TAG_GENERAL_NAME_X400 = 0xA3;
    private static final int TAG_GENERAL_NAME_EDI = 0xA5;
    private static final int TAG_GENERAL_NAME_REGISTERED_ID = 0x88;
    // GeneralSubtree.minimum [0] / maximum [1] IMPLICIT INTEGER - примитивные контекстные теги
    private static final int TAG_SUBTREE_MINIMUM = 0x80;
    private static final int TAG_SUBTREE_MAXIMUM = 0x81;

    private GostExtensionParser() {}

    /**
     * Результат парсинга расширений X.509v3.
     */
    public static final class ExtensionsResult {
        public final String[] sanDnsNames;
        public final byte[][] sanIpAddresses;
        public final String[] sanRfc822Names;
        public final String[] sanUris;
        public final byte[][] sanDirectoryNames;
        public final OtherNameEntry[] sanOtherNames;
        public final String[] ianDnsNames;
        public final byte[][] ianIpAddresses;
        public final String[] ianRfc822Names;
        public final String[] ianUris;
        public final byte[][] ianDirectoryNames;
        public final OtherNameEntry[] ianOtherNames;
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

        /** Политики сертификата с опциональными CPS-квалификаторами. */
        public final CertificatePolicy[] certPolicies;

        /** Name Constraints (RFC 5280 §4.2.1.10) — null если расширение отсутствует. */
        public final NameConstraintsData nameConstraints;

        /**
         * Неподдерживаемые формы GeneralName, найденные в SAN (не в IAN): otherName,
         * x400Address, ediPartyName, registeredID. Неизменяемое множество.
         */
        public final Set<UnsupportedGeneralNameForm> sanUnsupportedNameForms;

        public final int keyUsageBits;
        public final byte[][] ekuOids;
        public final Set<String> presentExtensionOids;

        /**
         * Значения расширений (содержимое OCTET STRING extnValue, DER значения расширения) по OID
         * в dot-notation. Неизменяемая карта; массивы внутри не отдаются наружу без копии.
         */
        final Map<String, byte[]> extensionValues;

        private ExtensionsResult(
                String[] sanDnsNames,
                byte[][] sanIpAddresses,
                String[] sanRfc822Names,
                String[] sanUris,
                byte[][] sanDirectoryNames,
                OtherNameEntry[] sanOtherNames,
                String[] ianDnsNames,
                byte[][] ianIpAddresses,
                String[] ianRfc822Names,
                String[] ianUris,
                byte[][] ianDirectoryNames,
                OtherNameEntry[] ianOtherNames,
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
                Map<String, byte[]> extensionValues,
                byte[][] cpOids,
                CertificatePolicy[] certPolicies,
                NameConstraintsData nameConstraints,
                Set<UnsupportedGeneralNameForm> sanUnsupportedNameForms) {
            this.sanDnsNames = sanDnsNames;
            this.sanIpAddresses = sanIpAddresses;
            this.sanRfc822Names = sanRfc822Names;
            this.sanUris = sanUris;
            this.sanDirectoryNames = sanDirectoryNames;
            this.sanOtherNames = sanOtherNames;
            this.ianDnsNames = ianDnsNames;
            this.ianIpAddresses = ianIpAddresses;
            this.ianRfc822Names = ianRfc822Names;
            this.ianUris = ianUris;
            this.ianDirectoryNames = ianDirectoryNames;
            this.ianOtherNames = ianOtherNames;
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
            this.certPolicies = certPolicies;
            this.presentExtensionOids = presentExtensionOids;
            this.extensionValues = extensionValues;
            this.nameConstraints = nameConstraints;
            this.sanUnsupportedNameForms =
                    UnsupportedGeneralNameForm.immutableCopyOf(sanUnsupportedNameForms);
        }

        /**
         * Глубокая копия для выдачи наружу.
         *
         * <p>Поля результата - публичные {@code final}-массивы, но сами массивы изменяемы, а на тех
         * же объектах держится проверка цепочки. Отдать их как есть значило бы позволить вызывающему
         * исправить SAN, IP-адреса, ограничения имён или OID политик в разобранном сертификате.
         * Внутренняя проверка продолжает читать поля без копирования: на рукопожатии аллокаций
         * нет. Канонический {@link #empty()} возвращается как есть.</p>
         */
        ExtensionsResult copy() {
            if (this == EMPTY) {
                return EMPTY;
            }
            return new ExtensionsResult(
                    cloneStrings(sanDnsNames),
                    cloneByteArrays(sanIpAddresses),
                    cloneStrings(sanRfc822Names),
                    cloneStrings(sanUris),
                    cloneByteArrays(sanDirectoryNames),
                    cloneOtherNames(sanOtherNames),
                    cloneStrings(ianDnsNames),
                    cloneByteArrays(ianIpAddresses),
                    cloneStrings(ianRfc822Names),
                    cloneStrings(ianUris),
                    cloneByteArrays(ianDirectoryNames),
                    cloneOtherNames(ianOtherNames),
                    keyUsageValid,
                    crlSignValid,
                    ekuValid,
                    ekuClientAuth,
                    ekuOcspSigning,
                    ekuTimeStamping,
                    isCA,
                    pathLen,
                    keyCertSign,
                    hasUnknownCritical,
                    skiBytes == null ? null : skiBytes.clone(),
                    akiBytes == null ? null : akiBytes.clone(),
                    cloneStrings(aiaUris),
                    cloneStrings(ocspUris),
                    cloneStrings(caIssuersUris),
                    cloneStrings(cdpUris),
                    cloneStrings(freshestCrlUris),
                    cloneStrings(certPolicyOids),
                    keyUsageBits,
                    cloneByteArrays(ekuOids),
                    // множество и карта неизменяемы; карта package-private и наружу не видна
                    presentExtensionOids,
                    extensionValues,
                    cloneByteArrays(cpOids),
                    certPolicies == null ? null : certPolicies.clone(),
                    copyNameConstraints(nameConstraints),
                    sanUnsupportedNameForms);
        }

        private static String[] cloneStrings(String[] values) {
            return values == null ? null : values.clone();
        }

        private static byte[][] cloneByteArrays(byte[][] values) {
            if (values == null) {
                return null;
            }
            byte[][] copy = new byte[values.length][];
            for (int i = 0; i < values.length; i++) {
                copy[i] = values[i] == null ? null : values[i].clone();
            }
            return copy;
        }

        private static OtherNameEntry[] cloneOtherNames(OtherNameEntry[] values) {
            if (values == null) {
                return null;
            }
            OtherNameEntry[] copy = new OtherNameEntry[values.length];
            for (int i = 0; i < values.length; i++) {
                copy[i] =
                        values[i] == null
                                ? null
                                : new OtherNameEntry(values[i].oid(), values[i].valueDer().clone());
            }
            return copy;
        }

        static NameConstraintsData copyNameConstraints(NameConstraintsData source) {
            if (source == null || source == NameConstraintsData.EMPTY) {
                return source;
            }
            return new NameConstraintsData(
                    cloneStrings(source.permittedDnsNames),
                    cloneByteArrays(source.permittedIps),
                    cloneStrings(source.permittedRfc822Names),
                    cloneStrings(source.permittedUris),
                    cloneByteArrays(source.permittedDirectoryNames),
                    cloneStrings(source.excludedDnsNames),
                    cloneByteArrays(source.excludedIps),
                    cloneStrings(source.excludedRfc822Names),
                    cloneStrings(source.excludedUris),
                    cloneByteArrays(source.excludedDirectoryNames),
                    source.unsupportedNameForms,
                    source.hasUnsupportedRfc822Form,
                    source.hasInvalidMinMax,
                    source.nonCritical,
                    source.hasMalformed);
        }

        /** Канонический пустой результат — гарантирует {@code ==} сравнение. */
        private static final ExtensionsResult EMPTY =
                new ExtensionsResult(
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
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
                        Collections.emptyMap(),
                        null,
                        null,
                        null,
                        Collections.emptySet());

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
    static ExtensionsResult parseFromExtensionsBlock(byte[] der, int extTagOffset, int tbsLimit) {
        int[] extTlv = readTlv(der, extTagOffset, tbsLimit);
        // Extensions — последнее поле TBSCertificate: любые байты между концом [3]
        // и концом TBS означали бы неразобранные поля внутри подписанной области.
        if (extTlv[1] != tbsLimit) {
            throw new IllegalArgumentException(
                    "Extensions [3] must be the last field of TBSCertificate");
        }
        int pos = extTlv[0];
        int end = extTlv[1];

        // Extensions ::= SEQUENCE SIZE (1..MAX): пустой или не-SEQUENCE блок — не «нет
        // расширений», а повреждённая структура, молча терять её нельзя.
        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Extensions [3] must contain a SEQUENCE");
        }
        int[] seqTlv = readTlv(der, pos, end);
        if (seqTlv[1] != end) {
            throw new IllegalArgumentException("Trailing bytes after Extensions SEQUENCE");
        }
        if (seqTlv[0] >= seqTlv[1]) {
            throw new IllegalArgumentException("Extensions SEQUENCE must not be empty");
        }
        return parseExtensionsFromSequence(der, pos, end);
    }

    /**
     * Парсит Extensions ::= SEQUENCE OF Extension без обёртки [3] EXPLICIT.
     *
     * <p>Эквивалентно {@link #parseExtensionsFromSequence(byte[], int, int)} с пределом
     * {@code der.length}. Если известен конец охватывающей структуры (например, SET
     * атрибута CSR), используйте трёхаргументный вариант.</p>
     *
     * @param der          DER-поток
     * @param seqTagOffset смещение на тег SEQUENCE (0x30) — начало Extensions
     * @return результат парсинга расширений
     * @throws IllegalArgumentException если структура нарушена или выходит за границы
     */
    public static ExtensionsResult parseExtensionsFromSequence(byte[] der, int seqTagOffset) {
        return parseExtensionsFromSequence(der, seqTagOffset, der.length);
    }

    /**
     * Парсит Extensions ::= SEQUENCE OF Extension без обёртки [3] EXPLICIT.
     *
     * <p>Используется для CSR (PKCS#10), где расширения из extensionRequest атрибута
     * лежат как {@code SET { Extensions }} без контекстного тега [3], в отличие от
     * TBSCertificate в X.509 сертификате (RFC 5280 §4.1.2.9 vs PKCS#9 §5.4.1).</p>
     *
     * <p>Строгий разбор: каждое расширение целиком лежит внутри Extensions SEQUENCE,
     * сама SEQUENCE ровно заканчивается на {@code limit}; не-SEQUENCE, пустая SEQUENCE
     * и хвост после неё отклоняются.</p>
     *
     * @param der          DER-поток
     * @param seqTagOffset смещение на тег SEQUENCE (0x30) — начало Extensions
     * @param limit        конец охватывающей структуры: Extensions SEQUENCE обязана заканчиваться ровно здесь
     * @return результат парсинга расширений
     * @throws IllegalArgumentException если структура нарушена или выходит за границы
     */
    public static ExtensionsResult parseExtensionsFromSequence(
            byte[] der, int seqTagOffset, int limit) {
        if (seqTagOffset >= limit || (der[seqTagOffset] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException(
                    "Extensions must be a SEQUENCE at offset " + seqTagOffset);
        }
        int[] seqTlv = readTlv(der, seqTagOffset, limit);
        // limit — конец охватывающей структуры, а не просто верхняя граница: хвост после
        // Extensions означал бы неразобранные байты внутри (подписанной) области.
        if (seqTlv[1] != limit) {
            throw new IllegalArgumentException("Trailing bytes after Extensions SEQUENCE");
        }
        int pos = seqTlv[0];
        int end = seqTlv[1];
        if (pos >= end) {
            throw new IllegalArgumentException("Extensions SEQUENCE must not be empty");
        }

        ArrayList<String> sanList = new ArrayList<>();
        ArrayList<byte[]> ipList = new ArrayList<>();
        ArrayList<String> sanRfc822List = new ArrayList<>();
        ArrayList<String> sanUriList = new ArrayList<>();
        ArrayList<byte[]> sanDirNameList = new ArrayList<>();
        ArrayList<OtherNameEntry> sanOtherNameList = new ArrayList<>();
        ArrayList<String> ianDnsList = new ArrayList<>();
        ArrayList<byte[]> ianIpList = new ArrayList<>();
        ArrayList<String> ianRfc822List = new ArrayList<>();
        ArrayList<String> ianUriList = new ArrayList<>();
        ArrayList<byte[]> ianDirNameList = new ArrayList<>();
        ArrayList<OtherNameEntry> ianOtherNameList = new ArrayList<>();
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
        // extnValue каждого расширения по OID: фильтр oid_filters сравнивает именно его
        Map<String, byte[]> extensionValuesByOid = new HashMap<>();
        int keyUsageBitsLocal = 0;
        ArrayList<byte[]> ekuOidList = new ArrayList<>();
        ArrayList<byte[]> cpOidList = new ArrayList<>();
        ArrayList<CertificatePolicy> certPolicyInfosList = new ArrayList<>();
        // Name Constraints (RFC 5280 §4.2.1.10)
        NameConstraintsData ncLocal = null;
        Set<UnsupportedGeneralNameForm> sanUnsupportedForms =
                EnumSet.noneOf(UnsupportedGeneralNameForm.class);

        int extCount = 0;
        while (pos < end) {
            if (extCount >= MAX_EXTENSIONS_PER_CERT) {
                throw new IllegalArgumentException(
                        "Too many X.509 extensions in certificate: " + extCount);
            }
            extCount++;
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                throw new IllegalArgumentException(
                        "Certificate extension must be a SEQUENCE at offset " + pos);
            }
            // Расширение целиком внутри Extensions SEQUENCE: иначе оно «съело» бы байты
            // за подписанной областью (signatureAlgorithm/signatureValue).
            int[] extSeqTlv = readTlv(der, pos, end);
            int extContent = extSeqTlv[0];
            int extContentEnd = extSeqTlv[1];

            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != TAG_OID) {
                throw new IllegalArgumentException(
                        "Certificate extension is missing OID at offset " + extContent);
            }
            int[] oidTlv = readTlv(der, extContent, extContentEnd);
            int oidStart = oidTlv[0];
            int oidLen = oidTlv[1] - oidTlv[0];

            int afterOid = oidTlv[1];
            // RFC 5280 §4.2: один и тот же OID не может встречаться дважды.
            // Проверяем до диспетчеризации по типу, иначе значение зависит от
            // порядка разбора — классический источник обхода ограничений.
            String oidDot = oidBytesToDottedString(der, oidStart, oidLen);
            if (!presentOids.add(oidDot)) {
                throw new IllegalArgumentException("Duplicate certificate extension: " + oidDot);
            }
            // Optional BOOLEAN (critical): строгий DER, иначе битый флаг превращает
            // неизвестное critical-расширение в «некритичное».
            boolean critical = false;
            if (afterOid < extContentEnd && (der[afterOid] & 0xFF) == TAG_BOOLEAN) {
                critical = readBoolean(der, afterOid, extContentEnd);
                afterOid = readTlv(der, afterOid, extContentEnd)[1];
            }

            // extnValue обязателен и завершает Extension. Копия значения изолирует
            // вложенные разборщики: они не могут прочитать за его границы.
            if (afterOid >= extContentEnd || (der[afterOid] & 0xFF) != TAG_OCTET_STRING) {
                throw new IllegalArgumentException(
                        "Certificate extension is missing extnValue at offset " + afterOid);
            }
            int[] octTlv = readTlv(der, afterOid, extContentEnd);
            if (octTlv[1] != extContentEnd) {
                throw new IllegalArgumentException(
                        "Trailing bytes after extnValue at offset " + octTlv[1]);
            }
            byte[] ev = Arrays.copyOfRange(der, octTlv[0], octTlv[1]);
            requireExtnValueShape(ev, oidDot, der, oidStart, oidLen);
            extensionValuesByOid.put(oidDot, ev);

            if (matchesOid(der, oidStart, oidLen, SAN_OID_BYTES)) {
                sanUnsupportedForms.addAll(
                        parseSanGeneralNames(
                                ev,
                                0,
                                ev.length,
                                sanList,
                                ipList,
                                sanRfc822List,
                                sanUriList,
                                sanDirNameList,
                                sanOtherNameList));
            } else if (matchesOid(der, oidStart, oidLen, IAN_OID_BYTES)) {
                // IAN в NameConstraints не участвует: его формы не накапливаются
                parseSanGeneralNames(
                        ev,
                        0,
                        ev.length,
                        ianDnsList,
                        ianIpList,
                        ianRfc822List,
                        ianUriList,
                        ianDirNameList,
                        ianOtherNameList);
            } else if (matchesOid(der, oidStart, oidLen, KU_OID_BYTES)) {
                kuPresent = true;
                if (ev.length > 0 && (ev[0] & 0xFF) == TAG_BIT_STRING) {
                    int[] bitTlv = readTlv(ev, 0, ev.length);
                    if (bitTlv[1] > bitTlv[0]) {
                        int valueStart = bitTlv[0] + 1;
                        int valueLen = bitTlv[1] - valueStart;
                        requireZeroPaddingBits(ev, bitTlv[0], bitTlv[1], "KeyUsage");
                        if (valueStart < bitTlv[1] && valueLen > 0) {
                            kuDigitalSignature =
                                    (ev[valueStart] & GostDerParser.KU_DIGITAL_SIGNATURE) != 0;
                            kuCrlSign = (ev[valueStart] & GostDerParser.KU_CRL_SIGN) != 0;
                            // keyCertSign — бит 5 = 0x04 в первом байте (KU не определяет биты
                            // ≥ 9)
                            kuKeyCertSign = (ev[valueStart] & GostDerParser.KU_KEY_CERT_SIGN) != 0;
                            // Собираем raw KU-маску для oid_filters matching
                            for (int k = 0; k < valueLen && k < 2; k++) {
                                keyUsageBitsLocal |= (ev[valueStart + k] & 0xFF) << (8 * k);
                            }
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, EKU_OID_BYTES)) {
                ekuPresent = true;
                ekuServerAuth = hasEku(ev, 0, ev.length, GostDerParser.SERVER_AUTH_OID_BYTES);
                ekuClientAuth = hasEku(ev, 0, ev.length, GostDerParser.CLIENT_AUTH_OID_BYTES);
                // EKU id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9).
                // anyExtendedKeyUsage НЕ принимаем: RFC 6960 §4.2.2.2 требует
                // делегирование именно через id-kp-OCSPSigning, anyEKU недостаточен.
                if (hasEku(ev, 0, ev.length, GostDerParser.OCSP_SIGNING_OID_BYTES)) {
                    ekuOcspSigning = true;
                }
                // EKU id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
                if (hasEku(ev, 0, ev.length, GostDerParser.TIME_STAMPING_OID_BYTES)) {
                    ekuTimeStamping = true;
                }
                // Собираем ВСЕ EKU OID для oid_filters matching (RFC 8446 §4.2.5)
                collectAllEkuOids(ev, 0, ev.length, ekuOidList);
            } else if (matchesOid(der, oidStart, oidLen, BC_OID_BYTES)) {
                // BasicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
                if (ev.length > 0 && (ev[0] & 0xFF) == TAG_SEQUENCE) {
                    int[] bcSeqTlv = readTlv(ev, 0, ev.length);
                    int bcInnerPos = bcSeqTlv[0];
                    int bcInnerEnd = bcSeqTlv[1];
                    // cA BOOLEAN (optional, default FALSE): строгий DER, как и critical
                    if (bcInnerPos < bcInnerEnd && (ev[bcInnerPos] & 0xFF) == TAG_BOOLEAN) {
                        isCA = readBoolean(ev, bcInnerPos, bcInnerEnd);
                        bcInnerPos = readTlv(ev, bcInnerPos, bcInnerEnd)[1];
                    }
                    // pathLen INTEGER (optional)
                    if (bcInnerPos < bcInnerEnd && (ev[bcInnerPos] & 0xFF) == TAG_INTEGER) {
                        // pathLenConstraint по RFC 5280 §4.2.1.9 - неотрицательный INTEGER.
                        // Знак и неминимальная запись отвергаются: иначе 02 01 FF читался бы как
                        // 255, а в ChainValidator проверка `pl >= 0` молча пропускала бы
                        // ограничение длины цепочки при отрицательном значении.
                        int[] pathLenAndEnd = readStrictNonNegativeInt(ev, bcInnerPos, bcInnerEnd);
                        pathLen = pathLenAndEnd[0];
                        bcInnerPos = pathLenAndEnd[1];
                    }
                    // Других полей в BasicConstraints нет: лишние байты — повреждённая структура
                    if (bcInnerPos != bcInnerEnd || bcSeqTlv[1] != ev.length) {
                        throw new IllegalArgumentException(
                                "Unexpected trailing data in BasicConstraints");
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, SKI_OID_BYTES)) {
                // SubjectKeyIdentifier — OCTET STRING внутри OCTET STRING (RFC 5280 §4.2.1.2).
                if (ev.length > 0 && (ev[0] & 0xFF) == TAG_OCTET_STRING) {
                    int[] innerTlv = readTlv(ev, 0, ev.length);
                    skiBytesLocal = Arrays.copyOfRange(ev, innerTlv[0], innerTlv[1]);
                }
            } else if (matchesOid(der, oidStart, oidLen, AKI_OID_BYTES)) {
                // AuthorityKeyIdentifier — SEQUENCE с опциональным [0] KeyIdentifier (RFC 5280
                // §4.2.1.1).
                if (ev.length > 0 && (ev[0] & 0xFF) == TAG_SEQUENCE) {
                    int[] akiSeqTlv = readTlv(ev, 0, ev.length);
                    int akiPos = akiSeqTlv[0];
                    int akiEnd = akiSeqTlv[1];
                    // [0] IMPLICIT на OCTET STRING — tag 0x80 (primitive) или 0xA0
                    // (constructed).
                    if (akiPos < akiEnd) {
                        int ctxTag = ev[akiPos] & 0xFF;
                        if ((ctxTag & 0xDF) == DerCodec.TAG_CTX_PRIMITIVE_0) {
                            int[] ctxTlv = readTlv(ev, akiPos, akiEnd);
                            akiBytesLocal = Arrays.copyOfRange(ev, ctxTlv[0], ctxTlv[1]);
                        }
                    }
                }
            } else if (matchesOid(der, oidStart, oidLen, AIA_OID_BYTES)) {
                // AuthorityInfoAccess — SEQUENCE of AccessDescription (RFC 5280 §4.2.2.1).
                parseAiaDescriptions(ev, 0, ev.length, aiaList, ocspList, caIssuersList);
            } else if (matchesOid(der, oidStart, oidLen, CDP_OID_BYTES)) {
                // CRLDistributionPoints (RFC 5280 §4.2.1.13) — точки распространения CRL.
                parseCdpUris(ev, 0, ev.length, cdpList);
            } else if (matchesOid(der, oidStart, oidLen, FRESHEST_CRL_OID_BYTES)) {
                // FreshestCRL (RFC 5280 §5.2.6) — точки распространения delta CRL.
                // Структура DistributionPoint идентична CDP.
                parseCdpUris(ev, 0, ev.length, freshestCrlList);
            } else if (matchesOid(der, oidStart, oidLen, CP_OID_BYTES)) {
                // CertificatePolicies (RFC 5280 §4.2.1.4) — OID политик сертификата.
                parseCertPolicyOids(
                        ev, 0, ev.length, certPolicyList, cpOidList, certPolicyInfosList);
            } else if (matchesOid(der, oidStart, oidLen, NC_OID_BYTES)) {
                // NameConstraints (RFC 5280 §4.2.1.10)
                ncLocal = parseNameConstraints(ev, critical);
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
        String[] sanRfc822Result =
                sanRfc822List.isEmpty() ? null : sanRfc822List.toArray(new String[0]);
        String[] sanUriResult = sanUriList.isEmpty() ? null : sanUriList.toArray(new String[0]);
        byte[][] sanDirNameResult =
                sanDirNameList.isEmpty() ? null : sanDirNameList.toArray(new byte[0][]);
        OtherNameEntry[] sanOtherNameResult =
                sanOtherNameList.isEmpty() ? null : sanOtherNameList.toArray(new OtherNameEntry[0]);
        String[] ianRfc822Result =
                ianRfc822List.isEmpty() ? null : ianRfc822List.toArray(new String[0]);
        String[] ianUriResult = ianUriList.isEmpty() ? null : ianUriList.toArray(new String[0]);
        byte[][] ianDirNameResult =
                ianDirNameList.isEmpty() ? null : ianDirNameList.toArray(new byte[0][]);
        OtherNameEntry[] ianOtherNameResult =
                ianOtherNameList.isEmpty() ? null : ianOtherNameList.toArray(new OtherNameEntry[0]);
        boolean kuValid = !kuPresent || kuDigitalSignature;
        boolean ekuValid = !ekuPresent || ekuServerAuth;
        boolean ekuClientAuthValid = !ekuPresent || ekuClientAuth;
        byte[][] ekuOidsResult = ekuOidList.isEmpty() ? null : ekuOidList.toArray(new byte[0][]);
        byte[][] cpOidsResult = cpOidList.isEmpty() ? null : cpOidList.toArray(new byte[0][]);
        CertificatePolicy[] certPoliciesResult =
                certPolicyInfosList.isEmpty()
                        ? null
                        : certPolicyInfosList.toArray(new CertificatePolicy[0]);
        return new ExtensionsResult(
                sanResult,
                ipResult,
                sanRfc822Result,
                sanUriResult,
                sanDirNameResult,
                sanOtherNameResult,
                ianDnsResult,
                ianIpResult,
                ianRfc822Result,
                ianUriResult,
                ianDirNameResult,
                ianOtherNameResult,
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
                Collections.unmodifiableSet(presentOids),
                Collections.unmodifiableMap(extensionValuesByOid),
                cpOidsResult,
                certPoliciesResult,
                ncLocal,
                sanUnsupportedForms);
    }

    /**
     * Проверяет, что extnValue известного расширения — ровно один TLV ожидаемого типа.
     *
     * <p>Без этого битое значение (не та структура, хвост после неё) превращалось в
     * «расширения нет»: теряются AKI/CDP/AIA, а для ограничений — молча слабее проверка.
     * Для неизвестных OID содержимое не интерпретируется и не проверяется.</p>
     */
    private static void requireExtnValueShape(
            byte[] ev, String oidDot, byte[] der, int oidStart, int oidLen) {
        int expectedTag;
        if (matchesOid(der, oidStart, oidLen, SKI_OID_BYTES)) {
            expectedTag = TAG_OCTET_STRING;
        } else if (matchesOid(der, oidStart, oidLen, KU_OID_BYTES)) {
            expectedTag = TAG_BIT_STRING;
        } else if (matchesOid(der, oidStart, oidLen, EKU_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, BC_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, AKI_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, AIA_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, CDP_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, FRESHEST_CRL_OID_BYTES)
                || matchesOid(der, oidStart, oidLen, CP_OID_BYTES)) {
            expectedTag = TAG_SEQUENCE;
        } else {
            return;
        }
        if (ev.length == 0 || (ev[0] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(
                    "Malformed extnValue of extension " + oidDot + ": unexpected structure");
        }
        if (readTlv(ev, 0, ev.length)[1] != ev.length) {
            throw new IllegalArgumentException(
                    "Trailing bytes in extnValue of extension " + oidDot);
        }
    }

    // ====================================================================
    // SAN parser
    // ====================================================================

    /**
     * Парсит GeneralNames SEQUENCE из SubjectAltName/IssuerAltName.
     * Извлекает все типы GeneralName: dNSName, iPAddress, rfc822Name, URI,
     * directoryName, otherName.
     *
     * <p>Строгий разбор: GeneralNames — непустая SEQUENCE, ровно заполняющая extnValue;
     * каждое имя целиком внутри неё; неизвестный тег отклоняется (CHOICE GeneralName
     * закрыт девятью альтернативами). x400Address, ediPartyName и registeredID
     * не сохраняются, но фиксируются в возвращаемом множестве, чтобы ChainValidator
     * мог отказать, если NameConstraints ограничивают ту же форму.</p>
     *
     * @return множество неподдерживаемых форм, встреченных в этом расширении
     */
    private static Set<UnsupportedGeneralNameForm> parseSanGeneralNames(
            byte[] der,
            int gnOuter,
            int gnOuterEnd,
            ArrayList<String> dnsList,
            ArrayList<byte[]> ipList,
            ArrayList<String> rfc822List,
            ArrayList<String> uriList,
            ArrayList<byte[]> dirNameList,
            ArrayList<OtherNameEntry> otherNameList) {
        if (gnOuter >= gnOuterEnd || (der[gnOuter] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("GeneralNames must be a SEQUENCE");
        }
        int[] gnSeqTlv = readTlv(der, gnOuter, gnOuterEnd);
        if (gnSeqTlv[1] != gnOuterEnd) {
            throw new IllegalArgumentException("Trailing bytes after GeneralNames SEQUENCE");
        }
        int gnPos = gnSeqTlv[0];
        int gnEnd = gnSeqTlv[1];
        if (gnPos >= gnEnd) {
            throw new IllegalArgumentException("GeneralNames must not be empty");
        }
        Set<UnsupportedGeneralNameForm> unsupportedForms =
                EnumSet.noneOf(UnsupportedGeneralNameForm.class);
        int sanCount = 0;
        while (gnPos < gnEnd) {
            if (sanCount >= MAX_SAN_ENTRIES) {
                throw new IllegalArgumentException("SAN entries exceed maximum " + MAX_SAN_ENTRIES);
            }
            sanCount++;
            int gnTag = der[gnPos] & 0xFF;
            if (gnTag == TAG_DNS_NAME) {
                int[] dnsTlv = readTlv(der, gnPos, gnEnd);
                String name = decodeIa5(der, dnsTlv[0], dnsTlv[1], "SAN dNSName");
                dnsList.add(name);
                gnPos = dnsTlv[1];
            } else if (gnTag == TAG_IP_ADDRESS) {
                int[] ipTlv = readTlv(der, gnPos, gnEnd);
                int len = ipTlv[1] - ipTlv[0];
                if (len == 4 || len == 16) {
                    ipList.add(Arrays.copyOfRange(der, ipTlv[0], ipTlv[1]));
                } else {
                    throw new IllegalArgumentException(
                            "Malformed iPAddress in SAN: expected 4 or 16 bytes, got " + len);
                }
                gnPos = ipTlv[1];
            } else if (gnTag == TAG_RFC822_NAME) {
                int[] rfcTlv = readTlv(der, gnPos, gnEnd);
                String email = decodeIa5(der, rfcTlv[0], rfcTlv[1], "SAN rfc822Name");
                rfc822List.add(email.toLowerCase(Locale.ROOT));
                gnPos = rfcTlv[1];
            } else if (gnTag == TAG_URI) {
                int[] uriTlv = readTlv(der, gnPos, gnEnd);
                String uri = decodeIa5(der, uriTlv[0], uriTlv[1], "SAN URI");
                uriList.add(uri);
                gnPos = uriTlv[1];
            } else if (gnTag == TAG_DIRECTORY_NAME) {
                int[] dirTlv = readTlv(der, gnPos, gnEnd);
                dirNameList.add(Arrays.copyOfRange(der, dirTlv[0], dirTlv[1]));
                gnPos = dirTlv[1];
            } else if (gnTag == TAG_GENERAL_NAME_OTHER) {
                // otherName [0] — IMPLICIT заменяет SEQUENCE OtherName.
                // Содержимое: <OID TLV><[0] EXPLICIT value>
                int[] otherTlv = readTlv(der, gnPos, gnEnd);
                unsupportedForms.add(UnsupportedGeneralNameForm.OTHER_NAME);
                int otherPos = otherTlv[0];
                int otherEnd = otherTlv[1];
                if (otherPos < otherEnd && (der[otherPos] & 0xFF) == TAG_OID) {
                    int[] oidTlv = readTlv(der, otherPos, otherEnd);
                    String oid = DerCodec.parseOid(der, otherPos);
                    int afterOid = oidTlv[1];
                    if (afterOid < otherEnd && (der[afterOid] & 0xFF) == 0xA0) {
                        int[] explicitTlv = readTlv(der, afterOid, otherEnd);
                        byte[] valueDer = Arrays.copyOfRange(der, explicitTlv[0], explicitTlv[1]);
                        otherNameList.add(new OtherNameEntry(oid, valueDer));
                    } else {
                        throw new IllegalArgumentException(
                                "Malformed otherName in SAN: missing [0] EXPLICIT value");
                    }
                } else {
                    throw new IllegalArgumentException(
                            "Malformed otherName in SAN: missing type-id OID");
                }
                gnPos = otherTlv[1];
            } else if (gnTag == TAG_GENERAL_NAME_X400
                    || gnTag == TAG_GENERAL_NAME_EDI
                    || gnTag == TAG_GENERAL_NAME_REGISTERED_ID) {
                unsupportedForms.add(unsupportedFormOf(gnTag));
                gnPos = readTlv(der, gnPos, gnEnd)[1];
            } else {
                throw new IllegalArgumentException(
                        "Unknown GeneralName tag 0x" + Integer.toHexString(gnTag) + " in SAN/IAN");
            }
        }
        return unsupportedForms;
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
                    String uri = decodeIa5(der, uriTlv[0], uriTlv[1], "AIA URI");
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
                        String uri = decodeIa5(der, uriTlv[0], uriTlv[1], "CDP URI");
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
     * Парсит CertificatePolicies: извлекает policyIdentifier OID как точечную строку,
     * параллельно собирает сырые DER-байты OID для oid_filters matching (RFC 8446 §4.2.5)
     * и извлекает CPS-квалификаторы (id-qt-cps) где присутствуют.
     * CertificatePolicies ::= SEQUENCE OF PolicyInformation
     * PolicyInformation ::= SEQUENCE { policyIdentifier OID,
     *                                  policyQualifiers SEQUENCE OF PolicyQualifierInfo OPTIONAL }
     */
    private static void parseCertPolicyOids(
            byte[] der,
            int cpOuter,
            int cpEnd,
            ArrayList<String> oidList,
            ArrayList<byte[]> cpOidBytes,
            ArrayList<CertificatePolicy> certPolicyInfosList) {
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
            String oidStr = null;
            String cpsUri = null;
            if (piPos < piEnd && (der[piPos] & 0xFF) == TAG_OID) {
                int[] oidTlv = readTlv(der, piPos);
                oidStr = oidBytesToDottedString(der, oidTlv[0], oidTlv[1] - oidTlv[0]);
                oidList.add(oidStr);
                cpOidBytes.add(Arrays.copyOfRange(der, oidTlv[0], oidTlv[1]));
                piPos = oidTlv[1];
            }
            // Парсим policyQualifiers если есть
            if (piPos < piEnd && (der[piPos] & 0xFF) == TAG_SEQUENCE) {
                int[] pqSeqTlv = readTlv(der, piPos);
                int pqPos = pqSeqTlv[0];
                int pqEnd = pqSeqTlv[1];
                while (pqPos < pqEnd) {
                    if ((der[pqPos] & 0xFF) != TAG_SEQUENCE) {
                        pqPos = readTlv(der, pqPos)[1];
                        continue;
                    }
                    int[] pqiTlv = readTlv(der, pqPos);
                    int pqiPos = pqiTlv[0];
                    int pqiEnd = pqiTlv[1];
                    if (pqiPos < pqiEnd && (der[pqiPos] & 0xFF) == TAG_OID) {
                        int[] qOidTlv = readTlv(der, pqiPos);
                        String qualifierOid =
                                oidBytesToDottedString(der, qOidTlv[0], qOidTlv[1] - qOidTlv[0]);
                        if (GostOids.POLICY_QT_CPS.equals(qualifierOid)) {
                            int afterQOid = qOidTlv[1];
                            if (afterQOid < pqiEnd
                                    && (der[afterQOid] & 0xFF) == DerCodec.TAG_IA5_STRING) {
                                int[] ia5Tlv = readTlv(der, afterQOid);
                                cpsUri = decodeIa5(der, ia5Tlv[0], ia5Tlv[1], "policy CPS URI");
                            }
                        }
                    }
                    pqPos = pqiTlv[1];
                }
            }
            if (oidStr != null) {
                certPolicyInfosList.add(new CertificatePolicy(oidStr, cpsUri));
            }
            pos = piSeqTlv[1];
        }
    }

    // ====================================================================
    // NameConstraints parser (RFC 5280 §4.2.1.10)
    // ====================================================================

    /**
     * Проверяет BIT STRING именованных битов (DER): число неиспользуемых бит 0..7, а сами
     * неиспользуемые биты последнего байта равны нулю.
     *
     * <p>Padding-бит с единицей иначе читался бы как значимый флаг KeyUsage
     * (например, keyCertSign или cRLSign), хотя по кодировке такого бита в значении нет.</p>
     *
     * @param der          буфер с BIT STRING
     * @param contentStart начало содержимого BIT STRING (байт числа неиспользуемых бит)
     * @param contentEnd   конец содержимого (эксклюзивный)
     * @param what         имя расширения для сообщения об ошибке
     * @throws IllegalArgumentException при нарушении кодировки
     */
    private static void requireZeroPaddingBits(
            byte[] der, int contentStart, int contentEnd, String what) {
        int unusedBits = der[contentStart] & 0xFF;
        boolean hasValueBytes = contentEnd - contentStart > 1;
        if (unusedBits > 7 || (!hasValueBytes && unusedBits != 0)) {
            throw new IllegalArgumentException("Invalid unused bits count in " + what);
        }
        if (hasValueBytes) {
            int paddingMask = (1 << unusedBits) - 1;
            if ((der[contentEnd - 1] & paddingMask) != 0) {
                throw new IllegalArgumentException("Non-zero padding bits in " + what);
            }
        }
    }

    /**
     * Парсит расширение NameConstraints из extnValue OCTET STRING.
     *
     * <p>Поддерживаемые типы GeneralName: dNSName [2], iPAddress [7],
     * rfc822Name [1], URI [6], directoryName [4].
     * Валидные, но нереализованные типы (otherName, x400Address, ediPartyName,
     * registeredID) выставляют hasUnsupportedNameType. Любое структурное
     * нарушение выставляет hasMalformed: ChainValidator обязан отклонить
     * такую цепочку.</p>
     *
     * <p>iPAddress в NameConstraints кодируется с маской: 8 байт (IPv4)
     * или 32 байта (IPv6) — в отличие от SAN, где 4/16 байт без маски.</p>
     *
     * @param der      содержимое extnValue (изолированная копия, без OCTET STRING-обёртки)
     * @param critical true если расширение помечено как critical
     * @return распарсенные NameConstraints; hasMalformed=true при нарушении структуры
     */
    private static NameConstraintsData parseNameConstraints(byte[] der, boolean critical) {
        // der — изолированная копия extnValue: границы SEQUENCE сверяются с её концом
        int ncEnd = der.length;
        if (ncEnd == 0 || (der[0] & 0xFF) != TAG_SEQUENCE) {
            return malformedNameConstraints(critical);
        }
        int[] ncSeqTlv = readTlv(der, 0, ncEnd);
        if (ncSeqTlv[1] != ncEnd) {
            return malformedNameConstraints(critical);
        }
        int pos = ncSeqTlv[0];
        int end = ncSeqTlv[1];

        ArrayList<String> permDns = null;
        ArrayList<byte[]> permIp = null;
        ArrayList<String> permRfc822 = null;
        ArrayList<String> permUri = null;
        ArrayList<byte[]> permDirName = null;
        ArrayList<String> exclDns = null;
        ArrayList<byte[]> exclIp = null;
        ArrayList<String> exclRfc822 = null;
        ArrayList<String> exclUri = null;
        ArrayList<byte[]> exclDirName = null;
        Set<UnsupportedGeneralNameForm> unsupportedForms =
                EnumSet.noneOf(UnsupportedGeneralNameForm.class);
        boolean hasInvalidMinMax = false;
        boolean hasUnsupportedRfc822Form = false;
        boolean hasMalformed = false;
        boolean sawPermitted = false;
        boolean sawExcluded = false;

        while (pos < end) {
            int tag = der[pos] & 0xFF;
            if (tag != TAG_CTX_0 && tag != TAG_CTX_1) {
                hasMalformed = true;
                break;
            }
            int[] subtreeTlv = readTlv(der, pos);
            if (subtreeTlv[1] > end) {
                hasMalformed = true;
                break;
            }
            if (tag == TAG_CTX_0) {
                if (sawPermitted) {
                    hasMalformed = true;
                    break;
                }
                sawPermitted = true;
            } else {
                if (sawExcluded) {
                    hasMalformed = true;
                    break;
                }
                sawExcluded = true;
            }
            boolean isExcluded = (tag == TAG_CTX_1);

            ArrayList<String> dnsOut = new ArrayList<>();
            ArrayList<byte[]> ipOut = new ArrayList<>();
            ArrayList<String> rfc822Out = new ArrayList<>();
            ArrayList<String> uriOut = new ArrayList<>();
            ArrayList<byte[]> dirNameOut = new ArrayList<>();
            SubtreeFlags flags =
                    parseGeneralSubtrees(
                            der,
                            subtreeTlv[0],
                            subtreeTlv[1],
                            dnsOut,
                            ipOut,
                            rfc822Out,
                            uriOut,
                            dirNameOut);

            unsupportedForms.addAll(flags.unsupportedForms);
            if (flags.hasInvalidMinMax) hasInvalidMinMax = true;
            if (flags.hasUnsupportedRfc822Form) hasUnsupportedRfc822Form = true;
            if (flags.hasMalformed) {
                hasMalformed = true;
                break;
            }

            if (isExcluded) {
                if (!dnsOut.isEmpty()) exclDns = addToList(exclDns, dnsOut);
                if (!ipOut.isEmpty()) exclIp = addToIpList(exclIp, ipOut);
                if (!rfc822Out.isEmpty()) exclRfc822 = addToList(exclRfc822, rfc822Out);
                if (!uriOut.isEmpty()) exclUri = addToList(exclUri, uriOut);
                if (!dirNameOut.isEmpty()) exclDirName = addToIpList(exclDirName, dirNameOut);
            } else {
                if (!dnsOut.isEmpty()) permDns = addToList(permDns, dnsOut);
                if (!ipOut.isEmpty()) permIp = addToIpList(permIp, ipOut);
                if (!rfc822Out.isEmpty()) permRfc822 = addToList(permRfc822, rfc822Out);
                if (!uriOut.isEmpty()) permUri = addToList(permUri, uriOut);
                if (!dirNameOut.isEmpty()) permDirName = addToIpList(permDirName, dirNameOut);
            }
            pos = subtreeTlv[1];
        }

        if (pos != end) hasMalformed = true;
        if (!sawPermitted && !sawExcluded) hasMalformed = true;

        return new NameConstraintsData(
                permDns == null ? null : permDns.toArray(new String[0]),
                permIp == null ? null : permIp.toArray(new byte[0][]),
                permRfc822 == null ? null : permRfc822.toArray(new String[0]),
                permUri == null ? null : permUri.toArray(new String[0]),
                permDirName == null ? null : permDirName.toArray(new byte[0][]),
                exclDns == null ? null : exclDns.toArray(new String[0]),
                exclIp == null ? null : exclIp.toArray(new byte[0][]),
                exclRfc822 == null ? null : exclRfc822.toArray(new String[0]),
                exclUri == null ? null : exclUri.toArray(new String[0]),
                exclDirName == null ? null : exclDirName.toArray(new byte[0][]),
                unsupportedForms,
                hasUnsupportedRfc822Form,
                hasInvalidMinMax,
                !critical,
                hasMalformed);
    }

    private static NameConstraintsData malformedNameConstraints(boolean critical) {
        return new NameConstraintsData(
                null, null, null, null, null, null, null, null, null, null, Set.of(), false, false,
                !critical, true);
    }

    /**
     * Парсит содержимое [0]/[1] GeneralSubtrees (SEQUENCE OF GeneralSubtree).
     *
     * <p>RFC 5280 использует IMPLICIT TAGS: содержимое [0]/[1] — это сразу
     * последовательность GeneralSubtree SEQUENCE. Legacy EXPLICIT-обёртка
     * принимается только если она является единственным элементом внутри
     * [0]/[1], без хвостовых данных. Любое нарушение структуры выставляет
     * hasMalformed.</p>
     *
     * @return набор признаков разбора: неподдерживаемые формы имён, недопустимые
     *         min/max, mailbox-форма rfc822Name, структурное нарушение
     */
    private static SubtreeFlags parseGeneralSubtrees(
            byte[] der,
            int start,
            int end,
            ArrayList<String> dnsOut,
            ArrayList<byte[]> ipOut,
            ArrayList<String> rfc822Out,
            ArrayList<String> uriOut,
            ArrayList<byte[]> dirNameOut) {
        Set<UnsupportedGeneralNameForm> unsupportedForms =
                EnumSet.noneOf(UnsupportedGeneralNameForm.class);
        boolean hasInvalidMinMax = false;
        boolean hasUnsupportedRfc822Form = false;
        boolean hasMalformed = false;
        int pos = start;

        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            return new SubtreeFlags(
                    unsupportedForms, hasInvalidMinMax, hasUnsupportedRfc822Form, true);
        }
        int[] firstTlv = readTlv(der, pos);
        int seqStart = start;
        int seqEnd = end;
        if (firstTlv[0] < firstTlv[1] && (der[firstTlv[0]] & 0xFF) == TAG_SEQUENCE) {
            int[] innerTlv = readTlv(der, firstTlv[0]);
            if (innerTlv[0] < innerTlv[1] && isGeneralNameTag(der[innerTlv[0]] & 0xFF)) {
                if (firstTlv[1] != end) {
                    hasMalformed = true;
                }
                seqStart = firstTlv[0];
                seqEnd = firstTlv[1];
            }
        }
        pos = seqStart;

        while (pos < seqEnd) {
            if ((der[pos] & 0xFF) != TAG_SEQUENCE) {
                hasMalformed = true;
                break;
            }
            int[] subtreeSeqTlv = readTlv(der, pos);
            int sPos = subtreeSeqTlv[0];
            int sEnd = subtreeSeqTlv[1];
            if (sPos >= sEnd || sEnd > seqEnd) {
                hasMalformed = true;
                break;
            }
            int gnTag = der[sPos] & 0xFF;
            if (!isGeneralNameTag(gnTag)) {
                hasMalformed = true;
                break;
            }
            int[] gnTlv = readTlv(der, sPos);
            if (gnTlv[1] > sEnd) {
                hasMalformed = true;
                break;
            }

            if (gnTag == TAG_DNS_NAME) {
                String name = decodeIa5(der, gnTlv[0], gnTlv[1], "NameConstraints dNSName");
                dnsOut.add(name.toLowerCase(Locale.ROOT));
            } else if (gnTag == TAG_IP_ADDRESS) {
                int ipLen = gnTlv[1] - gnTlv[0];
                if (ipLen != 8 && ipLen != 32) {
                    hasMalformed = true;
                    break;
                }
                ipOut.add(Arrays.copyOfRange(der, gnTlv[0], gnTlv[1]));
            } else if (gnTag == TAG_RFC822_NAME) {
                String name = decodeIa5(der, gnTlv[0], gnTlv[1], "NameConstraints rfc822Name");
                if (name.indexOf('@') >= 0) {
                    hasUnsupportedRfc822Form = true;
                } else {
                    rfc822Out.add(name.toLowerCase(Locale.ROOT));
                }
            } else if (gnTag == TAG_URI) {
                String name = decodeIa5(der, gnTlv[0], gnTlv[1], "NameConstraints URI");
                uriOut.add(name);
            } else if (gnTag == TAG_DIRECTORY_NAME) {
                dirNameOut.add(Arrays.copyOfRange(der, gnTlv[0], gnTlv[1]));
            } else {
                // isGeneralNameTag уже отсёк всё, кроме otherName/x400/EDI/registeredID
                unsupportedForms.add(unsupportedFormOf(gnTag));
            }

            int afterBase = gnTlv[1];
            boolean sawMin = false;
            boolean sawMax = false;
            while (afterBase < sEnd) {
                // minimum [0] / maximum [1] IMPLICIT BaseDistance (RFC 5280 §4.2.1.10,
                // модуль с IMPLICIT TAGS): примитивные теги 0x80/0x81, содержимое - тело
                // INTEGER. Конструктивная форма 0xA0/0xA1 с вложенным INTEGER - не DER.
                int ctxTag = der[afterBase] & 0xFF;
                if (ctxTag != TAG_SUBTREE_MINIMUM && ctxTag != TAG_SUBTREE_MAXIMUM) {
                    hasMalformed = true;
                    break;
                }
                boolean isMinimum = ctxTag == TAG_SUBTREE_MINIMUM;
                if (isMinimum ? sawMin : sawMax) {
                    hasMalformed = true;
                    break;
                }
                if (isMinimum) {
                    sawMin = true;
                } else {
                    sawMax = true;
                }
                // Границы - по GeneralSubtree: значение не может зайти в соседние байты.
                int[] distanceTlv = readTlv(der, afterBase);
                int distanceLen = distanceTlv[1] - distanceTlv[0];
                if (distanceTlv[1] > sEnd
                        || distanceLen == 0
                        || !isMinimalIntegerContent(der, distanceTlv[0], distanceLen)) {
                    hasMalformed = true;
                    break;
                }
                BigInteger distance = new BigInteger(der, distanceTlv[0], distanceLen);
                if (distance.signum() < 0) {
                    hasMalformed = true;
                    break;
                }
                // minimum, отличный от 0, и любой maximum не поддерживаются: ChainValidator
                // отвергает такие ограничения, а не применяет их частично.
                if (!isMinimum || distance.signum() != 0) {
                    hasInvalidMinMax = true;
                }
                afterBase = distanceTlv[1];
            }
            if (afterBase != sEnd) {
                hasMalformed = true;
            }
            pos = subtreeSeqTlv[1];
            if (hasMalformed) {
                break;
            }
        }

        return new SubtreeFlags(
                unsupportedForms, hasInvalidMinMax, hasUnsupportedRfc822Form, hasMalformed);
    }

    /**
     * Проверяет минимальность DER-кодирования содержимого INTEGER: ведущий 0x00 или 0xFF
     * допустим только если без него изменился бы знак.
     */
    private static boolean isMinimalIntegerContent(byte[] der, int start, int len) {
        if (len < 2) return true;
        int first = der[start] & 0xFF;
        int secondHighBit = der[start + 1] & 0x80;
        return !((first == 0x00 && secondHighBit == 0) || (first == 0xFF && secondHighBit != 0));
    }

    /** Результат разбора одного GeneralSubtrees. */
    private static final class SubtreeFlags {
        final Set<UnsupportedGeneralNameForm> unsupportedForms;
        final boolean hasInvalidMinMax;
        final boolean hasUnsupportedRfc822Form;
        final boolean hasMalformed;

        SubtreeFlags(
                Set<UnsupportedGeneralNameForm> unsupportedForms,
                boolean hasInvalidMinMax,
                boolean hasUnsupportedRfc822Form,
                boolean hasMalformed) {
            this.unsupportedForms = unsupportedForms;
            this.hasInvalidMinMax = hasInvalidMinMax;
            this.hasUnsupportedRfc822Form = hasUnsupportedRfc822Form;
            this.hasMalformed = hasMalformed;
        }
    }

    /**
     * Декодирует IA5String из DER и отвергает управляющие символы.
     *
     * <p>Значение приходит от собеседника и может попасть в сообщение исключения или в журнал.
     * Символы 0x00-0x1F и 0x7F (в том числе CR/LF) позволили бы подделать строку журнала,
     * поэтому такой сертификат считается некорректным: RFC 5280 §4.2.1.6 требует для
     * dNSName и URI осмысленный IA5String, а не произвольные управляющие байты.
     *
     * @param der   буфер DER
     * @param start начало содержимого
     * @param end   конец содержимого (исключая)
     * @param field название поля для сообщения об ошибке
     * @return декодированная строка без управляющих символов
     * @throws IllegalArgumentException если в значении есть управляющий символ
     */
    private static String decodeIa5(byte[] der, int start, int end, String field) {
        String value = new String(der, start, end - start, StandardCharsets.US_ASCII);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                throw new IllegalArgumentException(
                        "Control character in " + field + " (IA5String)");
            }
        }
        return value;
    }

    /**
     * Отображает тег GeneralName на неподдерживаемую форму.
     *
     * @throws IllegalArgumentException если тег принадлежит поддерживаемой форме или неизвестен
     */
    private static UnsupportedGeneralNameForm unsupportedFormOf(int gnTag) {
        switch (gnTag) {
            case TAG_GENERAL_NAME_OTHER:
                return UnsupportedGeneralNameForm.OTHER_NAME;
            case TAG_GENERAL_NAME_X400:
                return UnsupportedGeneralNameForm.X400_ADDRESS;
            case TAG_GENERAL_NAME_EDI:
                return UnsupportedGeneralNameForm.EDI_PARTY_NAME;
            case TAG_GENERAL_NAME_REGISTERED_ID:
                return UnsupportedGeneralNameForm.REGISTERED_ID;
            default:
                throw new IllegalArgumentException(
                        "Not an unsupported GeneralName tag: 0x" + Integer.toHexString(gnTag));
        }
    }

    private static boolean isGeneralNameTag(int tag) {
        return tag == TAG_GENERAL_NAME_OTHER
                || tag == TAG_RFC822_NAME
                || tag == TAG_DNS_NAME
                || tag == TAG_GENERAL_NAME_X400
                || tag == TAG_DIRECTORY_NAME
                || tag == TAG_GENERAL_NAME_EDI
                || tag == TAG_URI
                || tag == TAG_IP_ADDRESS
                || tag == TAG_GENERAL_NAME_REGISTERED_ID;
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
