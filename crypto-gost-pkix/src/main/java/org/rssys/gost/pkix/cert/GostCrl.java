package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Минимальный парсер CRL (Certificate Revocation List, RFC 5280 §5) для ГОСТ Р 34.10-2012.
 *
 * <p>Конструктор парсит структуру (version, issuer, thisUpdate, nextUpdate, границы TBS и
 * подписи), но НЕ revoked-список — список извлекается только после успешной проверки
 * подписи через {@link #verify(PublicKeyParameters)} (fail-closed).
 *
 * <p>Инвариант fail-closed: {@link #getRevokedCertificates()} брошен до успешного вызова
 * {@link #verify(PublicKeyParameters)}. При невалидной подписи revoked-список не парсится.</p>
 *
 * <p>После однократного завершения {@link #verify(PublicKeyParameters)} в одном потоке,
 * чтение полей {@code revokedMap}, {@code crlNumber}, {@code baseCrlNumber} из других
 * потоков безопасно — happens-before через единственное volatile поле {@code revokedMap}.
 * Запись (повторный вызов {@code verify()}) — не thread-safe.</p>
 *
 * @see CrlVerifier
 * @see GostCrlBuilder
 * @see RevokedEntry
 */
public final class GostCrl {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.GostCrl");


    private final byte[] crlData;
    private final int tbsStart;
    private final int tbsLen;
    private final int version;
    private final int issuerDnOff;
    private final int issuerDnLen;
    private final Instant thisUpdate;
    private final Instant nextUpdate;
    private final String issuerDnStr;
    private final GostDnParser.DnField[] issuerDnFields;
    // Позиция после header TBSCertList (до revoked или extensions)
    private final int revokedPos;
    // TBS-конец для верификации подписи
    private final int tbsEnd;
    // signature value в DER
    private final byte[] sigValue;

    // Кэш revoked-списка: null до вызова verify(), заполняется при успехе.
    // Единая структура (LinkedHashMap) вместо отдельных List + Set —
    // исключает дублирование данных, оба метода isRevoked/getReason — O(1).
    // Happens-before: единственное volatile поле — запись в verify(),
    // чтение во всех get-методах (getRevokedCertificates, isRevoked, getReason).
    private volatile Map<BigInteger, RevokedEntry> revokedMap;

    // CRL-level extensions (заполняются при verify)
    private volatile BigInteger crlNumber;
    private volatile BigInteger baseCrlNumber;

    /**
     * Парсит DER-закодированный CertificateList (RFC 5280 §5.1).
     *
     * <p>Парсит структуру, но не revoked-список. Revoked-список извлекается
     * только после успешной верификации подписи через {@link #verify(PublicKeyParameters)}.
     *
     * @param derEncoded полный CRL в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null} или обнаружен невалидный синтаксис
     */
    public GostCrl(byte[] derEncoded) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("CRL DER must not be null");
        }
        this.crlData = derEncoded.clone();

        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
        int[] clSeq = parseSequence(crlData, 0);
        int clPos = clSeq[0];
        int clEnd = clSeq[1];

        if (clPos >= clEnd) {
            throw new IllegalArgumentException("Truncated DER: empty CertificateList SEQUENCE");
        }

        // tbsCertList ::= SEQUENCE
        int[] tbsSeq = parseSequence(crlData, clPos);
        this.tbsStart = clPos;
        this.tbsEnd = tbsSeq[1];
        this.tbsLen = tbsSeq[1] - clPos;
        int tbPos = tbsSeq[0];
        int tbEnd = tbsSeq[1];

        // version — OPTIONAL
        int v = 1;
        if (tbPos < tbEnd && (crlData[tbPos] & 0xFF) == TAG_INTEGER) {
            int[] verTlv = readTlv(crlData, tbPos);
            if (verTlv[0] < verTlv[1]) {
                v = (crlData[verTlv[0]] & 0xFF) + 1;
            }
            tbPos = verTlv[1];
        } else if (tbPos < tbEnd && (crlData[tbPos] & 0xFF) == 0xA0) {
            int[] verExplTlv = readTlv(crlData, tbPos);
            int verInner = verExplTlv[0];
            if (verInner < verExplTlv[1] && (crlData[verInner] & 0xFF) == TAG_INTEGER) {
                int[] verIntTlv = readTlv(crlData, verInner);
                if (verIntTlv[0] < verIntTlv[1]) {
                    v = (crlData[verIntTlv[0]] & 0xFF) + 1;
                }
            }
            tbPos = verExplTlv[1];
        }
        this.version = v;

        // signature AlgorithmIdentifier — пропускаем
        if (tbPos >= tbEnd || (crlData[tbPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: signature AlgorithmIdentifier missing");
        }
        tbPos = readTlv(crlData, tbPos)[1];

        // issuer Name
        if (tbPos >= tbEnd || (crlData[tbPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: issuer Name missing");
        }
        int[] issuerTlv = readTlv(crlData, tbPos);
        this.issuerDnOff = tbPos;
        this.issuerDnLen = issuerTlv[1] - tbPos;
        GostDnParser.DnParseResult issuerResult =
                GostDnParser.parseDnString(crlData, this.issuerDnOff, this.issuerDnLen);
        this.issuerDnStr = issuerResult != null ? issuerResult.dnString : null;
        this.issuerDnFields =
                issuerResult != null
                        ? issuerResult.fields.toArray(new GostDnParser.DnField[0])
                        : new GostDnParser.DnField[0];
        tbPos = issuerTlv[1];

        // thisUpdate — обязательное поле
        if (tbPos >= tbEnd) {
            throw new IllegalArgumentException("CRL: thisUpdate missing");
        }
        int thisUpdateTag = crlData[tbPos] & 0xFF;
        if (thisUpdateTag != TAG_UTC_TIME && thisUpdateTag != TAG_GENERALIZED_TIME) {
            throw new IllegalArgumentException("CRL: expected Time at thisUpdate");
        }
        int[] thisUpdateTlv = readTlv(crlData, tbPos);
        this.thisUpdate = parseTime(crlData, tbPos);
        tbPos = thisUpdateTlv[1];

        // nextUpdate — OPTIONAL
        Instant nu = null;
        if (tbPos < tbEnd
                && ((crlData[tbPos] & 0xFF) == TAG_UTC_TIME
                        || (crlData[tbPos] & 0xFF) == TAG_GENERALIZED_TIME)) {
            int[] nuTlv = readTlv(crlData, tbPos);
            nu = parseTime(crlData, tbPos);
            tbPos = nuTlv[1];
        }
        this.nextUpdate = nu;

        // Запоминаем позицию для revoked-списка / extensions
        this.revokedPos = tbPos;

        // signatureAlgorithm — между tbsCertList и signatureValue
        clPos = tbsSeq[1];
        if (clPos >= clEnd || (crlData[clPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: signatureAlgorithm missing");
        }
        clPos = readTlv(crlData, clPos)[1];

        // signatureValue BIT STRING
        if (clPos >= clEnd || (crlData[clPos] & 0xFF) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("CRL: signatureValue BIT STRING missing");
        }
        int[] sigBitTlv = readTlv(crlData, clPos);
        if (sigBitTlv[1] <= sigBitTlv[0]) {
            throw new IllegalArgumentException(
                    "CRL: empty BIT STRING for signature at offset " + clPos);
        }
        if (crlData[sigBitTlv[0]] != 0) {
            throw new IllegalArgumentException("CRL: signature BIT STRING has unused bits != 0");
        }
        this.sigValue = Arrays.copyOfRange(crlData, sigBitTlv[0] + 1, sigBitTlv[1]);
    }

    /**
     * Создаёт CRL из DER-байтов.
     *
     * @param der DER-encoded CertificateList
     * @return распарсенный CRL
     */
    public static GostCrl fromDer(byte[] der) {
        return new GostCrl(der);
    }

    /**
     * Создаёт CRL из PEM или DER-байтов с автоопределением формата.
     *
     * @param data PEM или DER-байты CRL
     * @return распарсенный CRL
     */
    public static GostCrl fromPemOrDer(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("CRL data must not be null or empty");
        }
        if ((data[0] & 0xFF) == 0x30) {
            return new GostCrl(data);
        }
        if (GostPemUtils.isPem(data)) {
            return new GostCrl(GostPemUtils.pemToDer(data));
        }
        throw new IllegalArgumentException(
                "Unrecognized CRL format: first byte 0x"
                        + Integer.toHexString(data[0] & 0xFF)
                        + " (expected 0x30 for DER or 0x2D for PEM)");
    }

    // ========================================================================
    // Всегда доступные геттеры
    // ========================================================================

    /** @return версия CRL (1 = v1, 2 = v2 по RFC 5280) */
    public int getVersion() {
        return version;
    }

    /** @return DER-закодированный issuer DN (полный SEQUENCE TLV) */
    public byte[] getIssuerDnBytes() {
        return Arrays.copyOfRange(crlData, issuerDnOff, issuerDnOff + issuerDnLen);
    }

    /** @return issuer DN в строковом представлении или null */
    public String getIssuerDn() {
        return issuerDnStr;
    }

    /** @return поля issuer DN */
    public GostDnParser.DnField[] getIssuerDnFields() {
        return issuerDnFields.clone();
    }

    /** @return дата выпуска CRL (thisUpdate) */
    public Instant getThisUpdate() {
        return thisUpdate;
    }

    /** @return дата следующего обновления CRL (nextUpdate) или null */
    public Instant getNextUpdate() {
        return nextUpdate;
    }

    /**
     * Проверяет, истёк ли срок действия CRL.
     *
     * @return true если nextUpdate есть и в прошлом (с допуском 5 минут)
     */
    public boolean isExpired() {
        if (nextUpdate == null) {
            return false;
        }
        return System.currentTimeMillis() > nextUpdate.toEpochMilli() + GostOids.CLOCK_SKEW_MS;
    }

    /** @return полный DER-encoded CRL (defensive copy) */
    public byte[] getEncoded() {
        return crlData.clone();
    }

    /** @return PEM-представление CRL */
    public String toPem() {
        return GostPemUtils.toPem(crlData, "X509 CRL");
    }

    // ========================================================================
    // Верификация подписи и доступ к revoked-списку
    // ========================================================================

    /**
     * Проверяет подпись CRL открытым ключом CA.
     *
     * <p>Инвариант безопасности (fail-closed): проверяет сроки, подпись и
     * отсутствие indirect/partial/delta CRL ДО парсинга revoked-списка. После успешной
     * верификации revoked-список парсится и кэшируется. Без успешного вызова
     * этого метода {@link #getRevokedCertificates()} бросает
     * {@link IllegalStateException}.
     *
     * @param caKey открытый ключ CA, подписавшего CRL
     * @throws PkixException если CRL невалиден (thisUpdate в будущем, истёк,
     *         невалидная подпись, IDP-расширение, delta CRL, структурная ошибка)
     */
    public void verify(PublicKeyParameters caKey) throws PkixException {
        verify(caKey, false);
    }

    /**
     * Пакетно-приватный: верификация с управлением delta-допуском.
     * Используется {@link CrlVerifier} для парсинга delta CRL без reject.
     *
     * @param caKey      открытый ключ CA
     * @param allowDelta true — не бросать исключение при deltaCRLIndicator
     */
    void verify(PublicKeyParameters caKey, boolean allowDelta) throws PkixException {
        if (caKey == null) {
            throw new IllegalArgumentException("caKey must not be null");
        }

        // Проверка даты thisUpdate — не в будущем (fail-closed)
        if (thisUpdate.toEpochMilli() > System.currentTimeMillis() + GostOids.CLOCK_SKEW_MS) {
            throw new PkixException(
                    PkixException.Reason.THIS_UPDATE_FUTURE, "CRL: thisUpdate is in the future");
        }

        // Проверка даты nextUpdate — не в прошлом (fail-closed)
        if (isExpired()) {
            throw new PkixException(PkixException.Reason.EXPIRED, "CRL: expired");
        }

        // Верификация подписи
        int hlen = caKey.getParams().hlen;
        Digest.Algorithm hashAlg =
                hlen == GostOids.STREEBOG_512_HASH_LEN
                        ? Digest.Algorithm.STREEBOG_512
                        : Digest.Algorithm.STREEBOG_256;
        Digest digest = new Digest(hashAlg);
        digest.update(crlData, tbsStart, tbsLen);
        byte[] hash = digest.digest();

        if (!Signature.verifyHash(hash, sigValue, caKey)) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "CRL: signature verification failed");
        }

        // Подпись валидна — парсим revoked-список
        List<RevokedEntry> entries = new ArrayList<>();
        int tbPos = revokedPos;
        int tbEnd = this.tbsEnd;

        if (tbPos >= tbEnd) {
            // Пустой CRL — нет ни revoked, ни extensions
            revokedMap = Collections.emptyMap();
            return;
        }

        // [0] EXPLICIT — crlExtensions без revoked (ранний вызов parseCrlExtensions)
        if ((crlData[tbPos] & 0xFF) == 0xA0) {
            int[] extExplTlv = readTlv(crlData, tbPos);
            parseCrlExtensions(crlData, extExplTlv[0], extExplTlv[1], allowDelta);
            revokedMap = Collections.emptyMap();
            return;
        }

        // revokedCertificates SEQUENCE OF RevokedCertificate
        if ((crlData[tbPos] & 0xFF) != TAG_SEQUENCE) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
        }
        int[] revokedSeq = readTlv(crlData, tbPos);
        int rvPos = revokedSeq[0];
        int rvEnd = revokedSeq[1];

        while (rvPos < rvEnd) {
            int[] rcSeq = parseSequence(crlData, rvPos);
            int rcPos = rcSeq[0];

            // serialNumber INTEGER
            if (rcPos >= rcSeq[1] || (crlData[rcPos] & 0xFF) != TAG_INTEGER) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
            }
            int[] serialTlv = readTlv(crlData, rcPos);
            byte[] serial = Arrays.copyOfRange(crlData, serialTlv[0], serialTlv[1]);
            rcPos = serialTlv[1];

            // revocationDate Time
            String revDate = null;
            if (rcPos < rcSeq[1]) {
                int tag = crlData[rcPos] & 0xFF;
                if (tag == TAG_UTC_TIME || tag == TAG_GENERALIZED_TIME) {
                    int[] revTimeTlv = readTlv(crlData, rcPos);
                    Instant d = parseTime(crlData, rcPos);
                    revDate = formatGeneralizedTime(d);
                    rcPos = revTimeTlv[1];
                }
            }

            // entryExtensions SEQUENCE OPTIONAL — парсим reasonCode
            ReasonCode reason = null;
            if (rcPos < rcSeq[1] && (crlData[rcPos] & 0xFF) == TAG_SEQUENCE) {
                int[] entryExtSeq = readTlv(crlData, rcPos);
                int ep = entryExtSeq[0];
                int ee = entryExtSeq[1];
                while (ep < ee) {
                    int[] extTlv = parseSequence(crlData, ep);
                    int oc = extTlv[0];
                    int oce = extTlv[1];
                    if (oc < oce && (crlData[oc] & 0xFF) == TAG_OID) {
                        int[] oidTlv = readTlv(crlData, oc);
                        oc = oidTlv[1];
                        if (matchesOid(crlData, oidTlv[0], oidTlv[1] - oidTlv[0],
                                CRL_REASON_OID_BYTES)) {
                            if (oc < oce && (crlData[oc] & 0xFF) == TAG_OCTET_STRING) {
                                int[] octTlv = readTlv(crlData, oc);
                                if (octTlv[0] < octTlv[1]
                                        && (crlData[octTlv[0]] & 0xFF) == TAG_ENUMERATED) {
                                    int[] enumTlv = readTlv(crlData, octTlv[0]);
                                    if (enumTlv[0] < enumTlv[1]) {
                                        int code = crlData[enumTlv[0]] & 0xFF;
                                        reason = ReasonCode.fromValue(code);
                                        if (reason == null) {
                                            LOG.log(Level.DEBUG,
                                                    "CRL: unknown reasonCode {0}, treating as absent",
                                                    code);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ep = extTlv[1];
                }
            }

            entries.add(new RevokedEntry(
                    serial, revDate != null ? revDate : "19700101000000Z", reason, null, null));

            rvPos = rcSeq[1];
        }

        // crlExtensions [0] после revoked
        if (rvPos < tbEnd && (crlData[rvPos] & 0xFF) == 0xA0) {
            int[] extExplTlv = readTlv(crlData, rvPos);
            parseCrlExtensions(crlData, extExplTlv[0], extExplTlv[1], allowDelta);
        }

        // Единая структура (LinkedHashMap) для O(1) поиска по isRevoked/getReason.
        // LinkedHashMap сохраняет порядок вставки — getRevokedCertificates() вернёт записи
        // в том же порядке, что и в DER.
        Map<BigInteger, RevokedEntry> map = new LinkedHashMap<>();
        for (RevokedEntry entry : entries) {
            map.put(new BigInteger(1, entry.serial()), entry);
        }
        revokedMap = Collections.unmodifiableMap(map);
    }

    /**
     * Список отозванных сертификатов.
     *
     * <p>Создаёт копию при каждом вызове через {@link List#copyOf}.
     * CRL содержат единицы-сотни записей, метод не на горячем пути —
     * копирование ссылок допустимо. Хранение отдельного {@code revokedList}
     * вернуло бы второе поле и дублирование данных.</p>
     *
     * @return неизменяемый список записей об отозванных сертификатах
     * @throws IllegalStateException если {@link #verify(PublicKeyParameters)} не был вызван
     */
    public List<RevokedEntry> getRevokedCertificates() {
        if (revokedMap == null) {
            throw new IllegalStateException(
                    "Call verify(PublicKeyParameters) before getRevokedCertificates()");
        }
        return List.copyOf(revokedMap.values());
    }

    /**
     * Проверяет, отозван ли сертификат с заданным серийным номером.
     *
     * @param certSerial серийный номер сертификата (raw DER INTEGER value)
     * @return true если сертификат найден в revoked-списке
     * @throws IllegalStateException если verify() не был вызван
     */
    public boolean isRevoked(byte[] certSerial) {
        if (revokedMap == null) {
            throw new IllegalStateException(
                    "Call verify(PublicKeyParameters) before isRevoked()");
        }
        return revokedMap.containsKey(new BigInteger(1, certSerial));
    }

    // ========================================================================
    // CRL-level extensions (доступны после verify)
    // ========================================================================

    /** @return cRLNumber из CRL-расширения или null */
    public BigInteger getCrlNumber() {
        return crlNumber;
    }

    /** @return BaseCRLNumber из deltaCRLIndicator или null */
    public BigInteger getBaseCrlNumber() {
        return baseCrlNumber;
    }

    /** @return true если CRL является Delta CRL */
    public boolean isDelta() {
        return baseCrlNumber != null;
    }

    /**
     * Возвращает reasonCode для отозванного сертификата.
     *
     * @param certSerial серийный номер (raw DER INTEGER)
     * @return ReasonCode или null если запись без reasonCode
     * @throws IllegalStateException если verify() не был вызван
     */
    public ReasonCode getReason(byte[] certSerial) {
        if (revokedMap == null) {
            throw new IllegalStateException(
                    "Call verify(PublicKeyParameters) before getReason()");
        }
        RevokedEntry entry = revokedMap.get(new BigInteger(1, certSerial));
        return entry != null ? entry.reason() : null;
    }

    // ========================================================================
    // Утилиты парсинга CRL-расширений
    // ========================================================================

    /**
     * Парсит CRL-level extensions: IDP (reject), cRLNumber (извлечь),
     * deltaCRLIndicator (извлечь, reject если allowDelta=false).
     *
     * @param allowDelta true — не бросать исключение для deltaCRLIndicator
     */
    private void parseCrlExtensions(byte[] der, int extPos, int extEnd, boolean allowDelta)
            throws PkixException {
        if (extPos >= extEnd || (der[extPos] & 0xFF) != TAG_SEQUENCE) return;
        int[] eSeq = readTlv(der, extPos);
        int p = eSeq[0];
        int pe = eSeq[1];
        while (p < pe) {
            int[] extTlv = parseSequence(der, p);
            int oc = extTlv[0];
            int oce = extTlv[1];

            // OID всегда первый в extension SEQUENCE
            if (oc < oce && (der[oc] & 0xFF) == TAG_OID) {
                int[] oidTlv = readTlv(der, oc);
                int afterOid = oidTlv[1];

                if (matchesOid(
                        der, oidTlv[0], oidTlv[1] - oidTlv[0], IDP_OID_BYTES)) {
                    throw new PkixException(PkixException.Reason.IDP_NOT_SUPPORTED,
                            "CRL: issuingDistributionPoint not supported");
                }

                if (matchesOid(
                        der, oidTlv[0], oidTlv[1] - oidTlv[0], DELTA_CRL_INDICATOR_OID_BYTES)) {
                    this.baseCrlNumber = parseExtensionInteger(der, afterOid, oce);
                    if (!allowDelta) {
                        throw new PkixException(PkixException.Reason.IDP_NOT_SUPPORTED,
                                "CRL: delta CRL not supported (deltaCRLIndicator present)");
                    }
                }

                if (matchesOid(
                        der, oidTlv[0], oidTlv[1] - oidTlv[0], CRL_NUMBER_OID_BYTES)) {
                    this.crlNumber = parseExtensionInteger(der, afterOid, oce);
                }
            }
            p = extTlv[1];
        }
    }

    /**
     * Извлекает INTEGER из extnValue OCTET STRING.
     * Принимает позицию сразу после OID — пропускает опциональный BOOLEAN
     * (нужен для critical-расширений, например deltaCRLIndicator).
     */
    private static BigInteger parseExtensionInteger(byte[] der, int pos, int end) {
        if (pos < end && (der[pos] & 0xFF) == TAG_BOOLEAN) {
            pos = readTlv(der, pos)[1];
        }
        if (pos < end && (der[pos] & 0xFF) == TAG_OCTET_STRING) {
            int[] octTlv = readTlv(der, pos);
            if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_INTEGER) {
                int[] intTlv = readTlv(der, octTlv[0]);
                return new BigInteger(Arrays.copyOfRange(der, intTlv[0], intTlv[1]));
            }
        }
        return null;
    }

    private static final DateTimeFormatter GEN_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private static String formatGeneralizedTime(Instant d) {
        return GEN_TIME.format(d);
    }

    // ========================================================================
    // Identity
    // ========================================================================

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GostCrl that = (GostCrl) o;
        return Arrays.equals(crlData, that.crlData);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(crlData);
    }

    @Override
    public String toString() {
        return "GostCrl{issuer="
                + GostDnParser.truncateForLog(issuerDnStr, 128)
                + ", version="
                + version
                + ", thisUpdate="
                + thisUpdate
                + "}";
    }
}
