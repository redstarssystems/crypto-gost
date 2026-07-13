package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
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

    /** Максимальный размер CRL в DER по умолчанию (64 МБ).
     *  Покрывает полные CRL крупных национальных УЦ. */
    public static final int DEFAULT_MAX_CRL_SIZE = 67_108_864;

    /** Максимальное число отозванных записей CRL по умолчанию.
     *  Минимальная запись ≈20–24 байт; при 64 МБ входа потолок ≈2.9M по байтам.
     *  1M — разумный запас без избыточной CPU-стоимости per-entry разбора. */
    public static final int DEFAULT_MAX_REVOKED_ENTRIES = 1_000_000;

    // Значения, установленные через конструктор (настраиваемые лимиты)
    private final int maxSize;
    private final int maxRevokedEntries;

    // Лимит длины INTEGER в CRL-расширениях (cRLNumber, BaseCRLNumber).
    // RFC 5280 §5.2.3: cRLNumber SHOULD be small; на практике 2-3 байта.
    // Без лимита new BigInteger может аллоцировать до ≈maxSize на одно вхождение.
    private static final int MAX_CRL_EXT_INTEGER_OCTETS = 8;

    private volatile BigInteger baseCrlNumber;

    // IDP-расширение (2.5.29.28) — заполняются при verify
    private volatile boolean idpPresent;
    private volatile boolean idpOnlyContainsUserCerts;
    private volatile boolean idpOnlyContainsCACerts;
    private volatile boolean idpIndirectCrl;

    // AKI extension (2.5.29.35) — keyIdentifier подписанта CRL
    private volatile byte[] akiBytes;

    // FreshestCRL extension (2.5.29.46) — URI delta CRL
    private volatile String[] freshestCrlUris;

    /**
     * Парсит DER-закодированный CertificateList (RFC 5280 §5.1).
     *
     * <p>Использует лимиты по умолчанию: {@value #DEFAULT_MAX_CRL_SIZE} байт размера,
     * {@value #DEFAULT_MAX_REVOKED_ENTRIES} отозванных записей.
     * Для настройки лимитов используйте {@link #GostCrl(byte[], int, int)}.
     *
     * <p>Парсит структуру, но не revoked-список. Revoked-список извлекается
     * только после успешной верификации подписи через {@link #verify(PublicKeyParameters)}.
     *
     * @param derEncoded полный CRL в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null} или обнаружен невалидный синтаксис
     */
    public GostCrl(byte[] derEncoded) {
        this(derEncoded, DEFAULT_MAX_CRL_SIZE, DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Парсит DER-закодированный CertificateList с настраиваемыми лимитами.
     *
     * @param derEncoded         полный CRL в DER-кодировке, не null
     * @param maxSize            максимальный размер CRL в байтах (защита от OOM)
     * @param maxRevokedEntries  максимальное число отозванных записей (защита от CPU-амплификации)
     * @throws IllegalArgumentException если {@code derEncoded == null} или превышен {@code maxSize}
     */
    public GostCrl(byte[] derEncoded, int maxSize, int maxRevokedEntries) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("CRL DER must not be null");
        }
        this.maxSize = maxSize;
        this.maxRevokedEntries = maxRevokedEntries;
        if (derEncoded.length > maxSize) {
            throw new IllegalArgumentException(
                    "CRL DER exceeds maximum size " + maxSize + ", got " + derEncoded.length);
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
     * Создаёт CRL из DER-байтов с лимитами по умолчанию.
     *
     * @param der DER-encoded CertificateList
     * @return распарсенный CRL
     */
    public static GostCrl fromDer(byte[] der) {
        return fromDer(der, DEFAULT_MAX_CRL_SIZE, DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Создаёт CRL из DER-байтов с настраиваемыми лимитами.
     *
     * @param der               DER-encoded CertificateList
     * @param maxSize           максимальный размер CRL в байтах
     * @param maxRevokedEntries максимальное число отозванных записей
     * @return распарсенный CRL
     */
    public static GostCrl fromDer(byte[] der, int maxSize, int maxRevokedEntries) {
        return new GostCrl(der, maxSize, maxRevokedEntries);
    }

    /**
     * Создаёт CRL из PEM или DER-байтов с автоопределением формата и лимитами по умолчанию.
     *
     * @param data PEM или DER-байты CRL
     * @return распарсенный CRL
     */
    public static GostCrl fromPemOrDer(byte[] data) {
        return fromPemOrDer(data, DEFAULT_MAX_CRL_SIZE, DEFAULT_MAX_REVOKED_ENTRIES);
    }

    /**
     * Создаёт CRL из PEM или DER-байтов с автоопределением формата и настраиваемыми лимитами.
     *
     * @param data              PEM или DER-байты CRL
     * @param maxSize           максимальный размер CRL в байтах
     * @param maxRevokedEntries максимальное число отозванных записей
     * @return распарсенный CRL
     */
    public static GostCrl fromPemOrDer(byte[] data, int maxSize, int maxRevokedEntries) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("CRL data must not be null or empty");
        }
        if ((data[0] & 0xFF) == 0x30) {
            return new GostCrl(data, maxSize, maxRevokedEntries);
        }
        if (GostPemUtils.isPem(data)) {
            byte[] der = GostPemUtils.pemToDer(data);
            return new GostCrl(der, maxSize, maxRevokedEntries);
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
        Digest.Algorithm hashAlg = GostSignatureHelper.digestAlgByHlen(hlen);
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

        int revokedCount = 0;
        while (rvPos < rvEnd) {
            if (revokedCount >= maxRevokedEntries) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "CRL revoked entries exceed maximum " + maxRevokedEntries);
            }
            revokedCount++;
            int[] rcSeq = parseSequence(crlData, rvPos);
            int rcPos = rcSeq[0];

            // serialNumber INTEGER
            if (rcPos >= rcSeq[1] || (crlData[rcPos] & 0xFF) != TAG_INTEGER) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
            }
            int[] serialTlv = readTlv(crlData, rcPos);
            // RFC 5280 §4.1.2.2: serialNumber не более 20 октетов ПО ВЕЛИЧИНЕ. Отсекаем до
            // копирования и new BigInteger(1, serial) — иначе одна запись с
            // ≈10MB serial даёт неограниченную аллокацию (DoS).
            //
            // Меряем ВЕЛИЧИНУ, а не кодированную длину: положительная 20-октетная величина
            // со старшим битом кодируется 21 байтом (ведущий 0x00 для знака), и это легитимно
            // (симметрично GostCertificateBuilder, который сверяет bitLength). Иначе получаем
            // false-reject валидного CRL. Non-minimal кодировки (лишние ведущие нули) здесь
            // НЕ отвергаем: серийники сравниваются как new BigInteger(1, serial), т.е. величина
            // нормализуется — malleability уже нейтрализована, а толерантность нужна для interop.
            //
            // Guard serialOctets > 0 обязателен: при zero-length INTEGER (02 00), где значение —
            // последние байты буфера, чтение crlData[serialTlv[0]] иначе дало бы AIOOBE.
            int serialMagnitudeOctets = serialTlv[1] - serialTlv[0];
            if (serialMagnitudeOctets > 0 && crlData[serialTlv[0]] == 0x00) {
                serialMagnitudeOctets--;
            }
            if (serialMagnitudeOctets > GostOids.MAX_SERIAL_OCTETS) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "CRL revoked entry serial exceeds "
                                + GostOids.MAX_SERIAL_OCTETS
                                + " octets");
            }
            byte[] serial = Arrays.copyOfRange(crlData, serialTlv[0], serialTlv[1]);
            rcPos = serialTlv[1];

            // revocationDate Time
            String revDate = null;
            if (rcPos < rcSeq[1]) {
                int tag = crlData[rcPos] & 0xFF;
                if (tag == TAG_UTC_TIME || tag == TAG_GENERALIZED_TIME) {
                    int[] revTimeTlv = readTlv(crlData, rcPos);
                    Instant d = parseTime(crlData, rcPos);
                    revDate = GostSignatureHelper.formatGeneralizedTime(d);
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
                        if (matchesOid(
                                crlData, oidTlv[0], oidTlv[1] - oidTlv[0], CRL_REASON_OID_BYTES)) {
                            if (oc < oce && (crlData[oc] & 0xFF) == TAG_OCTET_STRING) {
                                int[] octTlv = readTlv(crlData, oc);
                                if (octTlv[0] < octTlv[1]
                                        && (crlData[octTlv[0]] & 0xFF) == TAG_ENUMERATED) {
                                    int[] enumTlv = readTlv(crlData, octTlv[0]);
                                    if (enumTlv[0] < enumTlv[1]) {
                                        int code = crlData[enumTlv[0]] & 0xFF;
                                        reason = ReasonCode.fromValue(code);
                                        if (reason == null) {
                                            LOG.log(
                                                    Level.DEBUG,
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

            entries.add(
                    new RevokedEntry(
                            serial,
                            revDate != null ? revDate : "19700101000000Z",
                            reason,
                            null,
                            null));

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
            throw new IllegalStateException("Call verify(PublicKeyParameters) before isRevoked()");
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

    /** @return true если CRL содержит IssuingDistributionPoint расширение */
    public boolean isIdp() {
        return idpPresent;
    }

    /** @return true если IDP содержит indirectCRL флаг (indirect CRL — вне scope) */
    public boolean isIndirectCrl() {
        return idpIndirectCrl;
    }

    /** @return true если IDP с флагом onlyContainsUserCerts */
    public boolean isOnlyContainsUserCerts() {
        return idpOnlyContainsUserCerts;
    }

    /** @return true если IDP с флагом onlyContainsCACerts */
    public boolean isOnlyContainsCACerts() {
        return idpOnlyContainsCACerts;
    }

    /** @return true если CRL содержит FreshestCRL (2.5.29.46) */
    public boolean isFreshestCrl() {
        return freshestCrlUris != null;
    }

    /**
     * AuthorityKeyIdentifier (RFC 5280 §5.2.1): идентификатор ключа подписанта CRL.
     * Обычно совпадает с SKI сертификата подписанта.
     *
     * @return байты keyIdentifier или null
     */
    public byte[] getAuthorityKeyIdentifier() {
        return akiBytes != null ? akiBytes.clone() : null;
    }

    /**
     * FreshestCRL (RFC 5280 §5.2.6): URI для получения delta CRL.
     * Структура DistributionPoint идентична CDP.
     *
     * @return копия массива URI или null
     */
    public String[] getFreshestCrlUris() {
        return freshestCrlUris == null ? null : freshestCrlUris.clone();
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
            throw new IllegalStateException("Call verify(PublicKeyParameters) before getReason()");
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

                if (matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], IDP_OID_BYTES)) {
                    parseIdpExtension(der, afterOid, oce);
                }

                if (matchesOid(
                        der, oidTlv[0], oidTlv[1] - oidTlv[0], DELTA_CRL_INDICATOR_OID_BYTES)) {
                    this.baseCrlNumber = parseExtensionInteger(der, afterOid, oce);
                    if (!allowDelta) {
                        throw new PkixException(
                                PkixException.Reason.DELTA_CRL_NOT_SUPPORTED,
                                "CRL: delta CRL not supported (deltaCRLIndicator present)");
                    }
                }

                if (matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], FRESHEST_CRL_OID_BYTES)) {
                    parseFreshestCrlExtension(der, afterOid, oce);
                }

                if (matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], AKI_OID_BYTES)) {
                    parseAkiExtension(der, afterOid, oce);
                }

                if (matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], CRL_NUMBER_OID_BYTES)) {
                    this.crlNumber = parseExtensionInteger(der, afterOid, oce);
                }
            }
            p = extTlv[1];
        }
    }

    /**
     * Парсит IssuingDistributionPoint extension (RFC 5280 §5.2.5).
     *
     * <p>Извлекает флаги: onlyContainsUserCerts, onlyContainsCACerts, indirectCRL.
     * Остальные поля ([0] distributionPoint, [3] onlySomeReasons,
     * [5] onlyContainsAttributeCerts) игнорируются.
     *
     * <p>Принимает позицию сразу после OID — пропускает опциональный BOOLEAN (critical).
     *
     * @param der DER-поток CRL
     * @param pos позиция после OID в extension SEQUENCE
     * @param end конец extension SEQUENCE
     */
    private void parseIdpExtension(byte[] der, int pos, int end) throws PkixException {
        if (pos < end && (der[pos] & 0xFF) == TAG_BOOLEAN) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end || (der[pos] & 0xFF) != TAG_OCTET_STRING) {
            return;
        }
        int[] octTlv = readTlv(der, pos);
        int idpPos = octTlv[0];
        int idpEnd = octTlv[1];
        if (idpPos >= idpEnd || (der[idpPos] & 0xFF) != TAG_SEQUENCE) {
            return;
        }
        int[] idpSeq = readTlv(der, idpPos);
        int p = idpSeq[0];
        int pe = idpSeq[1];

        boolean onlyContainsUserCerts = false;
        boolean onlyContainsCACerts = false;
        boolean indirectCRL = false;

        while (p < pe) {
            int tag = der[p] & 0xFF;
            if (tag == 0xA1 || tag == 0x81) {
                // [1] onlyContainsUserCerts BOOLEAN
                onlyContainsUserCerts = parseIdpBoolean(der, p);
            } else if (tag == 0xA2 || tag == 0x82) {
                // [2] onlyContainsCACerts BOOLEAN
                onlyContainsCACerts = parseIdpBoolean(der, p);
            } else if (tag == 0xA4 || tag == 0x84) {
                // [4] indirectCRL BOOLEAN
                indirectCRL = parseIdpBoolean(der, p);
            }
            p = readTlv(der, p)[1];
        }

        this.idpPresent = true;
        this.idpOnlyContainsUserCerts = onlyContainsUserCerts;
        this.idpOnlyContainsCACerts = onlyContainsCACerts;
        this.idpIndirectCrl = indirectCRL;

        if (indirectCRL) {
            throw new PkixException(
                    PkixException.Reason.IDP_NOT_SUPPORTED,
                    "CRL: indirect CRL (issuingDistributionPoint with indirectCRL) not supported");
        }
    }

    /**
     * Парсит FreshestCRL extension (RFC 5280 §5.2.6).
     * Структура DistributionPoint идентична CDP — переиспользует
     * {@link GostExtensionParser#parseCdpUris} для извлечения URI.
     *
     * @param der DER-поток CRL
     * @param pos позиция после OID в extension SEQUENCE
     * @param end конец extension SEQUENCE
     */
    private void parseFreshestCrlExtension(byte[] der, int pos, int end) {
        if (pos < end && (der[pos] & 0xFF) == TAG_BOOLEAN) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end || (der[pos] & 0xFF) != TAG_OCTET_STRING) {
            return;
        }
        int[] octTlv = readTlv(der, pos);
        var uriList = new ArrayList<String>();
        GostExtensionParser.parseCdpUris(der, octTlv[0], octTlv[1], uriList);
        if (!uriList.isEmpty()) {
            this.freshestCrlUris = uriList.toArray(String[]::new);
        }
    }

    /**
     * Парсит AuthorityKeyIdentifier extension (RFC 5280 §5.2.1).
     * Извлекает keyIdentifier [0] IMPLICIT. Поля authorityCertIssuer [1]
     * и authorityCertSerialNumber [2] игнорируются.
     *
     * @param der DER-поток CRL
     * @param pos позиция после OID в extension SEQUENCE
     * @param end конец extension SEQUENCE
     */
    private void parseAkiExtension(byte[] der, int pos, int end) {
        if (pos < end && (der[pos] & 0xFF) == TAG_BOOLEAN) {
            pos = readTlv(der, pos)[1];
        }
        if (pos >= end || (der[pos] & 0xFF) != TAG_OCTET_STRING) {
            return;
        }
        int[] octTlv = readTlv(der, pos);
        if (octTlv[0] >= octTlv[1] || (der[octTlv[0]] & 0xFF) != TAG_SEQUENCE) {
            return;
        }
        int[] akiSeqTlv = readTlv(der, octTlv[0]);
        int akiPos = akiSeqTlv[0];
        int akiEnd = akiSeqTlv[1];
        if (akiPos < akiEnd) {
            int tag = der[akiPos] & 0xFF;
            // [0] IMPLICIT keyIdentifier — tag 0x80 (primitive) или 0xA0 (constructed)
            if (tag == 0x80 || tag == 0xA0) {
                int[] ctxTlv = readTlv(der, akiPos);
                this.akiBytes = Arrays.copyOfRange(der, ctxTlv[0], ctxTlv[1]);
            }
        }
    }

    /**
     * Извлекает BOOLEAN значение из контекстно-тегированного поля IDP
     * (RFC 5280 §5.2.5, Appendix A — DEFINITIONS IMPLICIT TAGS).
     *
     * <p>Каноническая кодировка — IMPLICIT: тег 0x81/0x82/0x84,
     * значение — байт 0x00/0xFF напрямую, без вложенного BOOLEAN-TLV.
     * Также поддерживается EXPLICIT (constructed 0xA1/0xA2/0xA4
     * с вложенным 01 01 FF) — толерантность к чужим кодировщикам.
     */
    private static boolean parseIdpBoolean(byte[] der, int pos) {
        int tag = der[pos] & 0xFF;
        int[] tlv = readTlv(der, pos);
        if (tlv[1] > tlv[0]) {
            if (tag == 0x81 || tag == 0x82 || tag == 0x84) {
                // IMPLICIT BOOLEAN: первый байт содержимого — значение
                return der[tlv[0]] != 0;
            }
            // EXPLICIT BOOLEAN: constructed с вложенным BOOLEAN TLV
            if (tlv[0] < tlv[1] && (der[tlv[0]] & 0xFF) == TAG_BOOLEAN) {
                int[] boolTlv = readTlv(der, tlv[0]);
                return boolTlv[0] < boolTlv[1] && der[boolTlv[0]] != 0;
            }
        }
        return false;
    }

    /**
     * Извлекает INTEGER из extnValue OCTET STRING.
     * Принимает позицию сразу после OID — пропускает опциональный BOOLEAN
     * (нужен для critical-расширений, например deltaCRLIndicator).
     */
    private static BigInteger parseExtensionInteger(byte[] der, int pos, int end)
            throws PkixException {
        if (pos < end && (der[pos] & 0xFF) == TAG_BOOLEAN) {
            pos = readTlv(der, pos)[1];
        }
        if (pos < end && (der[pos] & 0xFF) == TAG_OCTET_STRING) {
            int[] octTlv = readTlv(der, pos);
            if (octTlv[0] < octTlv[1] && (der[octTlv[0]] & 0xFF) == TAG_INTEGER) {
                int[] intTlv = readTlv(der, octTlv[0]);
                // Аномально большой cRLNumber/BaseCRLNumber (malformed per RFC 5280
                // §5.2.3) — fail-closed, чтобы не аллоцировать огромный BigInteger
                // и не продолжать с деградированным состоянием anti-rollback.
                if (intTlv[1] - intTlv[0] > MAX_CRL_EXT_INTEGER_OCTETS) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR,
                            "CRL extension INTEGER exceeds "
                                    + MAX_CRL_EXT_INTEGER_OCTETS
                                    + " octets");
                }
                return new BigInteger(Arrays.copyOfRange(der, intTlv[0], intTlv[1]));
            }
        }
        return null;
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
