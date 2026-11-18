package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Минимальный парсер CRL (Certificate Revocation List, RFC 5280 §5) для ГОСТ Р 34.10-2012.
 *
 * <p>Конструктор и {@code fromDer} сообщают о структурно битом CRL (ошибка DER, хвост за
 * CertificateList, подпись не до конца структуры) непроверяемым {@link IllegalArgumentException};
 * в {@link PkixException} его превращают проверяющие пути ({@link CrlVerifier}, CMS, X-Long).
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

    private static final GostLogger LOG = GostLogger.getLogger("org.rssys.gost.pkix.cert.GostCrl");

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
    private final int maxRevokedEntries;

    private volatile BigInteger baseCrlNumber;

    // IDP-расширение (2.5.29.28) — заполняются при verify
    private volatile boolean idpPresent;
    private volatile boolean idpOnlyContainsUserCerts;
    private volatile boolean idpOnlyContainsCACerts;
    private volatile boolean idpOnlySomeReasons;
    private volatile boolean idpIndirectCrl;
    private volatile boolean idpOnlyContainsAttributeCerts;
    private volatile boolean idpDistributionPointPresent;
    private volatile boolean idpNameRelativeToCrlIssuer;
    private volatile String[] idpDistributionPointUris;
    // Байты extnValue IDP: сравнение IDP base и delta (RFC 5280 §6.3.3(c)) побайтно
    private volatile byte[] idpExtnValue;

    // AKI extension (2.5.29.35) — keyIdentifier подписанта CRL
    private volatile byte[] akiBytes;

    // FreshestCRL extension (2.5.29.46) — URI delta CRL
    private volatile String[] freshestCrlUris;

    /**
     * Парсит DER-закодированный CertificateList (RFC 5280 §5.1).
     *
     * <p>Использует лимиты по умолчанию: {@value #DEFAULT_MAX_CRL_SIZE} байт размера,
     * {@value #DEFAULT_MAX_REVOKED_ENTRIES} отозванных записей.
     * Для настройки лимитов используйте {@link #GostCrl(byte[], CrlLimits)}.
     *
     * <p>Парсит структуру, но не revoked-список. Revoked-список извлекается
     * только после успешной верификации подписи через {@link #verify(PublicKeyParameters)}.
     *
     * @param derEncoded полный CRL в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null} или обнаружен невалидный синтаксис
     */
    public GostCrl(byte[] derEncoded) {
        this(derEncoded, CrlLimits.DEFAULT);
    }

    /**
     * Парсит DER-закодированный CertificateList с настраиваемыми лимитами.
     *
     * <p>Конструктор низкоуровневый: превышение размера даёт {@code IllegalArgumentException}.
     * Пути проверки заранее вызывают {@link CrlLimits#requireSize(byte[])} и получают причину
     * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}.</p>
     *
     * @param derEncoded полный CRL в DER-кодировке, не null
     * @param limits     пределы размера (защита от OOM) и числа записей (защита от CPU-амплификации)
     * @throws IllegalArgumentException если {@code derEncoded == null}, {@code limits == null}
     *                                  или превышен размер
     */
    public GostCrl(byte[] derEncoded, CrlLimits limits) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("CRL DER must not be null");
        }
        if (limits == null) {
            throw new IllegalArgumentException("limits must not be null");
        }
        int maxSize = limits.maxSize();
        this.maxRevokedEntries = limits.maxRevokedEntries();
        if (derEncoded.length > maxSize) {
            throw new IllegalArgumentException(
                    "CRL DER exceeds maximum size " + maxSize + ", got " + derEncoded.length);
        }
        this.crlData = derEncoded.clone();

        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
        int[] clSeq = parseSequence(crlData, 0);
        int clPos = clSeq[0];
        int clEnd = clSeq[1];
        // CertificateList занимает весь буфер: хвост после неё не принадлежит подписанной структуре
        if (clEnd != crlData.length) {
            throw new IllegalArgumentException("CRL: trailing data after CertificateList");
        }

        if (clPos >= clEnd) {
            throw new IllegalArgumentException("Truncated DER: empty CertificateList SEQUENCE");
        }

        // tbsCertList ::= SEQUENCE
        if ((crlData[clPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: tbsCertList must be SEQUENCE");
        }
        // Предел — конец CertificateList: TBS не должен выходить за неё
        int[] tbsSeq = readTlv(crlData, clPos, clEnd);
        this.tbsStart = clPos;
        this.tbsEnd = tbsSeq[1];
        this.tbsLen = tbsSeq[1] - clPos;
        int tbPos = tbsSeq[0];
        int tbEnd = tbsSeq[1];

        // version — OPTIONAL
        int v = 1;
        if (tbPos < tbEnd && (crlData[tbPos] & 0xFF) == TAG_INTEGER) {
            int[] verTlv = readTlv(crlData, tbPos, tbEnd);
            if (verTlv[0] < verTlv[1]) {
                v = (crlData[verTlv[0]] & 0xFF) + 1;
            }
            tbPos = verTlv[1];
        } else if (tbPos < tbEnd && (crlData[tbPos] & 0xFF) == 0xA0) {
            int[] verExplTlv = readTlv(crlData, tbPos, tbEnd);
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
        tbPos = readTlv(crlData, tbPos, tbEnd)[1];

        // issuer Name
        if (tbPos >= tbEnd || (crlData[tbPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: issuer Name missing");
        }
        int[] issuerTlv = readTlv(crlData, tbPos, tbEnd);
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
        int[] thisUpdateTlv = readTlv(crlData, tbPos, tbEnd);
        this.thisUpdate = parseTime(crlData, tbPos);
        tbPos = thisUpdateTlv[1];

        // nextUpdate — OPTIONAL
        Instant nu = null;
        if (tbPos < tbEnd
                && ((crlData[tbPos] & 0xFF) == TAG_UTC_TIME
                        || (crlData[tbPos] & 0xFF) == TAG_GENERALIZED_TIME)) {
            int[] nuTlv = readTlv(crlData, tbPos, tbEnd);
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
        clPos = readTlv(crlData, clPos, clEnd)[1];

        // signatureValue BIT STRING
        if (clPos >= clEnd || (crlData[clPos] & 0xFF) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("CRL: signatureValue BIT STRING missing");
        }
        int[] sigBitTlv = readTlv(crlData, clPos, clEnd);
        if (sigBitTlv[1] <= sigBitTlv[0]) {
            throw new IllegalArgumentException(
                    "CRL: empty BIT STRING for signature at offset " + clPos);
        }
        if (crlData[sigBitTlv[0]] != 0) {
            throw new IllegalArgumentException("CRL: signature BIT STRING has unused bits != 0");
        }
        if (sigBitTlv[1] != clEnd) {
            throw new IllegalArgumentException("CRL: trailing data after signatureValue");
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
        return fromDer(der, CrlLimits.DEFAULT);
    }

    /**
     * Создаёт CRL из DER-байтов с настраиваемыми лимитами.
     *
     * @param der    DER-encoded CertificateList
     * @param limits пределы размера и числа записей
     * @return распарсенный CRL
     */
    public static GostCrl fromDer(byte[] der, CrlLimits limits) {
        return new GostCrl(der, limits);
    }

    /**
     * Создаёт CRL из PEM или DER-байтов с автоопределением формата и лимитами по умолчанию.
     *
     * @param data PEM или DER-байты CRL
     * @return распарсенный CRL
     */
    public static GostCrl fromPemOrDer(byte[] data) {
        return fromPemOrDer(data, CrlLimits.DEFAULT);
    }

    /**
     * Создаёт CRL из PEM или DER-байтов с автоопределением формата и настраиваемыми лимитами.
     *
     * @param data   PEM или DER-байты CRL
     * @param limits пределы размера и числа записей
     * @return распарсенный CRL
     */
    public static GostCrl fromPemOrDer(byte[] data, CrlLimits limits) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("CRL data must not be null or empty");
        }
        if ((data[0] & 0xFF) == 0x30) {
            return new GostCrl(data, limits);
        }
        if (GostPemUtils.isPem(data)) {
            byte[] der = GostPemUtils.pemToDer(data);
            return new GostCrl(der, limits);
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

    /**
     * @param maxLen максимальная длина строки
     * @return issuer DN для журнала, обрезанный до maxLen символов (с суффиксом
     *         "...[truncated]"), или null; управляющие символы в DN уже экранированы
     */
    public String getIssuerDnForLog(int maxLen) {
        return GostDnParser.truncateForLog(issuerDnStr, maxLen);
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
     * <p>Инвариант безопасности (fail-closed): сначала проверяются сроки и подпись, и только
     * после успешной подписи строго разбираются revoked-список и расширения (неизвестное
     * critical-расширение, indirect CRL, delta CRL без допуска, структурная ошибка). После
     * успешного разбора revoked-список кэшируется. Без успешного вызова этого метода
     * {@link #getRevokedCertificates()} бросает {@link IllegalStateException}.
     *
     * <p><b>Область CRL здесь не применяется.</b> Метод проверяет подлинность и форму, но не
     * то, покрывает ли CRL конкретный сертификат (IssuingDistributionPoint: onlyContainsUserCerts,
     * onlyContainsCACerts, distributionPoint). Решение «сертификат не отозван» принимать по
     * {@link #isRevoked(byte[])} после этого метода нельзя: подлинный CRL другого сегмента
     * не содержит чужих сертификатов. Приёмку выполняет только {@link CrlVerifier}, который
     * принимает {@link GostCertificate} и применяет область.
     *
     * <p>Структурное нарушение (ошибка DER, повтор расширения, хвост) даёт
     * {@link PkixException} с причиной {@code PARSE_ERROR}, а не unchecked-исключение.
     *
     * <p><b>CRL без {@code nextUpdate} не принимается</b> (причина {@code NEXT_UPDATE_MISSING}):
     * RFC 5280 §5.1.2.5 обязывает УЦ включать это поле, а поведение клиента не задано, и без
     * него CRL не устаревает и его можно предъявлять бесконечно. Это политика проверяющей
     * стороны; разбор такого CRL конструктором по-прежнему разрешён.
     *
     * @param caKey открытый ключ CA, подписавшего CRL
     * @throws PkixException если CRL невалиден (thisUpdate в будущем, истёк, нет nextUpdate,
     *         невалидная подпись, indirect CRL (IDP с indirectCRL), delta CRL, неизвестное
     *         critical-расширение, структурная ошибка)
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

        requireValidNow();
        verifySignatureAndParse(caKey, allowDelta);
    }

    /**
     * Проверяет сроки CRL на текущий момент: {@code thisUpdate} не в будущем, {@code nextUpdate}
     * задан и CRL не истёк.
     *
     * <p>Вынесено из {@link #verify}, чтобы проверенный и закэшированный CRL перепроверялся на
     * каждом использовании без повторной подписи: срок истекает уже после проверки.</p>
     */
    void requireValidNow() throws PkixException {
        // Проверка даты thisUpdate — не в будущем (fail-closed)
        if (thisUpdate.toEpochMilli() > System.currentTimeMillis() + GostOids.CLOCK_SKEW_MS) {
            throw new PkixException(
                    PkixException.Reason.THIS_UPDATE_FUTURE, "CRL: thisUpdate is in the future");
        }

        // Без nextUpdate CRL не устаревает: isExpired() для него всегда false, и устаревший
        // список отзыва принимался бы вечно. Отказ здесь, а не в isExpired(): тот остаётся
        // геттером свойства, а requireValidNow() — общий вход всех путей приёмки
        if (nextUpdate == null) {
            throw new PkixException(
                    PkixException.Reason.NEXT_UPDATE_MISSING, "CRL: nextUpdate is missing");
        }

        // Проверка даты nextUpdate — не в прошлом (fail-closed)
        if (isExpired()) {
            throw new PkixException(PkixException.Reason.EXPIRED, "CRL: expired");
        }
    }

    /**
     * Проверяет подпись CRL и парсит revoked-список без проверки сроков.
     *
     * <p>Нужен для долгосрочной проверки, где окно выпуска CRL оценивается
     * отдельно от текущего времени. Легаси-метод {@link #verify(PublicKeyParameters)}
     * сохраняет прежний порядок: сначала сроки, затем подпись.</p>
     *
     * @param caKey      открытый ключ CA
     * @param allowDelta true — не бросать исключение при deltaCRLIndicator
     * @throws PkixException при невалидной подписи или структуре
     */
    void verifySignatureAndParse(PublicKeyParameters caKey, boolean allowDelta)
            throws PkixException {
        if (caKey == null) {
            throw new IllegalArgumentException("caKey must not be null");
        }

        // Верификация подписи
        int hlen = caKey.getParams().hlen;
        Digest.Algorithm hashAlg = GostSignatureHelper.digestAlgByHlen(hlen);
        Digest digest = new Digest(hashAlg);
        digest.update(crlData, tbsStart, tbsLen);
        byte[] hash = digest.digest();

        // Длина подписи берётся из недоверенного DER: неверная длина даёт false, а не исключение
        boolean signatureValid = Signature.verifyHash(hash, sigValue, caKey);
        if (!signatureValid) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "CRL: signature verification failed");
        }

        // Подпись валидна — только теперь разбираем неаутентичные до этого момента данные.
        // Любое структурное нарушение (IllegalArgumentException из DER-разбора) превращаем в
        // PkixException: CMS и TLS ловят только его, иначе исключение пройдёт мимо обработчиков.
        try {
            parseAfterSignature(allowDelta);
        } catch (RuntimeException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "CRL: malformed structure", e);
        }
    }

    /**
     * Разбирает revokedCertificates и crlExtensions после успешной проверки подписи.
     *
     * <p>Предусловие: подпись CRL проверена. Постусловие: {@code revokedMap} заполнен только
     * если весь TBS разобран без остатка; иначе остаётся {@code null}.</p>
     */
    private void parseAfterSignature(boolean allowDelta) throws PkixException {
        List<RevokedEntry> entries = new ArrayList<>();
        int tbPos = revokedPos;
        int tbEnd = this.tbsEnd;

        if (tbPos >= tbEnd) {
            // Пустой CRL — нет ни revoked, ни extensions
            revokedMap = Collections.emptyMap();
            return;
        }

        int firstTag = crlData[tbPos] & 0xFF;
        if (firstTag == TAG_SEQUENCE) {
            // revokedCertificates SEQUENCE OF RevokedCertificate
            int[] revokedSeq = readTlv(crlData, tbPos, tbEnd);
            parseRevokedEntries(revokedSeq[0], revokedSeq[1], entries);
            tbPos = revokedSeq[1];
        } else if (firstTag != TAG_CTX_EXTENSIONS) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
        }

        // crlExtensions [0] — последнее поле TBS: после него данных быть не может
        if (tbPos < tbEnd) {
            if ((crlData[tbPos] & 0xFF) != TAG_CTX_EXTENSIONS) {
                throw parseError("CRL: unexpected field after revoked list");
            }
            int[] extExplTlv = readTlv(crlData, tbPos, tbEnd);
            if (extExplTlv[1] != tbEnd) {
                throw parseError("CRL: trailing data after crlExtensions");
            }
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
     * Считает записи списка для сообщения о превышении предела.
     *
     * <p>Идёт по заголовкам оставшихся записей без разбора их содержимого и без сохранения записей
     * (на каждую запись создаются короткие массивы границ); подпись к этому моменту проверена,
     * проход выполняется один раз при превышении и ограничен принятым DER. Сбой подсчёта (испорченный
     * хвост) не подменяет исходную ошибку: сообщение тогда содержит нижнюю границу.</p>
     */
    private String describeEntryCount(int pos, int end, int counted) {
        int total = counted;
        try {
            int cursor = pos;
            while (cursor < end) {
                cursor = readTlv(crlData, cursor, end)[1];
                total++;
            }
            return Integer.toString(total);
        } catch (RuntimeException e) {
            return "at least " + (maxRevokedEntries + 1);
        }
    }

    /** Разбирает записи об отзыве; предел {@code rvEnd} — конец списка, не буфера. */
    private void parseRevokedEntries(int rvPos, int rvEnd, List<RevokedEntry> entries)
            throws PkixException {
        int revokedCount = 0;
        while (rvPos < rvEnd) {
            if (revokedCount >= maxRevokedEntries) {
                throw new PkixException(
                        PkixException.Reason.CRL_LIMIT_EXCEEDED,
                        "CRL revoked entries exceed maximum "
                                + maxRevokedEntries
                                + ", got "
                                + describeEntryCount(rvPos, rvEnd, revokedCount));
            }
            revokedCount++;
            if ((crlData[rvPos] & 0xFF) != TAG_SEQUENCE) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
            }
            int[] rcSeq = readTlv(crlData, rvPos, rvEnd);
            int rcPos = rcSeq[0];
            int rcEnd = rcSeq[1];

            // serialNumber INTEGER
            if (rcPos >= rcEnd || (crlData[rcPos] & 0xFF) != TAG_INTEGER) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "Failed to parse CRL revoked entries");
            }
            int[] serialTlv = readTlv(crlData, rcPos, rcEnd);
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

            // revocationDate Time. На статус не влияет, но проверяется так же строго, как остальные
            // даты: одно правило проще двух. Строка собирается из проверенных байт без Instant и
            // форматтера - это горячий путь на каждую запись.
            String revDate = null;
            if (rcPos < rcEnd) {
                int tag = crlData[rcPos] & 0xFF;
                if (tag == TAG_UTC_TIME || tag == TAG_GENERALIZED_TIME) {
                    int[] revTimeTlv = readTlv(crlData, rcPos, rcEnd);
                    boolean generalized = tag == TAG_GENERALIZED_TIME;
                    GostDerParser.parseTimeSeconds(
                            crlData, revTimeTlv[0], revTimeTlv[1] - revTimeTlv[0], generalized);
                    revDate =
                            GostDerParser.generalizedTimeString(
                                    crlData, revTimeTlv[0], generalized);
                    rcPos = revTimeTlv[1];
                }
            }

            // crlEntryExtensions SEQUENCE OPTIONAL: занимает остаток записи без хвоста.
            // Иной тег нельзя молча пропускать: под ним мог бы скрыться critical-признак.
            ReasonCode reason = null;
            if (rcPos < rcEnd) {
                if ((crlData[rcPos] & 0xFF) != TAG_SEQUENCE) {
                    throw parseError("CRL: unexpected field in revoked entry");
                }
                int[] extList = readTlv(crlData, rcPos, rcEnd);
                if (extList[1] != rcEnd) {
                    throw parseError("CRL: trailing data in revoked entry");
                }
                reason = parseEntryExtensions(extList[0], extList[1]);
            }

            entries.add(
                    new RevokedEntry(
                            serial,
                            revDate != null ? revDate : "19700101000000Z",
                            reason,
                            null,
                            null));

            rvPos = rcEnd;
        }
    }

    /**
     * Число отозванных записей без копирования списка.
     *
     * @throws IllegalStateException если {@link #verify(PublicKeyParameters)} не был вызван
     */
    int getRevokedCount() {
        Map<BigInteger, RevokedEntry> map = revokedMap;
        if (map == null) {
            throw new IllegalStateException("Call verify(PublicKeyParameters) first");
        }
        return map.size();
    }

    /** Длина DER без копирования массива. */
    int getEncodedLength() {
        return crlData.length;
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

    /** @return true если IDP содержит onlySomeReasons (partial CRL) */
    public boolean isOnlySomeReasons() {
        return idpOnlySomeReasons;
    }

    /** @return true если IDP содержит onlyContainsAttributeCerts */
    public boolean isOnlyContainsAttributeCerts() {
        return idpOnlyContainsAttributeCerts;
    }

    /** @return true если IDP содержит distributionPoint */
    public boolean isIdpDistributionPointPresent() {
        return idpDistributionPointPresent;
    }

    /** @return true если distributionPoint задан как nameRelativeToCRLIssuer */
    public boolean isIdpNameRelativeToCrlIssuer() {
        return idpNameRelativeToCrlIssuer;
    }

    /**
     * URI из distributionPoint.fullName.
     *
     * <p>Сопоставление с CDP сертификата в {@link CrlVerifier} выполняется точным
     * сравнением строк. Различие в регистре схемы/хоста или нормализации
     * URI даёт fail-closed отказ; это осознанное ограничение, а не ошибка
     * разбора.</p>
     *
     * @return массив URI или null, если distributionPoint отсутствует/не содержит URI
     */
    public String[] getIdpDistributionPointUris() {
        return idpDistributionPointUris != null ? idpDistributionPointUris.clone() : null;
    }

    /**
     * Байты extnValue расширения IssuingDistributionPoint для побайтного сравнения IDP base и
     * delta CRL (RFC 5280 §6.3.3(c)). Пакетный доступ: наружу не нужен.
     *
     * @return копия extnValue или null, если IDP нет
     */
    byte[] getIdpExtnValue() {
        return idpExtnValue != null ? idpExtnValue.clone() : null;
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

    // Индексы результата readExtension
    private static final int EXT_OID_START = 0;
    private static final int EXT_OID_END = 1;
    private static final int EXT_CRITICAL = 2;
    private static final int EXT_VALUE_START = 3;
    private static final int EXT_VALUE_END = 4;
    private static final int EXT_NEXT = 5;

    // [0] EXPLICIT crlExtensions в TBSCertList (RFC 5280 §5.1.2.7)
    private static final int TAG_CTX_EXTENSIONS = 0xA0;

    // Теги полей IssuingDistributionPoint (RFC 5280 §5.2.5, IMPLICIT TAGS)
    private static final int TAG_IDP_DISTRIBUTION_POINT = 0xA0;
    private static final int TAG_IDP_ONLY_USER_CERTS = 0x81;
    private static final int TAG_IDP_ONLY_CA_CERTS = 0x82;
    private static final int TAG_IDP_ONLY_SOME_REASONS = 0x83;
    private static final int TAG_IDP_INDIRECT_CRL = 0x84;
    private static final int TAG_IDP_ONLY_ATTRIBUTE_CERTS = 0x85;
    // Constructed-варианты (EXPLICIT BOOLEAN): терпимость к кодировщикам, отличным от канона
    private static final int TAG_IDP_ONLY_USER_CERTS_EXPLICIT = 0xA1;
    private static final int TAG_IDP_ONLY_CA_CERTS_EXPLICIT = 0xA2;
    private static final int TAG_IDP_INDIRECT_CRL_EXPLICIT = 0xA4;

    // Теги AuthorityKeyIdentifier (RFC 5280 §4.2.1.1)
    private static final int TAG_AKI_KEY_IDENTIFIER = 0x80;
    private static final int TAG_AKI_CERT_ISSUER = 0xA1;
    private static final int TAG_AKI_CERT_SERIAL = 0x82;

    // Номер поля — младшие 5 бит тега контекстного класса: порядок полей SEQUENCE
    private static final int TAG_NUMBER_MASK = 0x1F;

    private static PkixException parseError(String message) {
        return new PkixException(PkixException.Reason.PARSE_ERROR, message);
    }

    /**
     * Читает одно {@code Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }}.
     *
     * <p>Все чтения ограничены {@code limit} (пределом блока, не буфера): расширение не может
     * «съесть» байты соседей или подписи. Нарушение формы — {@link IllegalArgumentException}.</p>
     *
     * @return {oidStart, oidEnd, critical(0/1), valueStart, valueEnd, nextPos}, где value —
     *         содержимое OCTET STRING extnValue (внутренний DER)
     */
    private static int[] readExtension(byte[] der, int pos, int limit) {
        if (pos >= limit || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("CRL: Extension must be SEQUENCE");
        }
        int[] ext = readTlv(der, pos, limit);
        int q = ext[0];
        int end = ext[1];
        if (q >= end || (der[q] & 0xFF) != TAG_OID) {
            throw new IllegalArgumentException("CRL: Extension without OID");
        }
        int[] oid = readTlv(der, q, end);
        q = oid[1];
        boolean critical = false;
        if (q < end && (der[q] & 0xFF) == TAG_BOOLEAN) {
            critical = readBoolean(der, q, end);
            q = readTlv(der, q, end)[1];
        }
        if (q >= end || (der[q] & 0xFF) != TAG_OCTET_STRING) {
            throw new IllegalArgumentException("CRL: Extension without extnValue");
        }
        int[] value = readTlv(der, q, end);
        if (value[1] != end) {
            throw new IllegalArgumentException("CRL: trailing data in Extension");
        }
        return new int[] {oid[0], oid[1], critical ? 1 : 0, value[0], value[1], ext[1]};
    }

    /**
     * Есть ли среди расширений блока {@code [blockStart, currentExtStart)} расширение с тем же
     * OID. Повтор расширения запрещён RFC 5280 и даёт расхождение разборщиков; проверка идёт
     * повторным просмотром без коллекций (на записи приходятся единицы расширений, число
     * ограничено {@link GostOids#MAX_CRL_ENTRY_EXTENSIONS} и {@link GostOids#MAX_CRL_EXTENSIONS}).
     */
    private static boolean oidSeenBefore(
            byte[] der, int blockStart, int currentExtStart, int oidStart, int oidEnd) {
        int p = blockStart;
        while (p < currentExtStart) {
            int[] ext = readTlv(der, p, currentExtStart);
            int[] oid = readTlv(der, ext[0], ext[1]);
            if (arrayRangeEquals(der, oid[0], oid[1] - oid[0], der, oidStart, oidEnd - oidStart)) {
                return true;
            }
            p = ext[1];
        }
        return false;
    }

    /**
     * Парсит расширения уровня CRL: форма каждого расширения проверяется, дубликаты и
     * неизвестные critical-расширения отвергаются (RFC 5280 §5.2).
     *
     * @param blockStart начало содержимого {@code [0] EXPLICIT crlExtensions}
     * @param blockEnd   конец этого содержимого
     * @param allowDelta true — не бросать исключение для deltaCRLIndicator
     */
    private void parseCrlExtensions(byte[] der, int blockStart, int blockEnd, boolean allowDelta)
            throws PkixException {
        if (blockStart >= blockEnd || (der[blockStart] & 0xFF) != TAG_SEQUENCE) {
            throw parseError("CRL: crlExtensions must be SEQUENCE");
        }
        int[] list = readTlv(der, blockStart, blockEnd);
        if (list[1] != blockEnd) {
            throw parseError("CRL: trailing data in crlExtensions");
        }
        int pos = list[0];
        int end = list[1];
        int count = 0;
        while (pos < end) {
            if (++count > GostOids.MAX_CRL_EXTENSIONS) {
                throw parseError("CRL: too many extensions");
            }
            int[] ext = readExtension(der, pos, end);
            int oidStart = ext[EXT_OID_START];
            int oidLen = ext[EXT_OID_END] - oidStart;
            if (oidSeenBefore(der, list[0], pos, oidStart, ext[EXT_OID_END])) {
                throw parseError("CRL: duplicate extension");
            }
            boolean critical = ext[EXT_CRITICAL] != 0;
            int valueStart = ext[EXT_VALUE_START];
            int valueEnd = ext[EXT_VALUE_END];

            if (matchesOid(der, oidStart, oidLen, IDP_OID_BYTES)) {
                parseIdpExtension(der, valueStart, valueEnd);
            } else if (matchesOid(der, oidStart, oidLen, DELTA_CRL_INDICATOR_OID_BYTES)) {
                this.baseCrlNumber = parseExtensionInteger(der, valueStart, valueEnd);
                if (!allowDelta) {
                    throw new PkixException(
                            PkixException.Reason.DELTA_CRL_NOT_SUPPORTED,
                            "CRL: delta CRL not supported (deltaCRLIndicator present)");
                }
            } else if (matchesOid(der, oidStart, oidLen, AKI_OID_BYTES)) {
                parseAkiExtension(der, valueStart, valueEnd);
            } else if (matchesOid(der, oidStart, oidLen, CRL_NUMBER_OID_BYTES)) {
                this.crlNumber = parseExtensionInteger(der, valueStart, valueEnd);
            } else if (critical) {
                // Неизвестное critical-расширение, а также критический freshestCRL: проверяющий
                // его не исполняет, а RFC 5280 §5.2.6 требует для него non-critical.
                throw new PkixException(
                        PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                        "CRL: unsupported critical extension");
            } else if (matchesOid(der, oidStart, oidLen, FRESHEST_CRL_OID_BYTES)) {
                parseFreshestCrlExtension(der, valueStart, valueEnd);
            }
            pos = ext[EXT_NEXT];
        }
    }

    /**
     * Парсит расширения записи об отзыве (RFC 5280 §5.3) и возвращает reasonCode.
     *
     * @param start начало содержимого SEQUENCE расширений записи
     * @param end   конец этого содержимого (предел записи)
     */
    private ReasonCode parseEntryExtensions(int start, int end) throws PkixException {
        ReasonCode reason = null;
        int count = 0;
        int pos = start;
        while (pos < end) {
            if (++count > GostOids.MAX_CRL_ENTRY_EXTENSIONS) {
                throw parseError("CRL: too many entry extensions");
            }
            int[] ext = readExtension(crlData, pos, end);
            int oidStart = ext[EXT_OID_START];
            int oidLen = ext[EXT_OID_END] - oidStart;
            if (oidSeenBefore(crlData, start, pos, oidStart, ext[EXT_OID_END])) {
                throw parseError("CRL: duplicate entry extension");
            }
            // certificateIssuer — признак indirect CRL. Проверяется раньше правила
            // «critical и не reasonCode»: по RFC 5280 §5.3.3 оно всегда critical, и причина
            // отказа — неподдерживаемый indirect CRL, а не «неизвестное расширение».
            if (matchesOid(crlData, oidStart, oidLen, CERTIFICATE_ISSUER_OID_BYTES)) {
                throw new PkixException(
                        PkixException.Reason.IDP_NOT_SUPPORTED,
                        "CRL: certificateIssuer entry extension (indirect CRL) not supported");
            }
            if (matchesOid(crlData, oidStart, oidLen, CRL_REASON_OID_BYTES)) {
                reason = parseReasonCode(ext[EXT_VALUE_START], ext[EXT_VALUE_END]);
            } else if (ext[EXT_CRITICAL] != 0) {
                throw new PkixException(
                        PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION,
                        "CRL: unsupported critical entry extension");
            }
            pos = ext[EXT_NEXT];
        }
        return reason;
    }

    /**
     * reasonCode ::= ENUMERATED из одного октета (RFC 5280 §5.3.1). Неизвестное числовое
     * значение трактуется как «причина не указана»: запись всё равно считается отозванной,
     * это безопасно.
     */
    private ReasonCode parseReasonCode(int pos, int end) throws PkixException {
        if (pos >= end || (crlData[pos] & 0xFF) != TAG_ENUMERATED) {
            throw parseError("CRL: reasonCode must be ENUMERATED");
        }
        int[] enumTlv = readTlv(crlData, pos, end);
        if (enumTlv[1] != end || enumTlv[1] - enumTlv[0] != 1) {
            throw parseError("CRL: reasonCode must be a single octet");
        }
        int code = crlData[enumTlv[0]] & 0xFF;
        ReasonCode reason = ReasonCode.fromValue(code);
        if (reason == null) {
            LOG.log(Level.DEBUG, "CRL: unknown reasonCode {0}, treating as absent", code);
        }
        return reason;
    }

    /**
     * Парсит IssuingDistributionPoint (RFC 5280 §5.2.5).
     *
     * <p>Извлекает флаги: onlyContainsUserCerts, onlyContainsCACerts,
     * onlySomeReasons, indirectCRL, onlyContainsAttributeCerts и
     * distributionPoint. Область применяет {@link CrlVerifier}; сам разбор только
     * строго извлекает поля.
     *
     * <p>Поля идут в строго возрастающем порядке номера (так исключаются повторы);
     * порядок сравнивается по номеру поля, а не по байту тега: {@code A0} (поле [0]) обязан
     * предшествовать {@code 81} (поле [1]), хотя {@code 0xA0 > 0x81}. Неизвестный тег, повтор,
     * хвост и BOOLEAN не из одного октета 0x00/0xFF — {@link IllegalArgumentException}
     * (превращается в {@code PARSE_ERROR}).
     *
     * @param der   DER-поток CRL
     * @param pos   начало extnValue (внутренний DER)
     * @param end   конец extnValue
     */
    private void parseIdpExtension(byte[] der, int pos, int end) throws PkixException {
        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            throw parseError("CRL: IssuingDistributionPoint must be SEQUENCE");
        }
        int[] idpSeq = readTlv(der, pos, end);
        if (idpSeq[1] != end) {
            throw parseError("CRL: trailing data in IssuingDistributionPoint");
        }
        int p = idpSeq[0];
        int pe = idpSeq[1];

        boolean onlyContainsUserCerts = false;
        boolean onlyContainsCACerts = false;
        boolean onlySomeReasons = false;
        boolean indirectCRL = false;
        boolean onlyContainsAttributeCerts = false;
        boolean distributionPointPresent = false;
        boolean nameRelativeToCrlIssuer = false;
        boolean explicitBoolean = false;
        String[] distributionPointUris = null;

        int previousNumber = -1;
        while (p < pe) {
            int tag = der[p] & 0xFF;
            int number = tag & TAG_NUMBER_MASK;
            if (number <= previousNumber) {
                throw parseError("CRL: IssuingDistributionPoint fields out of order or repeated");
            }
            previousNumber = number;
            int[] field = readTlv(der, p, pe);
            switch (tag) {
                case TAG_IDP_DISTRIBUTION_POINT -> {
                    distributionPointPresent = true;
                    IdpDistributionPoint dp = parseIdpDistributionPoint(der, field[0], field[1]);
                    nameRelativeToCrlIssuer = dp.nameRelativeToCrlIssuer();
                    distributionPointUris = dp.uris();
                }
                case TAG_IDP_ONLY_USER_CERTS ->
                        onlyContainsUserCerts = implicitIdpBoolean(der, field);
                case TAG_IDP_ONLY_USER_CERTS_EXPLICIT -> {
                    onlyContainsUserCerts = explicitIdpBoolean(der, field);
                    explicitBoolean = true;
                }
                case TAG_IDP_ONLY_CA_CERTS -> onlyContainsCACerts = implicitIdpBoolean(der, field);
                case TAG_IDP_ONLY_CA_CERTS_EXPLICIT -> {
                    onlyContainsCACerts = explicitIdpBoolean(der, field);
                    explicitBoolean = true;
                }
                case TAG_IDP_ONLY_SOME_REASONS -> onlySomeReasons = true;
                case TAG_IDP_INDIRECT_CRL -> indirectCRL = implicitIdpBoolean(der, field);
                case TAG_IDP_INDIRECT_CRL_EXPLICIT -> {
                    indirectCRL = explicitIdpBoolean(der, field);
                    explicitBoolean = true;
                }
                // Наличие поля трактуем как true: даже FALSE-кодировка даёт fail-closed отказ,
                // что безопаснее попытки угадать семантику partial-флага.
                case TAG_IDP_ONLY_ATTRIBUTE_CERTS -> onlyContainsAttributeCerts = true;
                default -> throw parseError("CRL: unexpected IssuingDistributionPoint field");
            }
            p = field[1];
        }

        if (explicitBoolean) {
            // Терпимость к кодировщикам вне канона оставлена. Кодировку выбирает издатель CRL,
            // оператору нечего исправить, а CRL разбирается при каждой проверке: на DEBUG
            LOG.log(
                    Level.DEBUG,
                    "CRL: IssuingDistributionPoint uses non-canonical EXPLICIT BOOLEAN encoding");
        }

        this.idpPresent = true;
        this.idpOnlyContainsUserCerts = onlyContainsUserCerts;
        this.idpOnlyContainsCACerts = onlyContainsCACerts;
        this.idpOnlySomeReasons = onlySomeReasons;
        this.idpIndirectCrl = indirectCRL;
        this.idpOnlyContainsAttributeCerts = onlyContainsAttributeCerts;
        this.idpDistributionPointPresent = distributionPointPresent;
        this.idpNameRelativeToCrlIssuer = nameRelativeToCrlIssuer;
        this.idpDistributionPointUris = distributionPointUris;
        this.idpExtnValue = Arrays.copyOfRange(der, pos, end);

        if (indirectCRL) {
            throw new PkixException(
                    PkixException.Reason.IDP_NOT_SUPPORTED,
                    "CRL: indirect CRL (issuingDistributionPoint with indirectCRL) not supported");
        }
    }

    /**
     * Парсит DistributionPointName внутри issuingDistributionPoint.
     *
     * <p>Поддерживается только fullName с URI (GeneralName [6]). Остальные
     * варианты помечаются как непригодные для сопоставления; область их отклоняет,
     * чтобы partial scope не проверялся приблизительно. Допустимы только {@code A0}
     * (fullName) и {@code A1} (nameRelativeToCRLIssuer); любой иной тег — ошибка формы.</p>
     *
     * @param start начало содержимого поля [0] distributionPoint
     * @param end   конец этого содержимого
     */
    private IdpDistributionPoint parseIdpDistributionPoint(byte[] der, int start, int end) {
        if (start >= end) {
            throw new IllegalArgumentException("CRL: empty distributionPoint in IDP");
        }
        int tag = der[start] & 0xFF;
        int[] name = readTlv(der, start, end);
        if (name[1] != end) {
            throw new IllegalArgumentException("CRL: trailing data in distributionPoint");
        }
        if (tag == 0xA1) {
            return new IdpDistributionPoint(true, null);
        }
        if (tag != 0xA0) {
            throw new IllegalArgumentException("CRL: unexpected DistributionPointName tag");
        }
        List<String> uris = new ArrayList<>();
        int gp = name[0];
        int ge = name[1];
        while (gp < ge) {
            int gnTag = der[gp] & 0xFF;
            int[] gnTlv = readTlv(der, gp, ge);
            if (gnTag == 0x86) {
                uris.add(new String(der, gnTlv[0], gnTlv[1] - gnTlv[0], StandardCharsets.US_ASCII));
            }
            gp = gnTlv[1];
        }
        return new IdpDistributionPoint(false, uris.isEmpty() ? null : uris.toArray(String[]::new));
    }

    private record IdpDistributionPoint(boolean nameRelativeToCrlIssuer, String[] uris) {}

    /**
     * Парсит FreshestCRL (RFC 5280 §5.2.6): значение — SEQUENCE DistributionPoint. Структура
     * идентична CDP — переиспользует {@link GostExtensionParser#parseCdpUris}.
     *
     * @param pos начало extnValue (внутренний DER)
     * @param end конец extnValue
     */
    private void parseFreshestCrlExtension(byte[] der, int pos, int end) throws PkixException {
        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            throw parseError("CRL: FreshestCRL must be SEQUENCE");
        }
        if (readTlv(der, pos, end)[1] != end) {
            throw parseError("CRL: trailing data in FreshestCRL");
        }
        var uriList = new ArrayList<String>();
        GostExtensionParser.parseCdpUris(der, pos, end, uriList);
        if (!uriList.isEmpty()) {
            this.freshestCrlUris = uriList.toArray(String[]::new);
        }
    }

    /**
     * Парсит AuthorityKeyIdentifier (RFC 5280 §5.2.1). Извлекает keyIdentifier [0] IMPLICIT
     * (только каноничный {@code 0x80}); authorityCertIssuer [1] и authorityCertSerialNumber [2]
     * проверяются по форме и игнорируются. Поля идут в возрастающем порядке номера.
     *
     * @param pos начало extnValue (внутренний DER)
     * @param end конец extnValue
     */
    private void parseAkiExtension(byte[] der, int pos, int end) throws PkixException {
        if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
            throw parseError("CRL: AuthorityKeyIdentifier must be SEQUENCE");
        }
        int[] seq = readTlv(der, pos, end);
        if (seq[1] != end) {
            throw parseError("CRL: trailing data in AuthorityKeyIdentifier");
        }
        byte[] keyIdentifier = null;
        int previousNumber = -1;
        int p = seq[0];
        while (p < seq[1]) {
            int tag = der[p] & 0xFF;
            if (tag != TAG_AKI_KEY_IDENTIFIER
                    && tag != TAG_AKI_CERT_ISSUER
                    && tag != TAG_AKI_CERT_SERIAL) {
                throw parseError("CRL: unexpected AuthorityKeyIdentifier field");
            }
            int number = tag & TAG_NUMBER_MASK;
            if (number <= previousNumber) {
                throw parseError("CRL: AuthorityKeyIdentifier fields out of order or repeated");
            }
            previousNumber = number;
            int[] field = readTlv(der, p, seq[1]);
            if (tag == TAG_AKI_KEY_IDENTIFIER) {
                keyIdentifier = Arrays.copyOfRange(der, field[0], field[1]);
            }
            p = field[1];
        }
        this.akiBytes = keyIdentifier;
    }

    /** IMPLICIT BOOLEAN поля IDP: содержимое — ровно один октет 0x00 или 0xFF. */
    private static boolean implicitIdpBoolean(byte[] der, int[] field) {
        if (field[1] - field[0] != 1) {
            throw new IllegalArgumentException("CRL: IDP BOOLEAN must be a single octet");
        }
        return derBooleanValue(der[field[0]] & 0xFF);
    }

    /**
     * EXPLICIT BOOLEAN поля IDP (constructed {@code A1/A2/A4}): внутри ровно один BOOLEAN
     * 0x00/0xFF без хвоста.
     */
    private static boolean explicitIdpBoolean(byte[] der, int[] field) {
        if (field[0] >= field[1]) {
            throw new IllegalArgumentException("CRL: empty EXPLICIT BOOLEAN in IDP");
        }
        boolean value = readBoolean(der, field[0], field[1]);
        if (readTlv(der, field[0], field[1])[1] != field[1]) {
            throw new IllegalArgumentException("CRL: trailing data in EXPLICIT BOOLEAN in IDP");
        }
        return value;
    }

    private static boolean derBooleanValue(int octet) {
        if (octet == DER_BOOLEAN_TRUE) {
            return true;
        }
        if (octet == DER_BOOLEAN_FALSE) {
            return false;
        }
        throw new IllegalArgumentException("CRL: non-DER BOOLEAN value in IDP");
    }

    /**
     * Извлекает INTEGER из extnValue (внутренний DER) для cRLNumber и BaseCRLNumber.
     *
     * <p>RFC 5280 §5.2.3: значение неотрицательное, проверяющий обязан принимать до 20 октетов
     * величины. Лимит нужен, чтобы {@code new BigInteger} не аллоцировал до ≈maxSize на одно
     * вхождение. Кривое значение — {@code PARSE_ERROR}, а не «расширения нет»: иначе тихо
     * теряется защита от отката.
     */
    private static BigInteger parseExtensionInteger(byte[] der, int pos, int end)
            throws PkixException {
        if (pos >= end || (der[pos] & 0xFF) != TAG_INTEGER) {
            throw parseError("CRL: extension value must be INTEGER");
        }
        int[] intTlv = readTlv(der, pos, end);
        if (intTlv[1] != end) {
            throw parseError("CRL: trailing data in extension INTEGER");
        }
        int length = intTlv[1] - intTlv[0];
        if (length == 0) {
            throw parseError("CRL: empty extension INTEGER");
        }
        if ((der[intTlv[0]] & 0x80) != 0) {
            throw parseError("CRL: negative cRLNumber/BaseCRLNumber");
        }
        // Меряем величину, как у серийного номера: ведущий 0x00 знака не считается
        int magnitudeOctets = length;
        if (der[intTlv[0]] == 0x00) {
            magnitudeOctets--;
        }
        if (magnitudeOctets > GostOids.MAX_CRL_NUMBER_OCTETS) {
            throw parseError(
                    "CRL extension INTEGER exceeds " + GostOids.MAX_CRL_NUMBER_OCTETS + " octets");
        }
        return new BigInteger(Arrays.copyOfRange(der, intTlv[0], intTlv[1]));
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
                + GostDnParser.truncateForLog(issuerDnStr, GostCertificate.DN_LOG_MAX_CHARS)
                + ", version="
                + version
                + ", thisUpdate="
                + thisUpdate
                + "}";
    }
}
