package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.CheckReturnValue;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Парсер PKCS#10 CertificationRequest (Certificate Signing Request, RFC 2986 §4.1).
 *
 * <p>Разбирает DER-кодированный CSR и предоставляет доступ к полям:
 * subject DN, SPKI (публичный ключ), OID алгоритма подписи, значение подписи.
 * Из атрибутов обрабатываются {@code extensionRequest} (1.2.840.113549.1.9.14, RFC 2985 §5.4.2)
 * и {@code challengePassword} (RFC 2985 §5.4.1); остальные доступны в сыром виде через
 * {@link #getAttributes()}.</p>
 *
 * <p><b>Строгий разбор.</b> Проверяется структура: блок {@code [0]} содержит подряд идущие
 * {@code Attribute SEQUENCE { OID, SET }} без внешнего SET, значения непусты, хвостов нет,
 * повтор OID (в том числе {@code extensionRequest}) отвергается. Порядок элементов
 * {@code SET OF} не проверяется: чужие кодировщики не всегда сортируют, а подпись покрывает
 * байты как есть. Ошибки — {@link IllegalArgumentException}.</p>
 *
 * <p>Симметричен {@link GostCsrBuilder}: тот строит CSR, этот — читает.</p>
 *
 * <p><b>Безопасность:</b> конструктор НЕ валидирует границы DER-массива.
 * На повреждённом или обрезанном DER может выбросить любое непроверяемое исключение
 * ({@link ArrayIndexOutOfBoundsException}, {@link IllegalArgumentException}).
 * Вызывающий код, обрабатывающий недоверенный DER, ОБЯЗАН оборачивать
 * вызов в {@code try/catch(RuntimeException)}.</p>
 *
 * @see GostCsrBuilder
 * @see GostCertificate
 * @see GostDerParser
 */
public final class GostCsrParser {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.GostCsrParser");

    // Длина отпечатка ключа в журнале, байт: 8 байт хэша достаточно, чтобы отличать запросы
    // друг от друга, а запись остаётся короткой; это идентификатор для поиска, не проверка
    private static final int LOG_FINGERPRINT_LEN = 8;

    private final byte[] certData;
    private final int tbsOff;
    private final int tbsLen;
    private final byte[] sigAlgOidBytes;
    private final int sigOff;
    private final int sigLen;

    // Поля, извлечённые из TBS
    private final int version;
    private final int subjectDnOff;
    private final int subjectDnLen;
    private final String subjectDnStr;
    private final GostDnParser.DnField[] subjectDnFields;
    private final PublicKeyParameters publicKey;
    // Границы SPKI в certData: нужны, чтобы при отказе проверки подписи посчитать отпечаток ключа
    private final int spkiStart;
    private final int spkiEnd;
    private final GostExtensionParser.ExtensionsResult extResult;
    private final List<CsrAttribute> attributes;

    /** Признак отсутствия атрибута challengePassword. */
    private static final int NO_PASSWORD = -1;

    private final int passwordTag;
    private final int passwordStart;
    private final int passwordEnd;

    /**
     * Парсит DER-закодированный PKCS#10 CertificationRequest.
     *
     * @param derEncoded полный CSR в DER-кодировке, не null
     * @throws IllegalArgumentException если {@code derEncoded == null}
     *         или обнаружен невалидный синтаксис
     * @throws RuntimeException на повреждённом DER — конкретный подкласс не специфицирован
     */
    public GostCsrParser(byte[] derEncoded) {
        if (derEncoded == null) {
            throw new IllegalArgumentException("CSR DER must not be null");
        }
        this.certData = derEncoded.clone();

        int[] outer = parseSequence(certData, 0);
        int certContentStart = outer[0];
        if (certContentStart >= outer[1]) {
            throw new IllegalArgumentException("Truncated DER encoding: empty CSR SEQUENCE");
        }

        // Три потомка верхнего уровня: CertificationRequestInfo, SignatureAlgorithm, SignatureValue
        int[] tbsTlv = readTlv(certData, certContentStart, outer[1]);
        this.tbsOff = certContentStart;
        this.tbsLen = tbsTlv[1] - certContentStart;

        // SignatureAlgorithm (SEQUENCE с OID)
        int[] sigAlgTlv = readTlv(certData, tbsTlv[1], outer[1]);
        if (sigAlgTlv[0] < sigAlgTlv[1] && (certData[sigAlgTlv[0]] & 0xFF) == TAG_OID) {
            int[] oidTlv = readTlv(certData, sigAlgTlv[0], sigAlgTlv[1]);
            this.sigAlgOidBytes = Arrays.copyOfRange(certData, oidTlv[0], oidTlv[1]);
        } else {
            this.sigAlgOidBytes = new byte[0];
        }

        // SignatureValue (BIT STRING)
        int sigTagOffset = sigAlgTlv[1];
        if (sigTagOffset >= outer[1]) {
            throw new IllegalArgumentException("Truncated DER encoding: missing signature");
        }
        if ((certData[sigTagOffset] & 0x1F) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("Expected BIT STRING for signature");
        }
        int[] sigValTlv = readTlv(certData, sigTagOffset, outer[1]);
        if (sigValTlv[1] <= sigValTlv[0]) {
            throw new IllegalArgumentException(
                    "Truncated DER encoding: empty BIT STRING for signature at offset "
                            + sigTagOffset);
        }
        int unusedBits = certData[sigValTlv[0]] & 0xFF;
        if (unusedBits != 0) {
            throw new IllegalArgumentException("Unsupported BIT STRING with unused bits");
        }
        this.sigOff = sigValTlv[0] + 1;
        this.sigLen = sigValTlv[1] - sigValTlv[0] - 1;

        // Разбор CertificationRequestInfo (TBS)
        int tbsPos = tbsTlv[0];
        int tbsEnd = tbsTlv[1];

        // version INTEGER
        if (tbsPos >= tbsEnd || (certData[tbsPos] & 0xFF) != TAG_INTEGER) {
            throw new IllegalArgumentException("Expected version INTEGER in CSR");
        }
        int[] verTlv = readTlv(certData, tbsPos, tbsEnd);
        if (verTlv[0] >= verTlv[1]) {
            throw new IllegalArgumentException("Empty version INTEGER in CSR");
        }
        this.version = certData[verTlv[0]] & 0xFF;
        tbsPos = verTlv[1];

        // subject DN SEQUENCE
        if (tbsPos >= tbsEnd || (certData[tbsPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Expected subject DN SEQUENCE in CSR");
        }
        int[] dnTlv = readTlv(certData, tbsPos, tbsEnd);
        this.subjectDnOff = tbsPos;
        this.subjectDnLen = dnTlv[1] - tbsPos;
        tbsPos = dnTlv[1];

        GostDnParser.DnParseResult dnResult =
                GostDnParser.parseDnString(certData, subjectDnOff, subjectDnLen);
        this.subjectDnStr = dnResult.dnString;
        this.subjectDnFields =
                dnResult.fields.isEmpty()
                        ? null
                        : dnResult.fields.toArray(new GostDnParser.DnField[0]);

        // SPKI SEQUENCE
        if (tbsPos >= tbsEnd || (certData[tbsPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Expected SPKI SEQUENCE in CSR");
        }
        int[] spkiTlv = readTlv(certData, tbsPos, tbsEnd);
        byte[] spkiDer = Arrays.copyOfRange(certData, tbsPos, spkiTlv[1]);
        this.publicKey = GostDerCodec.decodePublicKey(spkiDer);
        this.spkiStart = tbsPos;
        this.spkiEnd = spkiTlv[1];
        tbsPos = spkiTlv[1];

        // [0] IMPLICIT Attributes: тег SET замещён тегом [0] (RFC 2986, IMPLICIT TAGS), поэтому
        // содержимое — сразу последовательность Attribute SEQUENCE, без внешнего SET.
        GostExtensionParser.ExtensionsResult ext = GostExtensionParser.ExtensionsResult.empty();
        List<CsrAttribute> parsedAttributes = new ArrayList<>();
        int passwordTag = NO_PASSWORD;
        int passwordStart = 0;
        int passwordEnd = 0;
        if (tbsPos < tbsEnd) {
            if ((certData[tbsPos] & 0xFF) != TAG_CTX_0) {
                throw new IllegalArgumentException(
                        "Expected [0] attributes after SubjectPublicKeyInfo in CSR");
            }
            int[] attrTlv = readTlv(certData, tbsPos, tbsEnd);
            if (attrTlv[1] != tbsEnd) {
                throw new IllegalArgumentException(
                        "Trailing bytes after attributes in CertificationRequestInfo");
            }
            Set<String> seenOids = new HashSet<>();
            int attrPos = attrTlv[0];
            int attrEnd = attrTlv[1];
            while (attrPos < attrEnd) {
                // Внутренний SET (и любой не-SEQUENCE) здесь недопустим: это не Attribute
                if ((certData[attrPos] & 0xFF) != TAG_SEQUENCE) {
                    throw new IllegalArgumentException(
                            "Expected Attribute SEQUENCE inside CSR attributes");
                }
                int[] attrSeqTlv = readTlv(certData, attrPos, attrEnd);
                int attrContent = attrSeqTlv[0];
                int attrContentEnd = attrSeqTlv[1];

                if (attrContent >= attrContentEnd || (certData[attrContent] & 0xFF) != TAG_OID) {
                    throw new IllegalArgumentException("Expected OID at start of CSR attribute");
                }
                int[] oidTlv = readTlv(certData, attrContent, attrContentEnd);
                String oid = oidBytesToDottedString(certData, oidTlv[0], oidTlv[1] - oidTlv[0]);
                if (!seenOids.add(oid)) {
                    // Повтор означает, что проверяющий и выпускающий могут увидеть разные значения
                    throw new IllegalArgumentException("Duplicate CSR attribute: " + oid);
                }

                int setPos = oidTlv[1];
                if (setPos >= attrContentEnd || (certData[setPos] & 0xFF) != TAG_SET) {
                    throw new IllegalArgumentException(
                            "CSR attribute " + oid + " must contain a SET of values");
                }
                int[] setTlv = readTlv(certData, setPos, attrContentEnd);
                if (setTlv[1] != attrContentEnd) {
                    throw new IllegalArgumentException(
                            "Trailing bytes after values of CSR attribute " + oid);
                }
                if (setTlv[0] >= setTlv[1]) {
                    throw new IllegalArgumentException(
                            "CSR attribute " + oid + " must have at least one value");
                }
                // Порядок элементов SET OF сознательно не проверяется: чужие кодировщики не всегда
                // сортируют, подпись покрывает байты как есть, а отказ дал бы ложные отказы.
                List<byte[]> values = new ArrayList<>();
                List<int[]> valueBounds = new ArrayList<>();
                int valuePos = setTlv[0];
                while (valuePos < setTlv[1]) {
                    int[] valueTlv = readTlv(certData, valuePos, setTlv[1]);
                    values.add(Arrays.copyOfRange(certData, valuePos, valueTlv[1]));
                    valueBounds.add(new int[] {valuePos, valueTlv[0], valueTlv[1]});
                    valuePos = valueTlv[1];
                }

                if (matchesOid(
                        certData, oidTlv[0], oidTlv[1] - oidTlv[0], EXTENSION_REQUEST_OID_BYTES)) {
                    // extensionRequest: values SET { Extensions }. Повреждённая структура —
                    // не «нет расширений»: молча потерять запрошенные расширения нельзя.
                    if (valueBounds.size() != 1) {
                        throw new IllegalArgumentException(
                                "extensionRequest must contain exactly one Extensions value");
                    }
                    int extensionsStart = valueBounds.get(0)[0];
                    if ((certData[extensionsStart] & 0xFF) != TAG_SEQUENCE) {
                        throw new IllegalArgumentException(
                                "extensionRequest SET must contain Extensions SEQUENCE");
                    }
                    ext =
                            GostExtensionParser.parseExtensionsFromSequence(
                                    certData, extensionsStart, valueBounds.get(0)[2]);
                } else if (matchesOid(
                        certData, oidTlv[0], oidTlv[1] - oidTlv[0], CHALLENGE_PASSWORD_OID_BYTES)) {
                    // Пароль проверяется здесь, а не в геттере: CSR с некорректным паролем
                    // отвергается целиком (fail-closed), даже если пароль вызывающему не нужен.
                    if (valueBounds.size() != 1) {
                        throw new IllegalArgumentException(
                                "challengePassword must contain exactly one value");
                    }
                    int[] bounds = valueBounds.get(0);
                    passwordTag = certData[bounds[0]] & 0xFF;
                    passwordStart = bounds[1];
                    passwordEnd = bounds[2];
                    Arrays.fill(
                            ChallengePasswordCodec.decode(
                                    certData, passwordTag, passwordStart, passwordEnd),
                            '\0');
                }
                parsedAttributes.add(new CsrAttribute(oid, values.toArray(new byte[0][])));
                attrPos = attrSeqTlv[1];
            }
        }
        this.extResult = ext;
        this.attributes = Collections.unmodifiableList(parsedAttributes);
        this.passwordTag = passwordTag;
        this.passwordStart = passwordStart;
        this.passwordEnd = passwordEnd;
    }

    // ========================================================================
    // Фабрики
    // ========================================================================

    /**
     * Создаёт парсер из DER-байтов CSR.
     *
     * @param der DER-кодированный CSR
     * @return распарсенный CSR
     */
    public static GostCsrParser fromDer(byte[] der) {
        return new GostCsrParser(der);
    }

    /**
     * Создаёт парсер из PEM или DER-байтов CSR.
     * Автоопределение формата: если первый байт '-' — PEM, иначе DER.
     *
     * @param data PEM или DER-байты CSR
     * @return распарсенный CSR
     */
    public static GostCsrParser fromPemOrDer(byte[] data) {
        if (GostPemUtils.isPem(data)) {
            return new GostCsrParser(GostPemUtils.pemToDer(data));
        }
        return new GostCsrParser(data);
    }

    // ========================================================================
    // Чтение полей
    // ========================================================================

    /** @return версия CSR (0 = v1 по RFC 2986) */
    public int getVersion() {
        return version;
    }

    /**
     * @return Subject DN в формате "CN=..., O=..., C=..."
     *         или null если парсинг DN не удался
     */
    public String getSubjectDn() {
        return subjectDnStr;
    }

    /**
     * Возвращает сырые DER-байты subject DN из CSR.
     * Используется для байтово-точного переноса DN в сертификат
     * без потерь при перекодировке через строку
     * (смена типа ASN.1-строки, потеря multi-valued RDN, исключение на неизвестном OID).
     *
     * @return DER-кодированный DN (SEQUENCE OF RDN), не null
     */
    public byte[] getSubjectDnDer() {
        return Arrays.copyOfRange(certData, subjectDnOff, subjectDnOff + subjectDnLen);
    }

    /**
     * Возвращает все значения указанного OID-атрибута из Subject DN.
     *
     * @param oidDot OID в точечной нотации, например "2.5.4.3" для CN
     * @return массив значений (может быть пустым, но не null)
     */
    public String[] getSubjectDnField(String oidDot) {
        return GostDnParser.getDnField(subjectDnFields, oidDot);
    }

    /** @return открытый ключ из SPKI */
    public PublicKeyParameters getPublicKey() {
        return publicKey;
    }

    /**
     * @return OID алгоритма подписи в точечной нотации,
     *         или null если OID не удалось распарсить
     */
    public String getSignatureAlgorithmOid() {
        if (sigAlgOidBytes.length == 0) return null;
        return oidBytesToDottedString(sigAlgOidBytes, 0, sigAlgOidBytes.length);
    }

    /** @return значение подписи (без BIT STRING обёртки). Defensive copy. */
    public byte[] getSignatureValue() {
        byte[] result = new byte[sigLen];
        System.arraycopy(certData, sigOff, result, 0, sigLen);
        return result;
    }

    /** @return сырые DER-байты CertificationRequestInfo (TBS). Defensive copy. */
    public byte[] getTbsCertRequest() {
        byte[] result = new byte[tbsLen];
        System.arraycopy(certData, tbsOff, result, 0, tbsLen);
        return result;
    }

    /** @return полный DER-кодированный CSR. Defensive copy. */
    public byte[] getEncoded() {
        return certData.clone();
    }

    /** @return CSR в PEM-формате с заголовком CERTIFICATE REQUEST */
    public String toPem() {
        return GostPemUtils.toPem(certData, "CERTIFICATE REQUEST");
    }

    // ========================================================================
    // Расширения из extensionRequest
    // ========================================================================

    /**
     * Возвращает результат парсинга расширений из атрибута extensionRequest.
     *
     * <p><b>Граница доверия:</b> {@code extensionRequest} — просьба подписчика, не полномочие.
     * Оператор УЦ обязан валидировать запрошенные расширения перед копированием в
     * выпускаемый сертификат: проверка владения доменом для SAN, никогда не выдавать
     * {@code CA=TRUE} по запросу подписчика без осознанного процесса выпуска
     * подчинённого УЦ, проверка полномочий на запрошенные EKU. Автоматическое
     * копирование {@code getExtensions()} в {@link GostCertificateBuilder} без
     * валидации небезопасно.</p>
     *
     * <p>Результат - независимая копия: изменение возвращённых массивов не влияет на разобранный
     * объект и на проверку цепочки.</p>
     *
     * @return результат парсинга расширений из extensionRequest атрибута.
     *         {@link GostExtensionParser.ExtensionsResult#empty()} если атрибут отсутствует.
     */
    public GostExtensionParser.ExtensionsResult getExtensions() {
        return extResult.copy();
    }

    /** @return true если CSR содержит атрибут extensionRequest с хотя бы одним расширением */
    public boolean hasExtensions() {
        return !extResult.presentExtensionOids.isEmpty();
    }

    // ========================================================================
    // Атрибуты PKCS#10
    // ========================================================================

    /**
     * Возвращает все атрибуты CSR в порядке следования в запросе, включая {@code extensionRequest}.
     *
     * <p><b>Секрет:</b> среди атрибутов может быть {@code challengePassword} в сыром виде,
     * обращайтесь с ним как с секретом (новой утечки нет: пароль и так лежит в
     * {@link #getEncoded()}).</p>
     *
     * @return неизменяемый список, пустой если атрибутов нет
     */
    public List<CsrAttribute> getAttributes() {
        return attributes;
    }

    /**
     * Возвращает атрибут по OID.
     *
     * <p>Может вернуть {@code challengePassword} в сыром виде, см. {@link #getAttributes()}.</p>
     *
     * @param oid OID в точечной нотации
     * @return атрибут или пустой {@link Optional}, если его нет в CSR
     * @throws IllegalArgumentException если {@code oid} не является корректным OID
     */
    public Optional<CsrAttribute> getAttribute(String oid) {
        // Корректность OID проверяется сразу: опечатка не должна выглядеть как «атрибута нет».
        // Сравниваются кодировки, а не строки: "01.2" и "1.2" - один и тот же OID.
        byte[] wanted = DerCodec.encodeOid(oid);
        for (CsrAttribute attribute : attributes) {
            if (Arrays.equals(DerCodec.encodeOid(attribute.oid()), wanted)) {
                return Optional.of(attribute);
            }
        }
        return Optional.empty();
    }

    /**
     * Возвращает значение атрибута {@code challengePassword} (RFC 2985 §5.4.1).
     *
     * <p>Принимаются все альтернативы {@code DirectoryString}: UTF8String, PrintableString,
     * TeletexString (как ISO-8859-1), BMPString и UniversalString. Значение декодируется строго
     * сразу в {@code char[]}, без промежуточной {@link String}: её копию затереть нельзя. При
     * чтении алфавит PrintableString X.680 не проверяется (старые кодировщики кладут в него
     * произвольный ASCII), при записи в {@link GostCsrBuilder} проверяется строго.</p>
     *
     * <p>Правила проверяются в конструкторе: CSR с некорректным паролем (нет одного значения,
     * неверная кодировка, меньше 1 или больше 255 знаков либо байт, управляющие знаки)
     * отвергается целиком, даже если вызывающему пароль не нужен. Поэтому метод после
     * успешного разбора не бросает исключений. Каждый вызов декодирует заново и возвращает
     * свежий массив, секрет в разборщике не кэшируется.</p>
     *
     * <p>Возвращённый массив затирает вызывающий. Сам CSR ({@link #getEncoded()},
     * {@link #toPem()}) содержит пароль всегда. Серверу сравнивать значение нужно по
     * декодированной последовательности знаков, а не по байтам: разные кодировки одного
     * пароля иначе дадут ложный отказ.</p>
     *
     * @return пароль или пустой {@link Optional}, если атрибута нет
     */
    public Optional<char[]> getChallengePassword() {
        if (passwordTag == NO_PASSWORD) {
            return Optional.empty();
        }
        return Optional.of(
                ChallengePasswordCodec.decode(certData, passwordTag, passwordStart, passwordEnd));
    }

    // ========================================================================
    // Верификация подписи
    // ========================================================================

    /**
     * Верифицирует подпись CSR с использованием указанного ключа.
     *
     * <p>Хэширует TBS (CertificationRequestInfo), проверяет подпись.
     * Выбор хеш-функции (Streebog-256/512) — по {@code key.getParams().hlen}
     * через {@link GostSignatureHelper#doHash(byte[], int, int, int)}.</p>
     *
     * @param key открытый ключ для проверки подписи
     * @return true если подпись действительна
     */
    @CheckReturnValue
    public boolean verify(PublicKeyParameters key) {
        int hlen = key.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(certData, tbsOff, tbsLen, hlen);

        byte[] sigCopy = new byte[sigLen];
        System.arraycopy(certData, sigOff, sigCopy, 0, sigLen);
        // Подпись неверной длины - не валидная подпись: verifyHash возвращает false
        return Signature.verifyHash(hash, sigCopy, key);
    }

    /**
     * Проверяет proof-of-possession: верифицирует подпись CSR
     * собственным публичным ключом из SPKI.
     *
     * @return true если CSR подписан ключом из SPKI
     */
    @CheckReturnValue
    public boolean verifySelf() {
        boolean ok = verify(publicKey);
        if (!ok) {
            // В предупреждении отпечаток открытого ключа вместо DN: у запроса нет серийного
            // номера, а DN заявителя несёт персональные данные (ФИО, СНИЛС, ИНН), и WARNING
            // включён по умолчанию. Усечённый DN доступен на DEBUG
            LOG.log(
                    Level.WARNING,
                    "CSR proof-of-possession verification failed: publicKeyFingerprint={0}",
                    publicKeyFingerprint());
            if (LOG.isLoggable(Level.DEBUG)) {
                LOG.log(
                        Level.DEBUG,
                        "CSR proof-of-possession verification failed: subject={0}",
                        subjectDnStr != null
                                ? GostDnParser.truncateForLog(
                                        subjectDnStr, GostCertificate.DN_LOG_MAX_CHARS)
                                : "null");
            }
        }
        return ok;
    }

    /**
     * Короткий отпечаток открытого ключа запроса для журнала: первые {@link #LOG_FINGERPRINT_LEN}
     * байт Стрибога-256 от DER {@code SubjectPublicKeyInfo} в шестнадцатеричной записи.
     * Идентифицирует запрос без персональных данных.
     */
    private String publicKeyFingerprint() {
        byte[] spki = Arrays.copyOfRange(certData, spkiStart, spkiEnd);
        byte[] hash = Digest.digest256(spki);
        return CertificateTextFormatter.hex(Arrays.copyOf(hash, LOG_FINGERPRINT_LEN), false);
    }

    // ========================================================================
    // Identity (equals, hashCode, toString)
    // ========================================================================

    /**
     * Сравнивает CSR побайтово по DER-кодировке.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GostCsrParser that = (GostCsrParser) o;
        return Arrays.equals(certData, that.certData);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(certData);
    }

    @Override
    public String toString() {
        return "GostCsrParser{subject="
                + GostDnParser.truncateForLog(subjectDnStr, GostCertificate.DN_LOG_MAX_CHARS)
                + ", algorithm="
                + (publicKey.getParams().hlen * 8)
                + "bit}";
    }
}
