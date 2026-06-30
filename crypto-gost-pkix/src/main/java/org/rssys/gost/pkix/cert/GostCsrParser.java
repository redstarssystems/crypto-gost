package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.util.Arrays;
import org.rssys.gost.api.Signature;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Парсер PKCS#10 CertificationRequest (Certificate Signing Request, RFC 2986 §4.1).
 *
 * <p>Разбирает DER-кодированный CSR и предоставляет доступ к полям:
 * subject DN, SPKI (публичный ключ), OID алгоритма подписи, значение подписи.
 * Из атрибутов распознаётся только {@code extensionRequest}
 * (1.2.840.113549.1.9.14, RFC 2985 §5.4.1) — остальные атрибуты
 * безопасно игнорируются.</p>
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

    private final byte[] certData;
    private final int tbsOff;
    private final int tbsLen;
    private final byte[] sigAlgOidBytes;
    private final int sigOff;
    private final int sigLen;

    // Поля, извлечённые из TBS
    private final int version;
    private final String subjectDnStr;
    private final GostDnParser.DnField[] subjectDnFields;
    private final PublicKeyParameters publicKey;
    private final GostExtensionParser.ExtensionsResult extResult;

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
        int[] tbsTlv = readTlv(certData, certContentStart);
        this.tbsOff = certContentStart;
        this.tbsLen = tbsTlv[1] - certContentStart;

        // SignatureAlgorithm (SEQUENCE с OID)
        int[] sigAlgTlv = readTlv(certData, tbsTlv[1]);
        if (sigAlgTlv[0] < sigAlgTlv[1] && (certData[sigAlgTlv[0]] & 0xFF) == TAG_OID) {
            int[] oidTlv = readTlv(certData, sigAlgTlv[0]);
            this.sigAlgOidBytes = Arrays.copyOfRange(certData, oidTlv[0], oidTlv[1]);
        } else {
            this.sigAlgOidBytes = new byte[0];
        }

        // SignatureValue (BIT STRING)
        int sigTagOffset = sigAlgTlv[1];
        if (sigTagOffset >= certData.length) {
            throw new IllegalArgumentException("Truncated DER encoding: missing signature");
        }
        if ((certData[sigTagOffset] & 0x1F) != TAG_BIT_STRING) {
            throw new IllegalArgumentException("Expected BIT STRING for signature");
        }
        int[] sigValTlv = readTlv(certData, sigTagOffset);
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
        int[] verTlv = readTlv(certData, tbsPos);
        if (verTlv[0] >= verTlv[1]) {
            throw new IllegalArgumentException("Empty version INTEGER in CSR");
        }
        this.version = certData[verTlv[0]] & 0xFF;
        tbsPos = verTlv[1];

        // subject DN SEQUENCE
        if (tbsPos >= tbsEnd || (certData[tbsPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Expected subject DN SEQUENCE in CSR");
        }
        int[] dnTlv = readTlv(certData, tbsPos);
        int dnOff = tbsPos;
        int dnLen = dnTlv[1] - tbsPos;
        tbsPos = dnTlv[1];

        GostDnParser.DnParseResult dnResult = GostDnParser.parseDnString(certData, dnOff, dnLen);
        this.subjectDnStr = dnResult.dnString;
        this.subjectDnFields =
                dnResult.fields.isEmpty()
                        ? null
                        : dnResult.fields.toArray(new GostDnParser.DnField[0]);

        // SPKI SEQUENCE
        if (tbsPos >= tbsEnd || (certData[tbsPos] & 0xFF) != TAG_SEQUENCE) {
            throw new IllegalArgumentException("Expected SPKI SEQUENCE in CSR");
        }
        int[] spkiTlv = readTlv(certData, tbsPos);
        byte[] spkiDer = Arrays.copyOfRange(certData, tbsPos, spkiTlv[1]);
        this.publicKey = GostDerCodec.decodePublicKey(spkiDer);
        tbsPos = spkiTlv[1];

        // [0] IMPLICIT Attributes — контент тега и есть SET OF Attribute
        GostExtensionParser.ExtensionsResult ext = GostExtensionParser.ExtensionsResult.empty();
        if (tbsPos < tbsEnd && (certData[tbsPos] & 0xFF) == TAG_CTX_0) {
            int[] attrTlv = readTlv(certData, tbsPos);
            int attrOuterValueStart = attrTlv[0];
            int attrOuterValueEnd = attrTlv[1];
            // [0] IMPLICIT: контент — SET OF Attribute
            int attrPos = attrOuterValueStart;
            int attrEnd = attrOuterValueEnd;
            if (attrPos < attrEnd && (certData[attrPos] & 0xFF) == TAG_SET) {
                int[] setTlv = readTlv(certData, attrPos);
                attrPos = setTlv[0];
                attrEnd = setTlv[1];
            }
            // Ищем extensionRequest среди атрибутов
            while (attrPos < attrEnd) {
                if ((certData[attrPos] & 0xFF) != TAG_SEQUENCE) {
                    attrPos = readTlv(certData, attrPos)[1];
                    continue;
                }
                int[] attrSeqTlv = readTlv(certData, attrPos);
                int attrContent = attrSeqTlv[0];
                int attrContentEnd = attrSeqTlv[1];

                // OID — первый элемент Attribute SEQUENCE
                if (attrContent >= attrContentEnd || (certData[attrContent] & 0xFF) != TAG_OID) {
                    attrPos = attrSeqTlv[1];
                    continue;
                }
                int[] oidTlv = readTlv(certData, attrContent);
                boolean isExtReq =
                        matchesOid(
                                certData,
                                oidTlv[0],
                                oidTlv[1] - oidTlv[0],
                                EXTENSION_REQUEST_OID_BYTES);

                // values SET — второй элемент Attribute SEQUENCE
                int afterOid = oidTlv[1];
                if (isExtReq && afterOid < attrContentEnd) {
                    int valTag = certData[afterOid] & 0xFF;
                    if (valTag == TAG_SET) {
                        int[] setTlv = readTlv(certData, afterOid);
                        int setPos = setTlv[0];
                        int setEnd = setTlv[1];
                        // Первый элемент SET — Extensions SEQUENCE
                        if (setPos < setEnd && (certData[setPos] & 0xFF) == TAG_SEQUENCE) {
                            ext = GostExtensionParser.parseExtensionsFromSequence(certData, setPos);
                        }
                    }
                }
                attrPos = attrSeqTlv[1];
            }
        }
        this.extResult = ext;
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
     * @return результат парсинга расширений из extensionRequest атрибута.
     *         {@link GostExtensionParser.ExtensionsResult#empty()} если атрибут отсутствует.
     */
    public GostExtensionParser.ExtensionsResult getExtensions() {
        return extResult;
    }

    /** @return true если CSR содержит атрибут extensionRequest с хотя бы одним расширением */
    public boolean hasExtensions() {
        return !extResult.presentExtensionOids.isEmpty();
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
    public boolean verify(PublicKeyParameters key) {
        int hlen = key.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(certData, tbsOff, tbsLen, hlen);

        byte[] sigCopy = new byte[sigLen];
        System.arraycopy(certData, sigOff, sigCopy, 0, sigLen);
        return Signature.verifyHash(hash, sigCopy, key);
    }

    /**
     * Проверяет proof-of-possession: верифицирует подпись CSR
     * собственным публичным ключом из SPKI.
     *
     * @return true если CSR подписан ключом из SPKI
     */
    public boolean verifySelf() {
        return verify(publicKey);
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
                + GostDnParser.truncateForLog(subjectDnStr, 128)
                + ", algorithm="
                + (publicKey.getParams().hlen * 8)
                + "bit}";
    }
}
