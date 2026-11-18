package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Парсер OCSP-ответа (RFC 6960).
 *
 * <p>Разбирает DER-кодированный OCSP-ответ в структурированный объект.
 * Все структурные поля доступны сразу после конструктора. Делегированные
 * сертификаты responder'а также доступны без верификации — caller использует
 * их для проверки подписи (RFC 6960 §4.2.2.2).</p>
 *
 * <p>{@link #verify(PublicKeyParameters)} проверяет криптографическую подпись
 * и устанавливает флаг {@link #isSignatureVerified()}.</p>
 */
public final class GostOcspResponse {

    /**
     * Наибольший размер DER OCSP-ответа, который разбирается (256 КБ). Загрузчик по сети не должен
     * принимать ответ больше этого предела: разобрать его всё равно нельзя.
     */
    public static final int MAX_OCSP_RESPONSE_SIZE = 262_144;

    private static final int MAX_DELEGATED_CERTS = 5;
    private static final int MAX_SINGLE_RESPONSES = 256;

    // Значения OCSPResponseStatus (RFC 6960 §4.2.1); 4 не используется и допустимым не считается
    private static final int STATUS_SUCCESSFUL = 0;
    private static final int STATUS_MALFORMED_REQUEST = 1;
    private static final int STATUS_INTERNAL_ERROR = 2;
    private static final int STATUS_TRY_LATER = 3;
    private static final int STATUS_SIG_REQUIRED = 5;
    private static final int STATUS_UNAUTHORIZED = 6;

    /** Тип responder ID в ответе (RFC 6960 §4.1.1). */
    public enum ResponderIdType {
        BY_NAME,
        BY_KEY
    }

    private final int responseStatus;
    private final Instant producedAt;
    private final List<SingleOcspResponse> responses;
    private final byte[] tbsRaw;
    private final byte[] sigValue;
    private final List<byte[]> delegatedCertificates;
    private final byte[] nonce;
    private final ResponderIdType responderIdType;
    private final byte[] responderKeyHash;
    private final byte[] responderIdDer;
    private final byte[] encoded;
    private byte[] basicResponseDer;
    private volatile boolean signatureVerified;

    /**
     * Парсит OCSP-ответ из DER-байтов.
     *
     * @param der DER-кодированный OCSPResponse
     * @throws PkixException при структурной ошибке DER
     */
    public GostOcspResponse(byte[] der) throws PkixException {
        if (der == null || der.length == 0) {
            throw new PkixException("OCSP response must not be null or empty");
        }
        if (der.length > MAX_OCSP_RESPONSE_SIZE) {
            throw new PkixException(
                    "OCSP response DER exceeds maximum size "
                            + MAX_OCSP_RESPONSE_SIZE
                            + ", got "
                            + der.length);
        }

        this.encoded = der.clone();

        try {
            // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes }
            int[] ocspSeq = parseSequence(der, 0);
            int pos = ocspSeq[0];
            int end = ocspSeq[1];

            // responseStatus ENUMERATED; читается с пределом конца OCSPResponse, иначе значение
            // могло бы лежать за границей охватывающей SEQUENCE
            if (pos >= end || (der[pos] & 0xFF) != TAG_ENUMERATED) {
                throw new PkixException("OCSP: expected ENUMERATED status");
            }
            int[] statusTlv = readTlv(der, pos, end);
            if (statusTlv[1] - statusTlv[0] > 1) {
                throw new PkixException(
                        "OCSP: ENUMERATED responseStatus too long ("
                                + (statusTlv[1] - statusTlv[0])
                                + " bytes), expected 1 byte per RFC 6960");
            }
            if (statusTlv[1] == statusTlv[0]) {
                throw new PkixException("OCSP: empty ENUMERATED responseStatus");
            }
            int statusVal = der[statusTlv[0]] & 0xFF;
            if (!isAllowedStatus(statusVal)) {
                throw new PkixException("OCSP: unsupported responseStatus " + statusVal);
            }
            this.responseStatus = statusVal;
            pos = statusTlv[1];

            if (statusVal != STATUS_SUCCESSFUL) {
                // responseBytes присутствует только в успешном ответе (RFC 6960 §4.2.1)
                if (pos != end) {
                    throw new PkixException(
                            "OCSP: responseBytes must be absent for non-successful status");
                }
                this.producedAt = null;
                this.responses = Collections.emptyList();
                this.tbsRaw = null;
                this.sigValue = null;
                this.delegatedCertificates = Collections.emptyList();
                this.nonce = null;
                this.responderIdType = null;
                this.responderKeyHash = null;
                this.responderIdDer = null;
                return;
            }

            // [0] EXPLICIT responseBytes
            if (pos >= end || (der[pos] & 0xFF) != DerCodec.TAG_CTX_CONSTRUCTED_0) {
                throw new PkixException("OCSP: expected [0] EXPLICIT responseBytes");
            }
            int[] rbExplTlv = readTlv(der, pos);
            pos = rbExplTlv[0];

            // ResponseBytes SEQUENCE { OID, OCTET STRING }
            int[] rbSeq = parseSequence(der, pos);
            int rbPos = rbSeq[0];
            int rbEnd = rbSeq[1];

            // OID id-pkix-ocsp-basic
            if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x06) {
                throw new PkixException("OCSP: expected OID");
            }
            int[] oidTlv = readTlv(der, rbPos);
            if (!matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0], OCSP_BASIC_OID_BYTES)) {
                throw new PkixException("OCSP: responseType is not id-pkix-ocsp-basic");
            }
            rbPos = oidTlv[1];

            // OCTET STRING -> BasicOCSPResponse
            if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x04) {
                throw new PkixException("OCSP: expected OCTET STRING");
            }
            int[] octTlv = readTlv(der, rbPos);
            this.basicResponseDer = Arrays.copyOfRange(der, octTlv[0], octTlv[1]);

            // BasicOCSPResponse SEQUENCE { tbsResponseData, sigAlg, sig, [0] certs }
            int[] basicSeq = parseSequence(der, octTlv[0]);
            int basicStart = basicSeq[0];
            int basicEnd = basicSeq[1];
            int bpPos = basicStart;

            // tbsResponseData — сохраняем для проверки подписи
            int[] tbsSeq = parseSequence(der, bpPos);
            this.tbsRaw = Arrays.copyOfRange(der, bpPos, tbsSeq[1]);
            bpPos = tbsSeq[1];

            // Парсим tbsResponseData
            int tbsPos = tbsSeq[0];
            int tbsEnd = tbsSeq[1];

            // version [0] EXPLICIT (опционально): допустима только v1 (RFC 6960 §4.2.2.3)
            tbsPos = skipOcspVersionV1(der, tbsPos, tbsEnd);

            // responderID: byName [1] или byKey [2] (RFC 6960 §4.1.1)
            if (tbsPos >= tbsEnd) {
                throw new PkixException("OCSP: expected responderID");
            }
            int savedResponderPos = tbsPos;
            int ridTag = der[tbsPos] & 0xFF;
            if (ridTag == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                // byName [1] — пропускаем, валидация DN не требуется
                tbsPos = readTlv(der, tbsPos)[1];
                this.responderIdType = ResponderIdType.BY_NAME;
                this.responderKeyHash = null;
            } else if (ridTag == DerCodec.TAG_CTX_CONSTRUCTED_2) {
                // byKey [2] EXPLICIT KeyHash, где KeyHash ::= OCTET STRING (RFC 6960 §4.1.1)
                int[] byKeyExpl = readTlv(der, tbsPos);
                int khPos = byKeyExpl[0];
                int khEnd = byKeyExpl[1];
                if (khPos >= khEnd || (der[khPos] & 0xFF) != DerCodec.TAG_OCTET_STRING) {
                    throw new PkixException("OCSP: expected OCTET STRING inside byKey responderID");
                }
                int[] keyHashTlv = readTlv(der, khPos);
                int khLen = keyHashTlv[1] - keyHashTlv[0];
                if (khLen < GostOids.SHA1_HASH_LEN || khLen > GostOids.STREEBOG_512_HASH_LEN) {
                    throw new PkixException("OCSP: responderKeyHash invalid length: " + khLen);
                }
                this.responderKeyHash = Arrays.copyOfRange(der, keyHashTlv[0], keyHashTlv[1]);
                this.responderIdType = ResponderIdType.BY_KEY;
                tbsPos = byKeyExpl[1];
            } else {
                throw new PkixException("OCSP: expected responderID (byName [1] or byKey [2])");
            }
            this.responderIdDer = Arrays.copyOfRange(der, savedResponderPos, tbsPos);

            // producedAt GeneralizedTime
            if (tbsPos >= tbsEnd || (der[tbsPos] & 0xFF) != 0x18) {
                throw new PkixException("OCSP: expected GeneralizedTime for producedAt");
            }
            try {
                this.producedAt = parseTime(der, tbsPos);
            } catch (IllegalArgumentException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "OCSP: malformed producedAt time", e);
            }
            tbsPos = readTlv(der, tbsPos)[1];

            // responses SEQUENCE OF SingleResponse
            if (tbsPos >= tbsEnd || (der[tbsPos] & 0xFF) != TAG_SEQUENCE) {
                throw new PkixException("OCSP: expected responses SEQUENCE");
            }
            int[] respSeq = parseSequence(der, tbsPos);
            int rpPos = respSeq[0];
            int respEnd = respSeq[1];

            List<SingleOcspResponse> parsedResponses = new ArrayList<>();
            int certIdHashLen = GostOids.STREEBOG_256_HASH_LEN;

            int responseCount = 0;
            while (rpPos < respEnd) {
                if (responseCount >= MAX_SINGLE_RESPONSES) {
                    throw new PkixException(
                            "Too many SingleResponse entries in OCSP response: " + responseCount);
                }
                int[] srSeq = parseSequence(der, rpPos);
                int[] certIdSeq = parseSequence(der, srSeq[0]);

                // CertID: hashAlgorithm SEQUENCE { OID, params }
                int cidPos = certIdSeq[0];
                int[] hashAlgSeq = parseSequence(der, cidPos);
                int haPos = hashAlgSeq[0];
                if (haPos >= hashAlgSeq[1] || (der[haPos] & 0xFF) != 0x06) {
                    throw new PkixException("OCSP: CertID hashAlgorithm OID missing");
                }
                int[] haOid = readTlv(der, haPos);
                boolean isStb256 =
                        matchesOid(der, haOid[0], haOid[1] - haOid[0], STREEBOG256_OID_BYTES);
                boolean isStb512 =
                        matchesOid(der, haOid[0], haOid[1] - haOid[0], STREEBOG512_OID_BYTES);
                if (!isStb256 && !isStb512) {
                    throw new PkixException(
                            "OCSP: CertID hashAlgorithm must be Streebog-256 or Streebog-512");
                }
                certIdHashLen =
                        isStb512 ? GostOids.STREEBOG_512_HASH_LEN : GostOids.STREEBOG_256_HASH_LEN;
                cidPos = hashAlgSeq[1];

                // issuerNameHash OCTET STRING
                int[] nameHashTlv = readTlv(der, cidPos);
                if (nameHashTlv[1] - nameHashTlv[0] != certIdHashLen) {
                    throw new PkixException(
                            "OCSP: issuerNameHash length mismatch for CertID hashAlgorithm");
                }
                byte[] issuerNameHash = Arrays.copyOfRange(der, nameHashTlv[0], nameHashTlv[1]);
                cidPos = nameHashTlv[1];

                // issuerKeyHash OCTET STRING
                int[] keyHashTlv = readTlv(der, cidPos);
                if (keyHashTlv[1] - keyHashTlv[0] != certIdHashLen) {
                    throw new PkixException(
                            "OCSP: issuerKeyHash length mismatch for CertID hashAlgorithm");
                }
                byte[] issuerKeyHash = Arrays.copyOfRange(der, keyHashTlv[0], keyHashTlv[1]);
                cidPos = keyHashTlv[1];

                // certSerialNumber INTEGER
                int[] cidSerialTlv = readTlv(der, cidPos);
                byte[] certIdSerial = Arrays.copyOfRange(der, cidSerialTlv[0], cidSerialTlv[1]);

                // certStatus
                int stPos = cidSerialTlv[1];
                if (stPos >= srSeq[1]) {
                    throw new PkixException("OCSP: certStatus missing");
                }
                int certStatusTag = der[stPos] & 0xFF;
                // RFC 6960 §2.2: good кодируется как [0] IMPLICIT NULL (длина строго 0).
                // Проверяем обе формы тега — primitive 0x80 и constructed 0xA0, которые
                // isGood() трактует как алиас: constructed good с непустым содержимым —
                // DER-malleability, отклоняем наравне с primitive.
                if ((certStatusTag == DerCodec.TAG_CTX_PRIMITIVE_0
                                || certStatusTag == DerCodec.TAG_CTX_CONSTRUCTED_0)
                        && (stPos + 1 >= srSeq[1] || der[stPos + 1] != 0x00)) {
                    throw new PkixException("OCSP: malformed good status");
                }
                stPos = readTlv(der, stPos)[1];

                // Пропускаем singleUpdateExtensions [0] EXPLICIT если есть
                int timePos = stPos;
                while (timePos < srSeq[1]) {
                    int tag = der[timePos] & 0xFF;
                    if (tag == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                        timePos = readTlv(der, timePos)[1];
                        continue;
                    }
                    if (tag == TAG_UTC_TIME || tag == TAG_GENERALIZED_TIME) {
                        break;
                    }
                    // Неизвестный тег — пропускаем TLV
                    timePos = readTlv(der, timePos)[1];
                }

                if (timePos >= srSeq[1]) {
                    throw new PkixException("OCSP: thisUpdate missing");
                }

                // thisUpdate
                Instant thisUpdate;
                try {
                    thisUpdate = parseTime(der, timePos);
                } catch (IllegalArgumentException e) {
                    throw new PkixException(
                            PkixException.Reason.PARSE_ERROR, "OCSP: malformed thisUpdate time", e);
                }
                timePos = readTlv(der, timePos)[1];

                // [0] EXPLICIT nextUpdate (опционально)
                Instant nextUpdate = null;
                if (timePos < srSeq[1] && (der[timePos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                    int[] nuExplTlv = readTlv(der, timePos);
                    if (nuExplTlv[0] < nuExplTlv[1]) {
                        try {
                            nextUpdate = parseTime(der, nuExplTlv[0]);
                        } catch (IllegalArgumentException e) {
                            throw new PkixException(
                                    PkixException.Reason.PARSE_ERROR,
                                    "OCSP: malformed nextUpdate time",
                                    e);
                        }
                    }
                }

                parsedResponses.add(
                        new SingleOcspResponse(
                                certIdSerial,
                                certStatusTag,
                                thisUpdate,
                                nextUpdate,
                                issuerNameHash,
                                issuerKeyHash));
                rpPos = srSeq[1];
                responseCount++;
            }
            this.responses = Collections.unmodifiableList(parsedResponses);

            // responseExtensions [1] EXPLICIT Extensions OPTIONAL — извлекаем nonce
            tbsPos = respSeq[1];
            byte[] parsedNonce = null;
            if (tbsPos < tbsEnd && (der[tbsPos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                int[] reExplTlv = readTlv(der, tbsPos);
                int[] reSeq = parseSequence(der, reExplTlv[0]);
                int rePos = reSeq[0];
                int reEnd = reSeq[1];
                while (rePos < reEnd) {
                    int[] extTlv = parseSequence(der, rePos);
                    int extContent = extTlv[0];
                    int extContentEnd = extTlv[1];
                    if (extContent < extContentEnd && (der[extContent] & 0xFF) == 0x06) {
                        int[] extOidTlv = readTlv(der, extContent);
                        if (matchesOid(
                                der,
                                extOidTlv[0],
                                extOidTlv[1] - extOidTlv[0],
                                OCSP_NONCE_OID_BYTES)) {
                            // Дубликат делает «верный» nonce неоднозначным — отклоняем
                            if (parsedNonce != null) {
                                throw new PkixException("OCSP response: duplicate nonce extension");
                            }
                            extContent = extOidTlv[1];
                            if (extContent < extContentEnd && (der[extContent] & 0xFF) == 0x01) {
                                extContent = readTlv(der, extContent)[1];
                            }
                            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x04) {
                                throw new PkixException(
                                        "OCSP response: nonce extension without extnValue"
                                                + " OCTET STRING");
                            }
                            int[] extnValueTlv = readTlv(der, extContent);
                            if (extnValueTlv[1] != extContentEnd) {
                                throw new PkixException(
                                        "OCSP response: trailing data after nonce extnValue");
                            }
                            parsedNonce =
                                    OcspNonceCodec.parseExtnValue(
                                            der, extnValueTlv[0], extnValueTlv[1]);
                        }
                    }
                    rePos = extTlv[1];
                }
            }
            this.nonce = parsedNonce;

            // signatureAlgorithm — пропускаем
            if (bpPos >= basicEnd || (der[bpPos] & 0xFF) != TAG_SEQUENCE) {
                throw new PkixException("OCSP: signatureAlgorithm missing");
            }
            int[] sigAlgTlv = readTlv(der, bpPos);
            bpPos = sigAlgTlv[1];

            // signature BIT STRING
            if (bpPos >= basicEnd || (der[bpPos] & 0xFF) != TAG_BIT_STRING) {
                throw new PkixException("OCSP: signature BIT STRING missing");
            }
            int[] sigBitTlv = readTlv(der, bpPos);
            if (sigBitTlv[1] <= sigBitTlv[0] + 1) {
                throw new PkixException("OCSP: signature BIT STRING too short");
            }
            this.sigValue = Arrays.copyOfRange(der, sigBitTlv[0] + 1, sigBitTlv[1]);
            bpPos = sigBitTlv[1];

            // certs [0] EXPLICIT SEQUENCE OF Certificate (опционально) — парсим сразу
            if (bpPos < basicEnd && (der[bpPos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                this.delegatedCertificates =
                        Collections.unmodifiableList(parseDelegatedCerts(der, bpPos));
            } else {
                this.delegatedCertificates = Collections.emptyList();
            }
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            throw new PkixException("Malformed OCSP response DER", e);
        }
    }

    private static boolean isAllowedStatus(int status) {
        return switch (status) {
            case STATUS_SUCCESSFUL,
                    STATUS_MALFORMED_REQUEST,
                    STATUS_INTERNAL_ERROR,
                    STATUS_TRY_LATER,
                    STATUS_SIG_REQUIRED,
                    STATUS_UNAUTHORIZED ->
                    true;
            default -> false;
        };
    }

    private static List<byte[]> parseDelegatedCerts(byte[] rawData, int certsPos)
            throws PkixException {
        int[] explTlv = readTlv(rawData, certsPos);
        int seqTagPos = explTlv[0];
        int[] seqTlv = readTlv(rawData, seqTagPos);
        int cpPos = seqTlv[0];
        int seqEnd = seqTlv[1];

        List<byte[]> result = new ArrayList<>();
        while (cpPos < seqEnd) {
            if (result.size() >= MAX_DELEGATED_CERTS) {
                throw new PkixException(
                        "Too many delegated OCSP responder certificates: " + result.size());
            }
            int[] certTlv = readTlv(rawData, cpPos);
            byte[] certDer = Arrays.copyOfRange(rawData, cpPos, certTlv[1]);
            result.add(certDer);
            cpPos = certTlv[1];
        }
        return result;
    }

    /**
     * Создаёт OCSP-ответ из DER-байтов.
     *
     * @param der DER-кодированный OCSPResponse
     * @return распарсенный OCSP-ответ
     */
    public static GostOcspResponse fromDer(byte[] der) throws PkixException {
        return new GostOcspResponse(der);
    }

    /**
     * Создаёт OCSP-ответ из PEM или DER-байтов с автоопределением формата.
     *
     * <p>Определяет формат по первому байту: {@code 0x30} = DER,
     * {@code 0x2D} = PEM (строка начинается с '-').
     *
     * @param data PEM или DER-байты OCSP-ответа
     * @return распарсенный OCSP-ответ
     * @throws PkixException при структурной ошибке DER
     */
    public static GostOcspResponse fromPemOrDer(byte[] data) throws PkixException {
        if (GostPemUtils.isPem(data)) {
            return new GostOcspResponse(GostPemUtils.pemToDer(data));
        }
        return new GostOcspResponse(data);
    }

    /**
     * @return полный DER-кодированный OCSPResponse (defensive copy)
     */
    /**
     * DER значения для revocation-values CAdES-X Long.
     *
     * <p>RFC 5126 §6.3.3 хранит {@code BasicOCSPResponse}, а не полный
     * {@code OCSPResponse}. Для ответов, разобранных из такого значения,
     * возвращается исходный BasicOCSPResponse; для остальных — полный
     * OCSPResponse.</p>
     */
    public byte[] getRevocationValueDer() {
        return basicResponseDer != null ? basicResponseDer.clone() : encoded.clone();
    }

    /**
     * Создаёт объект из BasicOCSPResponse, оборачивая его в OCSPResponse
     * со статусом successful для существующего парсера.
     */
    public static GostOcspResponse fromBasicResponse(byte[] basicDer) throws PkixException {
        if (basicDer == null || basicDer.length == 0) {
            throw new PkixException("BasicOCSPResponse must not be null or empty");
        }
        byte[] status = DerCodec.encodeTlv(0x0A, new byte[] {0x00});
        byte[] responseBytes =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.OCSP_BASIC),
                        DerCodec.encodeOctetString(basicDer));
        byte[] full =
                DerCodec.encodeSequence(
                        status, DerCodec.encodeContextConstructed(0, responseBytes));
        return new GostOcspResponse(full);
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    /**
     * Кодирует OCSP-ответ в PEM-формат (Base64 с заголовками).
     *
     * @return PEM-строка с заголовком {@code -----BEGIN OCSP RESPONSE-----}
     */
    public String toPem() {
        return GostPemUtils.toPem(encoded, "OCSP RESPONSE");
    }

    // ========================================================================
    // Всегда доступные геттеры
    // ========================================================================

    /** @return статус ответа (0 = успех, RFC 6960 §4.2.1) */
    public int getResponseStatus() {
        return responseStatus;
    }

    /** @return {@code true} если статус успешный */
    public boolean isSuccessful() {
        return responseStatus == STATUS_SUCCESSFUL;
    }

    /** @return дата создания ответа или {@code null} если статус не успешный */
    public Instant getProducedAt() {
        return producedAt;
    }

    /**
     * Возвращает nonce из responseExtensions OCSP-ответа (RFC 8954).
     *
     * <p>Это сырые байты значения {@code Nonce} (1..32 байта) без обёрток OCTET STRING.
     *
     * @return копия nonce или {@code null}, если nonce отсутствует в ответе
     */
    public byte[] getNonce() {
        return nonce != null ? nonce.clone() : null;
    }

    /**
     * Возвращает список SingleResponse из распарсенного, возможно ещё не
     * верифицированного, OCSP-ответа.
     *
     * <p><b>Контракт доверия:</b> статус в каждом {@link SingleOcspResponse}
     * ({@link SingleOcspResponse#isGood()}/{@link SingleOcspResponse#isRevoked()}/
     * {@link SingleOcspResponse#isUnknown()}) отражает лишь результат разбора DER и
     * не является доверенным до успешного вызова {@link #verify(PublicKeyParameters)}.
     * Перед принятием решения об отзыве вызывающий ОБЯЗАН сначала вызвать
     * {@code verify()}.</p>
     *
     * <p>В отличие от {@link GostCrl#getRevokedCertificates()}, здесь намеренно нет
     * guard'а на {@code signatureVerified}: parse/verify-разделение осознанное — метод
     * используется для инспекции распарсенного ответа независимо от проверки подписи
     * (interop и кросс-валидация с чужими реализациями, где GOST-подпись отсутствует
     * структурно).</p>
     *
     * @return неизменяемый список SingleResponse (статус не доверенный до verify())
     */
    public List<SingleOcspResponse> getResponses() {
        return responses;
    }

    /**
     * Извлекает nextUpdate из первого SingleResponse.
     *
     * @return дата следующего обновления или {@code null}
     */
    public Instant getNextUpdate() {
        if (responses.isEmpty()) return null;
        return responses.get(0).nextUpdate();
    }

    /**
     * Возвращает список DER-кодированных делегированных сертификатов responder'а
     * из поля certs BasicOCSPResponse (RFC 6960 §4.2.2.1).
     *
     * <p>Доступно до верификации: caller использует сертификаты для проверки
     * подписи OCSP-ответа (RFC 6960 §4.2.2.2).</p>
     *
     * @return список сертификатов (может быть пустым)
     */
    public List<byte[]> getDelegatedCertificates() {
        return delegatedCertificates;
    }

    /**
     * @return тип responder ID: {@link ResponderIdType#BY_NAME} или
     *         {@link ResponderIdType#BY_KEY}, или {@code null} если статус ответа не успешный
     */
    public ResponderIdType getResponderIdType() {
        return responderIdType;
    }

    /**
     * Возвращает хэш ключа responder'а, если responder ID — {@link ResponderIdType#BY_KEY}.
     *
     * <p>Хэш вычислен через Streebog (ГОСТ-конвенция). Non-GOST клиенты
     * не могут сопоставить это значение с сертификатом подписанта.
     * Для универсальной совместимости используйте byName.</p>
     *
     * @return копия хэша ключа или {@code null} если responder ID не byKey
     */
    public byte[] getResponderKeyHash() {
        return responderKeyHash != null ? responderKeyHash.clone() : null;
    }

    /**
     * Возвращает полный DER-кодированный ResponderID.
     *
     * <p>Байты включают EXPLICIT-тег (0xA1 for byName, 0xA2 for byKey)
     * и могут быть встроены в OcspIdentifier как есть.</p>
     *
     * @return копия сырого DER ResponderID, или {@code null} если статус не успешный
     */
    public byte[] getResponderIdDer() {
        return responderIdDer != null ? responderIdDer.clone() : null;
    }

    // ========================================================================
    // Верификация подписи
    // ========================================================================

    /**
     * Проверяет криптографическую подпись OCSP-ответа.
     *
     * @param caKey открытый ключ CA или делегированного responder'а
     * @throws PkixException если подпись невалидна
     */
    public void verify(PublicKeyParameters caKey) throws PkixException {
        if (caKey == null) {
            throw new IllegalArgumentException("caKey must not be null");
        }
        if (tbsRaw == null) {
            throw new PkixException("OCSP: cannot verify — response status is not successful");
        }

        int hlen = caKey.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(tbsRaw, hlen);

        // Длина подписи берётся из недоверенного DER: неверная длина даёт false, а не исключение
        boolean signatureValid = Signature.verifyHash(hash, sigValue, caKey);
        if (!signatureValid) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "OCSP: signature verification failed");
        }
        signatureVerified = true;
    }

    /**
     * @return {@code true} если подпись была успешно проверена
     */
    public boolean isSignatureVerified() {
        return signatureVerified;
    }
}
