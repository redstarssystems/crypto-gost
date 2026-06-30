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

    private static final int MAX_DELEGATED_CERTS = 5;

    private final int responseStatus;
    private final Instant producedAt;
    private final List<SingleOcspResponse> responses;
    private final byte[] tbsRaw;
    private final byte[] sigValue;
    private final List<byte[]> delegatedCertificates;
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

        // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes }
        int[] ocspSeq = parseSequence(der, 0);
        int pos = ocspSeq[0];
        int end = ocspSeq[1];

        // responseStatus ENUMERATED
        if (pos >= end || (der[pos] & 0xFF) != 0x0A) {
            throw new PkixException("OCSP: expected ENUMERATED status");
        }
        int[] statusTlv = readTlv(der, pos);
        int statusVal = 0;
        for (int i = statusTlv[0]; i < statusTlv[1]; i++) {
            statusVal = (statusVal << 8) | (der[i] & 0xFF);
        }
        this.responseStatus = statusVal;
        pos = statusTlv[1];

        if (statusVal != 0) {
            this.producedAt = null;
            this.responses = Collections.emptyList();
            this.tbsRaw = null;
            this.sigValue = null;
            this.delegatedCertificates = Collections.emptyList();
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

        // version [0] EXPLICIT (опционально)
        if (tbsPos < tbsEnd && (der[tbsPos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
            tbsPos = readTlv(der, tbsPos)[1];
        }

        // responderID: byName [1] или byKey [2]
        if (tbsPos >= tbsEnd) {
            throw new PkixException("OCSP: expected responderID");
        }
        int ridTag = der[tbsPos] & 0xFF;
        if (ridTag == DerCodec.TAG_CTX_CONSTRUCTED_0 || ridTag == DerCodec.TAG_CTX_CONSTRUCTED_1) {
            tbsPos = readTlv(der, tbsPos)[1];
        } else {
            throw new PkixException("OCSP: expected responderID");
        }

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

        while (rpPos < respEnd) {
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
            // RFC 6960 §2.2: good кодируется как [0] IMPLICIT NULL (длина строго 0)
            if (certStatusTag == DerCodec.TAG_CTX_PRIMITIVE_0
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
        }
        this.responses = Collections.unmodifiableList(parsedResponses);

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

    // ========================================================================
    // Всегда доступные геттеры
    // ========================================================================

    /** @return статус ответа (0 = успех, RFC 6960 §4.2.1) */
    public int getResponseStatus() {
        return responseStatus;
    }

    /** @return {@code true} если статус успешный */
    public boolean isSuccessful() {
        return responseStatus == 0;
    }

    /** @return дата создания ответа или {@code null} если статус не успешный */
    public Instant getProducedAt() {
        return producedAt;
    }

    /** @return список SingleResponse (неизменяемый) */
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

        if (!Signature.verifyHash(hash, sigValue, caKey)) {
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
