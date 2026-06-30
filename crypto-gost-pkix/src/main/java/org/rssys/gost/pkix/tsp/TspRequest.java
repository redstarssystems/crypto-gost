package org.rssys.gost.pkix.tsp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.util.DerCodec;

/**
 * Распарсенный запрос TimeStampReq (RFC 3161 §2.4.1).
 *
 * <p>Даёт серверу доступ ко всем полям запроса до принятия решения о выдаче штампа:
 * проверка политики, алгоритма хэширования, nonce.
 *
 * @param messageImprintHash  хэш, для которого запрашивается штамп
 * @param messageImprintAlgOid OID алгоритма хэширования
 * @param reqPolicy           OID запрошенной политики TSA (null — не указана)
 * @param nonce               nonce из запроса (null — не указан)
 * @param certReq             запрос сертификата TSA в ответе
 */
public record TspRequest(
        byte[] messageImprintHash,
        String messageImprintAlgOid,
        String reqPolicy,
        BigInteger nonce,
        boolean certReq) {

    /** Канонический конструктор — защитная копия messageImprintHash. */
    public TspRequest {
        messageImprintHash = messageImprintHash.clone();
    }

    /** Хэш, защитная копия. */
    @Override
    public byte[] messageImprintHash() {
        return messageImprintHash.clone();
    }

    /** Nonce и хэш не выводятся — не должны попадать в логи. */
    @Override
    public String toString() {
        return "TspRequest[messageImprintAlgOid="
                + messageImprintAlgOid
                + ", reqPolicy="
                + reqPolicy
                + ", certReq="
                + certReq
                + ", messageImprintHash=<"
                + messageImprintHash.length
                + " bytes>, nonce=<suppressed>]";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof TspRequest that)) return false;
        // messageImprintHash — клиентские данные, оба операнда известны вызывающему,
        // timing-атака неприменима; Arrays.equals здесь уместен
        return Arrays.equals(messageImprintHash, that.messageImprintHash)
                && Objects.equals(messageImprintAlgOid, that.messageImprintAlgOid)
                && Objects.equals(reqPolicy, that.reqPolicy)
                && Objects.equals(nonce, that.nonce)
                && certReq == that.certReq;
    }

    @Override
    public int hashCode() {
        int result =
                Objects.hash(messageImprintAlgOid, reqPolicy, nonce, certReq);
        result = 31 * result + Arrays.hashCode(messageImprintHash);
        return result;
    }

    /**
     * Создаёт TspRequest из DER-байтов TimeStampReq (RFC 3161 §2.4.1).
     *
     * @param tspRequestDer DER-байты TimeStampReq
     * @return распарсенный запрос
     * @throws PkixException при ошибке разбора
     */
    public static TspRequest fromDer(byte[] tspRequestDer) throws PkixException {
        Objects.requireNonNull(tspRequestDer, "tspRequestDer must not be null");

        byte[][] parts = DerCodec.parseSequenceContents(tspRequestDer, 0);
        if (parts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "TimeStampReq too short: expected version and messageImprint");
        }
        int idx = 0;

        // [0] version — пропускаем
        DerCodec.parseInteger(parts[idx++], 0);

        // [1] messageImprint: SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
        byte[][] miParts = DerCodec.parseSequenceContents(parts[idx++], 0);
        if (miParts.length < 2) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "messageImprint too short: expected hashAlgorithm and hashedMessage");
        }
        byte[][] hashAlgParts = DerCodec.parseSequenceContents(miParts[0], 0);
        if (hashAlgParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "messageImprint hashAlgorithm has no OID");
        }
        String hashAlgOid = DerCodec.parseOid(hashAlgParts[0], 0);
        byte[] hashedMessage = DerCodec.parseOctetString(miParts[1], 0);

        // [2] reqPolicy OID OPTIONAL
        String reqPolicy = null;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_OID) {
            reqPolicy = DerCodec.parseOid(parts[idx], 0);
            idx++;
        }

        // [3] nonce INTEGER OPTIONAL
        BigInteger nonce = null;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_INTEGER) {
            nonce = DerCodec.parseInteger(parts[idx], 0);
            idx++;
        }

        // [4] certReq BOOLEAN DEFAULT FALSE
        boolean certReq = false;
        if (idx < parts.length
                && parts[idx].length > 0
                && (parts[idx][0] & 0xFF) == DerCodec.TAG_BOOLEAN) {
            certReq = DerCodec.parseBoolean(parts[idx], 0);
        }

        return new TspRequest(hashedMessage, hashAlgOid, reqPolicy, nonce, certReq);
    }
}
