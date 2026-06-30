package org.rssys.gost.pkix.tsp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Данные TSTInfo (RFC 3161 §2.4.2) — информация из штампа времени.
 *
 * @param policyOid           OID политики TSA (обязательное)
 * @param messageImprintHash  хэш, для которого выдан штамп (обязательное)
 * @param messageImprintAlgOid OID алгоритма хэширования (обязательное)
 * @param serialNumber        серийный номер штампа (обязательное)
 * @param genTime             время генерации штампа, формат {@code YYYYMMDDHHMMSSZ}
 * @param accuracySeconds     точность в секундах (опционально)
 * @param accuracyMillis      точность в миллисекундах (опционально)
 * @param ordering            флаг упорядоченности (RFC 3161 §2.4.2, DEFAULT FALSE)
 * @param nonce               nonce из запроса (опционально)
 */
public record TstInfo(
        String policyOid,
        byte[] messageImprintHash,
        String messageImprintAlgOid,
        BigInteger serialNumber,
        String genTime,
        Integer accuracySeconds,
        Integer accuracyMillis,
        boolean ordering,
        BigInteger nonce) {

    /** Канонический конструктор — защитная копия messageImprintHash. */
    public TstInfo {
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
        return "TstInfo[policyOid="
                + policyOid
                + ", messageImprintAlgOid="
                + messageImprintAlgOid
                + ", serialNumber="
                + serialNumber
                + ", genTime="
                + genTime
                + ", accuracySeconds="
                + accuracySeconds
                + ", accuracyMillis="
                + accuracyMillis
                + ", ordering="
                + ordering
                + ", messageImprintHash=<"
                + messageImprintHash.length
                + " bytes>, nonce=<suppressed>]";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof TstInfo that)) return false;
        return Objects.equals(policyOid, that.policyOid)
                && Arrays.equals(messageImprintHash, that.messageImprintHash)
                && Objects.equals(messageImprintAlgOid, that.messageImprintAlgOid)
                && Objects.equals(serialNumber, that.serialNumber)
                && Objects.equals(genTime, that.genTime)
                && Objects.equals(accuracySeconds, that.accuracySeconds)
                && Objects.equals(accuracyMillis, that.accuracyMillis)
                && ordering == that.ordering
                && Objects.equals(nonce, that.nonce);
    }

    @Override
    public int hashCode() {
        int result =
                Objects.hash(
                        policyOid,
                        messageImprintAlgOid,
                        serialNumber,
                        genTime,
                        accuracySeconds,
                        accuracyMillis,
                        ordering,
                        nonce);
        result = 31 * result + Arrays.hashCode(messageImprintHash);
        return result;
    }
}
