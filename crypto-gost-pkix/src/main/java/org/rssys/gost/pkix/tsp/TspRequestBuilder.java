package org.rssys.gost.pkix.tsp;

import java.math.BigInteger;
import java.util.Objects;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель TimeStampReq (RFC 3161 §2.4.1).
 *
 * <pre>
 * TimeStampReq ::= SEQUENCE {
 *   version        INTEGER { v1(1) },
 *   messageImprint MessageImprint,
 *   reqPolicy      TSAPolicyId OPTIONAL,
 *   nonce          INTEGER OPTIONAL,
 *   certReq        BOOLEAN DEFAULT FALSE,
 *   extensions     [0] IMPLICIT Extensions OPTIONAL
 * }
 * </pre>
 */
public final class TspRequestBuilder {

    private byte[] messageImprintHash;
    private String messageImprintAlgOid;
    private String reqPolicy;
    private BigInteger nonce;
    private boolean certReq;
    private boolean nonceExplicitlySet;

    private TspRequestBuilder() {}

    public static TspRequestBuilder create() {
        return new TspRequestBuilder();
    }

    /**
     * Устанавливает MessageImprint — хэш данных, для которых запрашивается штамп.
     *
     * @param hash      хэш (32 или 64 байта для Стрибог)
     * @param hashAlgOid OID алгоритма хэширования (например, {@code 1.2.643.7.1.1.2.2})
     */
    public TspRequestBuilder messageImprint(byte[] hash, String hashAlgOid) {
        this.messageImprintHash = hash.clone();
        this.messageImprintAlgOid = Objects.requireNonNull(hashAlgOid);
        return this;
    }

    /** Устанавливает OID политики TSA (опционально). */
    public TspRequestBuilder reqPolicy(String oid) {
        this.reqPolicy = oid;
        return this;
    }

    /** Устанавливает nonce (опционально). Если не задан — авто-генерация в {@link #build()}.
     * Передача {@code null} отключает nonce в запросе (opt-out). */
    public TspRequestBuilder nonce(BigInteger nonce) {
        this.nonce = nonce;
        this.nonceExplicitlySet = true;
        return this;
    }

    /** Запрашивать сертификат TSA в ответе. */
    public TspRequestBuilder certReq(boolean certReq) {
        this.certReq = certReq;
        return this;
    }

    /**
     * Возвращает nonce — заданный явно через {@link #nonce(BigInteger)} или
     * авто-сгенерированный.
     *
     * @return nonce или {@code null} если nonce явно отключён через {@code nonce(null)}
     */
    public BigInteger getNonce() {
        if (nonce == null && !nonceExplicitlySet) {
            byte[] nonceBytes = new byte[8];
            CryptoRandom.INSTANCE.nextBytes(nonceBytes);
            nonce = new BigInteger(1, nonceBytes);
        }
        return nonce;
    }

    /**
     * Собирает TimeStampReq в DER.
     *
     * @return DER-байты TimeStampReq
     * @throws IllegalStateException если messageImprint не установлен
     */
    public byte[] build() {
        Objects.requireNonNull(messageImprintHash, "messageImprint must be set");
        Objects.requireNonNull(messageImprintAlgOid, "messageImprint hashAlgOid must be set");

        BigInteger effectiveNonce = getNonce();

        // version
        byte[] version = DerCodec.encodeInteger(1);

        // messageImprint: SEQUENCE { hashAlgorithm OID, hashedMessage OCTET STRING }
        byte[] hashAlgId =
                org.rssys.gost.pkix.cms.CmsAlgorithmIdentifier.encode(messageImprintAlgOid);
        byte[] hashedMessage = DerCodec.encodeOctetString(messageImprintHash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlgId, hashedMessage);

        // Собираем элементы
        java.util.List<byte[]> elements = new java.util.ArrayList<>();
        elements.add(version);
        elements.add(messageImprint);

        // reqPolicy OPTIONAL
        if (reqPolicy != null) {
            elements.add(DerCodec.encodeOid(reqPolicy));
        }

        // nonce
        if (effectiveNonce != null) {
            elements.add(DerCodec.encodeInteger(effectiveNonce));
        }

        // certReq DEFAULT FALSE — кодируем только при true (DER X.690 §11.5)
        if (certReq) {
            elements.add(DerCodec.encodeBoolean(true));
        }

        return DerCodec.encodeSequence(elements.toArray(new byte[0][]));
    }
}
