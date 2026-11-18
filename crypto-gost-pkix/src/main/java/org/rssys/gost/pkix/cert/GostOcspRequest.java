package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Парсер OCSP-запроса (RFC 6960 §4.1).
 *
 * <p>Разбирает DER-кодированный OCSPRequest в структурированный объект.
 * Извлекает список CertID, nonce (RFC 8954) и опциональную подпись (RFC 9215).
 */
public final class GostOcspRequest {

    private static final int MAX_OCSP_REQUEST_SIZE = 65_536;

    private final List<CertId> certIds;
    private final byte[] nonce;
    private final boolean signed;
    private final byte[] tbsRaw;
    private final byte[] sigValue;
    private final byte[] encoded;
    private volatile boolean signatureVerified;

    /**
     * Парсит OCSP-запрос из DER-байтов.
     *
     * @param der DER-кодированный OCSPRequest
     * @throws PkixException при структурной ошибке DER
     */
    public GostOcspRequest(byte[] der) throws PkixException {
        if (der == null || der.length == 0) {
            throw new PkixException("OCSP request must not be null or empty");
        }
        if (der.length > MAX_OCSP_REQUEST_SIZE) {
            throw new PkixException(
                    "OCSP request DER exceeds maximum size "
                            + MAX_OCSP_REQUEST_SIZE
                            + ", got "
                            + der.length);
        }

        this.encoded = der.clone();

        try {
            // OCSPRequest ::= SEQUENCE { TBSRequest, optionalSignature [0] EXPLICIT OPTIONAL }
            int[] ocspSeq = parseSequence(der, 0);
            int pos = ocspSeq[0];
            int end = ocspSeq[1];

            // TBSRequest
            if (pos >= end || (der[pos] & 0xFF) != TAG_SEQUENCE) {
                throw new PkixException("OCSP request: expected TBSRequest SEQUENCE");
            }
            int[] tbsSeq = parseSequence(der, pos);
            this.tbsRaw = Arrays.copyOfRange(der, pos, tbsSeq[1]);
            pos = tbsSeq[1];

            // optionalSignature [0] EXPLICIT
            if (pos < end && (der[pos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
                this.signed = true;
                int[] optSigTlv = readTlv(der, pos);
                int[] sigSeq = parseSequence(der, optSigTlv[0]);
                int sigPos = sigSeq[0];
                // signatureAlgorithm SEQUENCE — пропускаем
                sigPos = readTlv(der, sigPos)[1];
                // signature BIT STRING
                if (sigPos >= sigSeq[1] || (der[sigPos] & 0xFF) != TAG_BIT_STRING) {
                    throw new PkixException("OCSP request: signature BIT STRING missing");
                }
                int[] sigBitTlv = readTlv(der, sigPos);
                if (sigBitTlv[1] <= sigBitTlv[0] + 1) {
                    throw new PkixException("OCSP request: signature BIT STRING too short");
                }
                this.sigValue = Arrays.copyOfRange(der, sigBitTlv[0] + 1, sigBitTlv[1]);
            } else {
                this.signed = false;
                this.sigValue = null;
            }

            // Парсим TBSRequest
            int tbsPos = tbsSeq[0];
            int tbsEnd = tbsSeq[1];

            // version [0] EXPLICIT (опционально): допустима только v1 (RFC 6960 §4.1.1)
            tbsPos = skipOcspVersionV1(der, tbsPos, tbsEnd);

            // requestorName [1] EXPLICIT (опционально, пропускаем)
            if (tbsPos < tbsEnd && (der[tbsPos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                tbsPos = readTlv(der, tbsPos)[1];
            }

            // requestList SEQUENCE OF Request
            if (tbsPos >= tbsEnd || (der[tbsPos] & 0xFF) != TAG_SEQUENCE) {
                throw new PkixException("OCSP request: expected requestList SEQUENCE");
            }
            int[] reqListSeq = parseSequence(der, tbsPos);
            int rlPos = reqListSeq[0];
            int rlEnd = reqListSeq[1];

            List<CertId> parsedCertIds = new ArrayList<>();
            while (rlPos < rlEnd) {
                int[] reqSeq = parseSequence(der, rlPos);
                int[] certIdSeq = parseSequence(der, reqSeq[0]);
                parsedCertIds.add(parseCertId(der, certIdSeq));
                rlPos = reqSeq[1];
            }
            this.certIds = Collections.unmodifiableList(parsedCertIds);
            tbsPos = reqListSeq[1];

            // requestExtensions [2] EXPLICIT -> nonce
            this.nonce = parseNonce(der, tbsPos, tbsEnd);
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
            throw new PkixException("Malformed OCSP request DER", e);
        }
    }

    private static CertId parseCertId(byte[] der, int[] certIdSeq) throws PkixException {
        int cidPos = certIdSeq[0];

        // hashAlgorithm AlgorithmIdentifier SEQUENCE { OID, params }
        int[] hashAlgSeq = parseSequence(der, cidPos);
        int haPos = hashAlgSeq[0];
        if (haPos >= hashAlgSeq[1] || (der[haPos] & 0xFF) != 0x06) {
            throw new PkixException("OCSP request: CertID hashAlgorithm OID missing");
        }
        int[] haOidTlv = readTlv(der, haPos);
        String hashAlgOid = oidBytesToDottedString(der, haOidTlv[0], haOidTlv[1] - haOidTlv[0]);
        cidPos = hashAlgSeq[1];

        // issuerNameHash OCTET STRING
        int[] nameHashTlv = readTlv(der, cidPos);
        byte[] issuerNameHash = Arrays.copyOfRange(der, nameHashTlv[0], nameHashTlv[1]);
        cidPos = nameHashTlv[1];

        // issuerKeyHash OCTET STRING
        int[] keyHashTlv = readTlv(der, cidPos);
        byte[] issuerKeyHash = Arrays.copyOfRange(der, keyHashTlv[0], keyHashTlv[1]);
        cidPos = keyHashTlv[1];

        if (issuerNameHash.length == 0 || issuerKeyHash.length == 0) {
            throw new PkixException("OCSP request: CertID hash must not be empty");
        }

        // serialNumber INTEGER
        int[] serialTlv = readTlv(der, cidPos);
        byte[] serialNumber = Arrays.copyOfRange(der, serialTlv[0], serialTlv[1]);

        return new CertId(hashAlgOid, issuerNameHash, issuerKeyHash, serialNumber);
    }

    private static byte[] parseNonce(byte[] der, int pos, int end) throws PkixException {
        // requestExtensions [2] EXPLICIT (DerCodec.TAG_CTX_BASE | 2 = 0xA2)
        if (pos >= end || (der[pos] & 0xFF) != (DerCodec.TAG_CTX_BASE | 2)) {
            return null;
        }
        // Если [2] присутствует, но не разбирается — это ошибка разбора запроса, а не «nonce нет»:
        // IllegalArgumentException от readTlv оборачивает конструктор в PkixException
        int[] extExplTlv = readTlv(der, pos);
        int[] extSeq = parseSequence(der, extExplTlv[0]);
        int extPos = extSeq[0];
        int extEnd = extSeq[1];

        byte[] parsedNonce = null;
        while (extPos < extEnd) {
            int[] extTlv = parseSequence(der, extPos);
            int extContent = extTlv[0];
            int extContentEnd = extTlv[1];

            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x06) {
                extPos = extTlv[1];
                continue;
            }
            int[] extOidTlv = readTlv(der, extContent);
            boolean isNonce =
                    matchesOid(
                            der, extOidTlv[0], extOidTlv[1] - extOidTlv[0], OCSP_NONCE_OID_BYTES);
            extContent = extOidTlv[1];

            if (isNonce) {
                // Полный проход по расширениям нужен, чтобы увидеть дубликат: неоднозначность
                // «какой из двух nonce верный» недопустима
                if (parsedNonce != null) {
                    throw new PkixException("OCSP request: duplicate nonce extension");
                }
                // Критическое расширение: BOOLEAN true (опционально)
                if (extContent < extContentEnd && (der[extContent] & 0xFF) == 0x01) {
                    int[] boolTlv = readTlv(der, extContent);
                    extContent = boolTlv[1];
                }
                if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x04) {
                    throw new PkixException(
                            "OCSP request: nonce extension without extnValue OCTET STRING");
                }
                int[] extnValueTlv = readTlv(der, extContent);
                if (extnValueTlv[1] != extContentEnd) {
                    throw new PkixException("OCSP request: trailing data after nonce extnValue");
                }
                parsedNonce = OcspNonceCodec.parseExtnValue(der, extnValueTlv[0], extnValueTlv[1]);
            }
            extPos = extTlv[1];
        }
        return parsedNonce;
    }

    /**
     * Создаёт OCSP-запрос из DER-байтов.
     *
     * @param der DER-кодированный OCSPRequest
     * @return распарсенный OCSP-запрос
     */
    public static GostOcspRequest fromDer(byte[] der) throws PkixException {
        return new GostOcspRequest(der);
    }

    /**
     * Создаёт OCSP-запрос из PEM или DER-байтов с автоопределением формата.
     *
     * <p>Определяет формат по первому байту: {@code 0x30} = DER,
     * {@code 0x2D} = PEM (строка начинается с '-').
     *
     * @param data PEM или DER-байты OCSP-запроса
     * @return распарсенный OCSP-запрос
     * @throws PkixException при структурной ошибке DER
     */
    public static GostOcspRequest fromPemOrDer(byte[] data) throws PkixException {
        if (GostPemUtils.isPem(data)) {
            return new GostOcspRequest(GostPemUtils.pemToDer(data));
        }
        return new GostOcspRequest(data);
    }

    /**
     * @return полный DER-кодированный OCSPRequest (defensive copy)
     */
    public byte[] getEncoded() {
        return encoded.clone();
    }

    /**
     * Кодирует OCSP-запрос в PEM-формат (Base64 с заголовками).
     *
     * @return PEM-строка с заголовком {@code -----BEGIN OCSP REQUEST-----}
     */
    public String toPem() {
        return GostPemUtils.toPem(encoded, "OCSP REQUEST");
    }

    /**
     * @return список CertID из запроса (неизменяемый)
     */
    public List<CertId> getCertIds() {
        return certIds;
    }

    /**
     * Возвращает nonce из requestExtensions (RFC 8954).
     *
     * <p>Это сырые байты значения {@code Nonce} (1..32 байта) без обёрток OCTET STRING;
     * именно их передают в {@link GostOcspResponseBuilder#nonce(byte[])} для эхо-ответа.
     *
     * @return копия nonce или {@code null}, если расширение отсутствует
     */
    public byte[] getNonce() {
        return nonce != null ? nonce.clone() : null;
    }

    /**
     * @return {@code true} если запрос содержит подпись
     */
    public boolean isSigned() {
        return signed;
    }

    /**
     * Верифицирует подпись запроса (RFC 9215 §4.2).
     *
     * @param pubKey публичный ключ подписанта
     * @throws PkixException если подпись невалидна или запрос не подписан
     */
    public void verifySignature(PublicKeyParameters pubKey) throws PkixException {
        if (!signed) {
            throw new PkixException("OCSP request: not signed");
        }
        if (pubKey == null) {
            throw new IllegalArgumentException("pubKey must not be null");
        }
        if (tbsRaw == null) {
            throw new PkixException("OCSP request: cannot verify — no TBSRequest data");
        }

        int hlen = pubKey.getParams().hlen;
        Digest.Algorithm hashAlg = GostSignatureHelper.digestAlgByHlen(hlen);
        Digest digest = new Digest(hashAlg);
        digest.update(tbsRaw, 0, tbsRaw.length);
        byte[] hash = digest.digest();

        // Длина подписи берётся из недоверенного DER: неверная длина даёт false, а не исключение
        boolean signatureValid = Signature.verifyHash(hash, sigValue, pubKey);
        if (!signatureValid) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID,
                    "OCSP request: signature verification failed");
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
