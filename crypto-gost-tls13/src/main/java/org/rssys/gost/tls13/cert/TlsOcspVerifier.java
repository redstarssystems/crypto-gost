package org.rssys.gost.tls13.cert;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Верификация OCSP-ответа (RFC 6960) для TLS 1.3.
 *
 * <p>Содержит только статический метод {@link #verify(byte[], byte[], PublicKeyParameters)}.
 * Вынесен из {@link TlsCertificate} для разделения ответственности.</p>
 */
public final class TlsOcspVerifier {

    /** OID {@link org.rssys.gost.tls13.GostOids#DIGEST_256} — Streebog-256 */
    public static final byte[] STREEBOG256_OID_BYTES = {
            (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02
    };

    /** OID id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2) — RFC 8954 */
    private static final byte[] OCSP_NONCE_OID_BYTES = {
            (byte) 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02
    };

    private TlsOcspVerifier() {
    }

    /**
     * Верифицирует OCSP-ответ (RFC 6960).
     *
     * <p><b>Ограничения:</b></p>
     * <ul>
     *   <li>Поддерживается только OCSP от непосредственного issuer'а сертификата.</li>
     *   <li>Delegated OCSP responders (RFC 6960 §2.6) не поддерживаются.</li>
     *   <li>responderID не валидируется — authenticity гарантируется проверкой подписи переданным caKey.</li>
     * </ul>
     *
     * @param ocspResponse DER-кодированный OCSP-ответ (полная запись)
     * @param serialNumber серийный номер сертификата, для которого получен ответ
     * @param caKey        публичный ключ CA (подпись OCSP-ответа)
     * @throws TlsException если ответ невалиден или подпись не верна
     */
    public static void verify(byte[] ocspResponse, byte[] serialNumber,
                              PublicKeyParameters caKey) throws TlsException {
        verify(ocspResponse, serialNumber, caKey, null, null);
    }

    /**
     * Верифицирует OCSP-ответ с дополнительной проверкой CertID (issuerNameHash + issuerKeyHash).
     * <p>
     * Проверка CertID — defense-in-depth: серийный номер проверяется всегда,
     * а issuerNameHash/issuerKeyHash дополнительно гарантируют, что ответ
     * относится к тому же CA-сертификату.
     *
     * @param ocspResponse      DER-encoded OCSP-ответ
     * @param serialNumber      серийный номер проверяемого сертификата
     * @param caKey             публичный ключ CA (для подписи)
     * @param expectedIssuerDn  DER-encoded issuer DN (полный TLV) или null
     * @param issuerCertDer     DER-encoded issuer сертификат (для извлечения public key) или null
     * @throws TlsException при ошибке верификации
     */
    public static void verify(byte[] ocspResponse, byte[] serialNumber,
                              PublicKeyParameters caKey,
                              byte[] expectedIssuerDn,
                              byte[] issuerCertDer) throws TlsException {
        if (ocspResponse == null) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "No OCSP response available");
        }
        byte[] der = ocspResponse;

        int[] ocspSeq = TlsDerParser.parseSequence(der, 0);
        int pos = ocspSeq[0];
        int end = ocspSeq[1];

        // responseStatus ENUMERATED — OCSP-ответ всегда начинается со статуса, успех = 0 (RFC 6960 §4.2.1)
        if (pos >= end || (der[pos] & 0xFF) != 0x0A) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected ENUMERATED status");
        }
        int[] statusTlv = TlsDerParser.readTlv(der, pos);
        int statusVal = 0;
        for (int i = statusTlv[0]; i < statusTlv[1]; i++) {
            statusVal = (statusVal << 8) | (der[i] & 0xFF);
        }
        if (statusVal != 0) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: response status = " + statusVal + " (expected 0/successful)");
        }
        pos = statusTlv[1];

        // [0] EXPLICIT — обёртка responseBytes, без неё OCSP-ответ не по спецификации
        if (pos >= end || (der[pos] & 0xFF) != 0xA0) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected [0] EXPLICIT responseBytes");
        }
        int[] respBytesExplTlv = TlsDerParser.readTlv(der, pos);
        pos = respBytesExplTlv[0];

        // ResponseBytes: SEQUENCE { OID, OCTET STRING } — обязательная структура по RFC 6960 §4.2.1
        int[] respBytesSeq = TlsDerParser.parseSequence(der, pos);
        int rbPos = respBytesSeq[0];
        int rbEnd = respBytesSeq[1];

        // OID должен быть id-pkix-ocsp-basic ({@link org.rssys.gost.tls13.GostOids#OCSP_BASIC})
        if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x06) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected OID");
        }
        int[] oidTlv = TlsDerParser.readTlv(der, rbPos);
        if (!TlsDerParser.matchesOid(der, oidTlv[0], oidTlv[1] - oidTlv[0],
                TlsDerParser.OCSP_BASIC_OID_BYTES)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: responseType is not id-pkix-ocsp-basic");
        }
        rbPos = oidTlv[1];

        // OCTET STRING содержит BasicOCSPResponse — основное тело ответа
        if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x04) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected OCTET STRING");
        }
        int[] octTlv = TlsDerParser.readTlv(der, rbPos);

        // BasicOCSPResponse: SEQUENCE { tbsResponseData, sigAlg, sig } — как предписано RFC 6960 §4.2.1
        int[] basicSeq = TlsDerParser.parseSequence(der, octTlv[0]);
        int[] tbsSeq = TlsDerParser.parseSequence(der, basicSeq[0]);
        int tbsStart = basicSeq[0];
        int tbsEnd = tbsSeq[1];
        byte[] tbsRaw = Arrays.copyOfRange(der, tbsStart, tbsEnd);

        // Разбираем tbsResponseData для проверки статуса сертификата
        int tbsPos = tbsSeq[0];
        int tbsEnd2 = tbsSeq[1];

        // Пропускаем version [0] если есть — нас интересуют только данные о статусе
        if (tbsPos < tbsEnd2 && (der[tbsPos] & 0xFF) == 0xA0) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        }
        // responderID: [0]byName или [1]byKey — не валидируем, подпись CA гарантирует целостность
        if (tbsPos < tbsEnd2 && ((der[tbsPos] & 0xFF) == 0xA0 || (der[tbsPos] & 0xFF) == 0xA1)) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        } else {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected responderID");
        }
        // producedAt GeneralizedTime — время выпуска ответа, RFC 6960 требует
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != 0x18) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected GeneralizedTime for producedAt");
        }
        tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];

        // responses: SEQUENCE OF SingleResponse — перебираем, чтобы найти наш сертификат
        int[] respSeq = TlsDerParser.parseSequence(der, tbsPos);
        int rpPos = respSeq[0];

        // Каждый SingleResponse содержит CertID проверяемого сертификата
        int[] srSeq = TlsDerParser.parseSequence(der, rpPos);
        int[] certIdSeq = TlsDerParser.parseSequence(der, srSeq[0]);

        // CertID: первое поле — hashAlgorithm, последнее — serialNumber (RFC 6960 §4.1.1)
        // Проверяем, что алгоритм хеширования = Streebog-256 (RFC 6960 §3.2, MUST)
        int cidPos = certIdSeq[0];
        int[] hashAlgSeq = TlsDerParser.parseSequence(der, cidPos);
        int haPos = hashAlgSeq[0];
        if (haPos >= hashAlgSeq[1] || (der[haPos] & 0xFF) != 0x06) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: CertID hashAlgorithm OID missing");
        }
        int[] haOid = TlsDerParser.readTlv(der, haPos);
        if (!TlsDerParser.matchesOid(der, haOid[0], haOid[1] - haOid[0],
                STREEBOG256_OID_BYTES)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: CertID hashAlgorithm is not Streebog-256");
        }
        cidPos = hashAlgSeq[1]; // past AlgorithmIdentifier
        cidPos = TlsDerParser.readTlv(der, cidPos)[1];
        cidPos = TlsDerParser.readTlv(der, cidPos)[1];
        int[] cidSerialTlv = TlsDerParser.readTlv(der, cidPos);
        byte[] certIdSerial = Arrays.copyOfRange(der, cidSerialTlv[0], cidSerialTlv[1]);

        if (!Arrays.equals(certIdSerial, serialNumber)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: serialNumber mismatch");
        }

        // CertID: hashAlgorithm, issuerNameHash и issuerKeyHash (defense-in-depth)
        if (expectedIssuerDn != null && issuerCertDer != null) {
            int cidCheckPos = certIdSeq[0];
            int[] chkHashAlgSeq = TlsDerParser.parseSequence(der, cidCheckPos);
            int chkHaPos = chkHashAlgSeq[0];
            if (chkHaPos < chkHashAlgSeq[1] && (der[chkHaPos] & 0xFF) == 0x06) {
                int[] chkHaOid = TlsDerParser.readTlv(der, chkHaPos);
                if (!TlsDerParser.matchesOid(der, chkHaOid[0], chkHaOid[1] - chkHaOid[0],
                        STREEBOG256_OID_BYTES)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "OCSP: CertID hashAlgorithm is not Streebog-256");
                }
            }
            cidCheckPos = chkHashAlgSeq[1];
            int[] nameHashTlv = TlsDerParser.readTlv(der, cidCheckPos);
            cidCheckPos = nameHashTlv[1];
            int[] keyHashTlv = TlsDerParser.readTlv(der, cidCheckPos);

            byte[] certIdNameHash = Arrays.copyOfRange(der, nameHashTlv[0], nameHashTlv[1]);
            byte[] expectedNameHash = Digest.digest256(expectedIssuerDn);
            if (!Arrays.equals(certIdNameHash, expectedNameHash)) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "OCSP: issuerNameHash mismatch");
            }

            byte[] certIdKeyHash = Arrays.copyOfRange(der, keyHashTlv[0], keyHashTlv[1]);
            byte[] expectedKeyHash = OcspCertIdHasher.hashIssuerPublicKey(issuerCertDer);
            if (!Arrays.equals(certIdKeyHash, expectedKeyHash)) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "OCSP: issuerKeyHash mismatch");
            }
        }

        // certStatus: good = [0]{NULL}
        int stPos = cidSerialTlv[1];
        if (stPos >= srSeq[1] || (der[stPos] & 0xFF) != 0xA0) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: certStatus is not 'good'");
        }

        // проверка свежести nextUpdate
        int timePos = certIdSeq[1];
        if (timePos < srSeq[1] && (der[timePos] & 0xFF) == 0xA0) {
            timePos = TlsDerParser.readTlv(der, timePos)[1];
        }
        if (timePos >= srSeq[1]) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: thisUpdate missing");
        }
        timePos = TlsDerParser.readTlv(der, timePos)[1];
        if (timePos < srSeq[1] && (der[timePos] & 0xFF) == 0xA0) {
            int[] nuExplTlv = TlsDerParser.readTlv(der, timePos);
            if (nuExplTlv[0] < nuExplTlv[1]) {
                Date nextUpdate = TlsDerParser.parseTime(der, nuExplTlv[0]);
                if (new Date().after(nextUpdate)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "OCSP: response expired (nextUpdate in the past)");
                }
            }
        }

        // Signature: sigAlg SEQUENCE + sig BIT STRING
        int afterTbs = tbsEnd;
        if (afterTbs >= basicSeq[1] || (der[afterTbs] & 0xFF) != TlsDerParser.TAG_SEQUENCE) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: signatureAlgorithm missing");
        }
        int[] sigAlgTlv = TlsDerParser.readTlv(der, afterTbs);
        int afterSigAlg = sigAlgTlv[1];
        if (afterSigAlg >= basicSeq[1] || (der[afterSigAlg] & 0xFF) != TlsDerParser.TAG_BIT_STRING) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: signature BIT STRING missing");
        }
        int[] sigBitTlv = TlsDerParser.readTlv(der, afterSigAlg);
        byte[] sigBytes = Arrays.copyOfRange(der, sigBitTlv[0] + 1, sigBitTlv[1]);

        int hlen = caKey.getParams().hlen;
        Digest.Algorithm hashAlg = hlen == 64
                ? Digest.Algorithm.STREEBOG_512
                : Digest.Algorithm.STREEBOG_256;
        Digest digest = new Digest(hashAlg);
        digest.update(tbsRaw, 0, tbsRaw.length);
        byte[] hash = digest.digest();

        if (!Signature.verifyHash(hash, sigBytes, caKey)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: signature verification failed");
        }
    }

    /**
     * Проверяет OCSP nonce (RFC 8954) в OCSP-ответе.
     * <p>
     * Nonce находится в {@code tbsResponseData.responseExtensions} [1] EXPLICIT.
     * Если {@code strict} == true — отсутствие nonce в ответе вызывает ошибку.
     * Если {@code strict} == false — отсутствие nonce допустимо (responder может
     * не поддерживать), проверка выполняется только если nonce присутствует.
     *
     * @param ocspResponse DER-encoded OCSP-ответ
     * @param expectedNonce ожидаемый nonce (из запроса)
     * @param strict        true — nonce обязателен
     * @throws TlsException при несовпадении nonce
     */
    /**
     * Извлекает сертификаты делегированного OCSP-responder'а из поля certs
     * BasicOCSPResponse (RFC 6960 §4.2.2.1). Если поля нет — пустой список.
     *
     * @param ocspResponse полный DER OCSPResponse
     * @return список DER-encoded сертификатов из certs (может быть пустым)
     * @throws TlsException при ошибке парсинга
     */
    public static List<byte[]> extractDelegatedCerts(byte[] ocspResponse) throws TlsException {
        // OCSPResponse ::= SEQUENCE { responseStatus, responseBytes }
        int[] respSeq = TlsDerParser.parseSequence(ocspResponse, 0);
        int respEnd = respSeq[1];
        int rpPos = respSeq[0];
        // responseStatus ENUMERATED — пропускаем
        int[] statusTlv = TlsDerParser.readTlv(ocspResponse, rpPos);
        rpPos = statusTlv[1];
        if (rpPos >= respEnd) return Collections.emptyList();
        // responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING }
        int[] rbExpl = TlsDerParser.readTlv(ocspResponse, rpPos);
        int rbSeqStart = rbExpl[0];
        int[] rbSeq = TlsDerParser.parseSequence(ocspResponse, rbSeqStart);
        int rbPos = rbSeq[0];
        int[] rbOidTlv = TlsDerParser.readTlv(ocspResponse, rbPos);
        rbPos = rbOidTlv[1];
        // response OCTET STRING, внутри него BasicOCSPResponse
        int[] respOsTlv = TlsDerParser.readTlv(ocspResponse, rbPos);
        byte[] basicResp = Arrays.copyOfRange(ocspResponse, respOsTlv[0], respOsTlv[1]);
        // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, sigAlg, signature, certs OPTIONAL }
        int[] basicSeq = TlsDerParser.parseSequence(basicResp, 0);
        int basicEnd = basicSeq[1];
        int bpPos = basicSeq[0];
        // tbsResponseData — SEQUENCE
        int[] tbsSeq = TlsDerParser.parseSequence(basicResp, bpPos);
        bpPos = tbsSeq[1];
        // signatureAlgorithm — OID(06) + params
        int[] sigAlgTlv = TlsDerParser.readTlv(basicResp, bpPos);
        bpPos = sigAlgTlv[1];
        // signature BIT STRING
        int[] sigBsTlv = TlsDerParser.readTlv(basicResp, bpPos);
        bpPos = sigBsTlv[1];
        // certs [0] EXPLICIT SEQUENCE OF Certificate — если есть
        if (bpPos >= basicEnd) return Collections.emptyList();
        if ((basicResp[bpPos] & 0xFF) != 0xA0) return Collections.emptyList();
        // certs [0] EXPLICIT SEQUENCE OF Certificate
        int[] explTlv = TlsDerParser.readTlv(basicResp, bpPos);
        // explTlv[0] = position of first byte of SEQUENCE tag (0x30)
        // There's no tag+length between [0]'s header and the SEQUENCE
        // because [0]'s value IS the SEQUENCE
        int seqTagPos = explTlv[0]; // 0x30 tag
        int[] seqTlv = TlsDerParser.readTlv(basicResp, seqTagPos);
        int seqEnd = seqTlv[1]; // end of SEQUENCE_OF value
        int cpPos = seqTlv[0]; // start of first Certificate content
        List<byte[]> result = new ArrayList<>();
        while (cpPos < seqEnd) {
            int[] certTlv = TlsDerParser.readTlv(basicResp, cpPos);
            byte[] certDer = Arrays.copyOfRange(basicResp, cpPos, certTlv[1]);
            result.add(certDer);
            cpPos = certTlv[1];
        }
        return result;
    }

    public static void verifyNonce(byte[] ocspResponse, byte[] expectedNonce,
                                    boolean strict) throws TlsException {
        if (expectedNonce == null) return;

        byte[] der = ocspResponse;
        int[] ocspSeq = TlsDerParser.parseSequence(der, 0);
        int pos = ocspSeq[0];
        int end = ocspSeq[1];

        // Skip responseStatus (ENUMERATED)
        if (pos >= end || (der[pos] & 0xFF) != 0x0A) return;
        int[] statusTlv = TlsDerParser.readTlv(der, pos);
        pos = statusTlv[1];

        // responseBytes [0] EXPLICIT
        if (pos >= end || (der[pos] & 0xFF) != 0xA0) return;
        int[] respBytesTlv = TlsDerParser.readTlv(der, pos);
        pos = respBytesTlv[0];

        // ResponseBytes SEQUENCE { OID, OCTET STRING }
        int[] rbSeq = TlsDerParser.parseSequence(der, pos);
        int rbPos = rbSeq[0];
        int rbEnd = rbSeq[1];
        if (rbPos >= rbEnd) return;

        // Skip OID
        if ((der[rbPos] & 0xFF) != 0x06) return;
        int[] oidTlv = TlsDerParser.readTlv(der, rbPos);
        rbPos = oidTlv[1];

        // OCTET STRING with BasicOCSPResponse
        if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x04) return;
        int[] octTlv = TlsDerParser.readTlv(der, rbPos);

        // BasicOCSPResponse: SEQUENCE { tbsResponseData, sigAlg, sig }
        int[] basicSeq = TlsDerParser.parseSequence(der, octTlv[0]);
        int[] tbsSeq = TlsDerParser.parseSequence(der, basicSeq[0]);

        int tbsPos = tbsSeq[0];
        int tbsEnd2 = tbsSeq[1];

        // Skip version [0] if present
        if (tbsPos < tbsEnd2 && (der[tbsPos] & 0xFF) == 0xA0) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        }
        // Skip responderID
        if (tbsPos < tbsEnd2 && ((der[tbsPos] & 0xFF) == 0xA0 || (der[tbsPos] & 0xFF) == 0xA1)) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        } else {
            return;
        }
        // Skip producedAt
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != 0x18) return;
        tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];

        // Skip responses SEQUENCE OF
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != TlsDerParser.TAG_SEQUENCE) return;
        int[] respSeq = TlsDerParser.readTlv(der, tbsPos);
        tbsPos = respSeq[1];

        // responseExtensions [1] EXPLICIT
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != 0xA1) {
            if (strict) {
                throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                        "OCSP: responseExtensions missing (strict nonce)");
            }
            return;
        }
        int[] extExplTlv = TlsDerParser.readTlv(der, tbsPos);

        // Extensions SEQUENCE
        int[] extSeq = TlsDerParser.parseSequence(der, extExplTlv[0]);
        int extPos = extSeq[0];
        int extEnd = extSeq[1];

        while (extPos < extEnd) {
            int[] extTlv = TlsDerParser.parseSequence(der, extPos);
            int extContent = extTlv[0];
            int extContentEnd = extTlv[1];

            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x06) {
                extPos = extTlv[1];
                continue;
            }
            int[] extOidTlv = TlsDerParser.readTlv(der, extContent);
            boolean isNonce = TlsDerParser.matchesOid(der, extOidTlv[0],
                    extOidTlv[1] - extOidTlv[0], OCSP_NONCE_OID_BYTES);
            extContent = extOidTlv[1];

            if (isNonce) {
                // Октивируем critical flag (BOOLEAN, опционально)
                if (extContent < extContentEnd && (der[extContent] & 0xFF) == 0x01) {
                    int[] boolTlv = TlsDerParser.readTlv(der, extContent);
                    extContent = boolTlv[1];
                }
                // Nonce value: OCTET STRING
                if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x04) {
                    if (strict) {
                        throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                                "OCSP: nonce extension value is not OCTET STRING");
                    }
                    return;
                }
                int[] nonceOctTlv = TlsDerParser.readTlv(der, extContent);
                byte[] responseNonce = java.util.Arrays.copyOfRange(
                        der, nonceOctTlv[0], nonceOctTlv[1]);

                if (!java.util.Arrays.equals(responseNonce, expectedNonce)) {
                    throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                            "OCSP: nonce mismatch");
                }
                return; // nonce found and verified
            }
            extPos = extTlv[1];
        }

        // Nonce extension not found
        if (strict) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: nonce extension not found (strict nonce)");
        }
    }
}
