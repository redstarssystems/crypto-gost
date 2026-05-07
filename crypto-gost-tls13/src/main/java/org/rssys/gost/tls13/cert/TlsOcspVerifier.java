package org.rssys.gost.tls13.cert;

import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

import java.util.Arrays;
import java.util.Date;

/**
 * Верификация OCSP-ответа (RFC 6960) для TLS 1.3.
 *
 * <p>Содержит только статический метод {@link #verify(byte[], byte[], PublicKeyParameters)}.
 * Вынесен из {@link TlsCertificate} для разделения ответственности.</p>
 */
public final class TlsOcspVerifier {

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
        if (ocspResponse == null) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "No OCSP response available");
        }
        byte[] der = ocspResponse;

        int[] ocspSeq = TlsDerParser.parseSequence(der, 0);
        int pos = ocspSeq[0];
        int end = ocspSeq[1];

        // responseStatus: ENUMERATED — должен быть successful(0)
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

        // responseBytes [0] EXPLICIT
        if (pos >= end || (der[pos] & 0xFF) != 0xA0) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected [0] EXPLICIT responseBytes");
        }
        int[] respBytesExplTlv = TlsDerParser.readTlv(der, pos);
        pos = respBytesExplTlv[0];

        // ResponseBytes: SEQUENCE { OID, OCTET STRING }
        int[] respBytesSeq = TlsDerParser.parseSequence(der, pos);
        int rbPos = respBytesSeq[0];
        int rbEnd = respBytesSeq[1];

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

        if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x04) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected OCTET STRING");
        }
        int[] octTlv = TlsDerParser.readTlv(der, rbPos);

        // BasicOCSPResponse: SEQUENCE { tbsResponseData, sigAlg, sig }
        int[] basicSeq = TlsDerParser.parseSequence(der, octTlv[0]);
        int[] tbsSeq = TlsDerParser.parseSequence(der, basicSeq[0]);
        int tbsStart = basicSeq[0];
        int tbsEnd = tbsSeq[1];
        byte[] tbsRaw = Arrays.copyOfRange(der, tbsStart, tbsEnd);

        // Разбираем tbsResponseData
        int tbsPos = tbsSeq[0];
        int tbsEnd2 = tbsSeq[1];

        if (tbsPos < tbsEnd2 && (der[tbsPos] & 0xFF) == 0xA0) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        }
        // responderID: [0]byName или [1]byKey
        if (tbsPos < tbsEnd2 && ((der[tbsPos] & 0xFF) == 0xA0 || (der[tbsPos] & 0xFF) == 0xA1)) {
            tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];
        } else {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected responderID");
        }
        // producedAt GeneralizedTime
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != 0x18) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: expected GeneralizedTime for producedAt");
        }
        tbsPos = TlsDerParser.readTlv(der, tbsPos)[1];

        // responses: SEQUENCE OF SingleResponse
        int[] respSeq = TlsDerParser.parseSequence(der, tbsPos);
        int rpPos = respSeq[0];

        // SingleResponse: SEQUENCE { CertID, certStatus, ... }
        int[] srSeq = TlsDerParser.parseSequence(der, rpPos);
        int[] certIdSeq = TlsDerParser.parseSequence(der, srSeq[0]);

        // CertID serialNumber — последнее поле
        int cidPos = certIdSeq[0];
        cidPos = TlsDerParser.readTlv(der, cidPos)[1];
        cidPos = TlsDerParser.readTlv(der, cidPos)[1];
        cidPos = TlsDerParser.readTlv(der, cidPos)[1];
        int[] cidSerialTlv = TlsDerParser.readTlv(der, cidPos);
        byte[] certIdSerial = Arrays.copyOfRange(der, cidSerialTlv[0], cidSerialTlv[1]);

        if (!Arrays.equals(certIdSerial, serialNumber)) {
            throw new TlsException(TlsConstants.ALERT_BAD_CERTIFICATE,
                    "OCSP: serialNumber mismatch");
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
}
