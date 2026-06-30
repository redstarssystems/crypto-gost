package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Верификация OCSP-ответа (RFC 6960).
 *
 * <p>Парсинг структуры делегирован в {@link GostOcspResponse}.
 * Статические методы выполняют: поиск серийного номера, проверку статуса,
 * свежести (thisUpdate/nextUpdate), CertID, подписи и nonce.</p>
 */
public final class OcspVerifier {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.OcspVerifier");



    private OcspVerifier() {}

    /**
     * Верифицирует OCSP-ответ (RFC 6960).
     *
     * <p>Проверяет подпись и статус сертификата. НЕ проверяет nonce —
     * ответы без nonce уязвимы к replay-атакам (RFC 6960 §4.4.9, RFC 8954).
     * Для защиты от replay используйте
     * {@link #verify(byte[], byte[], PublicKeyParameters, byte[], byte[], byte[], boolean)}
     * с заданным expectedNonce.</p>
     *
     * @param ocspResponse DER-кодированный OCSP-ответ
     * @param serialNumber серийный номер сертификата
     * @param caKey        публичный ключ CA (подпись OCSP-ответа)
     * @throws PkixException если ответ невалиден
     */
    public static void verify(byte[] ocspResponse, byte[] serialNumber, PublicKeyParameters caKey)
            throws PkixException {
        verify(ocspResponse, serialNumber, caKey, null, null);
    }

    /**
     * Верифицирует OCSP-ответ с проверкой CertID (issuerNameHash + issuerKeyHash).
     *
     * @param ocspResponse      DER-encoded OCSP-ответ
     * @param serialNumber      серийный номер проверяемого сертификата
     * @param caKey             публичный ключ CA (для подписи)
     * @param expectedIssuerDn  DER-encoded issuer DN (полный TLV) или null
     * @param issuerCertDer     DER-encoded issuer сертификат или null
     * @throws PkixException при ошибке верификации
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            PublicKeyParameters caKey,
            byte[] expectedIssuerDn,
            byte[] issuerCertDer)
            throws PkixException {
        if (ocspResponse == null) {
            throw new PkixException("No OCSP response available");
        }
        LOG.log(
                Level.INFO,
                "Verifying OCSP response for certificate serial 0x{0}",
                new BigInteger(1, serialNumber).toString(16));

        GostOcspResponse ocsp = new GostOcspResponse(ocspResponse);

        if (!ocsp.isSuccessful()) {
            throw new PkixException(
                    "OCSP: response status = "
                            + ocsp.getResponseStatus()
                            + " (expected 0/successful)");
        }

        // Ищем SingleResponse с совпадающим серийным номером
        SingleOcspResponse target = null;
        for (SingleOcspResponse sr : ocsp.getResponses()) {
            if (Arrays.equals(sr.certSerialNumber(), serialNumber)) {
                target = sr;
                break;
            }
        }
        if (target == null) {
            throw new PkixException("OCSP: serialNumber not found in any SingleResponse");
        }

        // Проверка подписи — до certStatus (fail-closed, исключает подделку статуса)
        ocsp.verify(caKey);

        // certStatus проверка
        if (target.isRevoked()) {
            throw new PkixException(PkixException.Reason.REVOKED, "OCSP: certificate is revoked");
        }
        if (!target.isGood()) {
            throw new PkixException("OCSP: certStatus is not 'good'");
        }

        // Проверка свежести thisUpdate
        if (target.thisUpdate().isAfter(Instant.now().plusMillis(GostOids.CLOCK_SKEW_MS))) {
            throw new PkixException("OCSP: thisUpdate is in the future");
        }

        // Проверка nextUpdate
        if (target.nextUpdate() != null && Instant.now().isAfter(target.nextUpdate())) {
            throw new PkixException("OCSP: response expired (nextUpdate in the past)");
        }

        // CertID defense-in-depth
        if (expectedIssuerDn != null && issuerCertDer != null) {
            int hlen = caKey.getParams().hlen;
            int certIdHashLen =
                    hlen == GostOids.STREEBOG_512_HASH_LEN
                            ? GostOids.STREEBOG_512_HASH_LEN
                            : GostOids.STREEBOG_256_HASH_LEN;

            byte[] expectedNameHash =
                    GostSignatureHelper.doHash(expectedIssuerDn, certIdHashLen);
            if (!Arrays.equals(target.issuerNameHash(), expectedNameHash)) {
                throw new PkixException("OCSP: issuerNameHash mismatch");
            }

            byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(issuerCertDer, certIdHashLen);
            if (!Arrays.equals(target.issuerKeyHash(), expectedKeyHash)) {
                throw new PkixException("OCSP: issuerKeyHash mismatch");
            }
        }

        LOG.log(
                Level.INFO,
                "OCSP verification passed for certificate serial 0x{0}",
                new BigInteger(1, serialNumber).toString(16));
    }

    /**
     * Верифицирует OCSP-ответ с проверкой nonce (RFC 8954).
     *
     * @param ocspResponse      DER-encoded OCSP-ответ
     * @param serialNumber      серийный номер проверяемого сертификата
     * @param caKey             публичный ключ CA (для подписи)
     * @param expectedIssuerDn  DER-encoded issuer DN (полный TLV) или null
     * @param issuerCertDer     DER-encoded issuer сертификат (для CertID) или null
     * @param expectedNonce     ожидаемый nonce (из запроса) или null — не проверять
     * @param strict            true — nonce обязателен в ответе
     * @throws PkixException при ошибке верификации
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            PublicKeyParameters caKey,
            byte[] expectedIssuerDn,
            byte[] issuerCertDer,
            byte[] expectedNonce,
            boolean strict)
            throws PkixException {
        verify(ocspResponse, serialNumber, caKey, expectedIssuerDn, issuerCertDer);
        verifyNonce(ocspResponse, expectedNonce, strict);
    }

    // ========================================================================
    // verifyNonce — независимый утилитный метод (не зависит от GostOcspResponse)
    // ========================================================================

    /**
     * Пропускает version [0] и responderID в tbsResponseData.
     */
    private static int skipTbsResponseDataHeader(byte[] der, int pos, int end)
            throws PkixException {
        if (pos < end && (der[pos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0) {
            pos = GostDerParser.readTlv(der, pos)[1];
        }
        if (pos < end
                && ((der[pos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_0
                        || (der[pos] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1)) {
            return GostDerParser.readTlv(der, pos)[1];
        }
        throw new PkixException("OCSP: expected responderID");
    }

    /**
     * Проверяет OCSP nonce (RFC 8954) в OCSP-ответе.
     */
    public static void verifyNonce(byte[] ocspResponse, byte[] expectedNonce, boolean strict)
            throws PkixException {
        if (expectedNonce == null) return;

        byte[] der = ocspResponse;
        int[] ocspSeq = GostDerParser.parseSequence(der, 0);
        int pos = ocspSeq[0];
        int end = ocspSeq[1];

        if (pos >= end || (der[pos] & 0xFF) != 0x0A) return;
        int[] statusTlv = GostDerParser.readTlv(der, pos);
        pos = statusTlv[1];

        if (pos >= end || (der[pos] & 0xFF) != DerCodec.TAG_CTX_CONSTRUCTED_0) return;
        int[] respBytesTlv = GostDerParser.readTlv(der, pos);
        pos = respBytesTlv[0];

        int[] rbSeq = GostDerParser.parseSequence(der, pos);
        int rbPos = rbSeq[0];
        int rbEnd = rbSeq[1];
        if (rbPos >= rbEnd) return;

        if ((der[rbPos] & 0xFF) != 0x06) return;
        int[] oidTlv = GostDerParser.readTlv(der, rbPos);
        rbPos = oidTlv[1];

        if (rbPos >= rbEnd || (der[rbPos] & 0xFF) != 0x04) return;
        int[] octTlv = GostDerParser.readTlv(der, rbPos);

        int[] basicSeq = GostDerParser.parseSequence(der, octTlv[0]);
        int[] tbsSeq = GostDerParser.parseSequence(der, basicSeq[0]);

        int tbsPos = tbsSeq[0];
        int tbsEnd2 = tbsSeq[1];

        try {
            tbsPos = skipTbsResponseDataHeader(der, tbsPos, tbsEnd2);
        } catch (PkixException e) {
            return;
        }
        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != 0x18) return;
        tbsPos = GostDerParser.readTlv(der, tbsPos)[1];

        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != GostDerParser.TAG_SEQUENCE) return;
        int[] respSeq = GostDerParser.readTlv(der, tbsPos);
        tbsPos = respSeq[1];

        if (tbsPos >= tbsEnd2 || (der[tbsPos] & 0xFF) != DerCodec.TAG_CTX_CONSTRUCTED_1) {
            if (strict) {
                throw new PkixException("OCSP: responseExtensions missing (strict nonce)");
            }
            return;
        }
        int[] extExplTlv = GostDerParser.readTlv(der, tbsPos);

        int[] extSeq = GostDerParser.parseSequence(der, extExplTlv[0]);
        int extPos = extSeq[0];
        int extEnd = extSeq[1];

        while (extPos < extEnd) {
            int[] extTlv = GostDerParser.parseSequence(der, extPos);
            int extContent = extTlv[0];
            int extContentEnd = extTlv[1];

            if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x06) {
                extPos = extTlv[1];
                continue;
            }
            int[] extOidTlv = GostDerParser.readTlv(der, extContent);
            boolean isNonce =
                    GostDerParser.matchesOid(
                            der,
                            extOidTlv[0],
                            extOidTlv[1] - extOidTlv[0],
                            GostDerParser.OCSP_NONCE_OID_BYTES);
            extContent = extOidTlv[1];

            if (isNonce) {
                if (extContent < extContentEnd && (der[extContent] & 0xFF) == 0x01) {
                    int[] boolTlv = GostDerParser.readTlv(der, extContent);
                    extContent = boolTlv[1];
                }
                if (extContent >= extContentEnd || (der[extContent] & 0xFF) != 0x04) {
                    if (strict) {
                        throw new PkixException("OCSP: nonce extension value is not OCTET STRING");
                    }
                    return;
                }
                int[] nonceOctTlv = GostDerParser.readTlv(der, extContent);
                byte[] responseNonce =
                        java.util.Arrays.copyOfRange(der, nonceOctTlv[0], nonceOctTlv[1]);

                if (!java.util.Arrays.equals(responseNonce, expectedNonce)) {
                    throw new PkixException("OCSP: nonce mismatch");
                }
                return;
            }
            extPos = extTlv[1];
        }

        if (strict) {
            throw new PkixException("OCSP: nonce extension not found (strict nonce)");
        }
    }
}
