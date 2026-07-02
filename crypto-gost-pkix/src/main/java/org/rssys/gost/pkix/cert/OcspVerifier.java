package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Верификация OCSP-ответа (RFC 6960).
 *
 * <p>Публичный API принимает {@link GostCertificate} — сертификат издателя
 * (CA или делегированного responder'а). EKU-проверка для делегированных
 * responder-сертификатов выполняется встроенно, отдельно вызывать не нужно.
 * CertID (issuerNameHash/issuerKeyHash) вычисляется автоматически.</p>
 *
 * <p>Низкоуровневые перегрузки, принимающие {@link PublicKeyParameters},
 * являются package-private — только для тестов и кросс-валидационных сценариев,
 * где недоступен {@link GostCertificate}.</p>
 */
public final class OcspVerifier {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cert.OcspVerifier");



    private OcspVerifier() {}

    // ========================================================================
    // Публичный API — по сертификату (проверка политик, EKU, делегирование)
    // ========================================================================

    /**
     * Верифицирует OCSP-ответ (RFC 6960) с полной проверкой политик.
     *
     * <p>Сначала пробует прямую подпись ключом issuer-сертификата (CA).
     * Если не сошлось — перебирает делегированные responder-сертификаты
     * из поля certs BasicOCSPResponse: для каждого проверяется
     * expiry → EKU (id-kp-OCSPSigning) → KeyUsage → цепочка подписи к issuer.</p>
     *
     * <p>CertID (issuerNameHash/issuerKeyHash) вычисляется автоматически
     * из issuerCert.</p>
     *
     * @param ocspResponse DER-кодированный OCSP-ответ
     * @param serialNumber серийный номер проверяемого сертификата
     * @param issuerCert   сертификат издателя
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse, byte[] serialNumber, GostCertificate issuerCert)
            throws PkixException {
        verifyWithCert(ocspResponse, serialNumber, issuerCert, null, false);
    }

    /**
     * Верифицирует OCSP-ответ с проверкой nonce (RFC 8954).
     *
     * @param ocspResponse  DER-кодированный OCSP-ответ
     * @param serialNumber  серийный номер проверяемого сертификата
     * @param issuerCert    сертификат издателя
     * @param expectedNonce ожидаемый nonce (из запроса) или null — не проверять
     * @param strict        true — nonce обязателен в ответе
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuerCert,
            byte[] expectedNonce,
            boolean strict)
            throws PkixException {
        verifyWithCert(ocspResponse, serialNumber, issuerCert, expectedNonce, strict);
    }

    private static void verifyWithCert(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuerCert,
            byte[] expectedNonce,
            boolean strict)
            throws PkixException {
        if (ocspResponse == null) {
            throw new PkixException("No OCSP response available");
        }
        if (issuerCert == null) {
            throw new PkixException("issuerCert must not be null");
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
        SingleOcspResponse target = findSingleResponse(ocsp, serialNumber);

        // Попытка прямого подписания ключом issuer'а (CA)
        PublicKeyParameters caPub = issuerCert.getPublicKey();
        boolean sigOk;
        try {
            ocsp.verify(caPub);
            sigOk = true;
        } catch (PkixException e) {
            sigOk = false;
        }

        // Если подпись CA не подошла — пробуем делегированные responder-сертификаты
        if (!sigOk) {
            sigOk = tryDelegatedVerification(ocsp, issuerCert);
        }

        if (!sigOk) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID,
                    "OCSP signature verification failed");
        }

        // Статус, свежесть, CertID
        verifyStatusAndFreshness(target, ocspResponse, expectedNonce, strict);

        // CertID проверка — всегда, автоматически из issuerCert
        verifyCertId(target, caPub, issuerCert);

        LOG.log(
                Level.INFO,
                "OCSP verification passed for certificate serial 0x{0}",
                new BigInteger(1, serialNumber).toString(16));
    }

    /**
     * Перебирает делегированные responder-сертификаты из поля certs.
     * Порядок pre-checks (дёшево→дорого) из RFC 6960 §4.2.2.2:
     * expiry → EKU → KeyUsage → подпись делегированного сертификата.
     *
     * @return true если делегированный сертификат прошёл все проверки и подписал OCSP-ответ
     */
    private static boolean tryDelegatedVerification(
            GostOcspResponse ocsp, GostCertificate issuerCert) {
        List<byte[]> dcDers = ocsp.getDelegatedCertificates();
        if (dcDers.isEmpty()) {
            return false;
        }

        for (byte[] dcDer : dcDers) {
            GostCertificate dc = new GostCertificate(dcDer);

            if (dc.isExpired()) continue;
            if (!dc.isOcspSigning()) continue;
            if (!dc.isKeyUsageValid()) continue;

            // Делегированный сертификат должен быть подписан issuer'ом
            if (!dc.verifySignature(issuerCert.getPublicKey())) continue;

            // Проверяем подпись OCSP-ответа ключом делегированного сертификата
            try {
                ocsp.verify(dc.getPublicKey());
                return true;
            } catch (PkixException ignored) {
                // Пробуем следующий delegated cert
            }
        }
        return false;
    }

    /**
     * Проверяет CertID (issuerNameHash/issuerKeyHash) автоматически
     * из issuerCert.
     */
    private static void verifyCertId(
            SingleOcspResponse target, PublicKeyParameters issuerPub, GostCertificate issuerCert)
            throws PkixException {
        int hlen = issuerPub.getParams().hlen;
        int certIdHashLen =
                hlen == GostOids.STREEBOG_512_HASH_LEN
                        ? GostOids.STREEBOG_512_HASH_LEN
                        : GostOids.STREEBOG_256_HASH_LEN;

        // issuerNameHash = hash(subject DN issuer-а)
        byte[] issuerNameDer = issuerCert.getSubjectDnBytes();
        byte[] expectedNameHash = GostSignatureHelper.doHash(issuerNameDer, certIdHashLen);
        if (!Arrays.equals(target.issuerNameHash(), expectedNameHash)) {
            throw new PkixException("OCSP: issuerNameHash mismatch");
        }

        // issuerKeyHash = hash(публичного ключа issuer-а)
        byte[] expectedKeyHash =
                CertIdHasher.hashIssuerPublicKey(issuerCert.getEncoded(), certIdHashLen);
        if (!Arrays.equals(target.issuerKeyHash(), expectedKeyHash)) {
            throw new PkixException("OCSP: issuerKeyHash mismatch");
        }
    }

    /**
     * Проверяет certStatus, свежесть (thisUpdate/nextUpdate) и nonce.
     * Общая часть для certificate-based и key-based путей верификации.
     */
    static void verifyStatusAndFreshness(
            SingleOcspResponse target,
            byte[] ocspResponse,
            byte[] expectedNonce,
            boolean strict)
            throws PkixException {
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

        // Nonce проверка
        if (expectedNonce != null) {
            verifyNonce(ocspResponse, expectedNonce, strict);
        }
    }

    private static SingleOcspResponse findSingleResponse(
            GostOcspResponse ocsp, byte[] serialNumber) throws PkixException {
        for (SingleOcspResponse sr : ocsp.getResponses()) {
            if (Arrays.equals(sr.certSerialNumber(), serialNumber)) {
                return sr;
            }
        }
        throw new PkixException("OCSP: serialNumber not found in any SingleResponse");
    }

    // ========================================================================
    // Низкоуровневые перегрузки (package-private) — только для тестов
    // и кросс-валидационных сценариев без GostCertificate
    // ========================================================================

    /**
     * Только для тестов формата DER/подписи. Без проверки политики (EKU).
     * Для production используйте перегрузку с {@link GostCertificate}.
     */
    static void verify(byte[] ocspResponse, byte[] serialNumber, PublicKeyParameters caKey)
            throws PkixException {
        verify(ocspResponse, serialNumber, caKey, null, null);
    }

    /**
     * Только для тестов формата DER/подписи. Без проверки политики (EKU).
     */
    static void verify(
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

        SingleOcspResponse target = findSingleResponse(ocsp, serialNumber);

        // Проверка подписи — до certStatus (fail-closed, исключает подделку статуса)
        ocsp.verify(caKey);

        verifyStatusAndFreshness(target, ocspResponse, null, false);

        // CertID defense-in-depth (опционально в низкоуровневом API)
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
     * Только для тестов формата DER/подписи. Без проверки политики (EKU).
     */
    static void verify(
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
