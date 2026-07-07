package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;

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
    public static void verify(byte[] ocspResponse, byte[] serialNumber, GostCertificate issuerCert)
            throws PkixException {
        verifyWithCert(
                ocspResponse, serialNumber, issuerCert, issuerCert, null, GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Верифицирует OCSP-ответ с проверкой nonce (RFC 8954).
     *
     * @param ocspResponse  DER-кодированный OCSP-ответ
     * @param serialNumber  серийный номер проверяемого сертификата
     * @param issuerCert    сертификат издателя
     * @param expectedNonce ожидаемый nonce (из запроса) или null — не проверять
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuerCert,
            byte[] expectedNonce)
            throws PkixException {
        verifyWithCert(
                ocspResponse,
                serialNumber,
                issuerCert,
                issuerCert,
                expectedNonce,
                GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Верифицирует OCSP-ответ с проверкой nonce и настраиваемой политикой свежести.
     *
     * <p>Перегрузка для случаев, когда CA легитимно выпускает OCSP-ответы без
     * {@code nextUpdate}, но с фактическим сроком годности, отличным от дефолтных
     * {@value org.rssys.gost.pkix.GostOids#MAX_OCSP_AGE_MS} мс (RFC 6960 §2.4 —
     * relying party применяет локальную политику свежести).</p>
     *
     * @param ocspResponse  DER-кодированный OCSP-ответ
     * @param serialNumber  серийный номер проверяемого сертификата
     * @param issuerCert    сертификат издателя
     * @param expectedNonce ожидаемый nonce (из запроса) или null — не проверять
     * @param maxOcspAgeMs  максимальный возраст ответа без {@code nextUpdate} в мс
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuerCert,
            byte[] expectedNonce,
            long maxOcspAgeMs)
            throws PkixException {
        verifyWithCert(
                ocspResponse, serialNumber, issuerCert, issuerCert, expectedNonce, maxOcspAgeMs);
    }

    /**
     * Верифицирует OCSP-ответ с раздельными ролями RFC 6960: источник CertID-хэшей
     * и authority подписи ответа задаются явно.
     *
     * <p>В штатной конфигурации обе роли исполняет один сертификат CA (см. перегрузки
     * с одним {@code issuerCert}). Раздельные параметры нужны в редких легитимных
     * сценариях — например, при плановой смене ключа CA (key rollover) с действующим
     * кросс-сертификатом, когда ответ подписан новым ключом, а CertID листа считается
     * от старого издателя.</p>
     *
     * <p><b>Важно:</b> authority обязан криптографически цепляться к истинному издателю
     * листа. Совпадение одного лишь Subject DN двух CA (RFC 6960 §4.2.2.2) доверия не
     * создаёт — при отсутствии кросс-сертификата верификация корректно завершится
     * отказом (fail-closed).</p>
     *
     * @param ocspResponse      DER-кодированный OCSP-ответ
     * @param serialNumber      серийный номер проверяемого сертификата
     * @param certIdIssuer      истинный издатель листа — источник issuerNameHash/issuerKeyHash
     * @param responderAuthority authority подписи ответа (прямой ключ или издатель делегата)
     * @param expectedNonce     ожидаемый nonce (из запроса) или null — не проверять
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate certIdIssuer,
            GostCertificate responderAuthority,
            byte[] expectedNonce)
            throws PkixException {
        verifyWithCert(
                ocspResponse,
                serialNumber,
                certIdIssuer,
                responderAuthority,
                expectedNonce,
                GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Верифицирует OCSP-ответ с раздельными ролями RFC 6960 и настраиваемой политикой
     * свежести. Полная перегрузка — см. {@link #verify(byte[], byte[], GostCertificate,
     * GostCertificate, byte[])} о смысле раздельных {@code certIdIssuer} и
     * {@code responderAuthority}.
     *
     * @param ocspResponse       DER-кодированный OCSP-ответ
     * @param serialNumber       серийный номер проверяемого сертификата
     * @param certIdIssuer       истинный издатель листа — источник issuerNameHash/issuerKeyHash
     * @param responderAuthority authority подписи ответа (прямой ключ или издатель делегата)
     * @param expectedNonce      ожидаемый nonce (из запроса) или null — не проверять
     * @param maxOcspAgeMs       максимальный возраст ответа без {@code nextUpdate} в мс
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate certIdIssuer,
            GostCertificate responderAuthority,
            byte[] expectedNonce,
            long maxOcspAgeMs)
            throws PkixException {
        verifyWithCert(
                ocspResponse,
                serialNumber,
                certIdIssuer,
                responderAuthority,
                expectedNonce,
                maxOcspAgeMs);
    }

    private static void verifyWithCert(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate certIdIssuer,
            GostCertificate responderAuthority,
            byte[] expectedNonce,
            long maxOcspAgeMs)
            throws PkixException {
        if (ocspResponse == null) {
            throw new PkixException("No OCSP response available");
        }
        if (certIdIssuer == null) {
            throw new PkixException("certIdIssuer must not be null");
        }
        if (responderAuthority == null) {
            throw new PkixException("responderAuthority must not be null");
        }
        LOG.log(
                Level.DEBUG,
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

        // Подпись ответа принадлежит authority (RFC 6960 §4.2.2.2): либо напрямую
        // его ключом, либо делегированным responder-сертификатом, выпущенным authority.
        PublicKeyParameters authorityPub = responderAuthority.getPublicKey();
        GostCertificate signerCert; // сертификат, чьим ключом подписан ответ
        boolean sigOk;
        try {
            ocsp.verify(authorityPub);
            sigOk = true;
            signerCert = responderAuthority;
        } catch (PkixException e) {
            sigOk = false;
            signerCert = null;
        }

        // Если прямая подпись authority не подошла — пробуем делегированные responder'ы
        if (!sigOk) {
            signerCert = tryDelegatedVerification(ocsp, responderAuthority);
            sigOk = signerCert != null;
        }

        if (!sigOk) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "OCSP signature verification failed");
        }

        // Проверка byKey responder ID: хэш ключа должен совпадать с ключом подписанта
        verifyResponderId(ocsp, signerCert);

        // Статус, свежесть, CertID
        verifyStatusAndFreshness(target, ocsp, expectedNonce, maxOcspAgeMs);

        // CertID (issuerNameHash/issuerKeyHash) считается от ИСТИННОГО издателя листа
        // (certIdIssuer), а не от authority: это разные роли RFC 6960. При обычной
        // конфигурации оба параметра — один и тот же сертификат CA.
        verifyCertId(target, certIdIssuer.getPublicKey(), certIdIssuer);

        LOG.log(
                Level.DEBUG,
                "OCSP verification passed for certificate serial 0x{0}",
                new BigInteger(1, serialNumber).toString(16));
    }

    /**
     * Перебирает делегированные responder-сертификаты из поля certs.
     * Порядок pre-checks (дёшево→дорого) из RFC 6960 §4.2.2.2:
     * expiry → EKU → KeyUsage → подпись делегированного сертификата.
     *
     * <p>Проверка отзыва (CRL/OCSP) делегированного responder-сертификата
     * не выполняется. Осознанное решение: RFC 6960 §4.2.2.2.1 определяет
     * id-pkix-ocsp-nocheck — делегированные responder-сертификаты короткоживущие
     * (24–48 часов), проверка их отзыва через OCSP создала бы циклическую
     * зависимость.
     *
     * @return совпавший делегированный сертификат или {@code null}
     */
    private static GostCertificate tryDelegatedVerification(
            GostOcspResponse ocsp, GostCertificate issuerCert) {
        List<byte[]> dcDers = ocsp.getDelegatedCertificates();
        if (dcDers.isEmpty()) {
            return null;
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
                return dc;
            } catch (PkixException ignored) {
                // Пробуем следующий delegated cert
            }
        }
        return null;
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
        if (!MessageDigest.isEqual(target.issuerNameHash(), expectedNameHash)) {
            throw new PkixException("OCSP: issuerNameHash mismatch");
        }

        // issuerKeyHash = hash(публичного ключа issuer-а)
        byte[] expectedKeyHash =
                CertIdHasher.hashIssuerPublicKey(issuerCert.getEncoded(), certIdHashLen);
        if (!MessageDigest.isEqual(target.issuerKeyHash(), expectedKeyHash)) {
            throw new PkixException("OCSP: issuerKeyHash mismatch");
        }
    }

    /**
     * Проверяет byKey responder ID: хэш публичного ключа подписанта
     * должен совпадать с {@link GostOcspResponse#getResponderKeyHash()}.
     *
     * <p>Хэш вычисляется через Streebog — ГОСТ-конвенция. Для byName
     * проверка не требуется (DN подписанта проверяется через цепочку).</p>
     */
    private static void verifyResponderId(GostOcspResponse ocsp, GostCertificate signerCert)
            throws PkixException {
        if (ocsp.getResponderIdType() != GostOcspResponse.ResponderIdType.BY_KEY) {
            return;
        }
        byte[] expectedKeyHash =
                CertIdHasher.hashIssuerPublicKey(signerCert, ocsp.getResponderKeyHash().length);
        if (!MessageDigest.isEqual(ocsp.getResponderKeyHash(), expectedKeyHash)) {
            throw new PkixException("OCSP: responder key hash mismatch");
        }
    }

    /**
     * Проверяет certStatus, свежесть (thisUpdate/nextUpdate) и nonce.
     * Общая часть для certificate-based и key-based путей верификации.
     *
     * @param maxOcspAgeMs максимальный возраст ответа без {@code nextUpdate}
     *                     (локальная политика свежести, RFC 6960 §2.4)
     */
    static void verifyStatusAndFreshness(
            SingleOcspResponse target,
            GostOcspResponse ocsp,
            byte[] expectedNonce,
            long maxOcspAgeMs)
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
        if (target.nextUpdate() == null
                && Instant.now().isAfter(target.thisUpdate().plusMillis(maxOcspAgeMs))) {
            throw new PkixException("OCSP: response too old (no nextUpdate)");
        }

        // Nonce проверка
        if (expectedNonce != null) {
            verifyNonce(ocsp, expectedNonce);
        }
    }

    private static SingleOcspResponse findSingleResponse(GostOcspResponse ocsp, byte[] serialNumber)
            throws PkixException {
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
                Level.DEBUG,
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

        verifyStatusAndFreshness(target, ocsp, null, GostOids.MAX_OCSP_AGE_MS);

        // CertID defense-in-depth (опционально в низкоуровневом API)
        if (expectedIssuerDn != null && issuerCertDer != null) {
            int hlen = caKey.getParams().hlen;
            int certIdHashLen =
                    hlen == GostOids.STREEBOG_512_HASH_LEN
                            ? GostOids.STREEBOG_512_HASH_LEN
                            : GostOids.STREEBOG_256_HASH_LEN;

            byte[] expectedNameHash = GostSignatureHelper.doHash(expectedIssuerDn, certIdHashLen);
            if (!MessageDigest.isEqual(target.issuerNameHash(), expectedNameHash)) {
                throw new PkixException("OCSP: issuerNameHash mismatch");
            }

            byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(issuerCertDer, certIdHashLen);
            if (!MessageDigest.isEqual(target.issuerKeyHash(), expectedKeyHash)) {
                throw new PkixException("OCSP: issuerKeyHash mismatch");
            }
        }

        LOG.log(
                Level.DEBUG,
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
            byte[] expectedNonce)
            throws PkixException {
        verify(ocspResponse, serialNumber, caKey, expectedIssuerDn, issuerCertDer);
        if (expectedNonce != null) {
            GostOcspResponse ocsp = new GostOcspResponse(ocspResponse);
            verifyNonce(ocsp, expectedNonce);
        }
    }

    // ========================================================================
    // verifyNonce
    // ========================================================================

    /**
     * Проверяет OCSP nonce (RFC 8954) в распарсенном OCSP-ответе.
     * Использует уже извлечённый nonce из {@link GostOcspResponse#getNonce()},
     * без повторного парсинга DER.
     *
     * @param ocsp          распарсенный OCSP-ответ
     * @param expectedNonce ожидаемое значение nonce (из запроса)
     * @throws PkixException при несовпадении nonce
     */
    static void verifyNonce(GostOcspResponse ocsp, byte[] expectedNonce) throws PkixException {
        if (expectedNonce == null) return;

        byte[] responseNonce = ocsp.getNonce();
        if (responseNonce == null) {
            throw new PkixException(
                    "OCSP: response missing nonce, but nonce was expected in request");
        }

        if (!MessageDigest.isEqual(responseNonce, expectedNonce)) {
            throw new PkixException("OCSP: nonce mismatch");
        }
    }
}
