package org.rssys.gost.pkix.cert;

import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

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

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cert.OcspVerifier");

    /** Причины, по которым делегированный сертификат ответчика не принят (запись на DEBUG). */
    private static final String SKIP_EXPIRED = "expired or not yet valid";

    private static final String SKIP_NOT_OCSP_SIGNING = "no id-kp-OCSPSigning";
    private static final String SKIP_KEY_USAGE = "keyUsage forbids signing";
    private static final String SKIP_NOT_ISSUED_BY_CA = "not signed by the issuer";
    private static final String SKIP_RESPONSE_SIGNATURE = "response signature does not match";

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
                ocspResponse,
                serialNumber,
                issuerCert,
                issuerCert,
                null,
                GostOids.MAX_OCSP_AGE_MS,
                null);
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
                GostOids.MAX_OCSP_AGE_MS,
                null);
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
     * @param maxThisUpdateAge необязательный предел возраста {@code thisUpdate} для всех
     *                      ответов (в том числе с {@code nextUpdate}); {@code null} — не задан.
     *                      Ответ без {@code nextUpdate} ограничен меньшим из двух пределов.
     *                      Должен быть положительным; допуск часов не применяется
     * @throws IllegalArgumentException если {@code maxThisUpdateAge} нулевой или отрицательный
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuerCert,
            byte[] expectedNonce,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws PkixException {
        verifyWithCert(
                ocspResponse,
                serialNumber,
                issuerCert,
                issuerCert,
                expectedNonce,
                maxOcspAgeMs,
                maxThisUpdateAge);
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
                GostOids.MAX_OCSP_AGE_MS,
                null);
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
     * @param maxThisUpdateAge   необязательный предел возраста {@code thisUpdate} для всех
     *                           ответов; {@code null} — не задан (подробнее см.
     *                           {@link #verify(byte[], byte[], GostCertificate, byte[], long,
     *                           Duration)})
     * @throws IllegalArgumentException если {@code maxThisUpdateAge} нулевой или отрицательный
     * @throws PkixException если ответ невалиден
     */
    public static void verify(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate certIdIssuer,
            GostCertificate responderAuthority,
            byte[] expectedNonce,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws PkixException {
        verifyWithCert(
                ocspResponse,
                serialNumber,
                certIdIssuer,
                responderAuthority,
                expectedNonce,
                maxOcspAgeMs,
                maxThisUpdateAge);
    }

    /**
     * Проверяет предел возраста {@code thisUpdate}: {@code null} допустим (предел не задан),
     * ноль и отрицательное значение отвергаются сразу, чтобы ошибка настройки не отключала
     * проверку молча. Общая точка для всех слоёв (TLS, JSSE), чтобы правило было одно.
     *
     * @param maxThisUpdateAge предел или {@code null}
     * @return тот же предел
     * @throws IllegalArgumentException если значение нулевое или отрицательное
     */
    public static Duration requireValidMaxThisUpdateAge(Duration maxThisUpdateAge) {
        // Duration.isPositive() появился только в Java 18 и отсутствует в API Android 14
        if (maxThisUpdateAge != null
                && (maxThisUpdateAge.isNegative() || maxThisUpdateAge.isZero())) {
            throw new IllegalArgumentException("maxThisUpdateAge must be positive");
        }
        return maxThisUpdateAge;
    }

    private static void verifyWithCert(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate certIdIssuer,
            GostCertificate responderAuthority,
            byte[] expectedNonce,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws PkixException {
        // Ошибка настройки не должна зависеть от содержимого ответа: проверяем до разбора
        requireValidMaxThisUpdateAge(maxThisUpdateAge);
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

        // Серийный номер уникален лишь в пределах УЦ, поэтому запись выбираем по полному CertID
        SingleOcspResponse target =
                selectSingleResponse(ocsp, serialNumber, certIdIssuer, DuplicatePolicy.LENIENT);

        verifySignatureAndResponder(ocsp, responderAuthority);

        // CertID (issuerNameHash/issuerKeyHash) считается от ИСТИННОГО издателя листа
        // (certIdIssuer), а не от authority: это разные роли RFC 6960. При обычной
        // конфигурации оба параметра — один и тот же сертификат CA.
        // Сверка стоит до статуса: если все записи с нашим номером чужие, отказ должен
        // быть по CertID, а не ложным REVOKED от чужой записи.
        verifyCertId(target, certIdIssuer.getPublicKey(), certIdIssuer);

        // Статус, свежесть, nonce
        verifyStatusAndFreshness(target, ocsp, expectedNonce, maxOcspAgeMs, maxThisUpdateAge);

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
     * <p>Кроме сертификатов из самого ответа проверяются недоверенные кандидаты
     * (например, из certificate-values CAdES-X Long): они проходят те же проверки,
     * включая подпись издателем проверяемого сертификата, и якорями не становятся.
     *
     * @return совпавший делегированный сертификат или {@code null}
     */
    private static GostCertificate tryDelegatedVerification(
            GostOcspResponse ocsp,
            GostCertificate issuerCert,
            List<GostCertificate> untrustedResponderCandidates) {
        // Встроенные сертификаты идут первыми: кандидаты из certificate-values нужны
        // только когда ответчика нет в самом ответе (КриптоПро так и пишет).
        List<GostCertificate> delegates = new ArrayList<>();
        for (byte[] dcDer : ocsp.getDelegatedCertificates()) {
            // certs приходит из недоверенного ответа и разбирается до проверки подписи.
            // Конструктор на мусоре вправе бросить любое RuntimeException, поэтому catch
            // охватывает только этот разбор; нераспознанный сертификат просто не кандидат
            // в подписанты. DER и исключение в журнал не пишем: ввод недоверенный.
            try {
                delegates.add(new GostCertificate(dcDer));
            } catch (RuntimeException e) {
                LOG.log(
                        Level.DEBUG,
                        "Skipping unparsable certificate in OCSP response certs ({0} bytes)",
                        dcDer.length);
            }
        }
        for (GostCertificate candidate : untrustedResponderCandidates) {
            boolean duplicate = false;
            for (GostCertificate existing : delegates) {
                if (Arrays.equals(existing.getEncoded(), candidate.getEncoded())) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                delegates.add(candidate);
            }
        }

        // Итоговый отказ «OCSP signature verification failed» не говорит, какой из кандидатов
        // и почему отброшен, поэтому каждый пропуск пишется на DEBUG с серийным номером
        for (GostCertificate dc : delegates) {
            if (dc.isExpired()) {
                logDelegateSkipped(dc, SKIP_EXPIRED);
                continue;
            }
            if (!dc.isOcspSigning()) {
                logDelegateSkipped(dc, SKIP_NOT_OCSP_SIGNING);
                continue;
            }
            if (!dc.isKeyUsageValid()) {
                logDelegateSkipped(dc, SKIP_KEY_USAGE);
                continue;
            }

            // Делегированный сертификат должен быть подписан issuer'ом
            if (!dc.verifySignature(issuerCert.getPublicKey())) {
                logDelegateSkipped(dc, SKIP_NOT_ISSUED_BY_CA);
                continue;
            }

            // Проверяем подпись OCSP-ответа ключом делегированного сертификата
            try {
                ocsp.verify(dc.getPublicKey());
                logDelegatedNoCheckStatus(dc);
                return dc;
            } catch (PkixException ignored) {
                // Пробуем следующий delegated cert
                logDelegateSkipped(dc, SKIP_RESPONSE_SIGNATURE);
            }
        }
        return null;
    }

    private static void logDelegateSkipped(GostCertificate dc, String reason) {
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(
                    Level.DEBUG,
                    "Delegated OCSP responder candidate (serial 0x{0}) skipped: {1}",
                    dc.getSerialNumberBigInt().toString(16),
                    reason);
        }
    }

    /**
     * Диагностика соответствия делегированного responder-сертификата RFC 6960
     * §4.2.2.2.1. Решение доверять (pass/fail) НЕ меняется — отзыв делегата
     * по-прежнему не проверяется. Логируется лишь аномалия для аудита.
     *
     * <p>Аномалия (case 2 RFC): CA явно повесил на делегата точку проверки отзыва
     * (CDP или AIA-OCSP), но забыл id-pkix-ocsp-nocheck. Это регулярный CA/Browser
     * Forum инцидент. Легальные случаи 1 (nocheck есть) и 3 (ничего не указано) —
     * уровень DEBUG.</p>
     *
     * <p>Учитывается только id-ad-ocsp ({@code getOcspUris()}), не caIssuers: caIssuers
     * указывает на родительский CA-сертификат и к проверке отзыва делегата отношения
     * не имеет.</p>
     */
    private static void logDelegatedNoCheckStatus(GostCertificate dc) {
        if (isMissingNoCheckAnomaly(dc)) {
            LOG.log(
                    Level.WARNING,
                    "Delegated OCSP responder certificate (serial 0x{0}) has revocation"
                            + " pointers but lacks id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1)",
                    dc.getSerialNumberBigInt().toString(16));
        } else {
            LOG.log(
                    Level.DEBUG,
                    "Delegated OCSP responder certificate (serial 0x{0}) accepted;"
                            + " ocsp-nocheck={1}",
                    dc.getSerialNumberBigInt().toString(16),
                    dc.hasOcspNoCheck());
        }
    }

    /**
     * Предикат аномалии RFC 6960 §4.2.2.2.1 (case 2): у делегата есть точка проверки
     * отзыва (CDP или AIA-OCSP), но нет id-pkix-ocsp-nocheck. Вынесен отдельно, чтобы
     * тесты могли перебрать все четыре угла условия {@code AND/!} без хрупкого перехвата
     * лога. На решение доверять (pass/fail) НЕ влияет.
     *
     * <p>Учитывается только id-ad-ocsp ({@code getOcspUris()}), не caIssuers: caIssuers
     * указывает на родительский CA-сертификат и к проверке отзыва делегата отношения
     * не имеет.</p>
     */
    static boolean isMissingNoCheckAnomaly(GostCertificate dc) {
        boolean hasOwnRevocationPointer = dc.getCdpUris() != null || dc.getOcspUris() != null;
        return hasOwnRevocationPointer && !dc.hasOcspNoCheck();
    }

    /**
     * Проверяет подпись OCSP-ответа (напрямую или делегированным responder'ом)
     * и byKey responder ID. Возвращает сертификат фактического подписанта.
     */
    private static GostCertificate verifySignatureAndResponder(
            GostOcspResponse ocsp, GostCertificate responderAuthority) throws PkixException {
        return verifySignatureAndResponder(ocsp, responderAuthority, List.of());
    }

    private static GostCertificate verifySignatureAndResponder(
            GostOcspResponse ocsp,
            GostCertificate responderAuthority,
            List<GostCertificate> untrustedResponderCandidates)
            throws PkixException {
        PublicKeyParameters authorityPub = responderAuthority.getPublicKey();
        GostCertificate signerCert;
        boolean sigOk;
        try {
            ocsp.verify(authorityPub);
            sigOk = true;
            signerCert = responderAuthority;
        } catch (PkixException e) {
            sigOk = false;
            signerCert = null;
        }

        if (!sigOk) {
            signerCert =
                    tryDelegatedVerification(
                            ocsp, responderAuthority, untrustedResponderCandidates);
            sigOk = signerCert != null;
        }

        if (!sigOk) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "OCSP signature verification failed");
        }

        verifyResponderId(ocsp, signerCert);
        return signerCert;
    }

    /**
     * Проверяет CertID (issuerNameHash/issuerKeyHash) автоматически
     * из issuerCert.
     */
    private static void verifyCertId(
            SingleOcspResponse target, PublicKeyParameters issuerPub, GostCertificate issuerCert)
            throws PkixException {
        int certIdHashLen = certIdHashLength(target, issuerPub);

        // issuerNameHash = hash(subject DN issuer-а)
        byte[] expectedNameHash = CertIdHasher.hashIssuerName(issuerCert, certIdHashLen);
        if (!MessageDigest.isEqual(target.issuerNameHash(), expectedNameHash)) {
            throw new PkixException("OCSP: issuerNameHash mismatch");
        }

        // issuerKeyHash = hash(публичного ключа issuer-а)
        byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(issuerCert, certIdHashLen);
        if (!MessageDigest.isEqual(target.issuerKeyHash(), expectedKeyHash)) {
            throw new PkixException("OCSP: issuerKeyHash mismatch");
        }
    }

    /**
     * Длина хэша CertID: берётся из самой записи ответа, а не из ключа УЦ — алгоритм
     * хэширования CertID выбирает запрашивающая сторона и он не обязан совпадать с размером
     * ключа УЦ (Р 1323565.1.059-2024, пп. 7.2.2.2, 8.1). Парсер ответа гарантирует, что
     * длина хэша соответствует OID алгоритма (32 или 64); для записей с иной длиной
     * (синтетические записи в тестах) остаётся прежнее правило — длина по ключу издателя.
     */
    private static int certIdHashLength(SingleOcspResponse target, PublicKeyParameters issuerPub) {
        int declared = target.issuerNameHash().length;
        if (declared == GostOids.STREEBOG_256_HASH_LEN
                || declared == GostOids.STREEBOG_512_HASH_LEN) {
            return declared;
        }
        return issuerPub.getParams().hlen;
    }

    /** Полное совпадение CertID записи с издателем: issuerNameHash и issuerKeyHash. */
    private static boolean matchesCertId(SingleOcspResponse candidate, GostCertificate issuer) {
        int certIdHashLen = certIdHashLength(candidate, issuer.getPublicKey());
        // Сравнение идёт до проверки подписи и по каждой записи с нашим номером, поэтому
        // перегрузки по GostCertificate: они не разбирают DER издателя заново на каждую запись
        byte[] expectedNameHash = CertIdHasher.hashIssuerName(issuer, certIdHashLen);
        byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(issuer, certIdHashLen);
        // Обе сверки выполняются безусловно: результат нужен только как признак совпадения
        boolean nameMatches = MessageDigest.isEqual(candidate.issuerNameHash(), expectedNameHash);
        boolean keyMatches = MessageDigest.isEqual(candidate.issuerKeyHash(), expectedKeyHash);
        return nameMatches && keyMatches;
    }

    /**
     * Проверяет byKey responder ID: хэш публичного ключа подписанта
     * должен совпадать с {@link GostOcspResponse#getResponderKeyHash()}.
     *
     * <p>Хэш вычисляется через Streebog — ГОСТ-конвенция (32 или 64 байта). Норма
     * (п. 7.3.3.3) требует SHA-1: ответ с 20-байтным byKey принимается без сверки, потому
     * что подпись уже проверена конкретным ключом, а ResponderID — лишь идентификатор,
     * не источник доверия. Прочие длины отвергаются. Для byName сверка не выполняется:
     * имя в ответе с именем подписанта не сравнивается, доверие даёт только проверка
     * подписи конкретным ключом.</p>
     */
    private static void verifyResponderId(GostOcspResponse ocsp, GostCertificate signerCert)
            throws PkixException {
        if (ocsp.getResponderIdType() != GostOcspResponse.ResponderIdType.BY_KEY) {
            return;
        }
        byte[] responderKeyHash = ocsp.getResponderKeyHash();
        int hashLen = responderKeyHash.length;
        if (hashLen == GostOids.SHA1_HASH_LEN) {
            // Законный случай для сторонней службы: на каждом верном ответе не шумим
            LOG.log(Level.DEBUG, "OCSP responder key hash is SHA-1 (20 bytes), comparison skipped");
            return;
        }
        if (hashLen != GostOids.STREEBOG_256_HASH_LEN
                && hashLen != GostOids.STREEBOG_512_HASH_LEN) {
            // Иначе hashIssuerPublicKey бросил бы IllegalArgumentException наружу
            throw new PkixException("OCSP: unsupported responder key hash length: " + hashLen);
        }
        byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(signerCert, hashLen);
        if (!MessageDigest.isEqual(responderKeyHash, expectedKeyHash)) {
            throw new PkixException("OCSP: responder key hash mismatch");
        }
    }

    /**
     * Проверяет certStatus, свежесть (thisUpdate/nextUpdate) и nonce.
     * Общая часть для certificate-based и key-based путей верификации.
     *
     * @param maxOcspAgeMs максимальный возраст ответа без {@code nextUpdate}
     *                     (локальная политика свежести, RFC 6960 §2.4)
     * @param maxThisUpdateAge необязательный предел возраста {@code thisUpdate} для всех
     *                     ответов (Р 1323565.1.059-2024, п. 5.3) или {@code null}
     */
    static void verifyStatusAndFreshness(
            SingleOcspResponse target,
            GostOcspResponse ocsp,
            byte[] expectedNonce,
            long maxOcspAgeMs,
            Duration maxThisUpdateAge)
            throws PkixException {
        verifyStatus(target);

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
        // Сравнение возраста с пределом без сложения: для очень большого предела
        // thisUpdate.plus(предел) переполнилось бы и оборвало проверку из-за настройки.
        // Допуск часов не применяется, как и к maxOcspAgeMs
        if (maxThisUpdateAge != null
                && Duration.between(target.thisUpdate(), Instant.now()).compareTo(maxThisUpdateAge)
                        > 0) {
            throw new PkixException("OCSP: response older than allowed thisUpdate age");
        }

        // Nonce проверка
        if (expectedNonce != null) {
            verifyNonce(ocsp, expectedNonce);
        }
    }

    /**
     * Проверяет certStatus: {@code revoked} и любой статус, отличный от
     * {@code good} (включая {@code unknown}), отклоняются.
     */
    static void verifyStatus(SingleOcspResponse target) throws PkixException {
        if (target.isRevoked()) {
            throw new PkixException(PkixException.Reason.REVOKED, "OCSP: certificate is revoked");
        }
        if (!target.isGood()) {
            throw new PkixException(PkixException.Reason.OTHER, "OCSP: certStatus is not 'good'");
        }
    }

    /**
     * Оценивает окно выпуска OCSP-ответа для CAdES-X Long.
     *
     * <p>Возвращает {@code OUT_OF_WINDOW} только для структурно валидного
     * {@code good}-ответа. Все структурные ошибки и неверные статусы должны
     * быть проверены вызывающим кодом до этого метода.</p>
     */
    static EvidenceFreshness evaluateFreshness(
            SingleOcspResponse target,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            long maxOcspAgeMs) {
        Instant collection = window.collectionTime();
        Instant signing = window.signingTime();
        Instant thisUpdate = target.thisUpdate();
        Instant nextUpdate = target.nextUpdate();

        boolean issuedNotAfterCollection =
                !thisUpdate.isAfter(collection.plusMillis(GostOids.CLOCK_SKEW_MS));
        boolean issuedNotBeforeSigning =
                policy != RevocationFreshnessPolicy.STRICT
                        || !thisUpdate.isBefore(signing.minusMillis(GostOids.CLOCK_SKEW_MS));

        boolean freshAtCollection;
        if (nextUpdate != null) {
            freshAtCollection = !collection.isAfter(nextUpdate.plusMillis(GostOids.CLOCK_SKEW_MS));
        } else {
            freshAtCollection = !collection.isAfter(thisUpdate.plusMillis(maxOcspAgeMs));
        }

        return (issuedNotAfterCollection && issuedNotBeforeSigning && freshAtCollection)
                ? EvidenceFreshness.IN_WINDOW
                : EvidenceFreshness.OUT_OF_WINDOW;
    }

    /**
     * Проверяет одно OCSP-доказательство для CAdES-X Long.
     *
     * <p>Порядок: структура и подпись, serial/CertID, статус, затем окно.
     * {@code revoked}/{@code unknown} отклоняются до окна.</p>
     */
    static EvidenceFreshness verifyEvidence(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuer,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy)
            throws PkixException {
        return verifyEvidence(ocspResponse, serialNumber, issuer, window, policy, List.of());
    }

    /**
     * То же, что {@link #verifyEvidence(byte[], byte[], GostCertificate,
     * RevocationEvidenceWindow, RevocationFreshnessPolicy)}, но дополнительно ищет
     * делегированного ответчика среди недоверенных кандидатов.
     *
     * <p>Кандидат нужен, когда ответчик не встроен в ответ и лежит только в
     * certificate-values. Он проходит все проверки встроенного делегата и доверия
     * не получает.</p>
     */
    static EvidenceFreshness verifyEvidence(
            byte[] ocspResponse,
            byte[] serialNumber,
            GostCertificate issuer,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            List<GostCertificate> untrustedResponderCandidates)
            throws PkixException {
        List<GostCertificate> uniqueCandidates =
                normalizeResponderCandidates(untrustedResponderCandidates);
        if (ocspResponse == null) {
            throw new PkixException("No OCSP response available");
        }
        if (serialNumber == null) {
            throw new PkixException("serialNumber must not be null");
        }
        if (issuer == null) {
            throw new PkixException("issuer must not be null");
        }
        if (window == null) {
            throw new IllegalArgumentException("window must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }

        GostOcspResponse ocsp = new GostOcspResponse(ocspResponse);
        if (!ocsp.isSuccessful()) {
            throw new PkixException(
                    "OCSP: response status = "
                            + ocsp.getResponseStatus()
                            + " (expected 0/successful)");
        }

        SingleOcspResponse target =
                selectSingleResponse(ocsp, serialNumber, issuer, DuplicatePolicy.STRICT);
        verifySignatureAndResponder(ocsp, issuer, uniqueCandidates);
        verifyCertId(target, issuer.getPublicKey(), issuer);

        if (target.nextUpdate() != null && target.nextUpdate().isBefore(target.thisUpdate())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "OCSP: nextUpdate is before thisUpdate");
        }

        verifyStatus(target);

        return evaluateFreshness(target, window, policy, GostOids.MAX_OCSP_AGE_MS);
    }

    /**
     * Проверяет список кандидатов в делегированные ответчики: без null, сырой размер
     * ограничен, дубликаты по DER схлопываются, лимит действует на уникальные.
     *
     * <p>Лимит по уникальным, а не по сырому списку: дубли не должны вытеснять
     * легитимных кандидатов, а отдельный сырой предел защищает саму дедупликацию.</p>
     */
    private static List<GostCertificate> normalizeResponderCandidates(
            List<GostCertificate> candidates) throws PkixException {
        if (candidates == null) {
            throw new IllegalArgumentException("untrustedResponderCandidates must not be null");
        }
        if (candidates.size() > GostOids.MAX_RAW_OCSP_RESPONDER_CANDIDATES) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "OCSP: too many responder candidates: " + candidates.size());
        }
        List<GostCertificate> unique = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            GostCertificate candidate = candidates.get(i);
            if (candidate == null) {
                throw new IllegalArgumentException(
                        "untrustedResponderCandidates must not contain null, index " + i);
            }
            boolean duplicate = false;
            for (GostCertificate existing : unique) {
                if (Arrays.equals(existing.getEncoded(), candidate.getEncoded())) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                unique.add(candidate);
            }
        }
        if (unique.size() > GostOids.MAX_OCSP_RESPONDER_CANDIDATES) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "OCSP: too many distinct responder candidates: " + unique.size());
        }
        return unique;
    }

    /**
     * Политика при нескольких записях с одинаковым полным CertID.
     * {@link #LENIENT}: отказ только при разном статусе, при одинаковом берётся первая —
     * сохраняет поведение, принимавшееся до разбора по полному CertID.
     * {@link #STRICT}: отказ при любом дубликате (долговременное доказательство CAdES-X Long).
     */
    private enum DuplicatePolicy {
        LENIENT,
        STRICT
    }

    /**
     * Выбирает запись ответа для проверяемого сертификата.
     *
     * <p>Серийный номер уникален лишь в пределах одного УЦ, а служба может обслуживать
     * несколько УЦ, поэтому среди записей с нашим серийным номером берётся та, у которой
     * совпал полный CertID. Если совпадения нет, возвращается первая запись с нашим номером:
     * следующая за выбором {@link #verifyCertId} отвергнет её с понятной причиной.
     * Чужая запись никогда не заменяет нашу: подпись ответа проверяется в любом случае, а
     * принятие ответа возможно только после сверки CertID выбранной записи.</p>
     */
    private static SingleOcspResponse selectSingleResponse(
            GostOcspResponse ocsp,
            byte[] serialNumber,
            GostCertificate issuer,
            DuplicatePolicy duplicatePolicy)
            throws PkixException {
        SingleOcspResponse firstBySerial = null;
        SingleOcspResponse firstFullMatch = null;
        for (SingleOcspResponse sr : ocsp.getResponses()) {
            if (!Arrays.equals(sr.certSerialNumber(), serialNumber)) {
                continue;
            }
            if (firstBySerial == null) {
                firstBySerial = sr;
            }
            if (!matchesCertId(sr, issuer)) {
                continue;
            }
            if (firstFullMatch == null) {
                firstFullMatch = sr;
            } else if (duplicatePolicy == DuplicatePolicy.STRICT
                    || !sameStatus(firstFullMatch, sr)) {
                throw new PkixException(
                        "OCSP: multiple SingleResponse entries for the same CertID");
            }
        }
        if (firstBySerial == null) {
            throw new PkixException("OCSP: serialNumber not found in any SingleResponse");
        }
        return firstFullMatch != null ? firstFullMatch : firstBySerial;
    }

    // Первичная (0x80/0x82) и конструктивная (0xA0/0xA2) формы good и unknown — один статус,
    // как в isGood()/isUnknown() и verifyStatus: иначе разная кодировка давала бы ложное
    // противоречие
    private static boolean sameStatus(SingleOcspResponse a, SingleOcspResponse b) {
        return (a.isGood() && b.isGood())
                || (a.isRevoked() && b.isRevoked())
                || (a.isUnknown() && b.isUnknown())
                || a.certStatusTag() == b.certStatusTag();
    }

    /** Поиск первой записи по серийному номеру — для низкоуровневых тестовых перегрузок. */
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

        verifyStatusAndFreshness(target, ocsp, null, GostOids.MAX_OCSP_AGE_MS, null);

        // CertID defense-in-depth (опционально в низкоуровневом API)
        if (expectedIssuerDn != null && issuerCertDer != null) {
            int hlen = caKey.getParams().hlen;
            int certIdHashLen = hlen;

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
