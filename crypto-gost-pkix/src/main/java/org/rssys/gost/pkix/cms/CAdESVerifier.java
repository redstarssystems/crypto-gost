package org.rssys.gost.pkix.cms;

import static org.rssys.gost.pkix.cms.CAdESSupport.addIfAbsent;
import static org.rssys.gost.pkix.cms.CAdESSupport.buildEscHashInput;
import static org.rssys.gost.pkix.cms.CAdESSupport.computeTspMessageImprint;
import static org.rssys.gost.pkix.cms.CAdESSupport.containsDer;
import static org.rssys.gost.pkix.cms.CAdESSupport.extractEmbeddedCerts;
import static org.rssys.gost.pkix.cms.CAdESSupport.mergeCertsIntoField;
import static org.rssys.gost.pkix.cms.CAdESSupport.parseAttributeTlvs;
import static org.rssys.gost.pkix.cms.CAdESSupport.unsignedAttrsContent;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.CertRevocationEvidence;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationEvidenceWindow;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.cms.CAdESSupport.SignatureHashResult;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TstInfo;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Проверка CAdES-подписей (ETSI EN 319 122-1): BES, T, C, X Long Type 1 и контрподписи.
 *
 * <p>Уровень проверки виден в имени метода: каждый уровень - отдельный контракт
 * (T требует signature-time-stamp, C - референсы, XLong - значения сертификатов и отзыва).
 * Проверка уровня не оценивает атрибуты более высоких уровней: подпись, доукомплектованная
 * до T/C/XLong, по-прежнему проходит {@code verifyBES}, а список меток в результате пуст.</p>
 *
 * <p>Срок якоря: если политика {@link TrustAnchors} равна {@link AnchorExpiryPolicy#DEFAULT},
 * применяется {@link AnchorExpiryPolicy#REJECT}; явное значение сохраняется для подписи,
 * цепочки значений сертификатов и контрподписанта. Цепочка TSA всегда проверяется со строгим
 * {@link AnchorExpiryPolicy#REJECT}: доказательство времени не ослабляется.</p>
 *
 * <p>Сборка (встраивание меток, контрподписей, ссылок и значений) - в {@link CAdESExtender}.</p>
 */
public final class CAdESVerifier {

    private CAdESVerifier() {}

    // ========================================================================
    // Верификация CAdES-BES / CAdES-T
    // ========================================================================

    /**
     * Верифицирует CAdES-BES подпись (без меток времени).
     *
     * <p>Для каждого подписанта выполняет:
     * <ol>
     *   <li>Проверка CMS-подписи (AND-семантика: все подписанты обязаны пройти)</li>
     *   <li>Проверка {@code signingCertificateV2} в signed-атрибутах — fail-closed</li>
     * </ol>
     *
     * <p>Метки времени <b>не требуются</b> — в отличие от {@link #verifyT}, который
     * дополнительно проверяет {@code signature-time-stamp} в unsigned-атрибутах.
     * Если на вход передан CAdES-T/C/X Long, метки и остальные атрибуты старших уровней не
     * оцениваются (штатный жизненный цикл BES -> T -> C -> X Long), список меток в результате
     * пуст; для их проверки используйте метод соответствующего уровня.
     *
     * @param cadesBesDer CAdES-BES подпись (CMS SignedData с signingCertificateV2)
     * @param anchors     доверенные якоря подписанта (не null и не пусты)
     * @return результат с данными и сертификатами подписантов (без меток)
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyBES(byte[] cadesBesDer, TrustAnchors anchors)
            throws PkixException {
        return verifyBESInternal(cadesBesDer, null, requireAnchors(anchors));
    }

    /**
     * Верифицирует detached CAdES-BES подпись и привязывает её к документу.
     *
     * <p>Отличается от {@link #verifyBES} только тем, что SignedData не содержит
     * eContent, а message-digest проверяется по переданному документу.
     *
     * @param cadesBesDer CAdES-BES SignedData без eContent
     * @param content     подписанный документ (не null)
     * @param anchors     доверенные якоря подписанта (не null и не пусты)
     * @return результат, в котором {@code data()} возвращает защитную копию документа
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyBESDetached(
            byte[] cadesBesDer, byte[] content, TrustAnchors anchors) throws PkixException {
        requireDetachedContent(content);
        return verifyBESInternal(cadesBesDer, content, requireAnchors(anchors));
    }

    /**
     * Проверяет контракт detached-методов: документ обязателен.
     *
     * <p>{@code content == null} в detached-режиме означает ошибку вызова, а не
     * повреждённую подпись, поэтому используется {@link IllegalArgumentException},
     * как в CMS-API.
     */
    private static void requireDetachedContent(byte[] content) {
        if (content == null) {
            throw new IllegalArgumentException("content must not be null");
        }
    }

    /**
     * Проверяет якоря и приводит политику срока к определённому значению.
     *
     * <p>Пустые или отсутствующие якоря - ошибка вызова, а не повреждённая подпись, поэтому
     * {@link IllegalArgumentException}, как в CMS-API. {@code DEFAULT} трактуется как
     * {@link AnchorExpiryPolicy#REJECT} (CAdES строже общего TLS); явное значение сохраняется.
     * Нормализация выполняется один раз на входе, чтобы все проверки цепочек видели одну политику.
     */
    private static TrustAnchors requireAnchors(TrustAnchors anchors) {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException("anchors must not be null or empty");
        }
        return anchors.expiryPolicy() == AnchorExpiryPolicy.DEFAULT
                ? anchors.withExpiryPolicy(AnchorExpiryPolicy.REJECT)
                : anchors;
    }

    /**
     * Сертификаты якорей в виде массива для {@link TspResponse#verify} и сверок по DER.
     *
     * <p>{@link TspResponse#verify} сам строит набор якорей и применяет {@code DEFAULT -> REJECT},
     * поэтому политика срока из {@code anchors} в проверку цепочки TSA не доходит: она всегда
     * строгая, доказательство времени не ослабляется.
     */
    private static GostCertificate[] anchorCertificates(TrustAnchors anchors) {
        return anchors.certificates().toArray(new GostCertificate[0]);
    }

    private static VerifiedCAdESData verifyBESInternal(
            byte[] cadesBesDer, byte[] content, TrustAnchors anchors) throws PkixException {
        Objects.requireNonNull(cadesBesDer, "cadesBesDer must not be null");

        VerifiedSignedData cmsResult =
                verifyAllSigners(cadesBesDer, content, anchors, CrlLimits.DEFAULT);

        List<CAdESSignerResult> signerResults = new ArrayList<>();
        for (SignerResult sr : cmsResult.signers()) {
            verifySigningCertV2ForSigner(sr);
            signerResults.add(
                    new CAdESSignerResult(
                            sr.signerCertificate(),
                            sr.signedAttributes(),
                            List.of(),
                            List.of(),
                            List.of(),
                            List.of(),
                            List.of(),
                            CAdESXLongData.RevocationValuesDecoded.EMPTY,
                            null));
        }

        return new VerifiedCAdESData(cmsResult.data(), signerResults);
    }

    // ========================================================================
    // Верификация CAdES-T
    // ========================================================================

    /**
     * Верифицирует CAdES-T подпись.
     *
     * <p>Для каждого подписанта выполняет:
     * <ol>
     *   <li>Проверка CMS-подписи (AND-семантика: все подписанты обязаны пройти)</li>
     *   <li>Проверка {@code signingCertificateV2} в signed-атрибутах — fail-closed</li>
     *   <li>Проверка {@code signature-time-stamp} в unsigned-атрибутах:
     *     <ul>
     *       <li>messageImprint == hash(подписи подписанта)</li>
     *       <li>Подпись TSA на TimeStampToken валидна</li>
     *       <li>Цепочка TSA валидна</li>
     *       <li>Сертификат подписанта действителен на genTime метки</li>
     *     </ul>
     *   </li>
     * </ol>
     *
     * <p><b>Не проверяет:</b> content-time-stamp (ES-C, signed-атрибут CONTENT_TIME_STAMP).
     * Верификация content-timestamp — только в {@link #verifyXLong(byte[], TrustAnchors)}.
     *
     * @param cadesTDer CAdES-T подпись (CMS SignedData с signingCertificateV2 и метками)
     * @param anchors   доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат с данными и верифицированными подписантами
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyT(byte[] cadesTDer, TrustAnchors anchors)
            throws PkixException {
        return verifyTInternal(cadesTDer, null, requireAnchors(anchors));
    }

    /**
     * Верифицирует detached CAdES-T подпись и привязывает её к документу.
     *
     * <p>Отличается от {@link #verifyT} только тем, что SignedData не содержит
     * eContent, а message-digest проверяется по переданному документу.
     *
     * @param cadesTDer CAdES-T SignedData без eContent
     * @param content   подписанный документ (не null)
     * @param anchors   доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат, в котором {@code data()} возвращает защитную копию документа
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyTDetached(
            byte[] cadesTDer, byte[] content, TrustAnchors anchors) throws PkixException {
        requireDetachedContent(content);
        return verifyTInternal(cadesTDer, content, requireAnchors(anchors));
    }

    private static VerifiedCAdESData verifyTInternal(
            byte[] cadesTDer, byte[] content, TrustAnchors anchors) throws PkixException {
        Objects.requireNonNull(cadesTDer, "cadesTDer must not be null");
        CAdESTInternalResult internal = verifyCAdESTInternal(cadesTDer, content, anchors);
        requireSignatureTimestamps(internal, "CAdES-T");
        return new VerifiedCAdESData(internal.cmsResult().data(), internal.signerResults());
    }

    // ========================================================================
    // Верификация CAdES-C (Complete validation data references)
    // ========================================================================

    /**
     * Верифицирует CAdES-C подпись (CAdES-T + Complete validation data references).
     *
     * <p>Для каждого подписанта выполняет (RFC 5126 §6.2):
     * <ol>
     *   <li>Проверка CMS-подписи (AND-семантика)</li>
     *   <li>Проверка signingCertificateV2 (CAdES-BES)</li>
     *   <li>Проверка signature-time-stamp (CAdES-T)</li>
     *   <li>Проверка complete-certificate-references:
     *     <ul>
     *       <li>Атрибут присутствует, ровно один экземпляр</li>
     *       <li>Для каждого OtherCertID: certHash совпадает с сертификатом из embedded certs
     *           (dispatch строго по OID из OtherHash — whitelist Стрибог-256/512,
     *           PkixException на любой другой OID)</li>
     *       <li>Нет дубликатов (issuer + serial)</li>
     *       <li>Не превышены DoS-лимиты</li>
     *     </ul>
     *   </li>
     *   <li>Проверка complete-revocation-references:
     *     <ul>
     *       <li>Атрибут присутствует, ровно один экземпляр</li>
     *       <li>Количество CrlOcspRef = количество OtherCertID + 1</li>
     *       <li>Каждый CrlOcspRef содержит хотя бы один crlList ИЛИ ocspList</li>
     *       <li>crlNumber (если есть) логически non-negative</li>
     *     </ul>
     *   </li>
     * </ol>
     *
     * <p>crlHash НЕ сверяется с актуальными CRL — CRL не эмбеддятся в конверт.
     * Сверка crlHash и проверка отзыва выполняются в
     * {@link #verifyXLong(byte[], TrustAnchors)} по CRL/OCSP,
     * встроенным в revocation-values. На C-уровне статус отзыва не проверяется.
     *
     * <p><b>signature-time-stamp обязательна:</b> CAdES-C без неё (обычный BES с
     * добавленными C-атрибутами) отвергается. Метка необходима, но не достаточна:
     * она не привязывает C-референсы и не делает данные отзыва доверенными.
     * escTimeStamp (CAdES-C-time-stamp, OID {@code 1.2.840.113549.1.9.16.2.25})
     * на уровне C не проверяется; его проверяет {@link #verifyXLong(byte[], TrustAnchors)}.
     *
     * <p><b>Не проверяет:</b> content-time-stamp (ES-C, signed-атрибут CONTENT_TIME_STAMP).
     * Верификация content-timestamp — только в {@link #verifyXLong(byte[], TrustAnchors)}.
     *
     * @param cadesCDer CAdES-C подпись (CMS SignedData с C-атрибутами)
     * @param anchors   доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат с C-референсами для каждого подписанта
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyC(byte[] cadesCDer, TrustAnchors anchors)
            throws PkixException {
        return verifyCInternal(cadesCDer, null, requireAnchors(anchors));
    }

    /**
     * Верифицирует detached CAdES-C подпись и привязывает её к документу.
     *
     * <p>Отличается от {@link #verifyC} только тем, что SignedData не содержит
     * eContent, а message-digest проверяется по переданному документу.
     *
     * @param cadesCDer CAdES-C SignedData без eContent
     * @param content   подписанный документ (не null)
     * @param anchors   доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат, в котором {@code data()} возвращает защитную копию документа
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyCDetached(
            byte[] cadesCDer, byte[] content, TrustAnchors anchors) throws PkixException {
        requireDetachedContent(content);
        return verifyCInternal(cadesCDer, content, requireAnchors(anchors));
    }

    private static VerifiedCAdESData verifyCInternal(
            byte[] cadesCDer, byte[] content, TrustAnchors anchors) throws PkixException {
        Objects.requireNonNull(cadesCDer, "cadesCDer must not be null");

        CAdESTInternalResult internal = verifyCAdESTInternal(cadesCDer, content, anchors);
        requireSignatureTimestamps(internal, "CAdES-C");

        List<CAdESSignerResult> cadescResults = new ArrayList<>();
        List<SignerResult> signers = internal.cmsResult().signers();
        for (int i = 0; i < signers.size(); i++) {
            SignerResult sr = signers.get(i);
            CAdESSignerResult besTResult = internal.signerResults().get(i);

            List<CAdESCompleteData.OtherCertID> certRefs =
                    extractAndVerifyCertificateRefs(sr, internal.embeddedCerts());
            List<CAdESCompleteData.CrlOcspRef> revocRefs =
                    extractAndVerifyRevocationRefs(sr, certRefs.size() + 1);

            cadescResults.add(
                    new CAdESSignerResult(
                            besTResult.signerCertificate(),
                            besTResult.signedAttributes(),
                            besTResult.timestamps(),
                            besTResult.countersignatures(),
                            certRefs,
                            revocRefs,
                            List.of(),
                            CAdESXLongData.RevocationValuesDecoded.EMPTY,
                            null));
        }

        return new VerifiedCAdESData(internal.cmsResult().data(), cadescResults);
    }

    // ========================================================================
    // Верификация CAdES-X Long Type 1
    // ========================================================================

    /**
     * Верифицирует CAdES-X Long Type 1 (CAdES-C + certificate-values + revocation-values).
     *
     * <p>Полная проверка долгосрочной подписи (fail-closed, любое нарушение → PkixException):
     * <ol>
     *   <li>CMS-подпись (AND-семантика)</li>
     *   <li>signingCertificateV2 (CAdES-BES)</li>
     *   <li>signature-time-stamp (CAdES-T)</li>
     *   <li>complete-certificate-references + complete-revocation-references (CAdES-C)</li>
     *   <li>certificate-values: certHash/IssuerSerial каждого OtherCertID совпадает
     *       с embedded сертификатом; каждый сертификат входит в первичную проверенную
     *       цепочку по DER, все промежуточные CA ниже якоря обязательны, порядок
     *       канонизируется; в результате возвращается проверенная цепочка, а не сырой
     *       атрибут</li>
     *   <li>revocation-values: crlHash/OcspRepHash каждой CrlOcspRef совпадает с embedded
     *       CRL/OCSP, подписи CRL/OCSP валидны, сертификаты первичной цепочки НЕ отозваны;
     *       данные отзыва сопоставляются с канонизированным порядком первичной цепочки</li>
     * </ol>
     *
     * <p><b>Ограничение:</b> сертификаты OCSP-ответчиков и издателей CRL в
     * certificate-values не поддерживаются и отклоняются как посторонние. Поддержку
     * следует добавлять отдельно, проверяя их как сертификаты ответчика, а не как
     * звенья цепочки.</p>
     *
     * <p><b>signature-time-stamp и escTimeStamp обязательны:</b> X Long без
     * них отвергается. {@code escTimeStamp} (RFC 5126 §6.3.5, OID
     * {@code 1.2.840.113549.1.9.16.2.25}) привязывает SignatureValue,
     * signature-time-stamp и C-референсы, поэтому подмена ссылок и значений
     * ломает метку.</p>
     *
     * <p><b>Время отзыва:</b> доказательства CRL/OCSP проверяются на окно
     * между самым ранним signature-time-stamp и самым ранним escTimeStamp.
     * По умолчанию применяется {@link RevocationFreshnessPolicy#STRICT};
     * {@link RevocationFreshnessPolicy#ETSI_DEFAULT} отключает только нижнюю
     * границу относительно времени подписи. Цепочка сертификатов по-прежнему
     * проверяется на текущее время.</p>
     *
     * <p>time-stamped-certs-crls-references (OID {@code ...16.2.26}) для
     * Type 2 не реализован. {@code content-time-stamp} (OID {@code ...16.2.20}) -
     * другой signed-атрибут и остаётся опциональным.</p>
     *
     * <p>crlHash и ocspRepHash из complete-revocation-references сверяются
     * с embedded CRL/OCSP из revocation-values; отсутствие ocspRepHash
     * отвергается.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 DER
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат с certificate-values и revocation-values
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyXLong(byte[] cadesXLongDer, TrustAnchors anchors)
            throws PkixException {
        return verifyXLongInternal(
                cadesXLongDer,
                null,
                RevocationFreshnessPolicy.STRICT,
                requireAnchors(anchors),
                CrlLimits.DEFAULT);
    }

    /**
     * Верифицирует CAdES-X Long Type 1 с явной политикой свежести отзыва.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 DER
     * @param policy        политика свежести отзыва (не null)
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат с применённой политикой
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyXLong(
            byte[] cadesXLongDer, RevocationFreshnessPolicy policy, TrustAnchors anchors)
            throws PkixException {
        return verifyXLong(cadesXLongDer, policy, anchors, CrlLimits.DEFAULT);
    }

    /**
     * Верифицирует CAdES-X Long Type 1 с явной политикой свежести отзыва и пределами CRL.
     *
     * <p>Пределы действуют на CRL из revocation-values и из поля crls SignedData: превышение
     * размера или числа записей даёт {@link PkixException} с причиной
     * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}, проверка не пропускается. Отдельный предел
     * на входные данные ({@link CmsConstants#MAX_REVOC_VALUES_SIZE}, число CRL) не меняется.</p>
     *
     * @param cadesXLongDer CAdES-X Long Type 1 DER
     * @param policy        политика свежести отзыва (не null)
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @param limits        пределы размера и числа записей CRL (не null)
     * @return результат с применённой политикой
     * @throws PkixException при любой ошибке (fail-closed), в том числе при превышении пределов
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     * @throws NullPointerException если {@code policy} или {@code limits} равен null (как и
     *     остальные аргументы этого класса, проверяемые через {@code Objects.requireNonNull})
     */
    public static VerifiedCAdESData verifyXLong(
            byte[] cadesXLongDer,
            RevocationFreshnessPolicy policy,
            TrustAnchors anchors,
            CrlLimits limits)
            throws PkixException {
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        return verifyXLongInternal(cadesXLongDer, null, policy, requireAnchors(anchors), limits);
    }

    /**
     * Верифицирует detached CAdES-X Long Type 1 и привязывает подпись к документу.
     *
     * <p>Отличается от {@link #verifyXLong(byte[], TrustAnchors)} только тем, что SignedData не
     * содержит eContent, а message-digest проверяется по переданному документу.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 SignedData без eContent
     * @param content       подписанный документ (не null)
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат, в котором {@code data()} возвращает защитную копию документа
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyXLongDetached(
            byte[] cadesXLongDer, byte[] content, TrustAnchors anchors) throws PkixException {
        requireDetachedContent(content);
        return verifyXLongInternal(
                cadesXLongDer,
                content,
                RevocationFreshnessPolicy.STRICT,
                requireAnchors(anchors),
                CrlLimits.DEFAULT);
    }

    /**
     * Верифицирует detached CAdES-X Long Type 1 с явной политикой свежести.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 SignedData без eContent
     * @param content       подписанный документ (не null)
     * @param policy        политика свежести отзыва (не null)
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @return результат с применённой политикой
     * @throws PkixException при любой ошибке (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyXLongDetached(
            byte[] cadesXLongDer,
            byte[] content,
            RevocationFreshnessPolicy policy,
            TrustAnchors anchors)
            throws PkixException {
        return verifyXLongDetached(cadesXLongDer, content, policy, anchors, CrlLimits.DEFAULT);
    }

    /**
     * Верифицирует detached CAdES-X Long Type 1 с явной политикой свежести и пределами CRL.
     * Пределы действуют так же, как у {@link #verifyXLong(byte[], RevocationFreshnessPolicy,
     * TrustAnchors, CrlLimits)}.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 SignedData без eContent
     * @param content       подписанный документ (не null)
     * @param policy        политика свежести отзыва (не null)
     * @param anchors       доверенные якоря (подписанта + TSA; не null и не пусты)
     * @param limits        пределы размера и числа записей CRL (не null)
     * @return результат с применённой политикой
     * @throws PkixException при любой ошибке (fail-closed), в том числе при превышении пределов
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     * @throws NullPointerException если {@code policy} или {@code limits} равен null
     */
    public static VerifiedCAdESData verifyXLongDetached(
            byte[] cadesXLongDer,
            byte[] content,
            RevocationFreshnessPolicy policy,
            TrustAnchors anchors,
            CrlLimits limits)
            throws PkixException {
        requireDetachedContent(content);
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        return verifyXLongInternal(cadesXLongDer, content, policy, requireAnchors(anchors), limits);
    }

    /**
     * Добавляет сертификаты из certificate-values в поле certificates как
     * недоверенных кандидатов. Нужно для КриптоПро: промежуточные CA лежат
     * только в certificate-values. Якорями эти сертификаты не становятся.
     */
    private static byte[] augmentWithCertificateValuesCandidates(byte[] cadesDer)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            return cadesDer;
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        List<byte[]> candidates = new ArrayList<>();
        for (byte[] signerInfoDer : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
            byte[] unsignedContent = unsignedAttrsContent(siParts);
            if (unsignedContent == null) {
                continue;
            }
            for (byte[] attrDer : parseAttributeTlvs(unsignedContent)) {
                CmsAttribute attr = CmsAttribute.decode(attrDer);
                if (!GostOids.CERTIFICATE_VALUES.equals(attr.attrType())) {
                    continue;
                }
                byte[][] values = attr.attrValues();
                if (values.length != 1 || values[0].length > CmsConstants.MAX_CERT_VALUES_SIZE) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "CAdES-X Long: invalid certificate-values attribute");
                }
                for (GostCertificate cert : CAdESXLongData.decodeCertificateValues(values[0])) {
                    candidates.add(cert.getEncoded());
                }
            }
        }
        if (candidates.isEmpty()) {
            return cadesDer;
        }
        byte[] newCerts =
                mergeCertsIntoField(sd.certs(), candidates, CmsConstants.MAX_EMBEDDED_CERTS);
        byte[] newSignedData = sd.rebuild(newCerts, sd.signerInfosField());
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /**
     * Возвращает сертификаты токена штампа времени как недоверенных кандидатов:
     * поле certificates токена и вложенный certificate-values его подписантов.
     *
     * <p>КриптоПро оставляет certificates сигнатурного штампа пустым, а сертификат
     * TSA и его цепочку кладёт только во вложенный certificate-values; у escTimeStamp
     * в certificates лежит один сертификат TSA, а промежуточный УЦ есть лишь в
     * соседнем токене. Токен не пересобирается: подписанные данные и порядок байт
     * остаются исходными, что важно для хеш-входа escTimeStamp. Нечитаемый или
     * превышающий лимит вложенный атрибут - отказ, а не молчаливый пропуск.</p>
     */
    static List<GostCertificate> extractTokenCertificateCandidates(byte[] tokenDer)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(tokenDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            return List.of();
        }
        List<GostCertificate> candidates = new ArrayList<>(extractEmbeddedCerts(tokenDer));
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        for (byte[] signerInfoDer : signerInfos) {
            byte[] unsignedContent =
                    unsignedAttrsContent(DerCodec.parseSequenceContents(signerInfoDer, 0));
            if (unsignedContent == null) {
                continue;
            }
            for (byte[] attrDer : parseAttributeTlvs(unsignedContent)) {
                CmsAttribute attr = CmsAttribute.decode(attrDer);
                if (!GostOids.CERTIFICATE_VALUES.equals(attr.attrType())) {
                    continue;
                }
                byte[][] values = attr.attrValues();
                if (values.length != 1 || values[0].length > CmsConstants.MAX_CERT_VALUES_SIZE) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "CAdES: invalid certificate-values attribute in timestamp token");
                }
                for (GostCertificate cert : CAdESXLongData.decodeCertificateValues(values[0])) {
                    addIfAbsent(candidates, cert);
                }
            }
        }
        if (candidates.size() > CmsConstants.MAX_EMBEDDED_CERTS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES: too many certificates in timestamp token: " + candidates.size());
        }
        return candidates;
    }

    /**
     * Собирает недоверенных кандидатов для проверки штампов подписанта: внешние
     * сертификаты подписи и сертификаты всех токенов (signature-time-stamp,
     * escTimeStamp, content-time-stamp).
     *
     * <p>Токены разных типов ссылаются на общую цепочку TSA, но не обязаны
     * содержать её каждый. Кандидаты доверия не создают: якоря - только явно
     * переданные, а сертификат TSA из пула привязывается к signingCertificateV2.</p>
     */
    private static List<GostCertificate> collectTimestampCandidates(
            SignerResult sr, List<GostCertificate> embeddedCerts) throws PkixException {
        List<GostCertificate> pool = new ArrayList<>(embeddedCerts);
        List<CmsAttribute> attrs = new ArrayList<>(sr.unsignedAttributes());
        attrs.addAll(sr.signedAttributes());
        for (CmsAttribute attr : attrs) {
            String type = attr.attrType();
            if (!GostOids.SIGNATURE_TIME_STAMP.equals(type)
                    && !GostOids.ESC_TIME_STAMP.equals(type)
                    && !GostOids.CONTENT_TIME_STAMP.equals(type)) {
                continue;
            }
            for (byte[] token : attr.attrValues()) {
                for (GostCertificate cert : extractTokenCertificateCandidates(token)) {
                    addIfAbsent(pool, cert);
                }
            }
        }
        if (pool.size() > CmsConstants.MAX_EMBEDDED_CERTS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES: too many candidate certificates for timestamp verification: "
                            + pool.size());
        }
        return pool;
    }

    private static VerifiedCAdESData verifyXLongInternal(
            byte[] cadesXLongDer,
            byte[] content,
            RevocationFreshnessPolicy policy,
            TrustAnchors anchors,
            CrlLimits limits)
            throws PkixException {
        Objects.requireNonNull(cadesXLongDer, "cadesXLongDer must not be null");

        byte[] augmentedDer = augmentWithCertificateValuesCandidates(cadesXLongDer);
        CAdESTInternalResult internal =
                verifyCAdESTInternal(augmentedDer, content, anchors, limits);
        requireSignatureTimestamps(internal, "CAdES-X Long");
        List<GostCertificate> embeddedCerts = internal.embeddedCerts();

        List<CAdESSignerResult> xlongResults = new ArrayList<>();
        List<SignerResult> signers = internal.cmsResult().signers();
        for (int i = 0; i < signers.size(); i++) {
            SignerResult sr = signers.get(i);
            CAdESSignerResult besTResult = internal.signerResults().get(i);

            List<CAdESCompleteData.OtherCertID> certRefs =
                    extractAndVerifyCertificateRefs(sr, embeddedCerts);
            List<CAdESCompleteData.CrlOcspRef> revocRefs =
                    extractAndVerifyRevocationRefs(sr, certRefs.size() + 1);

            GostCertificate signerCert = sr.signerCertificate();

            Instant tSigMin = minTimestampGenTime(besTResult.timestamps());
            Instant tSigMax = maxTimestampGenTime(besTResult.timestamps());
            List<GostCertificate> tsaCandidates = collectTimestampCandidates(sr, embeddedCerts);
            Instant tEsc = extractAndVerifyEscTimestamps(sr, tsaCandidates, anchors);
            if (tSigMax.isAfter(tEsc.plusMillis(GostOids.CLOCK_SKEW_MS))) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "CAdES-X Long: escTimeStamp is earlier than signature-time-stamp");
            }
            if (tSigMin.isAfter(tEsc)) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "CAdES-X Long: signature-time-stamp is after escTimeStamp");
            }
            RevocationEvidenceWindow window = new RevocationEvidenceWindow(tSigMin, tEsc);

            TstInfo contentTimestamp = extractAndVerifyContentTimestamp(sr, tsaCandidates, anchors);

            CAdESXLongData.RevocationValuesDecoded revocValues =
                    extractAndVerifyRevocationValues(sr, revocRefs, limits);
            VerifiedCertificateValues certValues =
                    extractAndVerifyCertificateValues(
                            sr,
                            certRefs,
                            revocRefs,
                            revocValues,
                            signerCert,
                            window,
                            policy,
                            anchors,
                            limits);

            xlongResults.add(
                    new CAdESSignerResult(
                            signerCert,
                            besTResult.signedAttributes(),
                            besTResult.timestamps(),
                            besTResult.countersignatures(),
                            certRefs,
                            revocRefs,
                            certValues.chain(),
                            certValues.revocationValues(),
                            contentTimestamp));
        }

        return new VerifiedCAdESData(internal.cmsResult().data(), xlongResults, policy);
    }

    /**
     * Извлекает и верифицирует certificate-values из unsignedAttrs.
     *
     * <p>Сверяет каждый embedded сертификат с OtherCertID из C-референсов:
     * certHash совпадает (dispatch по OID из OtherHash), IssuerSerial совпадает.
     * Каждый сертификат атрибута должен DER-совпадать с элементом первичной
     * проверенной цепочки или доверенным якорем; все промежуточные CA ниже якоря
     * обязательны. Порядок атрибута произвольный и канонизируется. Отзыв проверяется
     * по первичной цепочке, а в результате возвращается проверенная цепочка.
     */
    private static VerifiedCertificateValues extractAndVerifyCertificateValues(
            SignerResult sr,
            List<CAdESCompleteData.OtherCertID> certRefs,
            List<CAdESCompleteData.CrlOcspRef> revocRefs,
            CAdESXLongData.RevocationValuesDecoded revocValues,
            GostCertificate signerCert,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            TrustAnchors anchors,
            CrlLimits limits)
            throws PkixException {

        GostCertificate[] trustedCerts = anchorCertificates(anchors);
        CmsAttribute attr = findAttrByOid(sr.unsignedAttributes(), GostOids.CERTIFICATE_VALUES);
        if (attr == null) {
            throw new PkixException(
                    "CAdES-X Long: certificate-values attribute not found in unsignedAttrs");
        }
        byte[][] attrValues = attr.attrValues();
        if (attrValues.length != 1) {
            throw new PkixException(
                    "CAdES-X Long: expected exactly one certificate-values value, got "
                            + attrValues.length);
        }

        if (attrValues[0].length > CmsConstants.MAX_CERT_VALUES_SIZE) {
            throw new PkixException(
                    "CAdES-X Long: certificate-values size exceeds limit, size="
                            + attrValues[0].length);
        }

        List<GostCertificate> certValues = CAdESXLongData.decodeCertificateValues(attrValues[0]);

        for (CAdESCompleteData.OtherCertID ref : certRefs) {
            boolean matched = false;
            for (GostCertificate cv : certValues) {
                if (matchesCertRef(cv, ref)) {
                    matched = true;
                    break;
                }
            }
            // Ссылка на доверенный корень допустима и без его копии в certificate-values:
            // проверяющий уже располагает якорем, а ссылка привязывает именно этот DER.
            for (int t = 0; !matched && t < trustedCerts.length; t++) {
                matched = matchesCertRef(trustedCerts[t], ref);
            }
            if (!matched) {
                throw new PkixException(
                        "CAdES-X Long: certHash/IssuerSerial mismatch in certificate-values");
            }
        }

        List<GostCertificate> primaryChain = sr.certificateChain();
        if (primaryChain == null || primaryChain.isEmpty()) {
            throw new PkixException(
                    "CAdES-X Long: primary verified certificate chain is unavailable");
        }

        // Членство по DER: сертификат из certificate-values должен быть в первичной
        // проверенной цепочке, среди доверенных якорей или покрыт CAdES-C reference.
        // C-ссылка связывает точный DER и защищена escTimeStamp; такие сертификаты
        // не используются как якоря (cross-signed альтернативы КриптоПро).
        for (GostCertificate cv : certValues) {
            if (!isInPrimaryChainOrTrusted(cv, primaryChain, trustedCerts)
                    && !hasCertRef(cv, certRefs)) {
                throw new PkixException(
                        "CAdES-X Long: certificate-values contains a certificate"
                                + " outside the primary verified chain and CAdES-C refs");
            }
        }

        // Все промежуточные сертификаты первичной цепочки ниже якоря обязательны
        // в certificate-values и должны иметь CAdES-C reference. Иначе данные
        // отзыва для них не будут сопоставлены и проверка будет молча пропущена.
        for (int i = 1; i < primaryChain.size() - 1; i++) {
            if (!containsDer(certValues, primaryChain.get(i))) {
                throw new PkixException(
                        "CAdES-X Long: certificate-values does not cover an intermediate"
                                + " certificate of the primary verified chain");
            }
            if (!hasCertRef(primaryChain.get(i), certRefs)) {
                throw new PkixException(
                        "CAdES-X Long: intermediate certificate of the primary verified chain"
                                + " has no CAdES-C reference");
            }
        }

        // Канонизируем порядок по первичной цепочке: порядок атрибута произвольный,
        // а резолвер якорей не должен встречать корень раньше промежуточного CA.
        List<GostCertificate> attributeChain = new ArrayList<>();
        attributeChain.add(signerCert);
        for (int i = 1; i < primaryChain.size(); i++) {
            if (containsDer(certValues, primaryChain.get(i))) {
                attributeChain.add(primaryChain.get(i));
            }
        }

        // Политика срока та же, что у CMS-проверки первичной цепочки: нормализована на входе.
        // Defense-in-depth: сертификаты атрибута, приведённые к порядку первичной
        // цепочки, тоже должны сходиться к якорю и проходить NC/pathLen.
        ChainValidator.validateChain(attributeChain, anchors);

        List<CertRevocationEvidence> evidence =
                buildEvidenceForPrimaryChain(primaryChain, certRefs, revocRefs, revocValues);
        List<CertRevocationEvidence> verifiedEvidence =
                ChainValidator.validateChainWithRevocationEvidence(
                        primaryChain,
                        anchors,
                        evidence,
                        window,
                        policy,
                        selectOcspResponderCandidates(
                                certValues, certRefs, primaryChain, trustedCerts),
                        limits);

        // Возвращаем канонизированную первичную цепочку, а не сырой атрибут:
        // порядок certificate-values произвольный, а потребитель получает только
        // проверенные сертификаты. С отзывом то же самое: наружу уходят значения, прошедшие
        // проверку валидатора, а не сырой атрибут revocation-values.
        return new VerifiedCertificateValues(
                primaryChain, filterVerifiedRevocationValues(revocValues, verifiedEvidence));
    }

    /**
     * Проверенные данные X Long для одного подписанта.
     *
     * @param chain            канонизированная первичная цепочка leaf-first
     * @param revocationValues CRL/OCSP, прошедшие проверку подписи и статуса отзыва
     */
    private record VerifiedCertificateValues(
            List<GostCertificate> chain, CAdESXLongData.RevocationValuesDecoded revocationValues) {}

    /**
     * Оставляет из встроенных revocation-values только значения, прошедшие проверку валидатора.
     *
     * <p>Фильтр идёт по содержимому DER ({@code getEncoded()}, то же, что лежит в evidence), а не
     * по идентичности объектов: evidence хранит копии массивов. Источник - ответ валидатора, а не
     * сырое evidence: подпись значений якоря и значений, не привязанных к сертификату ниже якоря,
     * не проверялась, и отдавать их потребителю как проверенные нельзя.</p>
     */
    private static CAdESXLongData.RevocationValuesDecoded filterVerifiedRevocationValues(
            CAdESXLongData.RevocationValuesDecoded revocValues,
            List<CertRevocationEvidence> verifiedEvidence) {
        Set<ByteBuffer> verifiedCrls = new HashSet<>();
        Set<ByteBuffer> verifiedOcsps = new HashSet<>();
        for (CertRevocationEvidence item : verifiedEvidence) {
            for (byte[] crlDer : item.crlDers()) {
                verifiedCrls.add(ByteBuffer.wrap(crlDer));
            }
            for (byte[] ocspDer : item.ocspResponseDers()) {
                verifiedOcsps.add(ByteBuffer.wrap(ocspDer));
            }
        }
        List<GostCrl> crls = new ArrayList<>();
        for (GostCrl crl : revocValues.crls()) {
            if (crl != null && verifiedCrls.contains(ByteBuffer.wrap(crl.getEncoded()))) {
                crls.add(crl);
            }
        }
        List<GostOcspResponse> ocsps = new ArrayList<>();
        for (GostOcspResponse ocsp : revocValues.ocspResponses()) {
            if (ocsp != null && verifiedOcsps.contains(ByteBuffer.wrap(ocsp.getEncoded()))) {
                ocsps.add(ocsp);
            }
        }
        return new CAdESXLongData.RevocationValuesDecoded(crls, ocsps);
    }

    /**
     * Отбирает из certificate-values недоверенных кандидатов в OCSP-ответчики:
     * сертификаты вне первичной цепочки и якорей, на которые есть CAdES-C reference.
     *
     * <p>Ссылка привязывает точный DER и защищена escTimeStamp, поэтому лишний
     * сертификат без ссылки кандидатом не становится. Остальные требования
     * (OCSPSigning, KeyUsage, срок, подпись издателем) проверяет OcspVerifier;
     * якорем кандидат не становится.</p>
     */
    static List<GostCertificate> selectOcspResponderCandidates(
            List<GostCertificate> certValues,
            List<CAdESCompleteData.OtherCertID> certRefs,
            List<GostCertificate> primaryChain,
            GostCertificate[] trustedCerts)
            throws PkixException {
        List<GostCertificate> candidates = new ArrayList<>();
        for (GostCertificate cv : certValues) {
            if (!isInPrimaryChainOrTrusted(cv, primaryChain, trustedCerts)
                    && hasCertRef(cv, certRefs)
                    && !containsDer(candidates, cv)) {
                candidates.add(cv);
            }
        }
        return candidates;
    }

    /** Проверяет DER-членство сертификата в первичной цепочке или доверенных якорях. */
    private static boolean isInPrimaryChainOrTrusted(
            GostCertificate cert,
            List<GostCertificate> primaryChain,
            GostCertificate[] trustedCerts) {
        if (containsDer(primaryChain, cert)) {
            return true;
        }
        byte[] encoded = cert.getEncoded();
        for (GostCertificate tc : trustedCerts) {
            if (Arrays.equals(encoded, tc.getEncoded())) {
                return true;
            }
        }
        return false;
    }

    /** Проверяет, есть ли для сертификата CAdES-C reference. */
    private static boolean hasCertRef(
            GostCertificate cert, List<CAdESCompleteData.OtherCertID> certRefs)
            throws PkixException {
        for (CAdESCompleteData.OtherCertID ref : certRefs) {
            if (matchesCertRef(cert, ref)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Строит все доказательства отзыва в порядке первичной цепочки.
     *
     * <p>Индекс 0 — подписант; далее CrlOcspRef ищется по OtherCertID.
     * Для каждой C-ссылки собираются все CRL/OCSP, чьи хеши совпали.
     * {@code ocspRepHash} обязателен: без него ответ не привязан к ссылке.</p>
     */
    private static List<CertRevocationEvidence> buildEvidenceForPrimaryChain(
            List<GostCertificate> primaryChain,
            List<CAdESCompleteData.OtherCertID> certRefs,
            List<CAdESCompleteData.CrlOcspRef> revocRefs,
            CAdESXLongData.RevocationValuesDecoded revocValues)
            throws PkixException {
        List<CertRevocationEvidence> result = new ArrayList<>(primaryChain.size());
        for (int i = 0; i < primaryChain.size(); i++) {
            CAdESCompleteData.CrlOcspRef ref = null;
            if (i == 0) {
                if (!revocRefs.isEmpty()) {
                    ref = revocRefs.get(0);
                }
            } else {
                for (int j = 0; j < certRefs.size(); j++) {
                    if (matchesCertRef(primaryChain.get(i), certRefs.get(j))) {
                        if (j + 1 < revocRefs.size()) {
                            ref = revocRefs.get(j + 1);
                        }
                        break;
                    }
                }
            }
            result.add(buildRevocationEvidence(ref, revocValues));
        }
        return result;
    }

    /** Собирает все CRL/OCSP одного CrlOcspRef, совпавшие по хешу. */
    private static CertRevocationEvidence buildRevocationEvidence(
            CAdESCompleteData.CrlOcspRef ref, CAdESXLongData.RevocationValuesDecoded revocValues)
            throws PkixException {
        List<byte[]> crls = new ArrayList<>();
        List<byte[]> ocsps = new ArrayList<>();
        if (ref != null) {
            for (CAdESCompleteData.CrlValidatedID cvi : ref.crlList()) {
                for (GostCrl crl : revocValues.crls()) {
                    if (crl == null) {
                        continue;
                    }
                    byte[] actualHash =
                            CAdESSupport.digestByOidOrThrow(
                                    cvi.crlHash().hashOid(), crl.getEncoded());
                    if (MessageDigest.isEqual(cvi.crlHash().hashValue(), actualHash)) {
                        crls.add(crl.getEncoded());
                    }
                }
            }
            for (CAdESCompleteData.OcspResponsesID orid : ref.ocspList()) {
                if (orid.ocspRepHash() == null) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "CAdES-X Long: ocspRepHash is missing; OCSP response is not bound");
                }
                for (GostOcspResponse ocsp : revocValues.ocspResponses()) {
                    if (ocsp == null) {
                        continue;
                    }
                    byte[] actualHash =
                            CAdESSupport.digestByOidOrThrow(
                                    orid.ocspRepHash().hashOid(), ocsp.getRevocationValueDer());
                    if (MessageDigest.isEqual(orid.ocspRepHash().hashValue(), actualHash)) {
                        ocsps.add(ocsp.getEncoded());
                    }
                }
            }
        }
        return new CertRevocationEvidence(crls, ocsps);
    }

    /**
     * Проверяет, покрывает ли CAdES-C reference конкретный сертификат.
     * <p>
     * Сверяет hash, issuer DN и serial. Общий helper для прямого и обратного
     * проходов, чтобы правила сопоставления не расходились.
     *
     * <p>issuerSerial необязателен (RFC 5126 §5.7.3.3): при его отсутствии решает хэш. Он
     * считается от всего DER сертификата хэшем Стрибога из белого списка, поэтому однозначно
     * задаёт сертификат, а issuer и serial избыточны.</p>
     */
    static boolean matchesCertRef(GostCertificate cert, CAdESCompleteData.OtherCertID ref)
            throws PkixException {
        byte[] actualHash =
                CAdESSupport.digestByOidOrThrow(ref.otherCertHash().hashOid(), cert.getEncoded());
        if (!MessageDigest.isEqual(ref.otherCertHash().hashValue(), actualHash)) {
            return false;
        }
        if (ref.issuerSerial() == null) {
            return true;
        }
        if (!Arrays.equals(ref.issuerSerial().issuerDer(), cert.getIssuerDnBytes())) {
            return false;
        }
        return ref.issuerSerial().serial().equals(cert.getSerialNumberBigInt());
    }

    /**
     * Извлекает revocation-values из unsignedAttrs и привязывает их к ссылкам C-уровня.
     *
     * <p>Сверяет crlHash/ocspRepHash каждой CrlOcspRef со встроенными CRL/OCSP; ссылка без
     * совпавшего значения отвергается. Подписи CRL и OCSP-ответов здесь НЕ проверяются: их
     * проверяет валидатор цепочки в {@code extractAndVerifyCertificateValues}, и только для
     * значений сертификатов ниже якоря. Возвращаемый набор сырой; потребителю отдаётся
     * отфильтрованный по результату валидатора.</p>
     */
    private static CAdESXLongData.RevocationValuesDecoded extractAndVerifyRevocationValues(
            SignerResult sr, List<CAdESCompleteData.CrlOcspRef> revocRefs, CrlLimits limits)
            throws PkixException {

        CmsAttribute attr = findAttrByOid(sr.unsignedAttributes(), GostOids.REVOCATION_VALUES);
        if (attr == null) {
            throw new PkixException(
                    "CAdES-X Long: revocation-values attribute not found in unsignedAttrs");
        }
        byte[][] attrValues = attr.attrValues();
        if (attrValues.length != 1) {
            throw new PkixException(
                    "CAdES-X Long: expected exactly one revocation-values value, got "
                            + attrValues.length);
        }

        if (attrValues[0].length > CmsConstants.MAX_REVOC_VALUES_SIZE) {
            throw new PkixException(
                    "CAdES-X Long: revocation-values size exceeds limit, size="
                            + attrValues[0].length);
        }

        CAdESXLongData.RevocationValuesDecoded revocValues =
                CAdESXLongData.decodeRevocationValues(attrValues[0], limits);

        if (revocValues.crls().size() > CmsConstants.MAX_EMBEDDED_CRLS) {
            throw new PkixException(
                    "CAdES-X Long: CRL count exceeds limit: " + revocValues.crls().size());
        }
        if (revocValues.ocspResponses().size() > CmsConstants.MAX_OCSP_VALUES) {
            throw new PkixException(
                    "CAdES-X Long: OCSP count exceeds limit: "
                            + revocValues.ocspResponses().size());
        }

        for (int i = 0; i < revocRefs.size(); i++) {
            CAdESCompleteData.CrlOcspRef ref = revocRefs.get(i);

            for (CAdESCompleteData.CrlValidatedID cvi : ref.crlList()) {
                byte[] expectedCrlHash = cvi.crlHash().hashValue();
                String hashOid = cvi.crlHash().hashOid();
                boolean matched = false;
                for (GostCrl crl : revocValues.crls()) {
                    if (crl == null) {
                        continue;
                    }
                    byte[] actualCrlHash =
                            CAdESSupport.digestByOidOrThrow(hashOid, crl.getEncoded());
                    if (MessageDigest.isEqual(expectedCrlHash, actualCrlHash)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    throw new PkixException(
                            "CAdES-X Long: crlHash mismatch at CrlOcspRef[" + i + "]");
                }
            }

            for (CAdESCompleteData.OcspResponsesID orid : ref.ocspList()) {
                if (orid.ocspRepHash() == null) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "CAdES-X Long: ocspRepHash is missing at CrlOcspRef["
                                    + i
                                    + "]; OCSP response is not bound");
                }
                boolean matched = false;
                byte[] expectedOcspHash = orid.ocspRepHash().hashValue();
                String hashOid = orid.ocspRepHash().hashOid();
                for (GostOcspResponse ocsp : revocValues.ocspResponses()) {
                    if (ocsp == null) {
                        continue;
                    }
                    byte[] actualOcspHash =
                            CAdESSupport.digestByOidOrThrow(hashOid, ocsp.getRevocationValueDer());
                    if (MessageDigest.isEqual(expectedOcspHash, actualOcspHash)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    throw new PkixException(
                            "CAdES-X Long: ocspRepHash mismatch at CrlOcspRef[" + i + "]");
                }
            }
        }

        return revocValues;
    }

    /**
     * Извлекает и верифицирует content-time-stamp (ES-C) из signed-атрибутов.
     *
     * <p>ContentTimestamp = TimeStampToken (SignedData с TSTInfo).
     * messageImprint = hash(контента) = messageDigest из signedAttrs.
     * Проверяется: TST-подпись, цепочка TSA, messageImprint, nonce.
     *
     * @return TstInfo или null, если атрибут отсутствует
     */
    private static TstInfo extractAndVerifyContentTimestamp(
            SignerResult sr, List<GostCertificate> tsaCandidates, TrustAnchors anchors)
            throws PkixException {
        CmsAttribute attr = findAttrByOid(sr.signedAttributes(), GostOids.CONTENT_TIME_STAMP);
        if (attr == null) {
            return null;
        }
        byte[][] attrValues = attr.attrValues();
        if (attrValues.length != 1) {
            throw new PkixException(
                    "CAdES-X Long: expected exactly one content-time-stamp value, got "
                            + attrValues.length);
        }

        CmsAttribute mdAttr = findAttrByOid(sr.signedAttributes(), GostOids.ATTR_MESSAGE_DIGEST);
        if (mdAttr == null || mdAttr.attrValues().length < 1) {
            throw new PkixException(
                    "CAdES-X Long: messageDigest not found for content-time-stamp check");
        }

        byte[] digestOctet = mdAttr.attrValues()[0];
        byte[] contentDigest = DerCodec.parseOctetString(digestOctet, 0);

        TspResponse tspResponse = TspResponse.parseTimeStampToken(attrValues[0]);

        // ГОСТ-ключ жёстко привязан к варианту Стрибог: 256b -> Streebog-256, 512b -> Streebog-512
        String hashOid =
                sr.signerCertificate().getKeySize() == 512
                        ? GostOids.DIGEST_512
                        : GostOids.DIGEST_256;

        tspResponse.verify(
                contentDigest, hashOid, null, tsaCandidates, anchorCertificates(anchors));
        checkCertValidityAtTime(sr.signerCertificate(), tspResponse.tstInfo().genTime());

        return tspResponse.tstInfo();
    }

    /**
     * Извлекает и верифицирует complete-certificate-references.
     *
     * <p>Для каждого OtherCertID ищет соответствующий сертификат
     * в embedded certs и сверяет certHash. Dispatch по hashAlgorithm OID
     * из DER — whitelist (Стрибог-256/512), PkixException при незнакомом OID.
     * Запрещено определять алгоритм по размеру ключа на верификации.
     */
    private static List<CAdESCompleteData.OtherCertID> extractAndVerifyCertificateRefs(
            SignerResult sr, List<GostCertificate> embeddedCerts) throws PkixException {

        CmsAttribute attr =
                findAttrByOid(sr.unsignedAttributes(), GostOids.COMPLETE_CERTIFICATE_REFS);
        if (attr == null) {
            throw new PkixException(
                    "CAdES-C: complete-certificate-references attribute not found in unsignedAttrs");
        }
        byte[][] vals = attr.attrValues();
        if (vals.length == 0) {
            throw new PkixException(
                    "CAdES-C: complete-certificate-references attribute has empty value");
        }

        // Проверка размера до parseSequenceContents
        if (vals[0].length > CmsConstants.MAX_CERT_REFS_SIZE) {
            throw new PkixException(
                    "CAdES-C: complete-certificate-references size "
                            + vals[0].length
                            + " exceeds limit "
                            + CmsConstants.MAX_CERT_REFS_SIZE);
        }

        List<CAdESCompleteData.OtherCertID> certRefs;
        try {
            certRefs = CAdESCompleteData.decodeCompleteCertificateRefs(vals[0]);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "CAdES-C: malformed complete-certificate-references DER: " + e.getMessage(),
                    e);
        }

        if (certRefs.size() > CmsConstants.MAX_CERT_REFS) {
            throw new PkixException(
                    "CAdES-C: complete-certificate-references has "
                            + certRefs.size()
                            + " entries, exceeds limit "
                            + CmsConstants.MAX_CERT_REFS);
        }

        // Проверка каждого certHash против embedded certs
        for (CAdESCompleteData.OtherCertID certId : certRefs) {
            String hashOid = certId.otherCertHash().hashOid();
            byte[] expectedHash = certId.otherCertHash().hashValue();

            boolean matched = false;
            for (GostCertificate embeddedCert : embeddedCerts) {
                byte[] certDer = embeddedCert.getEncoded();
                byte[] actualHash = CAdESSupport.digestByOidOrThrow(hashOid, certDer);
                if (java.security.MessageDigest.isEqual(expectedHash, actualHash)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                throw new PkixException(
                        "CAdES-C: certHash in CompleteCertificateRefs not matched "
                                + "to any embedded certificate");
            }
        }

        // Проверка дубликатов
        for (int i = 0; i < certRefs.size(); i++) {
            for (int j = i + 1; j < certRefs.size(); j++) {
                if (isDuplicateCertRef(certRefs.get(i), certRefs.get(j))) {
                    throw new PkixException(
                            "CAdES-C: duplicate OtherCertID in CompleteCertificateRefs");
                }
            }
        }

        return certRefs;
    }

    /**
     * Проверяет, что две ссылки указывают на один и тот же сертификат.
     *
     * <p>issuerSerial в OtherCertID необязателен (RFC 5126 §5.7.3.3), поэтому ссылки без него
     * сравниваются по хэшу: хэш всего DER сертификата однозначно его задаёт. Ограничение:
     * ссылки на один сертификат с разными алгоритмами хэша (Стрибог-256 и Стрибог-512) без
     * issuerSerial не распознаются как дубликаты - без самого сертификата это не определить.</p>
     */
    static boolean isDuplicateCertRef(
            CAdESCompleteData.OtherCertID a, CAdESCompleteData.OtherCertID b) {
        CAdESCompleteData.OtherHash hashA = a.otherCertHash();
        CAdESCompleteData.OtherHash hashB = b.otherCertHash();
        if (hashA.hashOid().equals(hashB.hashOid())
                && MessageDigest.isEqual(hashA.hashValue(), hashB.hashValue())) {
            return true;
        }
        if (a.issuerSerial() == null || b.issuerSerial() == null) {
            return false;
        }
        return Arrays.equals(a.issuerSerial().issuerDer(), b.issuerSerial().issuerDer())
                && a.issuerSerial().serial().equals(b.issuerSerial().serial());
    }

    /**
     * Извлекает и верифицирует complete-revocation-references.
     *
     * <p>Проверяет только структурную целостность: количество, непустоту ссылок,
     * валидность DER, лимиты. crlHash НЕ сверяется — CRL не эмбеддятся.
     */
    private static List<CAdESCompleteData.CrlOcspRef> extractAndVerifyRevocationRefs(
            SignerResult sr, int expectedCount) throws PkixException {

        CmsAttribute attr =
                findAttrByOid(sr.unsignedAttributes(), GostOids.COMPLETE_REVOCATION_REFS);
        if (attr == null) {
            throw new PkixException(
                    "CAdES-C: complete-revocation-references attribute not found in unsignedAttrs");
        }
        byte[][] vals = attr.attrValues();
        if (vals.length == 0) {
            throw new PkixException(
                    "CAdES-C: complete-revocation-references attribute has empty value");
        }

        // Проверка размера до parseSequenceContents
        if (vals[0].length > CmsConstants.MAX_REVOC_REFS_SIZE) {
            throw new PkixException(
                    "CAdES-C: complete-revocation-references size "
                            + vals[0].length
                            + " exceeds limit "
                            + CmsConstants.MAX_REVOC_REFS_SIZE);
        }

        List<CAdESCompleteData.CrlOcspRef> revocRefs;
        try {
            revocRefs = CAdESCompleteData.decodeCompleteRevocationRefs(vals[0]);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "CAdES-C: malformed complete-revocation-references DER: " + e.getMessage(),
                    e);
        }

        // Количество CrlOcspRef должно совпадать с OtherCertID + 1
        if (revocRefs.size() != expectedCount) {
            throw new PkixException(
                    "CAdES-C: CrlOcspRef count "
                            + revocRefs.size()
                            + " != OtherCertID count + 1 ("
                            + expectedCount
                            + ")");
        }

        if (revocRefs.size() > CmsConstants.MAX_CRL_REFS) {
            throw new PkixException(
                    "CAdES-C: complete-revocation-references has "
                            + revocRefs.size()
                            + " entries, exceeds limit "
                            + CmsConstants.MAX_CRL_REFS);
        }

        // Проверка каждого CrlOcspRef: хотя бы один механизм отзыва
        for (int i = 0; i < revocRefs.size(); i++) {
            CAdESCompleteData.CrlOcspRef ref = revocRefs.get(i);
            // Пустой CrlOcspRef допустим: доказательство может отсутствовать для якоря.

            if (ref.crlList().size() > CmsConstants.MAX_CRL_VALIDATED_IDS) {
                throw new PkixException(
                        "CAdES-C: CrlOcspRef["
                                + i
                                + "] crlList has "
                                + ref.crlList().size()
                                + " entries, exceeds limit "
                                + CmsConstants.MAX_CRL_VALIDATED_IDS);
            }
            if (ref.ocspList().size() > CmsConstants.MAX_OCSP_IDS) {
                throw new PkixException(
                        "CAdES-C: CrlOcspRef["
                                + i
                                + "] ocspList has "
                                + ref.ocspList().size()
                                + " entries, exceeds limit "
                                + CmsConstants.MAX_OCSP_IDS);
            }

            // Проверка crlNumber на non-negative
            for (CAdESCompleteData.CrlValidatedID cvi : ref.crlList()) {
                if (cvi.crlIdentifier() != null
                        && cvi.crlIdentifier().crlNumber() != null
                        && cvi.crlIdentifier().crlNumber().signum() < 0) {
                    throw new PkixException(
                            "CAdES-C: negative crlNumber in CrlValidatedID[" + i + "]");
                }
            }
        }

        return revocRefs;
    }

    /**
     * Ищет атрибут по OID в списке unsigned-атрибутов.
     */
    private static CmsAttribute findAttrByOid(List<CmsAttribute> attrs, String oid) {
        for (CmsAttribute attr : attrs) {
            if (oid.equals(attr.attrType())) {
                return attr;
            }
        }
        return null;
    }

    /**
     * Промежуточный результат верификации CAdES-T.
     * Содержит сырые SignerResult (signatureValue/unsignedAttributes) —
     * для {@link #verifyCountersignature} нужен доступ к данным countersignature.
     */
    private record CAdESTInternalResult(
            VerifiedSignedData cmsResult,
            List<CAdESSignerResult> signerResults,
            List<GostCertificate> embeddedCerts) {}

    /**
     * Проверяет CMS-часть CAdES: подписи всех подписантов и цепочки до якорей, без проверки
     * отзыва (отзыв CAdES проверяется отдельно, по доказательствам из атрибутов).
     * Detached при {@code content != null}.
     */
    private static VerifiedSignedData verifyAllSigners(
            byte[] cadesDer, byte[] content, TrustAnchors anchors, CrlLimits limits)
            throws PkixException {
        VerifyOptions options =
                VerifyOptions.trusting(anchors, SignerSelection.ALL, Revocation.none())
                        .crlLimits(limits);
        if (content != null) {
            options = options.detached(content);
        }
        return CmsSignedDataVerifier.verify(cadesDer, options);
    }

    /**
     * Общая часть {@link #verifyT} и {@link #verifyCountersignature}.
     * Верифицирует CMS-подписи (AND), проверяет signingCertificateV2 и метки времени.
     * Возвращает сырые SignerResult для дальнейшей обработки countersignature.
     */
    private static CAdESTInternalResult verifyCAdESTInternal(
            byte[] cadesDer, byte[] content, TrustAnchors anchors) throws PkixException {
        return verifyCAdESTInternal(cadesDer, content, anchors, CrlLimits.DEFAULT);
    }

    private static CAdESTInternalResult verifyCAdESTInternal(
            byte[] cadesDer, byte[] content, TrustAnchors anchors, CrlLimits limits)
            throws PkixException {

        VerifiedSignedData cmsResult = verifyAllSigners(cadesDer, content, anchors, limits);

        List<GostCertificate> embeddedCerts = extractEmbeddedCerts(cadesDer);
        List<CAdESSignerResult> signerResults = new ArrayList<>();
        for (SignerResult sr : cmsResult.signers()) {
            verifySigningCertV2ForSigner(sr);
            List<TstInfo> timestamps =
                    extractAndVerifyTimestamps(
                            sr, collectTimestampCandidates(sr, embeddedCerts), anchors);
            signerResults.add(
                    new CAdESSignerResult(
                            sr.signerCertificate(),
                            sr.signedAttributes(),
                            timestamps,
                            List.of(),
                            List.of(),
                            List.of(),
                            List.of(),
                            CAdESXLongData.RevocationValuesDecoded.EMPTY,
                            null));
        }

        return new CAdESTInternalResult(cmsResult, signerResults, embeddedCerts);
    }

    /**
     * Проверяет, что каждый подписант имеет хотя бы одну verified
     * signature-time-stamp.
     *
     * <p>Проверка вынесена отдельно от {@link #verifyCAdESTInternal}, потому что
     * countersignature допускает отсутствие метки, а CAdES-T/C/X Long - нет.
     * {@code level} попадает в сообщение и помогает отличить, на каком уровне
     * сработал fail-closed.
     */
    private static void requireSignatureTimestamps(CAdESTInternalResult internal, String level)
            throws PkixException {
        for (CAdESSignerResult sr : internal.signerResults()) {
            if (sr.timestamps().isEmpty()) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        level + ": no signature-time-stamp in unsignedAttrs for signer");
            }
        }
    }

    // ========================================================================
    // Верификация countersignature
    // ========================================================================

    /**
     * Верифицирует countersignature (RFC 5652 §11.4) поверх CAdES-BES/T.
     *
     * <p>Для каждого подписанта выполняет:
     * <ol>
     *   <li>Проверка CMS-подписи (AND-семантика)</li>
     *   <li>Проверка signingCertificateV2 (CAdES-BES)</li>
     *   <li>Проверка signature-time-stamp (CAdES-T)</li>
     *   <li>Проверка countersignature (RFC 5652 §11.4) — fail-closed:
     *     <ul>
     *       <li>Сверка messageDigest = hash(родительской signatureValue contents octets)</li>
     *       <li>Построение и валидация цепочки countersigner'а до якорей</li>
     *       <li>Верификация подписи countersigner'а</li>
     *     </ul>
     *   </li>
     * </ol>
     *
     * @param countersignedDer CMS SignedData с countersignature в unsignedAttrs
     * @param anchors          доверенные якоря (подписанта + countersigner'а + TSA; не null и не пусты)
     * @return результат с countersignature для каждого подписанта
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code anchors} равен null или пуст
     */
    public static VerifiedCAdESData verifyCountersignature(
            byte[] countersignedDer, TrustAnchors anchors) throws PkixException {
        return verifyCountersignatureInternal(countersignedDer, null, requireAnchors(anchors));
    }

    /**
     * Верифицирует detached countersignature и привязывает её к документу.
     *
     * <p>Отличается от {@link #verifyCountersignature} только тем, что SignedData
     * не содержит eContent, а message-digest проверяется по переданному документу.
     *
     * @param countersignedDer CMS SignedData без eContent с countersignature
     * @param content          подписанный документ (не null)
     * @param anchors          доверенные якоря (подписанта + countersigner'а + TSA; не null и не пусты)
     * @return результат, в котором {@code data()} возвращает защитную копию документа
     * @throws PkixException при любой ошибке верификации (fail-closed)
     * @throws IllegalArgumentException если {@code content == null} либо {@code anchors} равен
     *     null или пуст
     */
    public static VerifiedCAdESData verifyCountersignatureDetached(
            byte[] countersignedDer, byte[] content, TrustAnchors anchors) throws PkixException {
        requireDetachedContent(content);
        return verifyCountersignatureInternal(countersignedDer, content, requireAnchors(anchors));
    }

    private static VerifiedCAdESData verifyCountersignatureInternal(
            byte[] countersignedDer, byte[] content, TrustAnchors anchors) throws PkixException {
        Objects.requireNonNull(countersignedDer, "countersignedDer must not be null");

        CAdESTInternalResult internal = verifyCAdESTInternal(countersignedDer, content, anchors);

        List<CAdESSignerResult> resultsWithCs = new ArrayList<>();
        List<SignerResult> signers = internal.cmsResult().signers();
        for (int i = 0; i < signers.size(); i++) {
            SignerResult sr = signers.get(i);
            CAdESSignerResult besTResult = internal.signerResults().get(i);

            List<SignerResult> csResults =
                    verifyCountersignaturesForSigner(sr, internal.embeddedCerts(), anchors);

            resultsWithCs.add(
                    new CAdESSignerResult(
                            besTResult.signerCertificate(),
                            besTResult.signedAttributes(),
                            besTResult.timestamps(),
                            csResults,
                            besTResult.completeCertRefs(),
                            besTResult.completeRevocRefs(),
                            List.of(),
                            CAdESXLongData.RevocationValuesDecoded.EMPTY,
                            null));
        }

        return new VerifiedCAdESData(internal.cmsResult().data(), resultsWithCs);
    }

    /**
     * Проверяет countersignature в unsignedAttrs подписанта.
     *
     * <p>Для каждой найденной countersignature:
     * <ol>
     *   <li>Разбирает вложенный SignerInfo (sid, signedAttrs, signatureValue)</li>
     *   <li>Сверяет messageDigest = hash(родительского signatureValue contents octets)</li>
     *   <li>Строит и валидирует цепочку сертификата countersigner'а до якорей</li>
     *   <li>Верифицирует подпись countersigner'а</li>
     * </ol>
     *
     * @param parentSr      результат верификации родительского SignerInfo
     * @param embeddedCerts сертификаты из SignedData.certificates
     * @param anchors        доверенные якоря
     * @return список верифицированных countersignature (пустой если атрибут отсутствует)
     * @throws PkixException если countersignature есть но невалидна (fail-closed)
     */
    private static List<SignerResult> verifyCountersignaturesForSigner(
            SignerResult parentSr, List<GostCertificate> embeddedCerts, TrustAnchors anchors)
            throws PkixException {
        List<SignerResult> results = new ArrayList<>();

        int csCount = 0;
        for (CmsAttribute attr : parentSr.unsignedAttributes()) {
            if (!GostOids.ATTR_COUNTERSIGNATURE.equals(attr.attrType())) {
                continue;
            }
            byte[][] vals = attr.attrValues();
            if (vals.length == 0) {
                throw new PkixException(
                        PkixException.Reason.OTHER, "Countersignature: empty SET of values");
            }
            if (vals.length > CmsConstants.MAX_COUNTERSIGNATURES_PER_SIGNER) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Too many countersignature values: "
                                + vals.length
                                + " (max "
                                + CmsConstants.MAX_COUNTERSIGNATURES_PER_SIGNER
                                + ")");
            }
            // attrValues — SET OF Countersignature (SignerInfo)
            for (byte[] csSignerInfoDer : vals) {
                csCount++;
                if (csCount > CmsConstants.MAX_COUNTERSIGNATURES_PER_SIGNER) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many countersignatures (max "
                                    + CmsConstants.MAX_COUNTERSIGNATURES_PER_SIGNER
                                    + ")");
                }
                results.add(
                        verifyOneCountersignature(
                                csSignerInfoDer,
                                parentSr.signatureValue(),
                                embeddedCerts,
                                anchors));
            }
        }

        if (results.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersignature: not found in unsignedAttrs for signer");
        }
        return results;
    }

    /** Верифицирует один вложенный SignerInfo countersignature. */
    private static SignerResult verifyOneCountersignature(
            byte[] csSignerInfoDer,
            byte[] parentSignatureValue,
            List<GostCertificate> embeddedCerts,
            TrustAnchors anchors)
            throws PkixException {

        byte[][] siParts = DerCodec.parseSequenceContents(csSignerInfoDer, 0);
        if (siParts.length < 6) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "Countersignature SignerInfo too short: expected at least 6 fields");
        }
        int idx = 0;

        // [0] version — пропускаем
        idx++;

        // [1] sid — IssuerAndSerialNumber
        CmsIssuerAndSerialNumber sid = CmsIssuerAndSerialNumber.decode(siParts[idx++]);

        // [2] digestAlgorithm
        CmsAlgorithmIdentifier digestAlg = CmsAlgorithmIdentifier.decode(siParts[idx++]);
        String digestOid = digestAlg.algorithmOid();

        // [3] signedAttrs [0] IMPLICIT
        if (idx >= siParts.length || !DerCodec.isContextTag(siParts[idx], 0)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersignature SignerInfo does not contain signedAttrs");
        }
        byte[] signedAttrsWrapped = siParts[idx++];
        int[] saLenInfo = DerCodec.decodeLength(signedAttrsWrapped, 1);
        int saStart = 1 + saLenInfo[1];
        byte[] signedAttrsContent =
                java.util.Arrays.copyOfRange(
                        signedAttrsWrapped, saStart, signedAttrsWrapped.length);

        // Разбираем атрибуты
        List<byte[]> attrElems = new ArrayList<>();
        int pos = 0;
        while (pos < signedAttrsContent.length) {
            int[] attrLen = DerCodec.decodeLength(signedAttrsContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrElems.add(java.util.Arrays.copyOfRange(signedAttrsContent, pos, pos + attrTotal));
            pos += attrTotal;
        }

        byte[] signedAttrsForHash = DerCodec.encodeSetOf(attrElems.toArray(new byte[0][]));

        // Извлекаем messageDigest
        byte[] expectedDigest = null;
        List<CmsAttribute> signedAttributes = new ArrayList<>();
        for (byte[] attrDer : attrElems) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            signedAttributes.add(attr);
            if (GostOids.ATTR_MESSAGE_DIGEST.equals(attr.attrType())) {
                byte[][] msgVals = attr.attrValues();
                if (msgVals.length > 0) {
                    expectedDigest = DerCodec.parseOctetString(msgVals[0], 0);
                }
            }
        }

        if (expectedDigest == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersignature signedAttrs must contain message-digest");
        }

        // Сверяем messageDigest: hash(родительской signatureValue contents octets)
        byte[] actualDigest = digestForCountersig(parentSignatureValue, digestOid);
        if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersignature messageDigest does not match parent signatureValue");
        }

        // [4] signatureAlgorithm: OID сверяется с ключом сертификата ниже, как в основной подписи
        String signatureAlgOid = CmsAlgorithmIdentifier.decode(siParts[idx++]).algorithmOid();

        // [5] signature
        byte[] sigOctet = siParts[idx];
        byte[] csSignatureValue = DerCodec.parseOctetString(sigOctet, 0);

        // Находим сертификат countersigner'а по issuer+serial
        GostCertificate countersignerCert = findCountersignerCertificate(sid, embeddedCerts);
        if (countersignerCert == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersigner certificate not found in SignedData certificates");
        }

        // Контрподпись - такая же подпись, как основная: ключ без digitalSignature/nonRepudiation
        // и чужой OID алгоритма отвергаются до построения цепочки и проверки подписи.
        if (!countersignerCert.isKeyUsageValidForSigning()) {
            throw new PkixException(
                    PkixException.Reason.POLICY_VIOLATION,
                    "Countersignature signer certificate KeyUsage does not permit digital"
                            + " signatures");
        }
        CAdESSupport.validateSignatureAlgorithm(
                signatureAlgOid,
                countersignerCert.getPublicKey().getParams().hlen,
                "Countersignature");

        // Строим и валидируем цепочку; политика срока якоря нормализована на входе, как в CMS.
        List<GostCertificate> csChain =
                CertChainBuilder.buildChain(
                        countersignerCert, embeddedCerts, anchors.certificates());
        ChainValidator.validateChain(csChain, anchors);

        // Верифицируем подпись countersigner'а
        byte[] signedAttrsHash = digestForCountersig(signedAttrsForHash, digestOid);
        PublicKeyParameters countersignerKey = countersignerCert.getPublicKey();
        // Длина хэша берётся из digestAlgorithm чужого SignerInfo, длина подписи - из него же:
        // несовпадение с ключом отклоняем явно, а не через unchecked-исключение core.
        if (signedAttrsHash.length != countersignerKey.getParams().hlen) {
            throw new PkixException(
                    PkixException.Reason.ALG_MISMATCH,
                    "Countersignature digestAlgorithm "
                            + digestOid
                            + " does not match countersigner key size");
        }
        // Подпись неверной длины core не принимает: verifyHash возвращает false
        boolean countersignatureValid =
                Signature.verifyHash(signedAttrsHash, csSignatureValue, countersignerKey);
        if (!countersignatureValid) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "Countersignature signature invalid");
        }

        return new SignerResult(countersignerCert, csSignatureValue, signedAttributes, List.of());
    }

    private static byte[] digestForCountersig(byte[] data, String digestOid) throws PkixException {
        return CAdESSupport.digestByOidOrThrow(digestOid, data);
    }

    private static GostCertificate findCountersignerCertificate(
            CmsIssuerAndSerialNumber sid, List<GostCertificate> certs) {
        for (GostCertificate c : certs) {
            if (!c.getSerialNumberBigInt().equals(sid.serial())) {
                continue;
            }
            if (Arrays.equals(c.getIssuerDnBytes(), sid.issuer())) {
                return c;
            }
        }
        return null;
    }

    /**
     * Проверяет все escTimeStamp подписанта и возвращает минимальный genTime.
     */
    private static Instant extractAndVerifyEscTimestamps(
            SignerResult sr, List<GostCertificate> tsaCandidates, TrustAnchors anchors)
            throws PkixException {
        List<CmsAttribute> escAttrs = new ArrayList<>();
        for (CmsAttribute attr : sr.unsignedAttributes()) {
            if (GostOids.ESC_TIME_STAMP.equals(attr.attrType())) {
                escAttrs.add(attr);
            }
        }
        if (escAttrs.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "CAdES-X Long Type 1: escTimeStamp is missing");
        }

        byte[] input = buildEscHashInput(sr.signatureValue(), sr.unsignedAttributes());
        Instant min = null;
        for (CmsAttribute attr : escAttrs) {
            byte[][] values = attr.attrValues();
            if (values.length != 1) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "escTimeStamp: expected exactly one value, got " + values.length);
            }
            TspResponse response = TspResponse.parseTimeStampToken(values[0]);
            String hashOid = response.tstInfo().messageImprintAlgOid();
            if (!GostOids.DIGEST_256.equals(hashOid) && !GostOids.DIGEST_512.equals(hashOid)) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "escTimeStamp: unsupported messageImprint algorithm " + hashOid);
            }
            byte[] hash = CAdESSupport.digestByOidOrThrow(hashOid, input);
            response.verify(hash, hashOid, null, tsaCandidates, anchorCertificates(anchors));

            Instant genTime =
                    Instant.ofEpochMilli(
                            TspResponse.parseGeneralizedTimeToMs(response.tstInfo().genTime()));
            if (min == null || genTime.isBefore(min)) {
                min = genTime;
            }
        }
        return min;
    }

    private static Instant minTimestampGenTime(List<TstInfo> timestamps) throws PkixException {
        if (timestamps.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "CAdES-X Long: no signature-time-stamp");
        }
        Instant min = null;
        for (TstInfo timestamp : timestamps) {
            Instant value = tstGenTime(timestamp);
            if (min == null || value.isBefore(min)) {
                min = value;
            }
        }
        return min;
    }

    private static Instant maxTimestampGenTime(List<TstInfo> timestamps) throws PkixException {
        if (timestamps.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "CAdES-X Long: no signature-time-stamp");
        }
        Instant max = null;
        for (TstInfo timestamp : timestamps) {
            Instant value = tstGenTime(timestamp);
            if (max == null || value.isAfter(max)) {
                max = value;
            }
        }
        return max;
    }

    private static Instant tstGenTime(TstInfo timestamp) throws PkixException {
        return Instant.ofEpochMilli(TspResponse.parseGeneralizedTimeToMs(timestamp.genTime()));
    }

    /**
     * Проверяет наличие и корректность signingCertificateV2 в signed-атрибутах подписанта.
     * Fail-closed: отсутствие атрибута — PkixException.
     *
     * @param sr результат верификации подписанта (содержит signedAttributes)
     * @throws PkixException если signingCertificateV2 отсутствует или хэш не совпадает
     */
    private static void verifySigningCertV2ForSigner(SignerResult sr) throws PkixException {
        for (CmsAttribute attr : sr.signedAttributes()) {
            if (GostOids.SIGNING_CERTIFICATE_V2.equals(attr.attrType())) {
                byte[][] vals = attr.attrValues();
                if (vals.length > 0) {
                    CAdESAttributes.verifySigningCertificateV2(vals[0], sr.signerCertificate());
                    return;
                }
            }
        }
        throw new PkixException(
                PkixException.Reason.OTHER, "CAdES-T: signingCertificateV2 missing in signedAttrs");
    }

    /**
     * Извлекает и верифицирует метки времени.
     *
     * <p>Наличие атрибута не требуется - это решает вызывающий уровень
     * ({@link #requireSignatureTimestamps} для T/C/X Long). Если атрибут есть,
     * его SET обязан содержать ровно одно значение: несколько экземпляров
     * атрибута от разных TSA допускаются, но несколько значений внутри одного
     * экземпляра - нет (fail-closed против неоднозначной трактовки).
     * Используется countersignature, где timestamp опционален.
     */
    private static List<TstInfo> extractAndVerifyTimestamps(
            SignerResult sr, List<GostCertificate> tsaCandidates, TrustAnchors anchors)
            throws PkixException {
        List<TstInfo> timestamps = new ArrayList<>();
        for (CmsAttribute attr : sr.unsignedAttributes()) {
            if (!GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) continue;
            byte[][] vals = attr.attrValues();
            if (vals.length == 0) {
                throw new PkixException(
                        PkixException.Reason.OTHER, "signature-time-stamp: empty SET of values");
            }
            if (vals.length != 1) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "signature-time-stamp: expected exactly one value, got " + vals.length);
            }
            byte[] tsToken = vals[0];

            TspResponse tspResponse = TspResponse.parseTimeStampToken(tsToken);

            // messageImprint сверяем против подписи этого подписанта; дайджест — по заявленному
            // размеру ключа подписанта (согласовано с embed-стороной через один и тот же маппинг).
            byte[] sig = sr.signatureValue();
            String signerDigestOid =
                    GostSignatureHelper.keySizeToDigestOid(sr.signerCertificate().getKeySize());
            SignatureHashResult sh = computeTspMessageImprint(signerDigestOid, sig);

            tspResponse.verify(
                    sh.hash(), sh.oid(), null, tsaCandidates, anchorCertificates(anchors));

            checkCertValidityAtTime(sr.signerCertificate(), tspResponse.tstInfo().genTime());

            timestamps.add(tspResponse.tstInfo());
        }
        return timestamps;
    }

    private static void checkCertValidityAtTime(GostCertificate cert, String genTime)
            throws PkixException {
        long genTimeMs = TspResponse.parseGeneralizedTimeToMs(genTime);
        Instant genDate = Instant.ofEpochMilli(genTimeMs);

        Instant notBefore = cert.getNotBefore();
        Instant notAfter = cert.getNotAfter();

        if (notBefore != null && genDate.isBefore(notBefore.minusMillis(GostOids.CLOCK_SKEW_MS))) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Certificate not yet valid at timestamp genTime: " + genTime + " < notBefore");
        }
        if (notAfter != null && genDate.isAfter(notAfter.plusMillis(GostOids.CLOCK_SKEW_MS))) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Certificate expired before timestamp genTime: "
                            + genTime
                            + " > notAfter ("
                            + notAfter
                            + ")");
        }
    }
}
