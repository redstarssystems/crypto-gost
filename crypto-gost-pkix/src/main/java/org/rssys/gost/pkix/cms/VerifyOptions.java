package org.rssys.gost.pkix.cms;

import java.util.List;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Параметры проверки CMS SignedData для {@link CmsSignedDataVerifier#verify}.
 *
 * <p>Режим доверия задаётся фабрикой, поэтому недопустимые сочетания непредставимы:
 * <ul>
 *   <li>{@link #trusting(TrustAnchors, SignerSelection, Revocation)} - цепочка подписанта должна
 *       сойтись к якорям, отзыв проверяется по политике {@link Revocation};
 *   <li>{@link #signatureOnly(SignerSelection)} - явно небезопасный режим: проверяется только
 *       подпись, цепочка, срок и отзыв не проверяются; якорей и отзыва он не принимает вовсе.
 * </ul>
 *
 * <p>Объект неизменяем: {@link #detached(byte[])} и {@link #untrustedCandidates(List)} возвращают
 * новый экземпляр.</p>
 */
public final class VerifyOptions {

    private final TrustAnchors anchors;
    private final SignerSelection signers;
    private final Revocation revocation;
    private final byte[] detachedContent;
    private final List<GostCertificate> untrustedCandidates;
    private final CrlLimits crlLimits;

    private VerifyOptions(
            TrustAnchors anchors,
            SignerSelection signers,
            Revocation revocation,
            byte[] detachedContent,
            List<GostCertificate> untrustedCandidates,
            CrlLimits crlLimits) {
        this.anchors = anchors;
        this.signers = signers;
        this.revocation = revocation;
        this.detachedContent = detachedContent;
        this.untrustedCandidates = untrustedCandidates;
        this.crlLimits = crlLimits;
    }

    /**
     * Обычная проверка: подпись, цепочка до якорей, срок и отзыв по политике.
     *
     * <p>Срок якоря: если политика набора {@link AnchorExpiryPolicy#DEFAULT}, для CMS она
     * трактуется как {@link AnchorExpiryPolicy#REJECT}; явное значение сохраняется.</p>
     *
     * @param anchors    доверенные якоря (не null и не пусты)
     * @param signers    какие подписанты обязаны пройти (не null)
     * @param revocation политика отзыва (не null)
     * @return параметры проверки
     * @throws IllegalArgumentException если аргумент null или набор якорей пуст
     */
    public static VerifyOptions trusting(
            TrustAnchors anchors, SignerSelection signers, Revocation revocation) {
        if (anchors == null || anchors.isEmpty()) {
            throw new IllegalArgumentException(
                    "anchors must not be null or empty; use signatureOnly() for an explicit"
                            + " signature-only check");
        }
        requireNotNull(signers, "signers");
        requireNotNull(revocation, "revocation");
        TrustAnchors strict =
                anchors.expiryPolicy() == AnchorExpiryPolicy.DEFAULT
                        ? anchors.withExpiryPolicy(AnchorExpiryPolicy.REJECT)
                        : anchors;
        return new VerifyOptions(strict, signers, revocation, null, List.of(), CrlLimits.DEFAULT);
    }

    /**
     * Проверяет только подпись, без цепочки, срока и отзыва.
     *
     * <p><b>Небезопасно по умолчанию:</b> режим не проверяет, что сертификат подписанта выпущен
     * доверенным УЦ. Используйте, только если доверие установлено другим способом (например,
     * сертификат получен по доверенному каналу).</p>
     *
     * @param signers какие подписанты обязаны пройти (не null)
     * @return параметры проверки
     * @throws IllegalArgumentException если signers null
     */
    public static VerifyOptions signatureOnly(SignerSelection signers) {
        requireNotNull(signers, "signers");
        return new VerifyOptions(
                null, signers, Revocation.none(), null, List.of(), CrlLimits.DEFAULT);
    }

    /**
     * Проверка detached-подписи: подпись привязывается к переданному документу.
     *
     * <p>SignedData не должен содержать eContent. Документ копируется; обратная защитная копия
     * возвращается в {@link VerifiedSignedData#data()}.</p>
     *
     * @param content подписанный документ (не null)
     * @return новые параметры
     * @throws IllegalArgumentException если content null
     */
    public VerifyOptions detached(byte[] content) {
        requireNotNull(content, "content");
        return new VerifyOptions(
                anchors, signers, revocation, content.clone(), untrustedCandidates, crlLimits);
    }

    /**
     * Пул недоверенных сертификатов для поиска подписанта и промежуточных УЦ.
     *
     * <p>Нужен там, где сертификаты лежат не в самом SignedData (например, TSA-токен КриптоПро не
     * встраивает цепочку). Кандидаты - только пул поиска: якорями служат строго {@code anchors}.
     * Если подписант найден только среди кандидатов, он должен быть назван в
     * {@code signingCertificateV2} подписанных атрибутов (ровно один атрибут, совпавший certHash),
     * иначе отказ. Дубликаты по DER схлопываются, число ограничено
     * {@link CmsConstants#MAX_EMBEDDED_CERTS}.</p>
     *
     * @param candidates недоверенные сертификаты (не null, без null-элементов)
     * @return новые параметры
     * @throws IllegalArgumentException если список null/содержит null
     * @throws IllegalStateException если режим {@link #signatureOnly(SignerSelection)}: без
     *     цепочки пул не нужен
     */
    public VerifyOptions untrustedCandidates(List<GostCertificate> candidates) {
        if (anchors == null) {
            throw new IllegalStateException(
                    "untrustedCandidates is not applicable to signatureOnly()");
        }
        requireNotNull(candidates, "untrustedCandidates");
        for (GostCertificate candidate : candidates) {
            if (candidate == null) {
                throw new IllegalArgumentException("untrustedCandidates must not contain null");
            }
        }
        return new VerifyOptions(
                anchors, signers, revocation, detachedContent, List.copyOf(candidates), crlLimits);
    }

    /**
     * Пределы размера и числа записей CRL при разборе встроенных CRL и проверке отзыва.
     *
     * <p>По умолчанию {@link CrlLimits#DEFAULT}. Превышение даёт {@code PkixException} с причиной
     * {@code CRL_LIMIT_EXCEEDED}: проверка отзыва по такому CRL не пропускается ни при
     * обязательном, ни при необязательном отзыве. Пределы не меняют отдельный предел на входные
     * данные: встроенные CRL ограничены {@link CmsConstants#MAX_EMBEDDED_CRLS} штуками и
     * {@link CmsConstants#MAX_EMBEDDED_CRLS_TOTAL_SIZE} байтами суммарно, поэтому CRL крупнее
     * (например, полный CRL ФНС) во встроенном виде не принимается при любых {@code CrlLimits};
     * его передают как внешний ({@link Revocation}).</p>
     *
     * @param limits пределы размера и числа записей (не null)
     * @return новые параметры
     * @throws IllegalArgumentException если limits null
     */
    public VerifyOptions crlLimits(CrlLimits limits) {
        requireNotNull(limits, "limits");
        return new VerifyOptions(
                anchors, signers, revocation, detachedContent, untrustedCandidates, limits);
    }

    /** @return true для режима {@link #signatureOnly(SignerSelection)} */
    boolean isSignatureOnly() {
        return anchors == null;
    }

    /** @return якоря с применённой политикой срока; null для signatureOnly */
    TrustAnchors anchors() {
        return anchors;
    }

    SignerSelection signers() {
        return signers;
    }

    Revocation revocation() {
        return revocation;
    }

    /** @return документ для detached-проверки или null (копия не делается: внутренний вызов) */
    byte[] detachedContent() {
        return detachedContent;
    }

    List<GostCertificate> untrustedCandidates() {
        return untrustedCandidates;
    }

    CrlLimits crlLimits() {
        return crlLimits;
    }

    private static void requireNotNull(Object value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
    }

    /** Содержимое не выводится: может быть конфиденциальным. */
    @Override
    public String toString() {
        return "VerifyOptions[mode="
                + (anchors == null ? "signatureOnly" : "trusting")
                + ", signers="
                + signers
                + ", revocation="
                + revocation
                + ", detached="
                + (detachedContent != null)
                + "]";
    }
}
