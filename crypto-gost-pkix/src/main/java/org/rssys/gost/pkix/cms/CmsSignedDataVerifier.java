package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostDerParser;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;

/**
 * Проверка CMS SignedData.
 *
 * <p>Единственный входной метод - {@link #verify(byte[], VerifyOptions)}; все варианты проверки
 * задаются {@link VerifyOptions}:
 * <ul>
 *   <li>{@link SignerSelection#ANY} - OR-семантика: возвращается первый валидный подписант.
 *       Полезен для сценариев типа «достаточно подписи любого члена совета директоров».</li>
 *   <li>{@link SignerSelection#ALL} - AND-семантика: каждый подписант обязан пройти,
 *       иначе {@link PkixException} с указанием, какой подписант провалился.
 *       Используется {@link CAdESExtender} для multi-signer CAdES-T.</li>
 *   <li>{@link Revocation} - политика отзыва: {@link Revocation#none()},
 *       {@link Revocation#required(java.util.List)} (нет подходящего CRL - отказ) или
 *       {@link Revocation#ifAvailable(java.util.List)}. Проверяются embedded CRL из SignedData
 *       и внешние CRL через {@link CrlVerifier}.</li>
 * </ul>
 *
 * <p>При ошибке метод бросает {@link PkixException} (fail-closed).
 */
public final class CmsSignedDataVerifier {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CmsSignedDataVerifier");

    /** Пустой массив якорей для явного режима «только подпись». */
    private static final GostCertificate[] EMPTY_TRUSTED_CERTS = new GostCertificate[0];

    private CmsSignedDataVerifier() {}

    // ========================================================================
    // Публичные методы
    // ========================================================================

    /**
     * Верифицирует CMS SignedData по заданным параметрам.
     *
     * <p>Режим доверия, выбор подписантов, политика отзыва, detached-документ и пул кандидатов
     * задаются {@link VerifyOptions}; метод не имеет скрытых умолчаний. Семантика
     * {@link SignerSelection#ANY}: возвращается первый прошедший подписант, подписант с битой
     * подписью, недоверенной цепочкой или отзывом пропускается; {@link SignerSelection#ALL}:
     * любой отказ прерывает проверку.</p>
     *
     * <p>Detached-подпись принимается только с {@link VerifyOptions#detached(byte[])}, attached - только
     * без него: смешение режимов отвергается, чтобы подпись не проверялась не против того документа.</p>
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param options       параметры проверки (не null)
     * @return данные и прошедшие проверку подписанты
     * @throws PkixException если проверка не прошла: подпись, цепочка, срок, отзыв, привязка к документу
     * @throws IllegalArgumentException если {@code options} равен null
     */
    public static VerifiedSignedData verify(byte[] signedDataDer, VerifyOptions options)
            throws PkixException {
        if (options == null) {
            throw new IllegalArgumentException("options must not be null");
        }
        List<GostCertificate> candidates = normalizeCandidates(options.untrustedCandidates());
        TrustAnchors anchors = options.anchors();
        return verifyInternal(signedDataDer, options, anchors, candidates);
    }

    /** Проверяет список кандидатов: без null, дедупликация по DER, лимит размера. */
    private static List<GostCertificate> normalizeCandidates(List<GostCertificate> candidates)
            throws PkixException {
        if (candidates == null) {
            throw new IllegalArgumentException("untrustedCandidates must not be null");
        }
        List<GostCertificate> unique = new ArrayList<>();
        for (GostCertificate candidate : candidates) {
            if (candidate == null) {
                throw new IllegalArgumentException("untrustedCandidates must not contain null");
            }
            if (!containsDer(unique, candidate)) {
                unique.add(candidate);
            }
        }
        if (unique.size() > CmsConstants.MAX_EMBEDDED_CERTS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Too many untrusted candidate certificates: "
                            + unique.size()
                            + " > "
                            + CmsConstants.MAX_EMBEDDED_CERTS);
        }
        return unique;
    }

    private static boolean containsDer(List<GostCertificate> certs, GostCertificate cert) {
        byte[] der = cert.getEncoded();
        for (GostCertificate existing : certs) {
            if (Arrays.equals(existing.getEncoded(), der)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // Приватная логика
    // ========================================================================

    /**
     * Требует непустой список якорей без null-элементов (используется
     * {@code CmsSignedAndEnvelopedData}, где доверенные сертификаты приходят массивом).
     * <p>
     * Пустой список нельзя трактовать как «проверять только подпись»: это молчаливое отключение
     * доверия. Для явного режима есть {@link VerifyOptions#signatureOnly(SignerSelection)}.
     */
    static void requireTrustedCerts(GostCertificate[] trustedCerts) {
        if (trustedCerts == null || trustedCerts.length == 0) {
            throw new IllegalArgumentException(
                    "trustedCerts must not be empty; use VerifyOptions.signatureOnly()"
                            + " for explicit signature-only verification");
        }
        for (GostCertificate cert : trustedCerts) {
            if (cert == null) {
                throw new IllegalArgumentException("trustedCerts must not contain null");
            }
        }
    }

    private static VerifiedSignedData verifyInternal(
            byte[] signedDataDer,
            VerifyOptions options,
            TrustAnchors anchors,
            List<GostCertificate> untrustedCandidates)
            throws PkixException {
        boolean strict = options.signers() == SignerSelection.ALL;
        Revocation revocation = options.revocation();
        byte[] externalContent = options.detachedContent();
        GostCertificate[] trustedCerts =
                anchors != null
                        ? anchors.certificates().toArray(new GostCertificate[0])
                        : EMPTY_TRUSTED_CERTS;
        SignedDataParsed parsed = parseSignedData(signedDataDer, options.crlLimits());

        byte[] content;
        if (externalContent != null) {
            if (parsed.encapData() != null) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Detached verification requires SignedData without eContent");
            }
            content = externalContent;
        } else {
            if (parsed.encapData() == null) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Detached SignedData requires a detached verification method"
                                + " with the signed content");
            }
            content = parsed.encapData();
        }

        int totalSigners = parsed.signerInfos().length;
        if (totalSigners == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignedData contains no signerInfos");
        }
        List<SignerResult> results = new ArrayList<>();
        PkixException lastRevocationError = null;
        PkixException lastSignerError = null;
        List<GostCertificate> signerCandidates =
                signerCandidates(parsed.embeddedCerts(), trustedCerts);
        // Пул для построения цепочки: встроенные сертификаты и недоверенные кандидаты.
        List<GostCertificate> chainPool = new ArrayList<>(parsed.embeddedCerts());
        for (GostCertificate candidate : untrustedCandidates) {
            if (!containsDer(chainPool, candidate)) {
                chainPool.add(candidate);
            }
        }

        for (int sn = 0; sn < totalSigners; sn++) {
            byte[] signerInfoDer = parsed.signerInfos()[sn];
            LOG.log(Level.DEBUG, "Verifying signer {0}/{1}", sn + 1, totalSigners);

            SignerResult result;
            List<GostCertificate> chain = null;
            try {
                result =
                        verifyOneSigner(
                                signerInfoDer,
                                content,
                                signerCandidates,
                                untrustedCandidates,
                                parsed.eContentTypeOid());
                if (anchors != null) {
                    chain = buildAndValidateChain(result.signerCertificate(), chainPool, anchors);
                    result =
                            new SignerResult(
                                    result.signerCertificate(),
                                    result.signatureValue(),
                                    result.signedAttributes(),
                                    result.unsignedAttributes(),
                                    chain);
                }
            } catch (PkixException | IllegalArgumentException failure) {
                // SignerInfo целиком приходит от атакующего: unchecked-исключение разбора
                // нельзя пропускать наружу, иначе один битый подписант в режиме ANY оборвёт
                // проверку остальных, а в режиме ALL нарушит контракт PkixException.
                PkixException e =
                        failure instanceof PkixException pkix
                                ? pkix
                                : new PkixException(
                                        PkixException.Reason.PARSE_ERROR,
                                        "Malformed SignerInfo: " + failure.getMessage(),
                                        failure);
                if (strict) {
                    throw new PkixException(
                            e.reason(),
                            "Signer "
                                    + (sn + 1)
                                    + "/"
                                    + totalSigners
                                    + " failed verification: "
                                    + e.getMessage(),
                            e);
                }
                lastSignerError = e;
                LOG.log(Level.DEBUG, "Signer {0} failed: {1}", sn + 1, e.getMessage());
                continue;
            }

            // Проверка отзыва: отзыв подписанта невалидирует его, как и битая подпись.
            // В OR-режиме пробуем следующего, в AND-режиме — немедленное исключение.
            if (revocation.mode() != Revocation.Mode.NONE && chain != null) {
                try {
                    validateRevocation(
                            chain,
                            parsed.embeddedCrls(),
                            revocation.externalCrls(),
                            revocation.mode() == Revocation.Mode.REQUIRED,
                            options.crlLimits());
                } catch (PkixException e) {
                    if (strict) {
                        throw new PkixException(
                                e.reason(),
                                "Signer "
                                        + (sn + 1)
                                        + "/"
                                        + totalSigners
                                        + " failed revocation check: "
                                        + e.getMessage(),
                                e);
                    }
                    lastRevocationError = e;
                    LOG.log(
                            Level.DEBUG,
                            "Signer {0} failed revocation check: {1}",
                            sn + 1,
                            e.getMessage());
                    continue;
                }
            }

            LOG.log(
                    Level.DEBUG,
                    "SignedData verification passed (signer {0}/{1})",
                    sn + 1,
                    totalSigners);

            if (!strict) {
                // OR-семантика: первый успешный
                return new VerifiedSignedData(content, List.of(result), parsed.embeddedCrls());
            }
            results.add(result);
        }

        if (!strict) {
            if (lastRevocationError != null) {
                throw lastRevocationError;
            }
            if (lastSignerError != null) {
                throw lastSignerError;
            }
            throw new PkixException(PkixException.Reason.OTHER, "No signer passed verification");
        }
        return new VerifiedSignedData(content, results, parsed.embeddedCrls());
    }

    // Родственный, но НЕ идентичный разбор SignedData есть в SignedDataParts.parse() (пакет cms):
    // там — нейтральный raw-разбор полей для пересборки в CAdESExtender. Здесь разбор идёт дальше —
    // интерпретирует encapContentInfo и применяет DoS-лимиты (MAX_SIGNER_INFOS/MAX_EMBEDDED_CERTS),
    // прошёл отдельные P0-фиксы. Сознательно не унифицированы (см. javadoc SignedDataParts): цена
    // общей абстракции для двух разных контрактов выше выгоды.
    private static SignedDataParsed parseSignedData(byte[] signedDataDer, CrlLimits limits)
            throws PkixException {
        // Контейнер приходит от недоверенной стороны: ошибка DER-парсера - это битый вход, а не
        // программная ошибка, поэтому наружу выходит PkixException(PARSE_ERROR), как и у
        // CmsContentInfo.decode. Перехват узкий: NPE и прочие ошибки программы не маскируются,
        // а границы вложенных элементов проверяются явно, не через AIOOBE.
        try {
            return parseSignedDataChecked(signedDataDer, limits);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "Malformed SignedData: " + e.getMessage(), e);
        }
    }

    private static SignedDataParsed parseSignedDataChecked(byte[] signedDataDer, CrlLimits limits)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(signedDataDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Invalid contentType: expected id-signedData");
        }
        if (contentInfo.content() == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "ContentInfo does not contain SignedData");
        }

        byte[] signedDataBody = contentInfo.content();
        byte[][] signedDataParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        if (signedDataParts.length < 3) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData too short: expected at least version, digestAlgorithms, encapContentInfo");
        }

        int partIdx = 0;
        partIdx++; // [0] version
        partIdx++; // [1] digestAlgorithms — пропускаем

        // [2] encapContentInfo
        byte[] encapContentInfo = signedDataParts[partIdx++];
        byte[][] encapParts = DerCodec.parseSequenceContents(encapContentInfo, 0);
        if (encapParts.length < 1) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "encapContentInfo has no eContentType");
        }
        byte[] eContentTypeOid = encapParts[0];
        byte[] encapData = null;
        if (encapParts.length > 1) {
            // [0] EXPLICIT { OCTET STRING }. КриптоПро кодирует eContent в BER: неопределённая
            // длина [0] и составной OCTET STRING из сегментов; сегменты склеиваются в порядке
            // следования, как и в хэше подписанных атрибутов. Пустой, усечённый элемент, хвост и
            // чужой тег дают IllegalArgumentException, который parseSignedData превращает в
            // PARSE_ERROR (выход за границу массива исключён самой сборкой с проверкой границ).
            int explicitTag = encapParts[1][0] & 0xFF;
            if (explicitTag != DerCodec.TAG_CTX_CONSTRUCTED_0) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Unexpected tag in encapContentInfo: 0x"
                                + Integer.toHexString(explicitTag));
            }
            if (GostDerParser.isEmptyConstructed(encapParts[1])) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "encapContentInfo eContent is empty");
            }
            encapData = DerCodec.collectImplicitOctets(encapParts[1], 0);
        }

        // [3] certificates [0] IMPLICIT OPTIONAL
        List<GostCertificate> embeddedCerts;
        if (partIdx < signedDataParts.length
                && DerCodec.isContextTag(signedDataParts[partIdx], 0)) {
            embeddedCerts =
                    parseEmbeddedCertificates(
                            signedDataParts[partIdx++], CmsConstants.MAX_EMBEDDED_CERTS);
        } else {
            embeddedCerts = new ArrayList<>();
        }

        // [4] crls [1] IMPLICIT OPTIONAL
        List<GostCrl> embeddedCrls;
        if (partIdx < signedDataParts.length
                && DerCodec.isContextTag(signedDataParts[partIdx], 1)) {
            byte[] crlsField = signedDataParts[partIdx++];
            embeddedCrls = parseEmbeddedCrls(crlsField, limits);
        } else {
            embeddedCrls = new ArrayList<>();
        }

        // [last] signerInfos
        if (partIdx >= signedDataParts.length) {
            throw new PkixException(PkixException.Reason.OTHER, "No signerInfos in SignedData");
        }
        byte[] signerInfosField = signedDataParts[partIdx];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        if (signerInfos.length > CmsConstants.MAX_SIGNER_INFOS) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData signerInfos exceed maximum " + CmsConstants.MAX_SIGNER_INFOS);
        }

        return new SignedDataParsed(
                encapData, signerInfos, eContentTypeOid, embeddedCerts, embeddedCrls);
    }

    /**
     * Разбирает поле crls {@code [1] IMPLICIT SET OF RevocationInfoChoice} SignedData
     * (RFC 5652 §5.1) в список CRL (только CertificateList, other-ветка не поддерживается).
     *
     * <p>Проверяет суммарный размер поля и количество CRL — defence-in-depth поверх
     * уже существующих per-CRL лимитов ({@link GostCrl#DEFAULT_MAX_CRL_SIZE}).
     * GostCrl.fromDer() выполняет только структурный разбор, без verify() на этом этапе —
     * revoked-список не извлекается, CPU-стоимость низкая.
     *
     * <p>Package-private для переиспользования из {@link GostPkcs7#formatText(byte[])}:
     * та же DoS-защищённая логика разбора поля {@code crls [1]}, что и в верификации —
     * по образцу {@link #parseEmbeddedCertificates(byte[], int)}, чтобы не дублировать её.</p>
     *
     * @param crlsField DER-байты поля {@code [1]} (контекстный тег 1)
     * @return список разобранных CRL (возможно пустой)
     * @throws PkixException если превышены лимиты или CRL повреждён
     */
    static List<GostCrl> parseEmbeddedCrls(byte[] crlsField) throws PkixException {
        return parseEmbeddedCrls(crlsField, CrlLimits.DEFAULT);
    }

    /**
     * То же, что {@link #parseEmbeddedCrls(byte[])}, с заданными пределами CRL. Превышение размера
     * одного CRL даёт причину {@code CRL_LIMIT_EXCEEDED} (до создания {@link GostCrl}); число
     * записей проверяется позже, при проверке отзыва.
     *
     * @param crlsField DER-байты поля {@code [1]} (контекстный тег 1)
     * @param limits    пределы размера и числа записей CRL
     * @return список разобранных CRL (возможно пустой)
     * @throws PkixException если превышены пределы или CRL повреждён
     */
    static List<GostCrl> parseEmbeddedCrls(byte[] crlsField, CrlLimits limits)
            throws PkixException {
        int[] lenInfo = DerCodec.decodeLength(crlsField, 1);
        int contentStart = 1 + lenInfo[1];
        int contentEnd = crlsField.length;

        // Пустое содержимое [1] — легитимный случай (ноль CRL)
        if (contentStart >= contentEnd) {
            return new ArrayList<>();
        }

        // Проверяем общий размер поля до разбора (дёшево: byte[].length)
        if (crlsField.length > CmsConstants.MAX_EMBEDDED_CRLS_TOTAL_SIZE) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData crls field exceeds maximum size "
                            + CmsConstants.MAX_EMBEDDED_CRLS_TOTAL_SIZE
                            + ", got "
                            + crlsField.length);
        }

        List<GostCrl> crls = new ArrayList<>();
        int pos = contentStart;

        while (pos < contentEnd) {
            if (crls.size() >= CmsConstants.MAX_EMBEDDED_CRLS) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "SignedData embedded CRLs exceed maximum "
                                + CmsConstants.MAX_EMBEDDED_CRLS);
            }
            int[] crlLen = DerCodec.decodeLength(crlsField, pos + 1);
            int crlTotal = 1 + crlLen[1] + crlLen[0];
            if (pos + crlTotal > contentEnd) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "CRL TLV length exceeds remaining buffer in crls field");
            }
            byte[] crlDer = Arrays.copyOfRange(crlsField, pos, pos + crlTotal);
            limits.requireSize(crlDer);
            try {
                crls.add(GostCrl.fromDer(crlDer, limits));
            } catch (IllegalArgumentException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Corrupted CRL in SignedData crls field",
                        e);
            }
            pos += crlTotal;
        }
        return crls;
    }

    /**
     * Разбирает поле certificates {@code [0] IMPLICIT SET OF Certificate} SignedData
     * (RFC 5652 §5.1) в список сертификатов.
     *
     * <p>Вынесен из {@link #parseSignedData} как независимый от подписантов шаг: так
     * {@link GostPkcs7} переиспользует разбор certificates-only {@code .p7b} (без
     * signerInfos), не наследуя требование {@code signerInfos > 0}, которое к
     * извлечению сертификатов отношения не имеет.
     *
     * @param certsField DER-байты поля {@code [0]} (контекстный тег 0)
     * @param maxCerts   потолок числа сертификатов (защита от DoS)
     * @return список разобранных сертификатов (возможно пустой)
     * @throws PkixException если превышен лимит или сертификат повреждён (fail-closed)
     */
    static List<GostCertificate> parseEmbeddedCertificates(byte[] certsField, int maxCerts)
            throws PkixException {
        List<GostCertificate> certs = new ArrayList<>();
        int[] lenInfo = DerCodec.decodeLength(certsField, 1);
        int certsStart = 1 + lenInfo[1];
        int certsEnd = certsField.length;
        int pos = certsStart;
        int certCount = 0;
        while (pos < certsEnd) {
            if (certCount >= maxCerts) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "SignedData embedded certificates exceed maximum " + maxCerts);
            }
            certCount++;
            int[] certLen = DerCodec.decodeLength(certsField, pos + 1);
            int certTotal = 1 + certLen[1] + certLen[0];
            if (pos + certTotal > certsEnd) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Certificate TLV length exceeds remaining buffer in certificates field");
            }
            byte[] certDer = Arrays.copyOfRange(certsField, pos, pos + certTotal);
            try {
                certs.add(parseCert(certDer));
            } catch (CertificateException e) {
                // Fail-closed: битый сертификат в поле certificates не пропускаем молча —
                // иначе атакующий, контролирующий SignedData, может стратегически портить
                // DER, влияя на состав пула для построения цепочки.
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Corrupted certificate in SignedData certificates field",
                        e);
            }
            pos += certTotal;
        }
        return certs;
    }

    /**
     * Кандидаты для поиска сертификата подписанта: embedded-сертификаты и
     * явно доверенные сертификаты. Доверенные не становятся якорями сами по
     * себе; цепочка всё равно строится отдельно. Это нужно для TSP-токенов,
     * где КриптоПро не встраивает сертификат TSA.
     */
    private static List<GostCertificate> signerCandidates(
            List<GostCertificate> embedded, GostCertificate[] trustedCerts) {
        List<GostCertificate> result = new ArrayList<>(embedded);
        for (GostCertificate candidate : trustedCerts) {
            boolean duplicate = false;
            byte[] der = candidate.getEncoded();
            for (GostCertificate existing : result) {
                if (Arrays.equals(existing.getEncoded(), der)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                result.add(candidate);
            }
        }
        return result;
    }

    private static SignerResult verifyOneSigner(
            byte[] signerInfoDer,
            byte[] encapData,
            List<GostCertificate> embeddedCerts,
            List<GostCertificate> untrustedCandidates,
            byte[] eContentTypeOid)
            throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length < 6) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignerInfo too short: expected at least version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature");
        }
        int idx = 0;

        // [0] version
        idx++;

        // [1] sid
        CmsIssuerAndSerialNumber sid = CmsIssuerAndSerialNumber.decode(siParts[idx++]);

        // [2] digestAlgorithm
        CmsAlgorithmIdentifier digestAlg = CmsAlgorithmIdentifier.decode(siParts[idx++]);
        String digestOid = digestAlg.algorithmOid();

        // [3] signedAttrs [0] IMPLICIT OPTIONAL
        if (idx >= siParts.length || !DerCodec.isContextTag(siParts[idx], 0)) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignerInfo does not contain signedAttrs");
        }
        byte[] signedAttrsWrapped = siParts[idx++];
        int[] saLenInfo = DerCodec.decodeLength(signedAttrsWrapped, 1);
        int saStart = 1 + saLenInfo[1];
        byte[] signedAttrsContent =
                java.util.Arrays.copyOfRange(
                        signedAttrsWrapped, saStart, signedAttrsWrapped.length);

        java.util.List<byte[]> attrElems = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < signedAttrsContent.length) {
            int[] attrLen = DerCodec.decodeLength(signedAttrsContent, pos + 1);
            int attrTotal = 1 + attrLen[1] + attrLen[0];
            attrElems.add(java.util.Arrays.copyOfRange(signedAttrsContent, pos, pos + attrTotal));
            pos += attrTotal;
        }

        byte[] signedAttrsForHash = DerCodec.encodeSetOf(attrElems.toArray(new byte[0][]));

        List<CmsAttribute> signedAttributes = new ArrayList<>();
        byte[] expectedDigest = null;
        byte[] signedContentTypeOid = null;
        for (byte[] attrDer : attrElems) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            signedAttributes.add(attr);
            if (GostOids.ATTR_MESSAGE_DIGEST.equals(attr.attrType())) {
                byte[][] vals = attr.attrValues();
                if (vals.length > 0) {
                    expectedDigest = DerCodec.parseOctetString(vals[0], 0);
                }
            } else if (GostOids.ATTR_CONTENT_TYPE.equals(attr.attrType())) {
                byte[][] vals = attr.attrValues();
                if (vals.length > 0) {
                    signedContentTypeOid = vals[0];
                }
            }
        }

        // RFC 5652 §5.4: signedAttrs ОБЯЗАН содержать content-type и message-digest
        if (signedContentTypeOid == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signedAttrs must contain content-type attribute (RFC 5652 §5.4)");
        }
        if (!java.util.Arrays.equals(eContentTypeOid, signedContentTypeOid)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "contentType mismatch: signed-attr does not match eContentType");
        }

        if (expectedDigest == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signedAttrs must contain message-digest attribute (RFC 5652 §5.4)");
        }
        if (encapData != null) {
            byte[] actualDigest = digestFor(encapData, digestOid);
            if (!java.security.MessageDigest.isEqual(expectedDigest, actualDigest)) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Data digest does not match messageDigest attribute");
            }
        }

        // [4] signatureAlgorithm — читаем OID; консистентность с ключом проверяем ниже,
        // когда разрешён сертификат подписанта (fail-closed против algorithm-confusion).
        String signatureAlgOid = CmsAlgorithmIdentifier.decode(siParts[idx++]).algorithmOid();

        // [5] signature
        byte[] sigOctet = siParts[idx];
        byte[] signatureValue = DerCodec.parseOctetString(sigOctet, 0);
        idx++;

        // [6] unsignedAttrs [1] IMPLICIT OPTIONAL
        List<CmsAttribute> unsignedAttributes = new ArrayList<>();
        if (idx < siParts.length && DerCodec.isContextTag(siParts[idx], 1)) {
            byte[] unsignedAttrsWrapped = siParts[idx];
            int[] uaLenInfo = DerCodec.decodeLength(unsignedAttrsWrapped, 1);
            int uaStart = 1 + uaLenInfo[1];
            byte[] unsignedAttrsContent =
                    java.util.Arrays.copyOfRange(
                            unsignedAttrsWrapped, uaStart, unsignedAttrsWrapped.length);

            int uaPos = 0;
            while (uaPos < unsignedAttrsContent.length) {
                int[] attrLen = DerCodec.decodeLength(unsignedAttrsContent, uaPos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                unsignedAttributes.add(
                        CmsAttribute.decode(
                                java.util.Arrays.copyOfRange(
                                        unsignedAttrsContent, uaPos, uaPos + attrTotal)));
                uaPos += attrTotal;
            }
        }

        byte[] signedAttrsHash = digestFor(signedAttrsForHash, digestOid);

        GostCertificate signerCert =
                resolveSignerCert(sid, embeddedCerts, untrustedCandidates, signedAttributes);

        if (signerCert != null && !signerCert.isKeyUsageValidForSigning()) {
            throw new PkixException(
                    PkixException.Reason.POLICY_VIOLATION,
                    "Signer certificate KeyUsage does not permit digital signatures");
        }

        PublicKeyParameters pubKey;
        if (signerCert != null) {
            pubKey = signerCert.getPublicKey();
        } else {
            throw new PkixException(PkixException.Reason.OTHER, "Signer certificate not found");
        }

        CAdESSupport.validateSignatureAlgorithm(
                signatureAlgOid, pubKey.getParams().hlen, "SignerInfo");

        // Длина хэша задаётся digestAlgorithm из SignerInfo, а длина подписи - самим SignerInfo:
        // оба значения контролирует атакующий. Подпись с хэшем другой длины проверить нельзя в
        // принципе, поэтому несовпадение отклоняется как подмена алгоритма, а не как сбой core.
        if (signedAttrsHash.length != pubKey.getParams().hlen) {
            throw new PkixException(
                    PkixException.Reason.ALG_MISMATCH,
                    "SignerInfo digestAlgorithm "
                            + digestOid
                            + " does not match signer key size ("
                            + (pubKey.getParams().hlen * 8)
                            + " bit)");
        }
        // Подпись неверной длины core не принимает: verifyHash возвращает false
        boolean signatureValid = Signature.verifyHash(signedAttrsHash, signatureValue, pubKey);
        if (!signatureValid) {
            throw new PkixException(PkixException.Reason.SIGNATURE_INVALID, "Signature invalid");
        }

        return new SignerResult(signerCert, signatureValue, signedAttributes, unsignedAttributes);
    }

    private static byte[] digestFor(byte[] data, String digestOid) throws PkixException {
        return CAdESSupport.digestByOidOrThrow(digestOid, data);
    }

    /**
     * Находит сертификат подписанта. Сначала среди встроенных и доверенных (прежнее
     * поведение), затем среди недоверенных кандидатов.
     *
     * <p>Сертификат из кандидатов принимается только при привязке к подписанным
     * данным: ровно один {@code signingCertificateV2}, и ровно один сертификат из
     * совпавших по sid имеет такой certHash. Перебора после неудачной проверки
     * подписи нет: выбор детерминирован до неё.</p>
     */
    private static GostCertificate resolveSignerCert(
            CmsIssuerAndSerialNumber sid,
            List<GostCertificate> ownCerts,
            List<GostCertificate> untrustedCandidates,
            List<CmsAttribute> signedAttributes)
            throws PkixException {
        GostCertificate own = findCertByIssuerAndSerial(sid, ownCerts);
        if (own != null || untrustedCandidates.isEmpty()) {
            return own;
        }
        List<GostCertificate> sidMatches = new ArrayList<>();
        for (GostCertificate candidate : untrustedCandidates) {
            if (candidate.getSerialNumberBigInt().equals(sid.serial())
                    && issuerMatches(candidate, sid.issuer())
                    && !containsDer(sidMatches, candidate)) {
                sidMatches.add(candidate);
            }
        }
        if (sidMatches.isEmpty()) {
            return null;
        }
        return selectBoundCandidate(sidMatches, signedAttributes);
    }

    /**
     * Выбирает из совпавших по sid кандидатов единственный, названный в
     * {@code signingCertificateV2} подписанных атрибутов.
     *
     * <p>Требуется ровно один атрибут с одним значением и ровно один сертификат с
     * совпавшим certHash. Сверяется первый {@code ESSCertIDv2} атрибута (для подписанта
     * он единственный по RFC 5035 §4). Устаревший {@code signingCertificate} v1 (SHA-1)
     * не принимается. Отсутствие атрибута, несовпадение и неоднозначность -
     * отказ до проверки подписи (fail-closed, без перебора).</p>
     *
     * @param sidMatches       различные по DER кандидаты с тем же issuer и serial
     * @param signedAttributes подписанные атрибуты SignerInfo
     */
    static GostCertificate selectBoundCandidate(
            List<GostCertificate> sidMatches, List<CmsAttribute> signedAttributes)
            throws PkixException {
        byte[] essValue = null;
        for (CmsAttribute attr : signedAttributes) {
            if (!GostOids.SIGNING_CERTIFICATE_V2.equals(attr.attrType())) {
                continue;
            }
            byte[][] values = attr.attrValues();
            if (essValue != null || values.length != 1) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Signer certificate from untrusted candidates requires exactly one"
                                + " signingCertificateV2 value");
            }
            essValue = values[0];
        }
        if (essValue == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Signer certificate from untrusted candidates requires signingCertificateV2");
        }

        GostCertificate bound = null;
        for (GostCertificate match : sidMatches) {
            try {
                CAdESAttributes.verifySigningCertificateV2(essValue, match);
            } catch (PkixException e) {
                // Кандидат по sid подходит, но не связан с подписью через ESS: причина отказа
                // «signer certificate not found» иначе не отличима от отсутствия кандидатов
                if (LOG.isLoggable(Level.DEBUG)) {
                    LOG.log(
                            Level.DEBUG,
                            "Candidate certificate (serial 0x{0}) does not match"
                                    + " signingCertificateV2",
                            match.getSerialNumberBigInt().toString(16));
                }
                continue;
            }
            if (bound != null) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Ambiguous signer certificate among untrusted candidates");
            }
            bound = match;
        }
        if (bound == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "No candidate matches signingCertificateV2 of the signer");
        }
        return bound;
    }

    private static GostCertificate findCertByIssuerAndSerial(
            CmsIssuerAndSerialNumber sid, List<GostCertificate> certs) {
        for (GostCertificate c : certs) {
            if (!c.getSerialNumberBigInt().equals(sid.serial())) {
                continue;
            }
            if (issuerMatches(c, sid.issuer())) {
                return c;
            }
        }
        return null;
    }

    private static boolean issuerMatches(GostCertificate cert, byte[] issuerDer) {
        return Arrays.equals(cert.getIssuerDnBytes(), issuerDer);
    }

    private static GostCertificate parseCert(byte[] certDer) throws CertificateException {
        try {
            return GostCertificate.fromDer(certDer);
        } catch (Exception e) {
            throw new CertificateException("Failed to parse certificate DER", e);
        }
    }

    /**
     * Строит цепочку сертификатов и проверяет её через ChainValidator.
     * Возвращает построенную цепочку для дальнейшей проверки отзыва.
     *
     * @return цепочка leaf-first
     * @throws PkixException при ошибке построения или валидации цепочки
     */
    private static List<GostCertificate> buildAndValidateChain(
            GostCertificate signerCert, List<GostCertificate> embeddedCerts, TrustAnchors anchors)
            throws PkixException {
        // Политика срока якоря уже применена в VerifyOptions.trusting: DEFAULT там
        // превращается в REJECT, поэтому срок любого якоря проверяется независимо от n.
        List<GostCertificate> chain =
                CertChainBuilder.buildChain(signerCert, embeddedCerts, anchors.certificates());
        return ChainValidator.validateChain(chain, anchors);
    }

    /**
     * Проверяет статус отзыва для каждого сертификата цепочки (кроме trust anchor).
     *
     * <p>Для каждого сертификата проверяются ВСЕ matching CRL (с совпадающим issuer DN)
     * из embedded и external списков. Сертификат считается валидным, только если
     * ни один из проверенных CRL не определяет его как отозванный (fail-closed
     * против downgrade-атаки: если embedded CRL устарел, а внешний содержит отзыв —
     * верификатор дойдёт до внешнего и выявит отзыв).
     *
     * <p>Delta CRL (Reason.DELTA_CRL_NOT_SUPPORTED), CRL, не покрывающий сертификат
     * (partial/indirect, Reason.IDP_NOT_SUPPORTED) и CRL с неизвестным critical-расширением
     * (Reason.UNKNOWN_CRITICAL_EXTENSION, RFC 5280 §5.2 запрещает использовать такой CRL)
     * пропускаются как неподдерживаемые.
     * Остальные ошибки верификации пробрасываются немедленно (fail-closed).
     * При отсутствии подходящего CRL: {@code required} - отказ
     * ({@code REVOCATION_STATUS_UNKNOWN}), иначе предупреждение и сертификат проходит.
     *
     * @param chain        цепочка leaf-first
     * @param embeddedCrls CRL из поля crls [1] SignedData
     * @param externalCrls дополнительные CRL от вызывающего (не null)
     * @param required     true - отсутствие подходящего CRL недопустимо
     * @param limits       пределы размера и числа записей CRL; превышение - ошибка, а не
     *                     пропуск CRL
     * @throws PkixException если сертификат отозван, CRL невалиден, превышены пределы или
     *                       обязательный CRL не найден
     */
    private static void validateRevocation(
            List<GostCertificate> chain,
            List<GostCrl> embeddedCrls,
            List<GostCrl> externalCrls,
            boolean required,
            CrlLimits limits)
            throws PkixException {
        int n = chain.size();
        for (int i = 0; i < n - 1; i++) {
            GostCertificate cert = chain.get(i);
            GostCertificate issuer = chain.get(i + 1);

            byte[] certIssuerDn = cert.getIssuerDnBytes();
            byte[] certSerial = cert.getSerialNumber();

            List<GostCrl> candidates = new ArrayList<>();
            if (embeddedCrls != null) {
                candidates.addAll(embeddedCrls);
            }
            if (externalCrls != null) {
                candidates.addAll(externalCrls);
            }

            boolean foundValidCrl = false;
            for (GostCrl crl : candidates) {
                if (!Arrays.equals(crl.getIssuerDnBytes(), certIssuerDn)) {
                    continue;
                }
                try {
                    CrlVerifier.verify(crl.getEncoded(), cert, issuer, null, limits);
                    foundValidCrl = true;
                    // без break — проверяем все matching CRL;
                    // если любой последующий CRL обнаружит отзыв — пробрасывается исключение
                } catch (PkixException e) {
                    if (e.reason() == PkixException.Reason.IDP_NOT_SUPPORTED
                            || e.reason() == PkixException.Reason.DELTA_CRL_NOT_SUPPORTED
                            || e.reason() == PkixException.Reason.UNKNOWN_CRITICAL_EXTENSION) {
                        LOG.log(
                                Level.DEBUG,
                                "CRL skipped (unsupported type: {0}), issuer={1}",
                                e.getMessage(),
                                crl.getIssuerDnForLog(GostCertificate.DN_LOG_MAX_CHARS));
                        continue;
                    }
                    throw e;
                }
            }

            if (!foundValidCrl && required) {
                throw new PkixException(
                        PkixException.Reason.REVOCATION_STATUS_UNKNOWN,
                        "No valid CRL found for cert chain["
                                + i
                                + "], serial=0x"
                                + new BigInteger(1, certSerial).toString(16));
            }
            if (!foundValidCrl) {
                LOG.log(
                        Level.WARNING,
                        "No valid CRL found for cert chain[{0}], serial=0x{1}",
                        i,
                        new BigInteger(1, certSerial).toString(16));
            }
        }
    }

    private record SignedDataParsed(
            byte[] encapData,
            byte[][] signerInfos,
            byte[] eContentTypeOid,
            List<GostCertificate> embeddedCerts,
            List<GostCrl> embeddedCrls) {}
}
