package org.rssys.gost.pkix.cms;

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.util.GostLogger;
import org.rssys.gost.pkix.util.GostLogger.Level;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Проверка CMS SignedData.
 *
 * <p>Два режима верификации:
 * <ul>
 *   <li>{@link #verifyAny} — OR-семантика: возвращает первого валидного подписанта.
 *       Полезен для сценариев типа «достаточно подписи любого члена совета директоров».</li>
 *   <li>{@link #verifyAll} — AND-семантика: каждый подписант обязан пройти,
 *       иначе {@link PkixException} с указанием, какой подписант провалился.
 *       Используется {@link CAdESExtender} для multi-signer CAdES-T.</li>
 * </ul>
 *
 * <p>Для каждого режима есть вариант с автоматической проверкой отзыва
 * ({@code WithRevocationCheck}): проверяет embedded CRL из SignedData
 * и опционально внешние CRL через {@link CrlVerifier}.
 *
 * <p>При ошибке все методы бросают {@link PkixException} (fail-closed).
 */
public final class CmsSignedDataVerifier {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CmsSignedDataVerifier");

    private CmsSignedDataVerifier() {}

    // ========================================================================
    // Публичные методы
    // ========================================================================

    /**
     * Верифицирует SignedData DER — хотя бы один подписант должен пройти.
     * OR-семантика: возвращает первого успешно верифицированного подписанта.
     * Остальные подписанты не проверяются до конца — при обнаружении первого
     * валидного метод немедленно возвращает результат.
     *
     * <p>Для сценариев, где важны все подписанты, используйте {@link #verifyAll}.
     *
     * <p>Проверка отзыва сертификатов не выполняется — используйте
     * {@link #verifyAnyWithRevocationCheck} для автоматической проверки по CRL.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов
     * @return результат с данными и сертификатом первого валидного подписанта
     * @throws PkixException если ни один подписант не прошёл верификацию
     */
    public static VerifiedSignedData verifyAny(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, false, false, null);
    }

    /**
     * Верифицирует SignedData DER — все подписанты обязаны пройти.
     * AND-семантика: любой провал немедленно прерывает верификацию.
     *
     * <p>В отличие от {@link #verifyAny}, который возвращает первого валидного
     * и игнорирует остальных, этот метод требует успешной верификации каждого
     * подписанта. Используется {@link CAdESExtender} для multi-signer CAdES-T.
     *
     * <p>Проверка отзыва сертификатов не выполняется — используйте
     * {@link #verifyAllWithRevocationCheck} для автоматической проверки по CRL.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов
     * @return все успешно верифицированные подписанты
     * @throws PkixException если хотя бы один подписант провалился
     */
    public static MultiSignerVerifiedData verifyAll(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, true, false, null);
    }

    /**
     * Верифицирует SignedData с автоматической проверкой отзыва по embedded CRL.
     * OR-семантика: возвращает первого успешно верифицированного подписанта.
     * Если подписант отозван — пробуется следующий (как и при битой подписи).
     *
     * <p>Для каждого сертификата цепочки (кроме trust anchor) проверяются все CRL
     * с совпадающим issuer DN среди embedded CRL из SignedData. Если ни один
     * из matching CRL не определяет сертификат как отозванный — подписант
     * считается валидным. При отсутствии подходящего CRL проверка пропускается
     * (best-effort, warn).
     *
     * <p>Delta CRL и partial/indirect CRL (неподдерживаемые типы) пропускаются
     * при подборе кандидата — верификатор проверяет следующий подходящий CRL.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов (не пустой)
     * @return результат с данными и сертификатом первого валидного подписанта
     * @throws PkixException          если ни один подписант не прошёл верификацию
     *                                (в том числе все отозваны)
     * @throws IllegalArgumentException если {@code trustedCerts} пуст
     */
    public static VerifiedSignedData verifyAnyWithRevocationCheck(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyAnyWithRevocationCheck(signedDataDer, null, trustedCerts);
    }

    /**
     * Верифицирует SignedData с проверкой отзыва по embedded и внешним CRL.
     * OR-семантика.
     *
     * <p>Приоритет поиска CRL: сначала embedded (из SignedData), затем
     * {@code externalCrls}. Сопоставление — по issuer DN.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param externalCrls  дополнительные CRL для проверки (может быть null)
     * @param trustedCerts  список доверенных сертификатов (не пустой)
     * @return результат с данными и сертификатом первого валидного подписанта
     * @throws PkixException          при ошибке верификации или отзыве
     * @throws IllegalArgumentException если {@code trustedCerts} пуст
     */
    public static VerifiedSignedData verifyAnyWithRevocationCheck(
            byte[] signedDataDer, List<GostCrl> externalCrls, GostCertificate... trustedCerts)
            throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, false, true, externalCrls);
    }

    /**
     * Верифицирует SignedData с проверкой отзыва по embedded CRL, все подписанты.
     * AND-семантика.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param trustedCerts  список доверенных сертификатов (не пустой)
     * @return все успешно верифицированные подписанты
     * @throws PkixException          при ошибке верификации или отзыве
     * @throws IllegalArgumentException если {@code trustedCerts} пуст
     */
    public static MultiSignerVerifiedData verifyAllWithRevocationCheck(
            byte[] signedDataDer, GostCertificate... trustedCerts) throws PkixException {
        return verifyAllWithRevocationCheck(signedDataDer, null, trustedCerts);
    }

    /**
     * Верифицирует SignedData с проверкой отзыва по embedded и внешним CRL, все подписанты.
     * AND-семантика.
     *
     * @param signedDataDer DER-байты ContentInfo(id-signedData)
     * @param externalCrls  дополнительные CRL для проверки (может быть null)
     * @param trustedCerts  список доверенных сертификатов (не пустой)
     * @return все успешно верифицированные подписанты
     * @throws PkixException          при ошибке верификации или отзыве
     * @throws IllegalArgumentException если {@code trustedCerts} пуст
     */
    public static MultiSignerVerifiedData verifyAllWithRevocationCheck(
            byte[] signedDataDer, List<GostCrl> externalCrls, GostCertificate... trustedCerts)
            throws PkixException {
        return verifyInternal(signedDataDer, trustedCerts, true, true, externalCrls);
    }

    // ========================================================================
    // Приватная логика
    // ========================================================================

    @SuppressWarnings("unchecked")
    private static <T> T verifyInternal(
            byte[] signedDataDer,
            GostCertificate[] trustedCerts,
            boolean strict,
            boolean checkRevocation,
            List<GostCrl> externalCrls)
            throws PkixException {
        if (checkRevocation && (trustedCerts == null || trustedCerts.length == 0)) {
            throw new IllegalArgumentException(
                    "trustedCerts must not be empty for revocation checking");
        }
        SignedDataParsed parsed = parseSignedData(signedDataDer);

        int totalSigners = parsed.signerInfos().length;
        if (totalSigners == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "SignedData contains no signerInfos");
        }
        List<SignerResult> results = new ArrayList<>();
        PkixException lastRevocationError = null;

        for (int sn = 0; sn < totalSigners; sn++) {
            byte[] signerInfoDer = parsed.signerInfos()[sn];
            LOG.log(Level.DEBUG, "Verifying signer {0}/{1}", sn + 1, totalSigners);

            SignerResult result;
            List<GostCertificate> chain = null;
            try {
                result =
                        verifyOneSigner(
                                signerInfoDer,
                                parsed.encapData(),
                                parsed.embeddedCerts(),
                                parsed.eContentTypeOid());
                if (trustedCerts.length > 0) {
                    chain =
                            buildAndValidateChain(
                                    result.signerCertificate(),
                                    parsed.embeddedCerts(),
                                    Arrays.asList(trustedCerts));
                }
            } catch (PkixException e) {
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
                LOG.log(Level.DEBUG, "Signer {0} failed: {1}", sn + 1, e.getMessage());
                continue;
            }

            // Проверка отзыва: отзыв подписанта невалидирует его, как и битая подпись.
            // В OR-режиме пробуем следующего, в AND-режиме — немедленное исключение.
            if (checkRevocation && chain != null) {
                try {
                    validateRevocation(chain, parsed.embeddedCrls(), externalCrls);
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
                    Level.INFO,
                    "SignedData verification passed (signer {0}/{1})",
                    sn + 1,
                    totalSigners);

            if (!strict) {
                // OR-семантика: первый успешный
                return (T)
                        new VerifiedSignedData(
                                parsed.encapData(),
                                result.signerCertificate(),
                                result.unsignedAttributes(),
                                parsed.embeddedCrls());
            }
            results.add(result);
        }

        if (!strict) {
            if (lastRevocationError != null) {
                throw lastRevocationError;
            }
            throw new PkixException(PkixException.Reason.OTHER, "No signer passed verification");
        }
        return (T) new MultiSignerVerifiedData(parsed.encapData(), results, parsed.embeddedCrls());
    }

    // Родственный, но НЕ идентичный разбор SignedData есть в SignedDataParts.parse() (пакет cms):
    // там — нейтральный raw-разбор полей для пересборки в CAdESExtender. Здесь разбор идёт дальше —
    // интерпретирует encapContentInfo и применяет DoS-лимиты (MAX_SIGNER_INFOS/MAX_EMBEDDED_CERTS),
    // прошёл отдельные P0-фиксы. Сознательно не унифицированы (см. javadoc SignedDataParts): цена
    // общей абстракции для двух разных контрактов выше выгоды.
    private static SignedDataParsed parseSignedData(byte[] signedDataDer) throws PkixException {
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
            int[] lenInfo = DerCodec.decodeLength(encapParts[1], 1);
            int innerOff = 1 + lenInfo[1];
            int tag = encapParts[1][innerOff] & 0xFF;
            if (tag == DerCodec.TAG_OCTET_STRING_CONSTRUCTED) {
                int[] conLen = DerCodec.decodeLength(encapParts[1], innerOff + 1);
                int inner2 = innerOff + 1 + conLen[1];
                encapData = DerCodec.parseOctetString(encapParts[1], inner2);
            } else if (tag == DerCodec.TAG_OCTET_STRING) {
                encapData = DerCodec.parseOctetString(encapParts[1], innerOff);
            } else {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "Unexpected tag in encapContentInfo: 0x" + Integer.toHexString(tag));
            }
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
            embeddedCrls = parseEmbeddedCrls(crlsField);
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
            try {
                crls.add(GostCrl.fromDer(crlDer));
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

    private static SignerResult verifyOneSigner(
            byte[] signerInfoDer,
            byte[] encapData,
            List<GostCertificate> embeddedCerts,
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

        GostCertificate signerCert = findCertByIssuerAndSerial(sid, embeddedCerts);

        PublicKeyParameters pubKey;
        if (signerCert != null) {
            pubKey = signerCert.getPublicKey();
        } else {
            throw new PkixException(PkixException.Reason.OTHER, "Signer certificate not found");
        }

        validateSignatureAlgorithm(signatureAlgOid, pubKey.getParams().hlen);

        if (!Signature.verifyHash(signedAttrsHash, signatureValue, pubKey)) {
            throw new PkixException(PkixException.Reason.SIGNATURE_INVALID, "Signature invalid");
        }

        return new SignerResult(signerCert, signatureValue, signedAttributes, unsignedAttributes);
    }

    private static byte[] digestFor(byte[] data, String digestOid) throws PkixException {
        try {
            return GostSignatureHelper.digestByOid(digestOid, data);
        } catch (IllegalArgumentException e) {
            throw new PkixException("Unsupported digest algorithm: " + digestOid);
        }
    }

    /**
     * Проверяет OID из {@code SignerInfo.signatureAlgorithm} (RFC 5652 §5.3) в режиме fail-closed.
     *
     * <p>Легитимные продюсеры используют два семейства OID для ГОСТ Р 34.10-2012:
     * OID открытого ключа ({@code 1.2.643.7.1.1.1.1/.2}; так делают КриптоПро, openssl gost-engine
     * и данная библиотека) и signWithDigest ({@code 1.2.643.7.1.1.3.2/.3}; так делает BouncyCastle).
     * Оба принимаются. Реальная защита от подмены алгоритма — сверка объявленной OID-битности
     * (256/512) с кривой открытого ключа сертификата: несоответствие означает попытку
     * algorithm-confusion и отклоняется. Параметры алгоритма не проверяются строго — допустимы
     * и NULL, и их отсутствие (разные продюсеры кодируют по-разному).
     *
     * @param signatureAlgOid OID из signatureAlgorithm подписанта
     * @param keyHlen         длина хэша кривой ключа сертификата (32 -> 256-бит, 64 -> 512-бит)
     * @throws PkixException если OID не из ожидаемого множества либо его битность не совпадает
     *     с битностью ключа сертификата
     */
    private static void validateSignatureAlgorithm(String signatureAlgOid, int keyHlen)
            throws PkixException {
        boolean is256Oid =
                GostOids.PUBLIC_KEY_256.equals(signatureAlgOid)
                        || GostOids.SIGN_WITH_DIGEST_256.equals(signatureAlgOid);
        boolean is512Oid =
                GostOids.PUBLIC_KEY_512.equals(signatureAlgOid)
                        || GostOids.SIGN_WITH_DIGEST_512.equals(signatureAlgOid);

        if (!is256Oid && !is512Oid) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Unexpected SignerInfo signatureAlgorithm OID: " + signatureAlgOid);
        }

        boolean keyIs512 = keyHlen == GostOids.STREEBOG_512_HASH_LEN;
        if (is512Oid != keyIs512) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "SignerInfo signatureAlgorithm OID "
                            + signatureAlgOid
                            + " does not match signer key size ("
                            + (keyHlen * 8)
                            + " bit)");
        }
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
            GostCertificate signerCert,
            List<GostCertificate> embeddedCerts,
            List<GostCertificate> trustedCerts)
            throws PkixException {
        List<GostCertificate> chain =
                CertChainBuilder.buildChain(signerCert, embeddedCerts, trustedCerts);
        List<PublicKeyParameters> caKeys =
                trustedCerts.stream().map(GostCertificate::getPublicKey).toList();
        ChainValidator.validateChain(chain, caKeys);
        return chain;
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
     * <p>Delta CRL (Reason.DELTA_CRL_NOT_SUPPORTED) и partial/indirect CRL
     * (Reason.IDP_NOT_SUPPORTED) пропускаются.
     * Остальные ошибки верификации пробрасываются немедленно (fail-closed).
     * При отсутствии подходящего CRL проверка пропускается (best-effort, warn).
     *
     * @param chain        цепочка leaf-first
     * @param embeddedCrls CRL из поля crls [1] SignedData
     * @param externalCrls дополнительные CRL от вызывающего (может быть null)
     * @throws PkixException если сертификат отозван или CRL невалиден
     */
    private static void validateRevocation(
            List<GostCertificate> chain, List<GostCrl> embeddedCrls, List<GostCrl> externalCrls)
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
                    CrlVerifier.verify(
                            crl.getEncoded(), certSerial, issuer.getPublicKey(), certIssuerDn);
                    foundValidCrl = true;
                    // без break — проверяем все matching CRL;
                    // если любой последующий CRL обнаружит отзыв — пробрасывается исключение
                } catch (PkixException e) {
                    if (e.reason() == PkixException.Reason.IDP_NOT_SUPPORTED
                            || e.reason() == PkixException.Reason.DELTA_CRL_NOT_SUPPORTED) {
                        LOG.log(
                                Level.DEBUG,
                                "CRL skipped (unsupported type: {0}), issuer={1}",
                                e.getMessage(),
                                crl.getIssuerDn());
                        continue;
                    }
                    throw e;
                }
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
