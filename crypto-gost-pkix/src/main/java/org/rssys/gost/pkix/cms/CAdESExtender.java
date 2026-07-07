package org.rssys.gost.pkix.cms;

import java.io.IOException;
import java.lang.System.Logger;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.pkix.tsp.TstInfo;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * CAdES-T extender: встраивание и верификация меток времени (ETSI EN 319 122-2).
 *
 * <p>Поддерживает одного и нескольких подписантов:
 * для каждого подписанта запрашивается отдельная метка (messageImprint = hash(его-подписи)),
 * и встраивается в его собственные unsignedAttrs.
 *
 * <p>Порядок SignerInfo в результирующем SET OF может отличаться от порядка при чтении
 * из-за канонической DER-сортировки в {@link DerCodec#encodeSetOf}. Это безопасно:
 * каждая метка встраивается внутрь своего SignerInfo, не сопоставляется по индексу
 * при последующем чтении.
 */
public final class CAdESExtender {

    private static final Logger LOG = System.getLogger("org.rssys.gost.pkix.cms.CAdESExtender");

    private CAdESExtender() {}

    // ========================================================================
    // Построение CAdES-T
    // ========================================================================

    /**
     * Встраивает один TimeStampToken DER в unsignedAttrs всех подписантов.
     * Удобно для single-signer или когда все подписанты используют одну метку.
     */
    public static byte[] embedTimestamp(byte[] cadesBesDer, byte[] timeStampTokenDer)
            throws PkixException {
        return embedTimestamps(cadesBesDer, List.of(timeStampTokenDer));
    }

    /**
     * Встраивает TimeStampToken'ы один-к-одному в unsignedAttrs подписантов.
     *
     * @param cadesBesDer CAdES-BES подпись
     * @param tokens      список токенов, по одному на подписанта (в порядке чтения)
     * @return CAdES-T подпись
     */
    public static byte[] embedTimestamps(byte[] cadesBesDer, List<byte[]> tokens)
            throws PkixException {
        Objects.requireNonNull(cadesBesDer, "cadesBesDer must not be null");
        Objects.requireNonNull(tokens, "tokens must not be null");

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesBesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        byte[][] sdParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        if (sdParts.length < 4) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData too short: expected at least version, digestAlgorithms, encapContentInfo, signerInfos");
        }
        int sdIdx = 0;

        byte[] version = sdParts[sdIdx++];
        byte[] digestAlgs = sdParts[sdIdx++];
        byte[] encapContentInfo = sdParts[sdIdx++];

        byte[] existingCerts = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0)) {
            existingCerts = sdParts[sdIdx++];
        }

        byte[] crls = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 1)) {
            crls = sdParts[sdIdx++];
        }

        if (sdIdx >= sdParts.length) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "SignedData too short: missing signerInfos");
        }
        byte[] signerInfosField = sdParts[sdIdx];
        byte[][] origSignerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        int signerCount = origSignerInfos.length;
        if (tokens.size() != signerCount) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Token count ("
                            + tokens.size()
                            + ") must match signer count ("
                            + signerCount
                            + ")");
        }

        // Встраиваем токены — каждому подписанту свой
        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        List<byte[]> allTokensForCerts = new ArrayList<>();
        for (int i = 0; i < signerCount; i++) {
            byte[] token = tokens.get(i);
            modifiedSignerInfos.add(injectUnsignedAttr(origSignerInfos[i], token));
            allTokensForCerts.add(token);
        }

        // Объединяем сертификаты из всех токенов
        byte[] newCerts = mergeCertificates(existingCerts, allTokensForCerts);

        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));

        List<byte[]> sdElements = new ArrayList<>();
        sdElements.add(version);
        sdElements.add(digestAlgs);
        sdElements.add(encapContentInfo);
        if (newCerts != null) {
            sdElements.add(newCerts);
        }
        if (crls != null) {
            sdElements.add(crls);
        }
        sdElements.add(newSignerInfos);

        byte[] newSignedData = DerCodec.encodeSequence(sdElements.toArray(new byte[0][]));

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /**
     * Полный цикл: для каждого подписанта запрашивает TSP, встраивает метки.
     *
     * <p>Генерирует криптографический nonce для каждого TSP-запроса и сверяет его в ответе
     * (защита от replay-атак). Требует хотя бы один доверенный сертификат TSA —
     * встраивание метки без проверки подписи TSA небезопасно.
     */
    public static byte[] addTimestamp(
            byte[] cadesBesDer,
            String tsaUrl,
            TspTransport transport,
            GostCertificate... tsaTrusted)
            throws PkixException, IOException {
        Objects.requireNonNull(cadesBesDer, "cadesBesDer must not be null");
        Objects.requireNonNull(tsaUrl, "tsaUrl must not be null");
        Objects.requireNonNull(transport, "transport must not be null");
        if (tsaTrusted.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Adding a timestamp without verifying the TSA signature is insecure — "
                            + "provide at least one trusted TSA certificate");
        }

        // Извлекаем подписи всех подписантов
        List<byte[]> signatures = extractAllSignatures(cadesBesDer);

        List<byte[]> tokens = new ArrayList<>();
        for (byte[] signature : signatures) {
            SignatureHashResult sh = computeTspMessageImprint(signature);

            TspRequestBuilder reqBuilder =
                    TspRequestBuilder.create().messageImprint(sh.hash(), sh.oid()).certReq(true);
            byte[] tspReq = reqBuilder.build();

            byte[] tspRespDer = transport.send(tspReq, tsaUrl);
            TspResponse tspResponse = TspResponse.fromDer(tspRespDer);
            tspResponse.verify(sh.hash(), sh.oid(), reqBuilder.getNonce(), tsaTrusted);
            tokens.add(tspResponse.timeStampTokenDer());
        }

        return embedTimestamps(cadesBesDer, tokens);
    }

    /**
     * Полный цикл с разными TSA URL для каждого подписанта.
     *
     * <p>Порядок URL соответствует порядку SignerInfo в SET OF после
     * лексикографической DER-сортировки — <b>не</b> порядку вызовов
     * {@code CmsSignedDataBuilder.addSigner()}.
     *
     * <p>Генерирует криптографический nonce для каждого TSP-запроса и сверяет его в ответе
     * (защита от replay-атак). Требует хотя бы один доверенный сертификат TSA.
     *
     * @param cadesBesDer CAdES-BES подпись (CMS SignedData с signingCertificateV2)
     * @param tsaUrls     список URL меток времени, по одному на каждого подписанта
     * @param transport   реализация транспорта TSP
     * @param tsaTrusted  доверенные корневые сертификаты TSA
     * @return CAdES-T подпись
     * @throws PkixException если размер tsaUrls не совпадает с количеством подписантов
     */
    public static byte[] addTimestamp(
            byte[] cadesBesDer,
            List<String> tsaUrls,
            TspTransport transport,
            GostCertificate... tsaTrusted)
            throws PkixException, IOException {
        Objects.requireNonNull(cadesBesDer, "cadesBesDer must not be null");
        Objects.requireNonNull(tsaUrls, "tsaUrls must not be null");
        Objects.requireNonNull(transport, "transport must not be null");
        if (tsaTrusted.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Adding a timestamp without verifying the TSA signature is insecure — "
                            + "provide at least one trusted TSA certificate");
        }

        List<byte[]> signatures = extractAllSignatures(cadesBesDer);

        if (tsaUrls.size() != signatures.size()) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "tsaUrls count ("
                            + tsaUrls.size()
                            + ") must match signer count ("
                            + signatures.size()
                            + ")");
        }

        List<byte[]> tokens = new ArrayList<>();
        for (int i = 0; i < signatures.size(); i++) {
            byte[] signature = signatures.get(i);
            SignatureHashResult sh = computeTspMessageImprint(signature);

            TspRequestBuilder reqBuilder =
                    TspRequestBuilder.create().messageImprint(sh.hash(), sh.oid()).certReq(true);
            byte[] tspReq = reqBuilder.build();

            byte[] tspRespDer = transport.send(tspReq, tsaUrls.get(i));
            TspResponse tspResponse = TspResponse.fromDer(tspRespDer);
            tspResponse.verify(sh.hash(), sh.oid(), reqBuilder.getNonce(), tsaTrusted);
            tokens.add(tspResponse.timeStampTokenDer());
        }

        return embedTimestamps(cadesBesDer, tokens);
    }

    // ========================================================================
    // Построение countersignature (RFC 5652 §11.4)
    // ========================================================================

    /**
     * Встраивает countersignature (RFC 5652 §11.4) для каждого подписанта.
     * Принимает CAdES-BES или CAdES-T и возвращает SignedData с countersignature.
     *
     * <p>Countersignature подписывает содержимое октета signatureValue
     * родительского SignerInfo (contents octets, без DER-обёртки tag/length),
     * не eContent документа. Сертификат countersigner'а добавляется в поле
     * certificates SignedData.
     *
     * @param cadesDer          CAdES-BES или CAdES-T подпись (CMS SignedData)
     * @param countersignerKey  приватный ключ countersigner'а
     * @param countersignerCert сертификат countersigner'а
     * @return CMS SignedData с countersignature в unsignedAttrs
     * @throws PkixException при ошибке разбора SignedData
     */
    public static byte[] embedCountersignature(
            byte[] cadesDer,
            PrivateKeyParameters countersignerKey,
            GostCertificate countersignerCert)
            throws PkixException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(countersignerKey, "countersignerKey must not be null");
        Objects.requireNonNull(countersignerCert, "countersignerCert must not be null");

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        byte[][] sdParts = DerCodec.parseSequenceContents(signedDataBody, 0);
        if (sdParts.length < 4) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR,
                    "SignedData too short: expected at least version, digestAlgorithms, encapContentInfo, signerInfos");
        }
        int sdIdx = 0;

        byte[] version = sdParts[sdIdx++];
        byte[] digestAlgs = sdParts[sdIdx++];
        byte[] encapContentInfo = sdParts[sdIdx++];

        byte[] existingCerts = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0)) {
            existingCerts = sdParts[sdIdx++];
        }

        byte[] crls = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 1)) {
            crls = sdParts[sdIdx++];
        }

        if (sdIdx >= sdParts.length) {
            throw new PkixException(
                    PkixException.Reason.PARSE_ERROR, "SignedData too short: missing signerInfos");
        }
        byte[] signerInfosField = sdParts[sdIdx];
        byte[][] origSignerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        if (origSignerInfos.length > CmsConstants.MAX_SIGNER_INFOS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Too many SignerInfo for embedCountersignature: "
                            + origSignerInfos.length
                            + " (max "
                            + CmsConstants.MAX_SIGNER_INFOS
                            + ")");
        }

        boolean is512 = countersignerCert.getKeySize() == 512;
        String digestOid = is512 ? GostOids.DIGEST_512 : GostOids.DIGEST_256;

        List<byte[]> modifiedSignerInfos = new java.util.ArrayList<>();
        for (byte[] si : origSignerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);

            // Извлекаем signatureValue contents octets родителя
            byte[] parentSigOctet = null;
            for (int i = siParts.length - 1; i >= 0; i--) {
                if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                    parentSigOctet = siParts[i];
                    break;
                }
            }
            if (parentSigOctet == null) {
                throw new PkixException(
                        PkixException.Reason.OTHER, "Signature not found in SignerInfo");
            }
            byte[] parentSigValue = DerCodec.parseOctetString(parentSigOctet, 0);

            // Строим countersignature SignerInfo
            byte[] countersigDer =
                    CountersignatureBuilder.buildCountersignature(
                            parentSigValue, countersignerKey, countersignerCert, digestOid);

            // Значение атрибута id-countersignature = SET OF Countersignature (SignerInfo)
            // (RFC 5652 §11.4)
            byte[] attrDer = CmsAttribute.encode(GostOids.ATTR_COUNTERSIGNATURE, countersigDer);
            modifiedSignerInfos.add(injectUnsignedAttrDer(si, attrDer));
        }

        // Добавляем сертификат countersigner'а в certificates
        byte[] newCerts = mergeCountersignerCert(existingCerts, countersignerCert);

        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));

        List<byte[]> sdElements = new ArrayList<>();
        sdElements.add(version);
        sdElements.add(digestAlgs);
        sdElements.add(encapContentInfo);
        if (newCerts != null) {
            sdElements.add(newCerts);
        }
        if (crls != null) {
            sdElements.add(crls);
        }
        sdElements.add(newSignerInfos);

        byte[] newSignedData = DerCodec.encodeSequence(sdElements.toArray(new byte[0][]));
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /** Добавляет сертификат countersigner'а в существующее поле certificates [0] IMPLICIT. */
    private static byte[] mergeCountersignerCert(
            byte[] existingCertsField, GostCertificate countersignerCert) throws PkixException {
        List<byte[]> allCerts = new ArrayList<>();

        if (existingCertsField != null) {
            int[] lenInfo = DerCodec.decodeLength(existingCertsField, 1);
            int contentOff = 1 + lenInfo[1];
            int pos = contentOff;
            int end = existingCertsField.length;
            while (pos < end) {
                if (allCerts.size() >= CmsConstants.MAX_CERTS_IN_EMBED_CS) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many certificates in SignedData: "
                                    + (allCerts.size() + 1)
                                    + " (max "
                                    + CmsConstants.MAX_CERTS_IN_EMBED_CS
                                    + ")");
                }
                int[] certLen = DerCodec.decodeLength(existingCertsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                allCerts.add(
                        java.util.Arrays.copyOfRange(existingCertsField, pos, pos + certTotal));
                pos += certTotal;
            }
        }

        byte[] newCertDer = countersignerCert.getEncoded();
        // Проверяем, нет ли уже такого сертификата (по DER)
        boolean duplicate = false;
        for (byte[] existing : allCerts) {
            if (java.util.Arrays.equals(existing, newCertDer)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            allCerts.add(newCertDer);
        }

        if (allCerts.isEmpty()) {
            return null;
        }
        byte[][] sorted = allCerts.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
    }

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
     * <p>Метки времени <b>не требуются</b> — в отличие от {@link #verifyCAdEST}, который
     * дополнительно проверяет {@code signature-time-stamp} в unsigned-атрибутах.
     * Если на вход передан CAdES-T с метками — метки игнорируются;
     * для верификации меток используйте {@link #verifyCAdEST}.
     *
     * @param cadesBesDer  CAdES-BES подпись (CMS SignedData с signingCertificateV2)
     * @param trustedCerts доверенные корневые сертификаты подписанта
     * @return результат с данными и сертификатами подписантов (без меток)
     * @throws PkixException при любой ошибке верификации (fail-closed)
     */
    public static VerifiedCAdESData verifyCAdESBES(
            byte[] cadesBesDer, GostCertificate... trustedCerts) throws PkixException {
        Objects.requireNonNull(cadesBesDer, "cadesBesDer must not be null");
        if (trustedCerts.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-BES verification requires at least one trusted certificate");
        }

        MultiSignerVerifiedData cmsResult =
                CmsSignedDataVerifier.verifyAll(cadesBesDer, trustedCerts);

        List<CAdESSignerResult> signerResults = new ArrayList<>();
        for (SignerResult sr : cmsResult.signers()) {
            verifySigningCertV2ForSigner(sr);
            signerResults.add(
                    new CAdESSignerResult(
                            sr.signerCertificate(), sr.signedAttributes(), List.of(), List.of()));
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
     * @param cadesTDer    CAdES-T подпись (CMS SignedData с signingCertificateV2 и метками)
     * @param trustedCerts доверенные корневые сертификаты (подписанта + TSA)
     * @return результат с данными и верифицированными подписантами
     * @throws PkixException при любой ошибке верификации (fail-closed)
     */
    public static VerifiedCAdESData verifyCAdEST(byte[] cadesTDer, GostCertificate... trustedCerts)
            throws PkixException {
        Objects.requireNonNull(cadesTDer, "cadesTDer must not be null");
        if (trustedCerts.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-T verification requires at least one trusted certificate");
        }

        CAdESTInternalResult internal = verifyCAdESTInternal(cadesTDer, trustedCerts);
        for (CAdESSignerResult sr : internal.signerResults()) {
            if (sr.timestamps().isEmpty()) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "CAdES-T: no signature-time-stamp in unsignedAttrs for signer");
            }
        }
        return new VerifiedCAdESData(internal.cmsResult().data(), internal.signerResults());
    }

    /**
     * Промежуточный результат верификации CAdES-T.
     * Содержит сырые SignerResult (signatureValue/unsignedAttributes) —
     * для {@link #verifyCountersignature} нужен доступ к данным countersignature.
     */
    private record CAdESTInternalResult(
            MultiSignerVerifiedData cmsResult,
            List<CAdESSignerResult> signerResults,
            List<GostCertificate> embeddedCerts) {}

    /**
     * Общая часть {@link #verifyCAdEST} и {@link #verifyCountersignature}.
     * Верифицирует CMS-подписи (AND), проверяет signingCertificateV2 и метки времени.
     * Возвращает сырые SignerResult для дальнейшей обработки countersignature.
     */
    private static CAdESTInternalResult verifyCAdESTInternal(
            byte[] cadesDer, GostCertificate... trustedCerts) throws PkixException {

        MultiSignerVerifiedData cmsResult = CmsSignedDataVerifier.verifyAll(cadesDer, trustedCerts);

        List<CAdESSignerResult> signerResults = new ArrayList<>();
        for (SignerResult sr : cmsResult.signers()) {
            verifySigningCertV2ForSigner(sr);
            List<TstInfo> timestamps = extractAndVerifyTimestamps(sr, trustedCerts);
            signerResults.add(
                    new CAdESSignerResult(
                            sr.signerCertificate(), sr.signedAttributes(), timestamps, List.of()));
        }

        List<GostCertificate> embeddedCerts = extractEmbeddedCerts(cadesDer);
        return new CAdESTInternalResult(cmsResult, signerResults, embeddedCerts);
    }

    /**
     * Извлекает сертификаты из поля {@code [0] IMPLICIT certificates}
     * SignedData без полной верификации подписей.
     */
    private static List<GostCertificate> extractEmbeddedCerts(byte[] signedDataDer)
            throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(ci.contentType())) {
            return List.of();
        }
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        if (sdParts.length < 4) {
            return List.of();
        }
        // Пропускаем version, digestAlgorithms, encapContentInfo
        int sdIdx = 3;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0)) {
            return CmsSignedDataVerifier.parseEmbeddedCertificates(
                    sdParts[sdIdx], CmsConstants.MAX_EMBEDDED_CERTS);
        }
        return List.of();
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
     *       <li>Построение и валидация цепочки countersigner'а до trustedCerts</li>
     *       <li>Верификация подписи countersigner'а</li>
     *     </ul>
     *   </li>
     * </ol>
     *
     * @param countersignedDer CMS SignedData с countersignature в unsignedAttrs
     * @param trustedCerts     доверенные корневые сертификаты (подписанта + countersigner'а + TSA)
     * @return результат с countersignature для каждого подписанта
     * @throws PkixException при любой ошибке верификации (fail-closed)
     */
    public static VerifiedCAdESData verifyCountersignature(
            byte[] countersignedDer, GostCertificate... trustedCerts) throws PkixException {
        Objects.requireNonNull(countersignedDer, "countersignedDer must not be null");
        if (trustedCerts.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Countersignature verification requires at least one trusted certificate");
        }

        CAdESTInternalResult internal = verifyCAdESTInternal(countersignedDer, trustedCerts);

        List<CAdESSignerResult> resultsWithCs = new ArrayList<>();
        List<SignerResult> signers = internal.cmsResult().signers();
        for (int i = 0; i < signers.size(); i++) {
            SignerResult sr = signers.get(i);
            CAdESSignerResult besTResult = internal.signerResults().get(i);

            List<SignerResult> csResults =
                    verifyCountersignaturesForSigner(sr, internal.embeddedCerts(), trustedCerts);

            resultsWithCs.add(
                    new CAdESSignerResult(
                            besTResult.signerCertificate(),
                            besTResult.signedAttributes(),
                            besTResult.timestamps(),
                            csResults));
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
     *   <li>Строит и валидирует цепочку сертификата countersigner'а до trustedCerts</li>
     *   <li>Верифицирует подпись countersigner'а</li>
     * </ol>
     *
     * @param parentSr      результат верификации родительского SignerInfo
     * @param embeddedCerts сертификаты из SignedData.certificates
     * @param trustedCerts  доверенные корневые сертификаты
     * @return список верифицированных countersignature (пустой если атрибут отсутствует)
     * @throws PkixException если countersignature есть но невалидна (fail-closed)
     */
    private static List<SignerResult> verifyCountersignaturesForSigner(
            SignerResult parentSr,
            List<GostCertificate> embeddedCerts,
            GostCertificate... trustedCerts)
            throws PkixException {
        List<SignerResult> results = new ArrayList<>();

        int csCount = 0;
        for (CmsAttribute attr : parentSr.unsignedAttributes()) {
            if (!GostOids.ATTR_COUNTERSIGNATURE.equals(attr.attrType())) {
                continue;
            }
            byte[][] vals = attr.attrValues();
            if (vals.length == 0) {
                continue;
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
                                trustedCerts));
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
            GostCertificate... trustedCerts)
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

        // [4] signatureAlgorithm — пропускаем
        idx++;

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

        // Строим и валидируем цепочку
        List<GostCertificate> csChain =
                CertChainBuilder.buildChain(
                        countersignerCert, embeddedCerts, Arrays.asList(trustedCerts));
        List<PublicKeyParameters> caKeys =
                Arrays.stream(trustedCerts).map(GostCertificate::getPublicKey).toList();
        ChainValidator.validateChain(csChain, caKeys);

        // Верифицируем подпись countersigner'а
        byte[] signedAttrsHash = digestForCountersig(signedAttrsForHash, digestOid);
        if (!Signature.verifyHash(
                signedAttrsHash, csSignatureValue, countersignerCert.getPublicKey())) {
            throw new PkixException(
                    PkixException.Reason.SIGNATURE_INVALID, "Countersignature signature invalid");
        }

        return new SignerResult(countersignerCert, csSignatureValue, signedAttributes, List.of());
    }

    private static byte[] digestForCountersig(byte[] data, String digestOid) throws PkixException {
        if (GostOids.DIGEST_512.equals(digestOid)) {
            return Digest.digest512(data);
        }
        if (GostOids.DIGEST_256.equals(digestOid)) {
            return Digest.digest256(data);
        }
        throw new PkixException(
                PkixException.Reason.OTHER, "Unsupported digest algorithm: " + digestOid);
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

    // ========================================================================
    // Приватные утилиты
    // ========================================================================

    /** Встраивает SIGNATURE_TIME_STAMP атрибут в unsignedAttrs конкретного SignerInfo. */
    private static byte[] injectUnsignedAttr(byte[] signerInfoDer, byte[] timeStampTokenDer)
            throws PkixException {
        byte[] attrDer = CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP, timeStampTokenDer);
        return injectUnsignedAttrDer(signerInfoDer, attrDer);
    }

    /**
     * Встраивает готовый CmsAttribute DER в unsignedAttrs SignerInfo.
     * Используется и для SIGNATURE_TIME_STAMP, и для countersignature.
     *
     * @param signerInfoDer DER-байты SignerInfo
     * @param attrDer       полностью закодированный CmsAttribute (SEQUENCE { OID, SET { value... } })
     */
    private static byte[] injectUnsignedAttrDer(byte[] signerInfoDer, byte[] attrDer)
            throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "SignerInfo is empty");
        }

        int unsignedIdx = -1;
        for (int i = 0; i < siParts.length; i++) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                unsignedIdx = i;
                break;
            }
        }

        byte[] newUnsignedAttrs;
        if (unsignedIdx >= 0) {
            byte[] existingField = siParts[unsignedIdx];
            int[] lenInfo = DerCodec.decodeLength(existingField, 1);
            int contentOff = 1 + lenInfo[1];
            byte[] existingContent =
                    java.util.Arrays.copyOfRange(existingField, contentOff, existingField.length);

            // Разбираем существующие атрибуты как TLV-элементы для ресортировки
            List<byte[]> attrs = new ArrayList<>();
            int pos = 0;
            while (pos < existingContent.length) {
                int[] attrLen = DerCodec.decodeLength(existingContent, pos + 1);
                int attrTotal = 1 + attrLen[1] + attrLen[0];
                attrs.add(java.util.Arrays.copyOfRange(existingContent, pos, pos + attrTotal));
                pos += attrTotal;
            }
            attrs.add(attrDer);
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);
            byte[] expandedContent = DerCodec.concat(sorted);
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, expandedContent);
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, attrDer);
            byte[][] newParts = java.util.Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newUnsignedAttrs;
            siParts = newParts;
        }

        return DerCodec.encodeSequence(siParts);
    }

    /** Извлекает подписи всех подписантов из SignedData. */
    private static List<byte[]> extractAllSignatures(byte[] signedDataDer) throws PkixException {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(ci.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + ci.contentType());
        }
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        if (sdParts.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "SignedData body is empty");
        }
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        List<byte[]> signatures = new ArrayList<>();
        for (byte[] si : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);
            byte[] sigOctet = null;
            for (int i = siParts.length - 1; i >= 0; i--) {
                if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                    sigOctet = siParts[i];
                    break;
                }
            }
            if (sigOctet == null) {
                throw new PkixException(
                        PkixException.Reason.OTHER, "Signature not found in SignerInfo");
            }
            signatures.add(DerCodec.parseOctetString(sigOctet, 0));
        }
        return signatures;
    }

    /** Объединяет сертификаты из всех TimeStampToken'ов.
     *  @return DER-кодированное поле certificates или {@code null} если сертификатов нет */
    private static byte[] mergeCertificates(byte[] existingCertsField, List<byte[]> timeStampTokens)
            throws PkixException {
        List<byte[]> allCerts = new ArrayList<>();

        if (existingCertsField != null) {
            int[] lenInfo = DerCodec.decodeLength(existingCertsField, 1);
            int contentOff = 1 + lenInfo[1];
            int pos = contentOff;
            int end = existingCertsField.length;
            while (pos < end) {
                int[] certLen = DerCodec.decodeLength(existingCertsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                allCerts.add(
                        java.util.Arrays.copyOfRange(existingCertsField, pos, pos + certTotal));
                pos += certTotal;
            }
        }

        for (int tokenIdx = 0; tokenIdx < timeStampTokens.size(); tokenIdx++) {
            byte[] tsToken = timeStampTokens.get(tokenIdx);
            try {
                CmsContentInfo tsCi = CmsContentInfo.decode(tsToken);
                byte[][] tsSdParts = DerCodec.parseSequenceContents(tsCi.content(), 0);
                int tsIdx = 3;
                if (tsIdx < tsSdParts.length && DerCodec.isContextTag(tsSdParts[tsIdx], 0)) {
                    byte[] tsCerts = tsSdParts[tsIdx];
                    int[] lenInfo = DerCodec.decodeLength(tsCerts, 1);
                    int contentOff = 1 + lenInfo[1];
                    int pos = contentOff;
                    int end = tsCerts.length;
                    while (pos < end) {
                        int[] certLen = DerCodec.decodeLength(tsCerts, pos + 1);
                        int certTotal = 1 + certLen[1] + certLen[0];
                        allCerts.add(java.util.Arrays.copyOfRange(tsCerts, pos, pos + certTotal));
                        pos += certTotal;
                    }
                }
            } catch (Exception e) {
                LOG.log(
                        System.Logger.Level.WARNING,
                        "Failed to extract certificates from TimeStampToken #" + tokenIdx,
                        e);
            }
        }

        if (allCerts.isEmpty()) {
            return null;
        }
        byte[][] sorted = allCerts.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
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
     * Извлекает и верифицирует метки времени, не требуя их наличия.
     * Используется countersignature, где timestamp опционален.
     */
    private static List<TstInfo> extractAndVerifyTimestamps(
            SignerResult sr, GostCertificate... trustedCerts) throws PkixException {
        List<TstInfo> timestamps = new ArrayList<>();
        for (CmsAttribute attr : sr.unsignedAttributes()) {
            if (!GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) continue;
            byte[][] vals = attr.attrValues();
            if (vals.length == 0) continue;
            byte[] tsToken = vals[0];

            TspResponse tspResponse = TspResponse.parseTimeStampToken(tsToken);

            // messageImprint сверяем против подписи этого подписанта
            byte[] sig = sr.signatureValue();
            SignatureHashResult sh = computeTspMessageImprint(sig);

            tspResponse.verify(sh.hash(), sh.oid(), null, trustedCerts);

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

    /**
     * Хэш подписи для messageImprint запроса метки времени.
     * Выбор дайджеста по длине подписи: 64 байта -> 256-бит (ГОСТ Р 34.10-2012, 256-битная кривая),
     * 128 байт -> 512-бит (512-битная кривая).
     */
    private static SignatureHashResult computeTspMessageImprint(byte[] signature) {
        boolean is512 = (signature.length != 64);
        byte[] sigHash = is512 ? Digest.digest512(signature) : Digest.digest256(signature);
        String hashOid = is512 ? GostOids.DIGEST_512 : GostOids.DIGEST_256;
        return new SignatureHashResult(sigHash, hashOid);
    }

    private record SignatureHashResult(byte[] hash, String oid) {}
}
