package org.rssys.gost.pkix.cms;

import java.io.IOException;
import java.lang.System.Logger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.pkix.tsp.TstInfo;
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
                            sr.signerCertificate(), sr.signedAttributes(), List.of()));
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

        // AND-семантика: все подписанты обязаны пройти
        MultiSignerVerifiedData cmsResult =
                CmsSignedDataVerifier.verifyAll(cadesTDer, trustedCerts);

        List<CAdESSignerResult> signerResults = new ArrayList<>();
        for (SignerResult sr : cmsResult.signers()) {
            // Проверяем signingCertificateV2 для этого подписанта
            verifySigningCertV2ForSigner(sr);

            // Проверяем метки времени в его unsignedAttrs
            List<TstInfo> timestamps = verifyTimestampsForSigner(sr, trustedCerts);

            signerResults.add(
                    new CAdESSignerResult(
                            sr.signerCertificate(), sr.signedAttributes(), timestamps));
        }

        return new VerifiedCAdESData(cmsResult.data(), signerResults);
    }

    // ========================================================================
    // Приватные утилиты
    // ========================================================================

    /** Встраивает SIGNATURE_TIME_STAMP атрибут в unsignedAttrs конкретного SignerInfo. */
    private static byte[] injectUnsignedAttr(byte[] signerInfoDer, byte[] timeStampTokenDer)
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

        byte[] newAttr = CmsAttribute.encode(GostOids.SIGNATURE_TIME_STAMP, timeStampTokenDer);

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
            attrs.add(newAttr);
            byte[][] sorted = attrs.toArray(new byte[0][]);
            DerCodec.sortDer(sorted);
            byte[] expandedContent = DerCodec.concat(sorted);
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, expandedContent);
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            newUnsignedAttrs = DerCodec.encodeContextConstructed(1, newAttr);
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

    /** Проверяет метки времени для конкретного подписанта. */
    private static List<TstInfo> verifyTimestampsForSigner(
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
        if (timestamps.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-T: no signature-time-stamp in unsignedAttrs for signer");
        }
        return timestamps;
    }

    private static void checkCertValidityAtTime(GostCertificate cert, String genTime)
            throws PkixException {
        long genTimeMs = TspResponse.parseGeneralizedTimeToMs(genTime);
        Instant genDate = Instant.ofEpochMilli(genTimeMs);

        Instant notBefore = cert.getNotBefore();
        Instant notAfter = cert.getNotAfter();

        if (notBefore != null && genDate.isBefore(notBefore)) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Certificate not yet valid at timestamp genTime: " + genTime + " < notBefore");
        }
            if (notAfter != null && genDate.isAfter(notAfter)) {
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
