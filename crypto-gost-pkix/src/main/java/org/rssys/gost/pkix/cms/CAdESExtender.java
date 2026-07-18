package org.rssys.gost.pkix.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertRevocationData;
import org.rssys.gost.pkix.cert.ChainValidator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.pkix.tsp.TstInfo;
import org.rssys.gost.pkix.util.GostLogger;
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

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.pkix.cms.CAdESExtender");

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
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[] existingCerts = sd.certs();

        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

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

        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);

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
        List<ExtractedSignature> signatures = extractAllSignatures(cadesBesDer);

        List<byte[]> tokens = new ArrayList<>();
        for (ExtractedSignature es : signatures) {
            SignatureHashResult sh =
                    computeTspMessageImprint(es.digestAlgOid(), es.signatureValue());

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

        List<ExtractedSignature> signatures = extractAllSignatures(cadesBesDer);

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
            ExtractedSignature es = signatures.get(i);
            SignatureHashResult sh =
                    computeTspMessageImprint(es.digestAlgOid(), es.signatureValue());

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
     * @param countersigner     подписант countersignature (может быть HSM-адаптером)
     * @param countersignerCert сертификат countersigner'а
     * @return CMS SignedData с countersignature в unsignedAttrs
     * @throws PkixException при ошибке разбора SignedData
     */
    public static byte[] embedCountersignature(
            byte[] cadesDer, GostSigner countersigner, GostCertificate countersignerCert)
            throws PkixException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(countersigner, "countersigner must not be null");
        Objects.requireNonNull(countersignerCert, "countersignerCert must not be null");

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[] existingCerts = sd.certs();

        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        if (origSignerInfos.length > CmsConstants.MAX_SIGNER_INFOS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "Too many SignerInfo for embedCountersignature: "
                            + origSignerInfos.length
                            + " (max "
                            + CmsConstants.MAX_SIGNER_INFOS
                            + ")");
        }

        String digestOid = GostSignatureHelper.keySizeToDigestOid(countersignerCert.getKeySize());

        List<byte[]> modifiedSignerInfos = new java.util.ArrayList<>();
        for (byte[] si : origSignerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);

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

            byte[] countersigDer =
                    CountersignatureBuilder.buildCountersignature(
                            parentSigValue, countersigner, countersignerCert, digestOid);

            byte[] attrDer = CmsAttribute.encode(GostOids.ATTR_COUNTERSIGNATURE, countersigDer);
            modifiedSignerInfos.add(injectUnsignedAttrDer(si, attrDer));
        }

        byte[] newCerts = mergeCountersignerCert(existingCerts, countersignerCert);

        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));

        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /**
     * Встраивает countersignature (удобная перегрузка с ключом в памяти).
     *
     * <p>Делегирует в {@link #embedCountersignature(byte[], GostSigner, GostCertificate)}
     * через {@link GostSigner#of(PrivateKeyParameters)}.
     *
     * @param cadesDer          CAdES-BES или CAdES-T подпись
     * @param countersignerKey  приватный ключ countersigner'а
     * @param countersignerCert сертификат countersigner'а
     * @return CMS SignedData с countersignature
     * @throws PkixException при ошибке разбора SignedData
     */
    public static byte[] embedCountersignature(
            byte[] cadesDer,
            PrivateKeyParameters countersignerKey,
            GostCertificate countersignerCert)
            throws PkixException {
        return embedCountersignature(cadesDer, GostSigner.of(countersignerKey), countersignerCert);
    }

    /**
     * Добавляет сертификаты в поле certificates [0] IMPLICIT.
     * Сохраняет существующие, удаляет DER-дубликаты, сортирует, кодирует.
     *
     * @param existingCertsField существующее поле [0] или null
     * @param newCertDers        DER-байты новых сертификатов
     * @param maxTotalCerts      максимум сертификатов после слияния (DoS)
     * @return новое поле [0] или null если пусто
     */
    private static byte[] mergeCertsIntoField(
            byte[] existingCertsField, List<byte[]> newCertDers, int maxTotalCerts)
            throws PkixException {
        List<byte[]> allCerts = new ArrayList<>();

        if (existingCertsField != null) {
            int[] lenInfo = DerCodec.decodeLength(existingCertsField, 1);
            int contentOff = 1 + lenInfo[1];
            int pos = contentOff;
            int end = existingCertsField.length;
            while (pos < end) {
                if (allCerts.size() >= maxTotalCerts) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many certificates in SignedData: "
                                    + (allCerts.size() + 1)
                                    + " (max "
                                    + maxTotalCerts
                                    + ")");
                }
                int[] certLen = DerCodec.decodeLength(existingCertsField, pos + 1);
                int certTotal = 1 + certLen[1] + certLen[0];
                allCerts.add(
                        java.util.Arrays.copyOfRange(existingCertsField, pos, pos + certTotal));
                pos += certTotal;
            }
        }

        for (byte[] certDer : newCertDers) {
            boolean duplicate = false;
            for (byte[] existing : allCerts) {
                if (java.util.Arrays.equals(existing, certDer)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                if (allCerts.size() >= maxTotalCerts) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "Too many certificates in SignedData: "
                                    + (allCerts.size() + 1)
                                    + " (max "
                                    + maxTotalCerts
                                    + ")");
                }
                allCerts.add(certDer);
            }
        }

        if (allCerts.isEmpty()) {
            return null;
        }
        byte[][] sorted = allCerts.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(sorted));
    }

    /** Добавляет сертификат countersigner'а в существующее поле certificates [0] IMPLICIT. */
    private static byte[] mergeCountersignerCert(
            byte[] existingCertsField, GostCertificate countersignerCert) throws PkixException {
        return mergeCertsIntoField(
                existingCertsField,
                List.of(countersignerCert.getEncoded()),
                CmsConstants.MAX_CERTS_IN_EMBED_CS);
    }

    // ========================================================================
    // CAdES-C: Complete validation data references (RFC 5126 §6.2)
    // ========================================================================

    /**
     * Встраивает CAdES-C атрибуты в CAdES-BES/T подпись — основной метод.
     *
     * <p>Добавляет complete-certificate-references и complete-revocation-references
     * в unsignedAttrs каждого подписанта (RFC 5126 §6.2). Принимает CAdES-BES или CAdES-T
     * и возвращает CAdES-C.
     *
     * <p>Цепочка сертификатов строится вызывающим кодом — метод ожидает уже построенную,
     * валидированную цепочку. CRL-данные передаются как доменные объекты.
     *
     * @param cadesDer      CAdES-BES или CAdES-T подпись (CMS SignedData)
     * @param chain         цепочка [signer, intermediates..., trustedRoot]
     * @param crlsForChain  список CRL по одному на элемент chain; допускается null
     * @param ocspForChain  список OCSP-ответов по одному на элемент chain; допускается null
     * @return CAdES-C подпись (CMS SignedData с C-атрибутами)
     * @throws PkixException при ошибке разбора или несоответствии размеров списков
     */
    public static byte[] embedCompleteRefs(
            byte[] cadesDer,
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain)
            throws PkixException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(crlsForChain, "crlsForChain must not be null");
        Objects.requireNonNull(ocspForChain, "ocspForChain must not be null");

        CAdESCompleteData.CompleteRefsResult result =
                CAdESCompleteData.buildCompleteRefsResult(chain, crlsForChain, ocspForChain);

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[] existingCerts = sd.certs();

        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        // Кодируем атрибуты CompleteCertificateRefs и CompleteRevocationRefs
        List<byte[]> certRefDerList = new ArrayList<>();
        for (CAdESCompleteData.OtherCertID certId : result.certRefs()) {
            byte[] hashDer =
                    CAdESCompleteData.encodeOtherHashStreebog(
                            certId.otherCertHash().hashValue(), certId.otherCertHash().hashOid());
            byte[] issuerSerialDer =
                    CAdESCompleteData.encodeIssuerSerial(
                            certId.issuerSerial().issuerDer(), certId.issuerSerial().serial());
            certRefDerList.add(CAdESCompleteData.encodeOtherCertID(hashDer, issuerSerialDer));
        }
        byte[] certRefsDer = CAdESCompleteData.encodeCompleteCertificateRefs(certRefDerList);
        byte[] certRefsAttr = CmsAttribute.encode(GostOids.COMPLETE_CERTIFICATE_REFS, certRefsDer);

        List<byte[]> revocRefDerList = new ArrayList<>();
        for (CAdESCompleteData.CrlOcspRef ref : result.revocRefs()) {
            List<byte[]> crlValidatedDerList = new ArrayList<>();
            List<byte[]> ocspResponsesDerList = new ArrayList<>();

            for (CAdESCompleteData.CrlValidatedID cvi : ref.crlList()) {
                byte[] crlHashDer =
                        CAdESCompleteData.encodeOtherHashStreebog(
                                cvi.crlHash().hashValue(), cvi.crlHash().hashOid());
                byte[] crlIdDer =
                        CAdESCompleteData.encodeCrlIdentifier(
                                cvi.crlIdentifier().crlIssuerDer(),
                                cvi.crlIdentifier().crlIssuedTime(),
                                cvi.crlIdentifier().crlNumber());
                crlValidatedDerList.add(DerCodec.encodeSequence(crlHashDer, crlIdDer));
            }
            for (CAdESCompleteData.OcspResponsesID oid : ref.ocspList()) {
                byte[] encodedOcsp =
                        CAdESCompleteData.encodeOcspResponsesID(
                                oid.ocspIdentifier(), oid.ocspRepHash());
                ocspResponsesDerList.add(encodedOcsp);
            }
            revocRefDerList.add(
                    CAdESCompleteData.encodeCrlOcspRef(crlValidatedDerList, ocspResponsesDerList));
        }
        byte[] revocRefsDer = CAdESCompleteData.encodeCompleteRevocationRefs(revocRefDerList);
        byte[] revocRefsAttr = CmsAttribute.encode(GostOids.COMPLETE_REVOCATION_REFS, revocRefsDer);

        // Встраиваем оба атрибута в каждый SignerInfo
        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        for (byte[] signerInfoDer : origSignerInfos) {
            byte[] modified = injectUnsignedAttrDer(signerInfoDer, certRefsAttr);
            modified = injectUnsignedAttrDer(modified, revocRefsAttr);
            modifiedSignerInfos.add(modified);
        }

        // Добавляем сертификаты цепочки в certificates [0]
        byte[] newCerts = mergeChainCerts(existingCerts, chain);

        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));

        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    // ========================================================================
    // Построение CAdES-X Long Type 1
    // ========================================================================

    /**
     * Строит CAdES-X Long Type 1: CAdES-C + certificate-values + revocation-values.
     *
     * <p>Принимает CAdES-BES (с content-time-stamp) или CAdES-T/C DER.
     * Автоматически достраивает недостающие уровни: T-метку (signature-time-stamp),
     * C-референсы (embedCompleteRefs), затем встраивает X-Long атрибуты
     * (certificate-values, revocation-values).
     *
     * <p>Сертификаты цепочки добавляются в поле {@code certificates [0]} SignedData
     * через {@link #mergeCertsIntoField} — дедупликация по DER с лимитом
     * {@link CmsConstants#MAX_EMBEDDED_CERTS}.
     *
     * @param cadesDer       CAdES-BES (с content-time-stamp) или CAdES-T/C DER
     * @param chain          цепочка [signer, intermediates..., trustedRoot]
     * @param crlsForChain   CRL для каждого элемента chain (parallel list, null допускается)
     * @param ocspForChain   OCSP-ответы (parallel list, null допускается)
     * @param tspUrl         TSA URL для signature-time-stamp (null если уже есть)
     * @param tspTransport   HTTP-транспорт для TSP
     * @param trustedTsaCerts доверенные сертификаты TSA (fail-closed)
     * @return CAdES-X Long Type 1 DER
     * @throws PkixException при ошибке разбора или несоответствии размеров списков
     * @throws IOException   при ошибке TSP-запроса
     */
    public static byte[] embedXLongType1(
            byte[] cadesDer,
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            String tspUrl,
            TspTransport tspTransport,
            GostCertificate... trustedTsaCerts)
            throws PkixException, IOException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(crlsForChain, "crlsForChain must not be null");
        Objects.requireNonNull(ocspForChain, "ocspForChain must not be null");

        byte[] current = cadesDer.clone();

        if (crlsForChain.size() != chain.size()) {
            throw new PkixException(
                    "crlsForChain size " + crlsForChain.size() + " != chain size " + chain.size());
        }
        if (ocspForChain.size() != chain.size()) {
            throw new PkixException(
                    "ocspForChain size " + ocspForChain.size() + " != chain size " + chain.size());
        }

        if (tspUrl != null) {
            current = addTimestamp(current, tspUrl, tspTransport, trustedTsaCerts);
        }

        current = embedCompleteRefs(current, chain, crlsForChain, ocspForChain);

        return embedXLongValues(current, chain, crlsForChain, ocspForChain);
    }

    /**
     * Встраивает certificate-values и revocation-values в CAdES-C подпись.
     *
     * <p>Низкоуровневый метод: принимает уже готовый CAdES-C DER
     * и добавляет X-Long unsigned-атрибуты. Не делает TSP-запросов
     * и не строит C-референсы — используйте {@link #embedXLongType1}
     * для полного цикла.
     */
    private static byte[] embedXLongValues(
            byte[] cadesCDer,
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesCDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[] existingCerts = sd.certs();

        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        byte[] certValuesDer = CAdESXLongData.encodeCertificateValues(chain);
        byte[] certValuesAttr = CmsAttribute.encode(GostOids.CERTIFICATE_VALUES, certValuesDer);

        int revocEnd = Math.max(1, chain.size() - 1);
        byte[] revocValuesDer =
                CAdESXLongData.encodeRevocationValues(
                        crlsForChain.subList(0, revocEnd), ocspForChain.subList(0, revocEnd));
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        for (byte[] signerInfoDer : origSignerInfos) {
            byte[] modified = injectUnsignedAttrDer(signerInfoDer, certValuesAttr);
            modified = injectUnsignedAttrDer(modified, revocValuesAttr);
            modifiedSignerInfos.add(modified);
        }

        byte[] newCerts = mergeChainCerts(existingCerts, chain);

        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));

        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /**
     * Встраивает CAdES-C атрибуты — convenience-перегрузка с {@link CertRevocationData}.
     *
     * <p>Принимает данные отзыва в том же формате, что и
     * {@link ChainValidator#validateChainWithRevocation(List, List, List)} —
     * parallel list {@link CertRevocationData} по элементам chain.
     * Внутри преобразует {@code byte[]} в доменные объекты и делегирует в
     * основной метод.
     *
     * @param cadesDer        CAdES-BES или CAdES-T подпись
     * @param chain           цепочка [signer, intermediates..., trustedRoot]
     * @param revocationData  данные отзыва — parallel list (допускается null для элемента)
     * @return CAdES-C подпись
     * @throws PkixException при ошибке разбора или несоответствии размеров списков
     */
    public static byte[] embedCompleteRefs(
            byte[] cadesDer, List<GostCertificate> chain, List<CertRevocationData> revocationData)
            throws PkixException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(revocationData, "revocationData must not be null");

        if (revocationData.size() != chain.size()) {
            throw new PkixException(
                    "revocationData size "
                            + revocationData.size()
                            + " != chain size "
                            + chain.size());
        }

        List<GostCrl> crls = new ArrayList<>(chain.size());
        List<GostOcspResponse> ocspResponses = new ArrayList<>(chain.size());

        for (int i = 0; i < chain.size(); i++) {
            CertRevocationData rd = revocationData.get(i);
            if (rd != null && rd.crlDer() != null) {
                crls.add(new GostCrl(rd.crlDer()));
            } else {
                crls.add(null);
            }
            if (rd != null && rd.ocspResponse() != null) {
                ocspResponses.add(new GostOcspResponse(rd.ocspResponse()));
            } else {
                ocspResponses.add(null);
            }
        }

        return embedCompleteRefs(cadesDer, chain, crls, ocspResponses);
    }

    /**
     * Добавляет сертификаты цепочки в поле certificates [0] IMPLICIT.
     * Корневой сертификат сохраняется — implementation simplicity
     * (root уже передаётся отдельно через trustedCerts, функциональной
     * необходимости в его embedding нет).
     */
    private static byte[] mergeChainCerts(byte[] existingCertsField, List<GostCertificate> chain)
            throws PkixException {
        List<byte[]> derList = new ArrayList<>(chain.size());
        for (GostCertificate cert : chain) {
            derList.add(cert.getEncoded());
        }
        return mergeCertsIntoField(existingCertsField, derList, CmsConstants.MAX_EMBEDDED_CERTS);
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
     * @param cadesTDer    CAdES-T подпись (CMS SignedData с signingCertificateV2 и метками)
     * @param trustedCerts доверенные корневые сертификаты (подписанта + TSA)
     * @return результат с данными и верифицированными подписантами
     * @throws PkixException при любой ошибке верификации (fail-closed)
     *
     * <p><b>Не проверяет:</b> content-time-stamp (ES-C, signed-атрибут CONTENT_TIME_STAMP).
     * Верификация content-timestamp — только в {@link #verifyCAdESXLong}.
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
     * Проверка crlHash deferred to X-Long (где CRL встроены в revocation-values).
     * Фактический статус отзыва сертификатов не проверяется на C-уровне.
     *
     * <p><b>Не проверяет:</b> content-time-stamp (ES-C, signed-атрибут CONTENT_TIME_STAMP).
     * Верификация content-timestamp — только в {@link #verifyCAdESXLong}.
     *
     * @param cadesCDer     CAdES-C подпись (CMS SignedData с C-атрибутами)
     * @param trustedCerts  доверенные корневые сертификаты (подписанта + TSA)
     * @return результат с C-референсами для каждого подписанта
     * @throws PkixException при любой ошибке (fail-closed)
     */
    public static VerifiedCAdESData verifyCAdESC(byte[] cadesCDer, GostCertificate... trustedCerts)
            throws PkixException {
        Objects.requireNonNull(cadesCDer, "cadesCDer must not be null");
        if (trustedCerts.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-C verification requires at least one trusted certificate");
        }

        CAdESTInternalResult internal = verifyCAdESTInternal(cadesCDer, trustedCerts);

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
     *       с embedded сертификатом, цепочка сертификатов валидна</li>
     *   <li>revocation-values: crlHash/OcspRepHash каждой CrlOcspRef совпадает с embedded
     *       CRL/OCSP, подписи CRL/OCSP валидны, сертификаты цепочки НЕ отозваны</li>
     * </ol>
     *
     * <p>Закрывает deferred-проверку crlHash из C-уровня (план 224):
     * crlHash из complete-revocation-references сверяется с embedded CRL
     * из revocation-values.
     *
     * @param cadesXLongDer CAdES-X Long Type 1 DER
     * @param trustedCerts  доверенные корневые сертификаты (подписанта + TSA)
     * @return результат с certificate-values и revocation-values
     * @throws PkixException при любой ошибке (fail-closed)
     */
    public static VerifiedCAdESData verifyCAdESXLong(
            byte[] cadesXLongDer, GostCertificate... trustedCerts) throws PkixException {
        Objects.requireNonNull(cadesXLongDer, "cadesXLongDer must not be null");
        if (trustedCerts.length == 0) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long verification requires at least one trusted certificate");
        }

        CAdESTInternalResult internal = verifyCAdESTInternal(cadesXLongDer, trustedCerts);
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

            TstInfo contentTimestamp = extractAndVerifyContentTimestamp(sr, trustedCerts);

            CAdESXLongData.RevocationValuesDecoded revocValues =
                    extractAndVerifyRevocationValues(sr, revocRefs, embeddedCerts);
            List<GostCertificate> certValues =
                    extractAndVerifyCertificateValues(
                            sr,
                            certRefs,
                            revocRefs,
                            embeddedCerts,
                            revocValues,
                            signerCert,
                            trustedCerts);

            xlongResults.add(
                    new CAdESSignerResult(
                            signerCert,
                            besTResult.signedAttributes(),
                            besTResult.timestamps(),
                            besTResult.countersignatures(),
                            certRefs,
                            revocRefs,
                            certValues,
                            revocValues,
                            contentTimestamp));
        }

        return new VerifiedCAdESData(internal.cmsResult().data(), xlongResults);
    }

    /**
     * Извлекает и верифицирует certificate-values из unsignedAttrs.
     *
     * <p>Сверяет каждый embedded сертификат с OtherCertID из C-референсов:
     * certHash совпадает (dispatch по OID из OtherHash), IssuerSerial совпадает.
     * Строит и валидирует цепочку сертификатов через ChainValidator.
     */
    private static List<GostCertificate> extractAndVerifyCertificateValues(
            SignerResult sr,
            List<CAdESCompleteData.OtherCertID> certRefs,
            List<CAdESCompleteData.CrlOcspRef> revocRefs,
            List<GostCertificate> embeddedCerts,
            CAdESXLongData.RevocationValuesDecoded revocValues,
            GostCertificate signerCert,
            GostCertificate[] trustedCerts)
            throws PkixException {

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
            byte[] expectedHash = ref.otherCertHash().hashValue();
            String hashOid = ref.otherCertHash().hashOid();
            byte[] expectedIssuerDer = ref.issuerSerial().issuerDer();
            BigInteger expectedSerial = ref.issuerSerial().serial();

            boolean matched = false;
            for (GostCertificate cv : certValues) {
                byte[] actualHash = GostSignatureHelper.digestByOid(hashOid, cv.getEncoded());
                if (!MessageDigest.isEqual(expectedHash, actualHash)) {
                    continue;
                }
                if (!Arrays.equals(expectedIssuerDer, cv.getIssuerDnBytes())) {
                    continue;
                }
                if (!expectedSerial.equals(cv.getSerialNumberBigInt())) {
                    continue;
                }
                matched = true;
                break;
            }
            if (!matched) {
                throw new PkixException(
                        "CAdES-X Long: certHash/IssuerSerial mismatch in certificate-values");
            }
        }

        List<GostCertificate> fullChain = new ArrayList<>();
        fullChain.add(signerCert);
        for (GostCertificate cv : certValues) {
            if (!Arrays.equals(cv.getEncoded(), signerCert.getEncoded())) {
                fullChain.add(cv);
            }
        }

        List<PublicKeyParameters> trustedKeys = new ArrayList<>();
        for (GostCertificate tc : trustedCerts) {
            trustedKeys.add(tc.getPublicKey());
        }

        ChainValidator.validateChain(fullChain, trustedKeys);

        List<CertRevocationData> revocationData = new ArrayList<>(fullChain.size());
        for (int i = 0; i < fullChain.size(); i++) {
            byte[] crlDer = null;
            byte[] ocspDer = null;
            if (i < revocRefs.size()) {
                CAdESCompleteData.CrlOcspRef ref = revocRefs.get(i);
                for (CAdESCompleteData.CrlValidatedID cvi : ref.crlList()) {
                    for (GostCrl crl : revocValues.crls()) {
                        if (crl == null) continue;
                        byte[] actualHash =
                                GostSignatureHelper.digestByOid(
                                        cvi.crlHash().hashOid(), crl.getEncoded());
                        if (MessageDigest.isEqual(cvi.crlHash().hashValue(), actualHash)) {
                            crlDer = crl.getEncoded();
                            break;
                        }
                    }
                    if (crlDer != null) break;
                }
                for (CAdESCompleteData.OcspResponsesID orid : ref.ocspList()) {
                    for (GostOcspResponse ocsp : revocValues.ocspResponses()) {
                        if (ocsp == null) continue;
                        if (orid.ocspRepHash() == null) {
                            ocspDer = ocsp.getEncoded();
                            break;
                        }
                        byte[] actualHash =
                                GostSignatureHelper.digestByOid(
                                        orid.ocspRepHash().hashOid(), ocsp.getEncoded());
                        if (MessageDigest.isEqual(orid.ocspRepHash().hashValue(), actualHash)) {
                            ocspDer = ocsp.getEncoded();
                            break;
                        }
                    }
                    if (ocspDer != null) break;
                }
            }
            if (ocspDer == null && crlDer == null) {
                revocationData.add(null);
            } else {
                revocationData.add(new CertRevocationData(ocspDer, crlDer));
            }
        }
        ChainValidator.validateChainWithRevocation(fullChain, trustedKeys, revocationData);

        return certValues;
    }

    /**
     * Извлекает и верифицирует revocation-values из unsignedAttrs.
     *
     * <p>Сверяет crlHash/OcspRepHash каждой CrlOcspRef с embedded CRL/OCSP
     * из revocation-values. Проверяет подписи CRL и OCSP-ответов.
     * Закрывает deferred-проверку crlHash из плана 224.
     */
    private static CAdESXLongData.RevocationValuesDecoded extractAndVerifyRevocationValues(
            SignerResult sr,
            List<CAdESCompleteData.CrlOcspRef> revocRefs,
            List<GostCertificate> embeddedCerts)
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
                CAdESXLongData.decodeRevocationValues(attrValues[0]);

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
                            GostSignatureHelper.digestByOid(hashOid, crl.getEncoded());
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
                boolean matched = false;
                if (orid.ocspRepHash() != null) {
                    byte[] expectedOcspHash = orid.ocspRepHash().hashValue();
                    String hashOid = orid.ocspRepHash().hashOid();
                    for (GostOcspResponse ocsp : revocValues.ocspResponses()) {
                        if (ocsp == null) {
                            continue;
                        }
                        byte[] actualOcspHash =
                                GostSignatureHelper.digestByOid(hashOid, ocsp.getEncoded());
                        if (MessageDigest.isEqual(expectedOcspHash, actualOcspHash)) {
                            matched = true;
                            break;
                        }
                    }
                } else {
                    matched = true;
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
            SignerResult sr, GostCertificate... trustedCerts) throws PkixException {
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

        tspResponse.verify(contentDigest, hashOid, null, trustedCerts);
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
                byte[] actualHash;
                try {
                    actualHash = GostSignatureHelper.digestByOid(hashOid, certDer);
                } catch (IllegalArgumentException e) {
                    throw new PkixException(
                            "CAdES-C: unsupported hash algorithm OID in OtherHash: "
                                    + hashOid
                                    + " (only Streebog-256/512 supported)");
                }
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

        // Проверка дубликатов (issuer + serial)
        for (int i = 0; i < certRefs.size(); i++) {
            CAdESCompleteData.OtherCertID a = certRefs.get(i);
            if (a.issuerSerial() == null) continue;
            for (int j = i + 1; j < certRefs.size(); j++) {
                CAdESCompleteData.OtherCertID b = certRefs.get(j);
                if (b.issuerSerial() == null) continue;
                if (java.util.Arrays.equals(
                                a.issuerSerial().issuerDer(), b.issuerSerial().issuerDer())
                        && a.issuerSerial().serial().equals(b.issuerSerial().serial())) {
                    throw new PkixException(
                            "CAdES-C: duplicate OtherCertID in CompleteCertificateRefs");
                }
            }
        }

        return certRefs;
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
            if (ref.crlList().isEmpty() && ref.ocspList().isEmpty()) {
                throw new PkixException(
                        "CAdES-C: CrlOcspRef[" + i + "] has no crlList and no ocspList");
            }

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
        try {
            return GostSignatureHelper.digestByOid(digestOid, data);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Unsupported digest algorithm: " + digestOid);
        }
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
    private static List<ExtractedSignature> extractAllSignatures(byte[] signedDataDer)
            throws PkixException {
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

        List<ExtractedSignature> signatures = new ArrayList<>();
        for (byte[] si : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);
            // digestAlgorithm — третий элемент SignerInfo (version, sid, digestAlgorithm): RFC 5652
            // §5.3.
            // Дайджест messageImprint берём из заявленного алгоритма подписанта, а не выводим из
            // длины
            // подписи — критичный параметр не должен зависеть от косвенного признака.
            if (siParts.length < 3) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "SignerInfo too short: missing digestAlgorithm");
            }
            String digestOid = CmsAlgorithmIdentifier.decode(siParts[2]).algorithmOid();
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
            signatures.add(
                    new ExtractedSignature(DerCodec.parseOctetString(sigOctet, 0), digestOid));
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
                        GostLogger.Level.WARNING,
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

            // messageImprint сверяем против подписи этого подписанта; дайджест — по заявленному
            // размеру ключа подписанта (согласовано с embed-стороной через один и тот же маппинг).
            byte[] sig = sr.signatureValue();
            String signerDigestOid =
                    GostSignatureHelper.keySizeToDigestOid(sr.signerCertificate().getKeySize());
            SignatureHashResult sh = computeTspMessageImprint(signerDigestOid, sig);

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
     *
     * <p>Дайджест выбирается по <b>заявленному</b> алгоритму подписанта ({@code signerDigestOid}),
     * а не по длине подписи: критичный параметр messageImprint не выводится из косвенного признака.
     * Для сырых ГОСТ Р 34.10-2012 подписей длина фиксирована (64/128 байт), но принцип «брать из
     * объявленного значения» сохраняем как общее правило (fail-closed на неизвестный OID).
     *
     * <p>{@code signerDigestOid} приходит из разбора чужого SignerInfo (потенциально недоверенный
     * вход), поэтому неизвестный OID транслируется в {@link PkixException}, а не в сырой
     * {@link IllegalArgumentException} — чтобы не нарушить контракт метода для вызывающего кода.
     */
    private static SignatureHashResult computeTspMessageImprint(
            String signerDigestOid, byte[] signature) throws PkixException {
        try {
            byte[] sigHash = GostSignatureHelper.digestByOid(signerDigestOid, signature);
            return new SignatureHashResult(sigHash, signerDigestOid);
        } catch (IllegalArgumentException e) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TSP messageImprint: unsupported signer digest algorithm OID: "
                            + signerDigestOid);
        }
    }

    private record SignatureHashResult(byte[] hash, String oid) {}

    /** Подпись подписанта вместе с его заявленным OID дайджеста (для messageImprint метки). */
    private record ExtractedSignature(byte[] signatureValue, String digestAlgOid) {}
}
