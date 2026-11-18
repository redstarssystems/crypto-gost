package org.rssys.gost.pkix.cms;

import static org.rssys.gost.pkix.cms.CAdESSupport.addIfAbsent;
import static org.rssys.gost.pkix.cms.CAdESSupport.buildEscHashInput;
import static org.rssys.gost.pkix.cms.CAdESSupport.computeTspMessageImprint;
import static org.rssys.gost.pkix.cms.CAdESSupport.containsDer;
import static org.rssys.gost.pkix.cms.CAdESSupport.extractEmbeddedCerts;
import static org.rssys.gost.pkix.cms.CAdESSupport.findUnsignedAttrsIndex;
import static org.rssys.gost.pkix.cms.CAdESSupport.mergeCertsIntoField;
import static org.rssys.gost.pkix.cms.CAdESSupport.parseAttributeTlvs;
import static org.rssys.gost.pkix.cms.CAdESSupport.unsignedAttrsContent;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.CertRevocationData;
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
import org.rssys.gost.pkix.cms.CAdESSupport.SignatureHashResult;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.GostLogger;

/**
 * Сборка CAdES: встраивание меток времени, контрподписей, ссылок и значений (ETSI EN 319 122-1/2).
 * Проверка подписей выполняется в {@link CAdESVerifier}.
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
     * Строит DER-атрибуты complete-certificate-references и
     * complete-revocation-references без встраивания в SignedData.
     */
    private static byte[][] buildCompleteRefsAttributes(
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain)
            throws PkixException {
        CAdESCompleteData.CompleteRefsResult result =
                CAdESCompleteData.buildCompleteRefsResult(
                        chain,
                        crlsForChain,
                        ocspForChain,
                        ocspResponderCertificates(chain, ocspForChain));
        return encodeCompleteRefsAttributes(result);
    }

    /**
     * Собирает делегированные сертификаты OCSP-ответчиков из переданных ответов.
     *
     * <p>Сертификаты цепочки и дубликаты пропускаются. Подпись ответа и права ответчика
     * (EKU, ocsp-nocheck, цепочка) проверяет {@code OcspVerifier} при проверке свежести
     * доказательств, поэтому здесь отбор только по составу и лимиту.</p>
     *
     * @throws PkixException если ссылок получилось больше {@link CmsConstants#MAX_CERT_REFS}
     */
    private static List<GostCertificate> ocspResponderCertificates(
            List<GostCertificate> chain, List<GostOcspResponse> ocspForChain) throws PkixException {
        List<GostCertificate> responders = new ArrayList<>();
        for (GostOcspResponse ocsp : ocspForChain) {
            if (ocsp == null) {
                continue;
            }
            for (byte[] der : ocsp.getDelegatedCertificates()) {
                // certs взят из ещё не проверенного ответа: конструктор на мусоре вправе бросить
                // любое RuntimeException. Нераспознанный сертификат не может быть ответчиком
                // (OcspVerifier пропускает его так же), поэтому в ссылки он не попадает.
                // DER и исключение не пишем в журнал: ввод недоверенный.
                GostCertificate cert;
                try {
                    cert = new GostCertificate(der);
                } catch (RuntimeException e) {
                    LOG.log(
                            GostLogger.Level.DEBUG,
                            "Skipping unparsable certificate in OCSP response certs ({0} bytes)",
                            der.length);
                    continue;
                }
                if (!containsDer(chain, cert) && !containsDer(responders, cert)) {
                    responders.add(cert);
                }
            }
        }
        if (Math.max(0, chain.size() - 1) + responders.size() > CmsConstants.MAX_CERT_REFS) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-C: too many certificate references including OCSP responders: "
                            + (chain.size() - 1 + responders.size()));
        }
        return responders;
    }

    /** Кодирует уже построенный результат в DER-атрибуты ссылок. */
    private static byte[][] encodeCompleteRefsAttributes(
            CAdESCompleteData.CompleteRefsResult result) throws PkixException {
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
        return new byte[][] {certRefsAttr, revocRefsAttr};
    }

    /**
     * Встраивает CAdES-C атрибуты в CAdES-BES/T подпись — основной метод.
     *
     * <p>Добавляет complete-certificate-references и complete-revocation-references
     * в unsignedAttrs каждого подписанта (RFC 5126 §6.2). Принимает CAdES-T или
     * CAdES-C (то есть подпись, у которой уже есть signature-time-stamp).
     * CAdES-BES без метки отклоняется: CAdES-C обязан строиться на CAdES-T.
     *
     * <p>Цепочка сертификатов строится вызывающим кодом — метод ожидает уже построенную,
     * валидированную цепочку. CRL-данные передаются как доменные объекты.
     *
     * @param cadesDer      CAdES-T или CAdES-C подпись (CMS SignedData)
     * @param chain         цепочка [signer, intermediates..., trustedRoot]
     * @param crlsForChain  список CRL по одному на элемент chain; допускается null
     * @param ocspForChain  список OCSP-ответов по одному на элемент chain; допускается null
     * @return CAdES-C подпись (CMS SignedData с C-атрибутами)
     * @throws PkixException при ошибке разбора, отсутствии signature-time-stamp
     *                       или несоответствии размеров списков
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

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[] existingCerts = sd.certs();
        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        for (byte[] signerInfoDer : origSignerInfos) {
            if (!hasSignatureTimeEvidence(signerInfoDer)) {
                throw new PkixException(
                        PkixException.Reason.OTHER,
                        "CAdES-T input required: signature-time-stamp missing or malformed");
            }
        }

        byte[][] attrs = buildCompleteRefsAttributes(chain, crlsForChain, ocspForChain);
        byte[] certRefsAttr = attrs[0];
        byte[] revocRefsAttr = attrs[1];

        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        for (byte[] signerInfoDer : origSignerInfos) {
            byte[] modified = injectUnsignedAttrDer(signerInfoDer, certRefsAttr);
            modified = injectUnsignedAttrDer(modified, revocRefsAttr);
            modifiedSignerInfos.add(modified);
        }

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
     * <p>Принимает CAdES-T или CAdES-C (подпись с signature-time-stamp).
     * Автоматически достраивает недостающие уровни: если задан {@code tspUrl} -
     * T-метку (signature-time-stamp), затем C-референсы (embedCompleteRefs),
     * затем встраивает X-Long атрибуты (certificate-values, revocation-values).
     * BES без метки отклоняется: X Long обязан строиться на CAdES-T.
     *
     * <p>Сертификаты цепочки добавляются в поле {@code certificates [0]} SignedData
     * через {@link #mergeCertsIntoField} — дедупликация по DER с лимитом
     * {@link CmsConstants#MAX_EMBEDDED_CERTS}.
     *
     * @param cadesDer       CAdES-T или CAdES-C DER
     * @param chain          цепочка [signer, intermediates..., trustedRoot]
     * @param crlsForChain   CRL для каждого элемента chain (parallel list, null допускается)
     * @param ocspForChain   OCSP-ответы (parallel list, null допускается)
     * @param tspUrl         TSA URL для signature-time-stamp (null если уже есть)
     * @param tspTransport   HTTP-транспорт для TSP
     * @param trustedTsaCerts якоря доверия TSA (fail-closed): корень или сам сертификат TSA;
     *                        корень цепочки подписанта сюда не подставляется. Для вложенных
     *                        доказательств цепочка TSA обязана строиться до одного из них
     * @return CAdES-X Long Type 1 DER
     * @throws PkixException при ошибке разбора, отсутствии signature-time-stamp
     *                       или несоответствии размеров списков
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
        return embedXLongType1(
                cadesDer,
                chain,
                crlsForChain,
                ocspForChain,
                tspUrl,
                tspTransport,
                RevocationFreshnessPolicy.STRICT,
                trustedTsaCerts);
    }

    /**
     * Строит CAdES-X Long Type 1 с явной политикой свежести отзыва.
     *
     * <p>{@code tspUrl}/{@code tspTransport} обязательны: без TSA нельзя
     * построить {@code escTimeStamp}. Перед встраиванием проверяется, что
     * переданные CRL/OCSP удовлетворяют выбранной политике; при нарушении
     * выбрасывается {@link PkixException} с указанием, что делать.</p>
     *
     * @param cadesDer       CAdES-T или CAdES-C DER
     * @param chain          цепочка [signer, intermediates..., trustedRoot]
     * @param crlsForChain   CRL для каждого элемента chain
     * @param ocspForChain   OCSP-ответы для каждого элемента chain
     * @param tspUrl         TSA URL для signature-time-stamp и escTimeStamp
     * @param tspTransport   HTTP-транспорт для TSP
     * @param policy         политика свежести отзыва
     * @param trustedTsaCerts якоря доверия TSA: корень или сам сертификат TSA; корень цепочки
     *                        подписанта не подставляется, цепочка TSA обязана строиться до якоря
     * @return CAdES-X Long Type 1 DER
     * @throws PkixException при ошибке разбора, порядке меток, нарушении
     *         политики или несоответствии размеров списков
     * @throws IOException   при ошибке TSP-запроса
     */
    public static byte[] embedXLongType1(
            byte[] cadesDer,
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            String tspUrl,
            TspTransport tspTransport,
            RevocationFreshnessPolicy policy,
            GostCertificate... trustedTsaCerts)
            throws PkixException, IOException {
        return embedXLongType1(
                cadesDer,
                chain,
                crlsForChain,
                ocspForChain,
                tspUrl,
                tspTransport,
                policy,
                CrlLimits.DEFAULT,
                trustedTsaCerts);
    }

    /**
     * Строит CAdES-X Long Type 1 с явной политикой свежести отзыва и пределами CRL.
     *
     * <p>Пределы действуют на проверку переданных CRL перед встраиванием: превышение размера или
     * числа записей даёт {@link PkixException} с причиной
     * {@link PkixException.Reason#CRL_LIMIT_EXCEEDED}. Остальные параметры - как у
     * {@link #embedXLongType1(byte[], List, List, List, String, TspTransport,
     * RevocationFreshnessPolicy, GostCertificate...)}.</p>
     *
     * @param limits пределы размера и числа записей CRL (не null)
     * @return CAdES-X Long Type 1 DER
     * @throws PkixException при ошибке разбора, порядке меток, нарушении политики, превышении
     *         пределов CRL или несоответствии размеров списков
     * @throws IOException   при ошибке TSP-запроса
     * @throws NullPointerException если {@code limits} (как и остальные обязательные аргументы)
     *     равен null
     */
    public static byte[] embedXLongType1(
            byte[] cadesDer,
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            String tspUrl,
            TspTransport tspTransport,
            RevocationFreshnessPolicy policy,
            CrlLimits limits,
            GostCertificate... trustedTsaCerts)
            throws PkixException, IOException {
        Objects.requireNonNull(cadesDer, "cadesDer must not be null");
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(crlsForChain, "crlsForChain must not be null");
        Objects.requireNonNull(ocspForChain, "ocspForChain must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        if (crlsForChain.size() != chain.size()) {
            throw new PkixException(
                    "crlsForChain size " + crlsForChain.size() + " != chain size " + chain.size());
        }
        if (ocspForChain.size() != chain.size()) {
            throw new PkixException(
                    "ocspForChain size " + ocspForChain.size() + " != chain size " + chain.size());
        }
        if (tspUrl == null || tspTransport == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long Type 1 requires TSP URL/transport for escTimeStamp");
        }

        requireNoEscTimestamp(cadesDer);
        TimestampPresence presence = signatureTimestampPresence(cadesDer);
        if (presence == TimestampPresence.MIXED) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long: signature-time-stamp is present for some signers only");
        }

        byte[] current = cadesDer.clone();
        if (presence == TimestampPresence.NONE) {
            current = addTimestamp(current, tspUrl, tspTransport, trustedTsaCerts);
        }

        // КриптоПро считает действительным только такой signature-time-stamp,
        // внутри которого уже лежат X-Long-доказательства для цепочки TSA:
        // CertificateRefs, RevocationRefs, certificate-values и revocation-values.
        // Эти атрибуты не входят в подпись TST (она покрывает только signedAttrs),
        // поэтому их можно добавить после получения токена. Обновлённый токен
        // обязан попасть в esc-хеш, поэтому шаг выполняется до escTimeStamp.
        current =
                injectTimestampChainEvidence(
                        current, chain, crlsForChain, ocspForChain, trustedTsaCerts);

        byte[][] refs = buildCompleteRefsAttributes(chain, crlsForChain, ocspForChain);
        current =
                replaceUnsignedAttrs(
                        current,
                        new String[] {
                            GostOids.COMPLETE_CERTIFICATE_REFS, GostOids.COMPLETE_REVOCATION_REFS
                        },
                        refs);

        List<Instant> signatureTimes = extractSignatureTimestampInstants(current);
        Instant tSigMin = minInstant(signatureTimes);
        Instant tSigMax = maxInstant(signatureTimes);
        List<CertRevocationEvidence> evidence =
                buildEvidenceForChain(chain, crlsForChain, ocspForChain);

        // Ранняя проверка без esc-запроса: collection = now (не раньше t_sig).
        Instant preCollection = Instant.now();
        if (preCollection.isBefore(tSigMin)) {
            preCollection = tSigMin;
        }
        validateEmbedEvidence(
                chain,
                evidence,
                new RevocationEvidenceWindow(tSigMin, preCollection),
                policy,
                limits);

        EscEmbedResult esc = embedEscTimestamps(current, tspUrl, tspTransport, trustedTsaCerts);
        Instant tEsc = esc.minGenTime();
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

        validateEmbedEvidence(
                chain, evidence, new RevocationEvidenceWindow(tSigMin, tEsc), policy, limits);

        return embedXLongValues(esc.cadesDer(), chain, crlsForChain, ocspForChain);
    }

    private static void validateEmbedEvidence(
            List<GostCertificate> chain,
            List<CertRevocationEvidence> evidence,
            RevocationEvidenceWindow window,
            RevocationFreshnessPolicy policy,
            CrlLimits limits)
            throws PkixException {
        try {
            ChainValidator.validateRevocationEvidence(chain, evidence, window, policy, limits);
        } catch (PkixException e) {
            String hint =
                    policy == RevocationFreshnessPolicy.STRICT
                                    && e.reason()
                                            == PkixException.Reason
                                                    .REVOCATION_EVIDENCE_OUT_OF_WINDOW
                            ? "; evidence issued before signature time; obtain a fresh CRL/OCSP "
                                    + "or select ETSI_DEFAULT"
                            : "";
            throw new PkixException(
                    e.reason(),
                    "CAdES-X Long: revocation evidence does not satisfy "
                            + policy
                            + " ("
                            + e.getMessage()
                            + ")"
                            + hint,
                    e);
        }
    }

    /**
     * Добавляет X-Long-доказательства в каждый signature-time-stamp токен.
     *
     * <p>ПОЧЕМУ: КриптоПро при проверке escTimeStamp строит цепочку TSA не из
     * хранилища, а из вложенных в токен ссылок и значений. Без них токен
     * отклоняется как недействительный штамп. Подпись TST покрывает только
     * signedAttrs, поэтому unsignedAttrs можно добавить без перевычисления
     * подписи. Обновлённый токен обязан попасть в esc-хеш, поэтому метод
     * вызывается до запроса escTimeStamp.</p>
     */
    private static byte[] injectTimestampChainEvidence(
            byte[] cadesDer,
            List<GostCertificate> mainChain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            GostCertificate... trustedTsaCerts)
            throws PkixException {

        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        List<GostCertificate> candidates = new ArrayList<>(mainChain);
        for (GostCertificate cert : extractEmbeddedCerts(cadesDer)) {
            addIfAbsent(candidates, cert);
        }

        List<byte[]> modified = new ArrayList<>(signerInfos.length);
        for (byte[] signerInfo : signerInfos) {
            modified.add(
                    addEvidenceToTimestampAttrs(
                            signerInfo, candidates, crlsForChain, ocspForChain, trustedTsaCerts));
        }
        byte[] newSignerInfos = DerCodec.encodeSetOf(modified.toArray(new byte[0][]));
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    private static byte[] addEvidenceToTimestampAttrs(
            byte[] signerInfoDer,
            List<GostCertificate> candidates,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            GostCertificate... trustedTsaCerts)
            throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        int unsignedIdx = findUnsignedAttrsIndex(siParts);
        if (unsignedIdx < 0) {
            return signerInfoDer;
        }
        byte[] content = unsignedAttrsContent(siParts);
        List<byte[]> attrs = new ArrayList<>();
        for (byte[] attrDer : parseAttributeTlvs(content)) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            if (!GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                attrs.add(attrDer);
                continue;
            }
            byte[][] values = attr.attrValues();
            byte[][] updatedValues = new byte[values.length][];
            for (int i = 0; i < values.length; i++) {
                updatedValues[i] =
                        addEvidenceToTimestampToken(
                                values[i],
                                candidates,
                                crlsForChain,
                                ocspForChain,
                                false,
                                trustedTsaCerts);
            }
            attrs.add(CmsAttribute.encode(attr.attrType(), updatedValues));
        }
        byte[][] sorted = attrs.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        siParts[unsignedIdx] = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
        return DerCodec.encodeSequence(siParts);
    }

    private static byte[] addEvidenceToTimestampToken(
            byte[] tokenDer,
            List<GostCertificate> candidates,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain,
            boolean keepCertificates,
            GostCertificate... trustedTsaCerts)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(tokenDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "TimeStampToken is not SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        List<GostCertificate> tokenCerts = extractEmbeddedCerts(tokenDer);

        byte[][] tstSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        if (tstSignerInfos.length == 0) {
            throw new PkixException(PkixException.Reason.OTHER, "TimeStampToken has no SignerInfo");
        }
        GostCertificate tsaCert =
                findTimestampSignerCert(tstSignerInfos[0], tokenCerts, candidates);
        if (tsaCert == null) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long: TSA signer certificate not found in timestamp token");
        }

        List<GostCertificate> pool = new ArrayList<>(tokenCerts);
        for (GostCertificate cert : candidates) {
            addIfAbsent(pool, cert);
        }
        // Якоря цепочки TSA - только явно переданные доверенные сертификаты TSA.
        // Корень цепочки подписанта сюда не подставляется: он не обязан доверять
        // чужому TSA. Если TSA сам доверенный, buildChain вернёт [TSA], и вложение
        // будет содержать только его сертификат без ссылок.
        List<GostCertificate> anchors = new ArrayList<>(Arrays.asList(trustedTsaCerts));
        List<GostCertificate> tsaChain;
        try {
            tsaChain = CertChainBuilder.buildChain(tsaCert, pool, anchors);
        } catch (PkixException e) {
            // Без вложенных доказательств КриптоПро отвергает штамп подписи, поэтому
            // тихий пропуск выпускал бы заведомо невалидный X Long.
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long: cannot build TSA certificate chain for embedded evidence;"
                            + " pass the TSA root as trusted: "
                            + e.getMessage(),
                    e);
        }

        CAdESCompleteData.CompleteRefsResult refs = buildTimestampChainRefs(tsaChain, crlsForChain);
        byte[][] refAttrs = encodeCompleteRefsAttributes(refs);

        List<GostCertificate> reversedChain = new ArrayList<>(tsaChain);
        Collections.reverse(reversedChain);
        byte[] certValuesAttr =
                CmsAttribute.encode(
                        GostOids.CERTIFICATE_VALUES,
                        CAdESXLongData.encodeCertificateValues(reversedChain));

        GostCrl tsaCrl = findCrlForIssuer(crlsForChain, tsaCert.getIssuerDnBytes());
        List<GostCrl> tsaCrls = tsaCrl != null ? List.of(tsaCrl) : List.of();
        byte[] revocValuesAttr =
                CmsAttribute.encode(
                        GostOids.REVOCATION_VALUES,
                        CAdESXLongData.encodeRevocationValues(tsaCrls, List.of()));

        List<byte[]> modified = new ArrayList<>(tstSignerInfos.length);
        for (byte[] signerInfo : tstSignerInfos) {
            modified.add(
                    replaceUnsignedAttrsDer(
                            signerInfo,
                            new String[] {
                                GostOids.COMPLETE_CERTIFICATE_REFS,
                                GostOids.COMPLETE_REVOCATION_REFS,
                                GostOids.CERTIFICATE_VALUES,
                                GostOids.REVOCATION_VALUES
                            },
                            new byte[][] {
                                refAttrs[0], refAttrs[1], certValuesAttr, revocValuesAttr
                            }));
        }
        byte[] newSignerInfos = DerCodec.encodeSetOf(modified.toArray(new byte[0][]));
        // КриптоПро в signature-time-stamp оставляет certificates пустым, а TSA
        // и корень берёт из вложенного certValues. Если оставить сертификат TSA
        // в certificates, без AKI цепочка не строится (0x800B010A).
        byte[] newSignedData = sd.rebuild(keepCertificates ? sd.certs() : null, newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    /**
     * Строит ссылки для цепочки TSA. В отличие от цепочки подписанта, корень
     * входит в CertificateRefs: КриптоПро включает его для TSA-цепочки.
     */
    private static CAdESCompleteData.CompleteRefsResult buildTimestampChainRefs(
            List<GostCertificate> tsaChain, List<GostCrl> crlsForChain) throws PkixException {
        GostCertificate tsaCert = tsaChain.get(0);
        String hashOid = GostSignatureHelper.keySizeToDigestOid(tsaCert.getKeySize());

        List<CAdESCompleteData.OtherCertID> certRefs = new ArrayList<>();
        for (int i = 1; i < tsaChain.size(); i++) {
            GostCertificate ca = tsaChain.get(i);
            byte[] hash = GostSignatureHelper.digestByOid(hashOid, ca.getEncoded());
            certRefs.add(
                    new CAdESCompleteData.OtherCertID(
                            new CAdESCompleteData.OtherHash(hashOid, hash),
                            new CAdESCompleteData.IssuerSerial(
                                    ca.getIssuerDnBytes(), ca.getSerialNumberBigInt())));
        }

        List<CAdESCompleteData.CrlOcspRef> revocRefs = new ArrayList<>();
        GostCrl tsaCrl = findCrlForIssuer(crlsForChain, tsaCert.getIssuerDnBytes());
        List<CAdESCompleteData.CrlValidatedID> crlIds = new ArrayList<>();
        if (tsaCrl != null) {
            byte[] crlHash = GostSignatureHelper.digestByOid(hashOid, tsaCrl.getEncoded());
            crlIds.add(
                    new CAdESCompleteData.CrlValidatedID(
                            new CAdESCompleteData.OtherHash(hashOid, crlHash),
                            new CAdESCompleteData.CrlIdentifier(
                                    tsaCrl.getIssuerDnBytes(),
                                    GostSignatureHelper.formatUtcTime(tsaCrl.getThisUpdate()),
                                    tsaCrl.getCrlNumber())));
        }
        revocRefs.add(new CAdESCompleteData.CrlOcspRef(crlIds, List.of()));
        // По одному CrlOcspRef на каждую запись CertificateRefs, в том же порядке.
        // Для корня КриптоПро пишет пустой SEQUENCE: отзыва корня в X-Long нет.
        for (int i = 1; i < tsaChain.size(); i++) {
            revocRefs.add(new CAdESCompleteData.CrlOcspRef(List.of(), List.of()));
        }
        return new CAdESCompleteData.CompleteRefsResult(certRefs, revocRefs);
    }

    private static GostCertificate findTimestampSignerCert(
            byte[] signerInfoDer,
            List<GostCertificate> tokenCerts,
            List<GostCertificate> candidates)
            throws PkixException {
        byte[][] parts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (parts.length < 2) {
            return null;
        }
        CmsIssuerAndSerialNumber sid = CmsIssuerAndSerialNumber.decode(parts[1]);
        GostCertificate cert = findCertBySid(sid, tokenCerts);
        if (cert != null) {
            return cert;
        }
        // Сертификат из пула кандидатов привязывается к signingCertificateV2 так же,
        // как при проверке: иначе подмена на сертификат с тем же sid прошла бы до
        // построения цепочки.
        List<GostCertificate> sidMatches = new ArrayList<>();
        for (GostCertificate candidate : candidates) {
            if (candidate.getSerialNumberBigInt().equals(sid.serial())
                    && Arrays.equals(candidate.getIssuerDnBytes(), sid.issuer())
                    && !containsDer(sidMatches, candidate)) {
                sidMatches.add(candidate);
            }
        }
        if (sidMatches.isEmpty()) {
            return null;
        }
        return CmsSignedDataVerifier.selectBoundCandidate(sidMatches, signedAttributesOf(parts));
    }

    /** Разбирает подписанные атрибуты SignerInfo (пустой список, если их нет). */
    private static List<CmsAttribute> signedAttributesOf(byte[][] signerInfoParts)
            throws PkixException {
        List<CmsAttribute> result = new ArrayList<>();
        for (byte[] part : signerInfoParts) {
            if (!DerCodec.isContextTag(part, 0)) {
                continue;
            }
            int[] lenInfo = DerCodec.decodeLength(part, 1);
            byte[] content = Arrays.copyOfRange(part, 1 + lenInfo[1], part.length);
            for (byte[] attrDer : parseAttributeTlvs(content)) {
                result.add(CmsAttribute.decode(attrDer));
            }
            break;
        }
        return result;
    }

    private static GostCertificate findCertBySid(
            CmsIssuerAndSerialNumber sid, List<GostCertificate> certs) {
        for (GostCertificate cert : certs) {
            if (cert.getSerialNumberBigInt().equals(sid.serial())
                    && Arrays.equals(cert.getIssuerDnBytes(), sid.issuer())) {
                return cert;
            }
        }
        return null;
    }

    private static GostCrl findCrlForIssuer(List<GostCrl> crls, byte[] issuerDn) {
        for (GostCrl crl : crls) {
            if (crl != null && Arrays.equals(crl.getIssuerDnBytes(), issuerDn)) {
                return crl;
            }
        }
        return null;
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

        // КриптоПро кладёт в certificate-values всю цепочку, включая подписанта
        // и корень. Это допустимо по RFC 5126 §6.3.3 и нужно, чтобы проверка
        // escTimeStamp могла построить цепочку TSA из самого сообщения.
        List<GostCertificate> referencedCerts = new ArrayList<>(chain);
        // Сертификаты делегированных OCSP-ответчиков указаны в ссылках, значит обязаны
        // лежать и в certificate-values (иначе КриптоПро не найдёт сертификат ответчика).
        referencedCerts.addAll(ocspResponderCertificates(chain, ocspForChain));

        // Значения отзыва для всех звеньев, у которых есть доказательство (в том числе
        // у корня, если его CRL/OCSP передан): хеши ссылок сверяются со значениями.
        byte[] revocValuesDer = CAdESXLongData.encodeRevocationValues(crlsForChain, ocspForChain);
        byte[] revocValuesAttr = CmsAttribute.encode(GostOids.REVOCATION_VALUES, revocValuesDer);

        List<String> replaceOids = new ArrayList<>();
        List<byte[]> replaceAttrs = new ArrayList<>();
        replaceOids.add(GostOids.CERTIFICATE_VALUES);
        replaceOids.add(GostOids.REVOCATION_VALUES);
        if (!referencedCerts.isEmpty()) {
            replaceAttrs.add(
                    CmsAttribute.encode(
                            GostOids.CERTIFICATE_VALUES,
                            CAdESXLongData.encodeCertificateValues(referencedCerts)));
        } else {
            replaceAttrs.add(null);
        }
        replaceAttrs.add(revocValuesAttr);

        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        for (byte[] signerInfoDer : origSignerInfos) {
            byte[] modified =
                    replaceUnsignedAttrsDer(
                            signerInfoDer,
                            replaceOids.toArray(new String[0]),
                            replaceAttrs.toArray(new byte[0][]));
            modifiedSignerInfos.add(modified);
        }

        List<GostCertificate> certCandidates = new ArrayList<>(chain);
        byte[] newCerts = mergeChainCerts(existingCerts, certCandidates);

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
     * @param cadesDer        CAdES-T или CAdES-C подпись
     * @param chain           цепочка [signer, intermediates..., trustedRoot]
     * @param revocationData  данные отзыва — parallel list (допускается null для элемента)
     * @return CAdES-C подпись
     * @throws PkixException при ошибке разбора, отсутствии signature-time-stamp
     *                       или несоответствии размеров списков
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

        int unsignedIdx = findUnsignedAttrsIndex(siParts);

        byte[] newUnsignedAttrs;
        if (unsignedIdx >= 0) {
            List<byte[]> attrs = parseAttributeTlvs(unsignedAttrsContent(siParts));
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

    /**
     * Заменяет unsigned-атрибуты с указанными OID во всех SignerInfo.
     * Замена атомарна: при ошибке ни один SignerInfo не возвращается.
     */
    private static byte[] replaceUnsignedAttrs(
            byte[] cadesDer, String[] replaceOids, byte[][] newAttrs) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        List<byte[]> modified = new ArrayList<>(signerInfos.length);
        for (byte[] signerInfoDer : signerInfos) {
            modified.add(replaceUnsignedAttrsDer(signerInfoDer, replaceOids, newAttrs));
        }
        byte[] newSignerInfos = DerCodec.encodeSetOf(modified.toArray(new byte[0][]));
        byte[] newSignedData = sd.rebuild(sd.certs(), newSignerInfos);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData);
    }

    static byte[] replaceUnsignedAttrsDer(
            byte[] signerInfoDer, String[] replaceOids, byte[][] newAttrs) throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length == 0) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "SignerInfo is empty");
        }
        int unsignedIdx = findUnsignedAttrsIndex(siParts);
        List<byte[]> attrs = new ArrayList<>();
        if (unsignedIdx >= 0) {
            byte[] content = unsignedAttrsContent(siParts);
            for (byte[] attrDer : parseAttributeTlvs(content)) {
                String oid = CmsAttribute.decode(attrDer).attrType();
                boolean replace = false;
                for (String candidate : replaceOids) {
                    if (candidate.equals(oid)) {
                        replace = true;
                        break;
                    }
                }
                if (!replace) {
                    attrs.add(attrDer);
                }
            }
        }
        for (byte[] attr : newAttrs) {
            // null означает «не добавлять атрибут»: пустой SEQUENCE недопустим.
            if (attr != null) {
                attrs.add(attr);
            }
        }
        byte[][] sorted = attrs.toArray(new byte[0][]);
        DerCodec.sortDer(sorted);
        byte[] newUnsignedAttrs = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
        if (unsignedIdx >= 0) {
            siParts[unsignedIdx] = newUnsignedAttrs;
        } else {
            byte[][] newParts = Arrays.copyOf(siParts, siParts.length + 1);
            newParts[newParts.length - 1] = newUnsignedAttrs;
            siParts = newParts;
        }
        return DerCodec.encodeSequence(siParts);
    }

    private enum TimestampPresence {
        ALL,
        NONE,
        MIXED
    }

    private static TimestampPresence signatureTimestampPresence(byte[] cadesDer)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        int present = 0;
        for (byte[] signerInfoDer : signerInfos) {
            if (hasSignatureTimeEvidence(signerInfoDer)) {
                present++;
            }
        }
        if (present == 0) {
            return TimestampPresence.NONE;
        }
        return present == signerInfos.length ? TimestampPresence.ALL : TimestampPresence.MIXED;
    }

    private static void requireNoEscTimestamp(byte[] cadesDer) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        for (byte[] signerInfoDer : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
            byte[] content = unsignedAttrsContent(siParts);
            if (content == null) {
                continue;
            }
            for (byte[] attrDer : parseAttributeTlvs(content)) {
                if (GostOids.ESC_TIME_STAMP.equals(CmsAttribute.decode(attrDer).attrType())) {
                    throw new PkixException(
                            PkixException.Reason.OTHER,
                            "CAdES-X Long Type 1: escTimeStamp already present in input");
                }
            }
        }
    }

    /**
     * Структурно проверяет наличие signature-time-stamp с ровно одним значением
     * в каждом экземпляре атрибута.
     *
     * <p>Метод не проверяет подпись TSA и messageImprint - это делает
     * {@link #extractAndVerifyTimestamps}. Проверка нужна на embed-стороне,
     * чтобы библиотека не выпускала CAdES-C/X Long из BES без метки или с
     * заведомо отвергаемым верификатором атрибутом.
     */
    private static boolean hasSignatureTimeEvidence(byte[] signerInfoDer) throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        byte[] content = unsignedAttrsContent(siParts);
        if (content == null) {
            return false;
        }
        boolean found = false;
        for (byte[] attrDer : parseAttributeTlvs(content)) {
            CmsAttribute attr;
            try {
                attr = CmsAttribute.decode(attrDer);
            } catch (RuntimeException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR, "Malformed unsigned attribute");
            }
            if (GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                if (attr.attrValues().length != 1) {
                    return false;
                }
                found = true;
            }
        }
        return found;
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

    /**
     * Извлекает genTime всех signature-time-stamp без проверки подписи TSA.
     * Используется только producer-стороной для ранней проверки окна политики.
     */
    private static List<Instant> extractSignatureTimestampInstants(byte[] cadesDer)
            throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        SignedDataParts sd = SignedDataParts.parse(contentInfo.content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        List<Instant> result = new ArrayList<>();
        for (byte[] signerInfoDer : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
            byte[] unsignedContent = unsignedAttrsContent(siParts);
            if (unsignedContent == null) {
                continue;
            }
            for (byte[] attrDer : parseAttributeTlvs(unsignedContent)) {
                CmsAttribute attr = CmsAttribute.decode(attrDer);
                if (GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                    result.add(parseTimestampGenTime(attr));
                }
            }
        }
        if (result.isEmpty()) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "CAdES-X Long Type 1 requires signature-time-stamp");
        }
        return result;
    }

    private static Instant parseTimestampGenTime(CmsAttribute attr) throws PkixException {
        byte[][] values = attr.attrValues();
        if (values.length != 1) {
            throw new PkixException(
                    PkixException.Reason.OTHER,
                    "signature-time-stamp: expected exactly one value, got " + values.length);
        }
        TspResponse response = TspResponse.parseTimeStampToken(values[0]);
        return Instant.ofEpochMilli(
                TspResponse.parseGeneralizedTimeToMs(response.tstInfo().genTime()));
    }

    /**
     * Встраивает escTimeStamp каждому подписанту и возвращает минимальный genTime.
     */
    private static EscEmbedResult embedEscTimestamps(
            byte[] cadesDer, String tspUrl, TspTransport transport, GostCertificate... tsaTrusted)
            throws PkixException, IOException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(cadesDer);
        if (!GostOids.CMS_SIGNED_DATA.equals(contentInfo.contentType())) {
            throw new PkixException(
                    PkixException.Reason.OTHER, "Not a SignedData: " + contentInfo.contentType());
        }
        byte[] signedDataBody = contentInfo.content();
        SignedDataParts sd = SignedDataParts.parse(signedDataBody);
        byte[][] origSignerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);

        List<byte[]> modifiedSignerInfos = new ArrayList<>();
        List<byte[]> allTokens = new ArrayList<>();
        List<Instant> genTimes = new ArrayList<>();

        for (byte[] signerInfoDer : origSignerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
            byte[] unsignedContent = unsignedAttrsContent(siParts);
            List<CmsAttribute> attrs = new ArrayList<>();
            if (unsignedContent != null) {
                for (byte[] attrDer : parseAttributeTlvs(unsignedContent)) {
                    CmsAttribute attr = CmsAttribute.decode(attrDer);
                    if (GostOids.ESC_TIME_STAMP.equals(attr.attrType())) {
                        throw new PkixException(
                                PkixException.Reason.OTHER,
                                "CAdES-X Long Type 1: escTimeStamp already present in input");
                    }
                    attrs.add(attr);
                }
            }

            ExtractedSignature signature = extractSignatureFromSignerInfo(signerInfoDer);
            byte[] escInput = buildEscHashInput(signature.signatureValue(), attrs);
            SignatureHashResult sh = computeTspMessageImprint(signature.digestAlgOid(), escInput);

            TspRequestBuilder reqBuilder =
                    TspRequestBuilder.create().messageImprint(sh.hash(), sh.oid()).certReq(true);
            byte[] tspRespDer = transport.send(reqBuilder.build(), tspUrl);
            TspResponse tspResponse = TspResponse.fromDer(tspRespDer);
            tspResponse.verify(sh.hash(), sh.oid(), reqBuilder.getNonce(), tsaTrusted);

            // escTimeStamp остаётся обычным TimeStampToken без вложенных
            // доказательств: КриптоПро в эталоне принимает именно такую форму.
            // X-Long-доказательства нужны только в signature-time-stamp.
            byte[] token = tspResponse.timeStampTokenDer();
            genTimes.add(
                    Instant.ofEpochMilli(
                            TspResponse.parseGeneralizedTimeToMs(tspResponse.tstInfo().genTime())));
            allTokens.add(token);
            modifiedSignerInfos.add(
                    injectUnsignedAttrDer(
                            signerInfoDer, CmsAttribute.encode(GostOids.ESC_TIME_STAMP, token)));
        }

        byte[] newCerts = mergeCertificates(sd.certs(), allTokens);
        byte[] newSignerInfos = DerCodec.encodeSetOf(modifiedSignerInfos.toArray(new byte[0][]));
        byte[] newSignedData = sd.rebuild(newCerts, newSignerInfos);
        return new EscEmbedResult(
                CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, newSignedData), genTimes);
    }

    private static ExtractedSignature extractSignatureFromSignerInfo(byte[] signerInfoDer)
            throws PkixException {
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        if (siParts.length < 3) {
            throw new PkixException(PkixException.Reason.PARSE_ERROR, "Malformed SignerInfo");
        }
        String digestOid = CmsAlgorithmIdentifier.decode(siParts[2]).algorithmOid();
        for (int i = siParts.length - 1; i >= 0; i--) {
            if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                return new ExtractedSignature(DerCodec.parseOctetString(siParts[i], 0), digestOid);
            }
        }
        throw new PkixException(PkixException.Reason.OTHER, "Signature not found in SignerInfo");
    }

    private static List<CertRevocationEvidence> buildEvidenceForChain(
            List<GostCertificate> chain,
            List<GostCrl> crlsForChain,
            List<GostOcspResponse> ocspForChain) {
        List<CertRevocationEvidence> result = new ArrayList<>(chain.size());
        for (int i = 0; i < chain.size(); i++) {
            GostCrl crl = crlsForChain.get(i);
            GostOcspResponse ocsp = ocspForChain.get(i);
            List<byte[]> crlDers = crl != null ? List.of(crl.getEncoded()) : List.of();
            List<byte[]> ocspDers = ocsp != null ? List.of(ocsp.getEncoded()) : List.of();
            result.add(new CertRevocationEvidence(crlDers, ocspDers));
        }
        return result;
    }

    private static Instant minInstant(List<Instant> values) {
        Instant min = values.get(0);
        for (Instant value : values) {
            if (value.isBefore(min)) {
                min = value;
            }
        }
        return min;
    }

    private static Instant maxInstant(List<Instant> values) {
        Instant max = values.get(0);
        for (Instant value : values) {
            if (value.isAfter(max)) {
                max = value;
            }
        }
        return max;
    }

    private record EscEmbedResult(byte[] cadesDer, List<Instant> genTimes) {
        EscEmbedResult {
            cadesDer = cadesDer.clone();
            genTimes = List.copyOf(genTimes);
        }

        @Override
        public byte[] cadesDer() {
            return cadesDer.clone();
        }

        Instant minGenTime() {
            return minInstant(genTimes);
        }
    }

    /**
     * Объединяет сертификаты из всех TimeStampToken'ов с уже имеющимися в SignedData.
     *
     * <p>Отсутствие поля certificates в токене штатно (КриптоПро кладёт сертификаты TSA
     * только в вложенный certificate-values), а нечитаемая структура токена и превышение
     * лимита сертификатов - ошибка: иначе выпуск молча завершился бы неполным результатом
     * или раздул SignedData. Дубликаты по DER удаляются.
     *
     * @return DER-кодированное поле certificates или {@code null} если сертификатов нет
     * @throws PkixException при нечитаемом токене или превышении
     *         {@link CmsConstants#MAX_EMBEDDED_CERTS}
     */
    static byte[] mergeCertificates(byte[] existingCertsField, List<byte[]> timeStampTokens)
            throws PkixException {
        List<byte[]> tokenCerts = new ArrayList<>();
        for (int tokenIdx = 0; tokenIdx < timeStampTokens.size(); tokenIdx++) {
            try {
                CmsContentInfo tsCi = CmsContentInfo.decode(timeStampTokens.get(tokenIdx));
                byte[][] tsSdParts = DerCodec.parseSequenceContents(tsCi.content(), 0);
                int certsIdx = 3;
                if (certsIdx >= tsSdParts.length
                        || !DerCodec.isContextTag(tsSdParts[certsIdx], 0)) {
                    continue;
                }
                byte[] tsCerts = tsSdParts[certsIdx];
                int[] lenInfo = DerCodec.decodeLength(tsCerts, 1);
                int pos = 1 + lenInfo[1];
                while (pos < tsCerts.length) {
                    int[] certLen = DerCodec.decodeLength(tsCerts, pos + 1);
                    int certTotal = 1 + certLen[1] + certLen[0];
                    tokenCerts.add(java.util.Arrays.copyOfRange(tsCerts, pos, pos + certTotal));
                    pos += certTotal;
                }
            } catch (RuntimeException e) {
                throw new PkixException(
                        PkixException.Reason.PARSE_ERROR,
                        "Malformed TimeStampToken #" + tokenIdx + ": cannot read certificates",
                        e);
            }
        }
        return mergeCertsIntoField(existingCertsField, tokenCerts, CmsConstants.MAX_EMBEDDED_CERTS);
    }

    /** Подпись подписанта вместе с его заявленным OID дайджеста (для messageImprint метки). */
    private record ExtractedSignature(byte[] signatureValue, String digestAlgOid) {}
}
