package org.rssys.gost.pkix.cert;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.api.Signature;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

/**
 * Построитель DER-закодированного OCSPRequest (RFC 6960 §4.1) с поддержкой nonce (RFC 8954)
 * и опциональной подписью запроса (RFC 9215 §4.2).
 *
 * <p>Паттерн использования симметричен {@link GostOcspResponseBuilder}:
 * {@code build()} возвращает {@code byte[]} DER, nonce доступен через {@link #getNonce()}.
 *
 * <pre>
 * GostOcspRequestBuilder builder = GostOcspRequestBuilder.create()
 *     .targetCert(certDer)
 *     .issuerCert(issuerDer);
 * byte[] der = builder.build();
 * byte[] nonce = builder.getNonce();
 * </pre>
 *
 * <p>С подписью:
 * <pre>
 * GostOcspRequestBuilder builder = GostOcspRequestBuilder.create()
 *     .targetCert(certDer)
 *     .issuerCert(issuerDer)
 *     .signKey(signKey)
 *     .params(ecParams);
 * byte[] der = builder.build();
 * </pre>
 *
 * <p>Multi-cert (несколько CertID в одном запросе):
 * <pre>
 * GostOcspRequestBuilder builder = GostOcspRequestBuilder.create()
 *     .targetCert(certDer1).issuerCert(issuerDer1)
 *     .addRequest(certDer2, issuerDer2);
 * byte[] der = builder.build();
 * </pre>
 *
 * <p>Размер хэша CertID: {@code .hashLen(32)} (Streebog-256, по умолчанию) или
 * {@code .hashLen(64)} (Streebog-512).
 */
public final class GostOcspRequestBuilder {

    /**
     * Пара сертификатов (проверяемый, издатель) для одного CertID.
     */
    private record CertPair(byte[] targetCert, byte[] issuerCert) {}

    private final List<CertPair> certPairs = new ArrayList<>();
    private byte[] pendingTargetCert;
    private int hashLen = GostOids.STREEBOG_256_HASH_LEN;
    private boolean hashLenSet;
    private PrivateKeyParameters signKey;
    private ECParameters params;
    private byte[] generatedNonce;

    private GostOcspRequestBuilder() {}

    /**
     * Создаёт построитель OCSP-запроса.
     */
    public static GostOcspRequestBuilder create() {
        return new GostOcspRequestBuilder();
    }

    /**
     * Проверяемый сертификат (DER).
     * Каждый вызов запоминает новый targetCert; пара образуется следующим вызовом {@link #issuerCert}.
     */
    public GostOcspRequestBuilder targetCert(byte[] certDer) {
        this.pendingTargetCert = certDer;
        return this;
    }

    /**
     * Сертификат издателя (DER).
     * Образует пару с последним {@link #targetCert} и добавляет в список запросов.
     *
     * @throws IllegalStateException если {@link #targetCert} не был задан
     */
    public GostOcspRequestBuilder issuerCert(byte[] issuerDer) {
        if (pendingTargetCert == null) {
            throw new IllegalStateException("issuerCert must follow targetCert");
        }
        this.certPairs.add(new CertPair(pendingTargetCert, issuerDer));
        this.pendingTargetCert = null;
        return this;
    }

    /**
     * Добавляет пару (проверяемый сертификат, издатель) в список запросов.
     * Атомарный метод — не зависит от состояния {@link #targetCert}/{@link #issuerCert}.
     */
    public GostOcspRequestBuilder addRequest(byte[] target, byte[] issuer) {
        this.certPairs.add(new CertPair(target, issuer));
        return this;
    }

    /**
     * Длина хэша CertID в байтах (32 = Streebog-256, 64 = Streebog-512).
     * По умолчанию 32.
     */
    public GostOcspRequestBuilder hashLen(int hlen) {
        this.hashLen = hlen;
        this.hashLenSet = true;
        return this;
    }

    /**
     * Закрытый ключ для подписи запроса. Если не задан — запрос без подписи.
     * При задании {@code signKey} поле {@code params} обязательно.
     */
    public GostOcspRequestBuilder signKey(PrivateKeyParameters key) {
        this.signKey = key;
        return this;
    }

    /**
     * Параметры эллиптической кривой для подписи (обязательно при {@link #signKey}).
     */
    public GostOcspRequestBuilder params(ECParameters params) {
        this.params = params;
        return this;
    }

    /**
     * Nonce, сгенерированный при последнем вызове {@link #build()}.
     *
     * @return 16-байтовый nonce или {@code null} если {@code build()} ещё не вызывался
     * @throws IllegalStateException если {@code build()} ещё не вызывался
     */
    public byte[] getNonce() {
        if (generatedNonce == null) {
            throw new IllegalStateException("getNonce() must be called after build()");
        }
        return generatedNonce.clone();
    }

    /**
     * Собирает OCSPRequest (RFC 6960 §4.1).
     *
     * @return DER-кодированный OCSPRequest
     */
    public byte[] build() {
        if (pendingTargetCert != null) {
            throw new IllegalStateException("targetCert set but issuerCert not called");
        }
        if (certPairs.isEmpty()) {
            throw new IllegalStateException("at least one cert/issuer pair must be set");
        }

        int certIdHashLen = resolveCertIdHashLen();
        generatedNonce = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(generatedNonce);

        try {
            TbsRequestData data = buildTbsRequestData(certPairs, certIdHashLen, generatedNonce);
            byte[] tbsDer = data.tbsDer();

            if (signKey != null) {
                return buildSignedRequest(tbsDer, signKey, params);
            }
            return DerCodec.encodeSequence(tbsDer);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build OCSPRequest", e);
        }
    }

    /**
     * Определяет длину хэша CertID с учётом валидации.
     */
    private int resolveCertIdHashLen() {
        if (signKey != null) {
            if (params == null) {
                throw new IllegalStateException("params must be set when signKey is provided");
            }
            if (hashLenSet && hashLen != params.hlen) {
                throw new IllegalStateException(
                        "hashLen (" + hashLen + ") must match params.hlen (" + params.hlen + ")");
            }
            return params.hlen;
        }
        return hashLen;
    }

    /**
     * Промежуточный результат построения TBSRequest.
     */
    private record TbsRequestData(byte[] tbsDer) {}

    /**
     * Строит сырой DER TBSRequest (RFC 6960 §4.1.1) с nonce-расширением.
     */
    private static TbsRequestData buildTbsRequestData(
            List<CertPair> pairs, int hlen, byte[] nonce) {
        ByteArrayOutputStream rlOut = new ByteArrayOutputStream();
        try {
            for (CertPair pair : pairs) {
                byte[] certId = buildCertId(pair.targetCert(), pair.issuerCert(), hlen);
                rlOut.write(DerCodec.encodeSequence(certId));
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException("Unexpected IOException from ByteArrayOutputStream", e);
        }
        byte[] requestList = DerCodec.encodeSequence(rlOut.toByteArray());
        byte[] nonceExt = buildNonceExtension(nonce);
        byte[] extensions = DerCodec.encodeSequence(nonceExt);
        byte[] requestExtensions = DerCodec.encodeContextConstructed(2, extensions);

        byte[] tbsRequestContent = DerCodec.concat(requestList, requestExtensions);
        byte[] tbsRequest = DerCodec.encodeSequence(tbsRequestContent);
        return new TbsRequestData(tbsRequest);
    }

    /**
     * Строит Extension с id-pkix-ocsp-nonce.
     */
    private static byte[] buildNonceExtension(byte[] nonce) {
        byte[] oid = DerCodec.encodeOid(GostOids.OCSP_NONCE);
        byte[] value = DerCodec.encodeOctetString(nonce);
        return DerCodec.encodeSequence(oid, value);
    }

    /**
     * CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
     */
    private static byte[] buildCertId(byte[] certDer, byte[] issuerDer, int hlen) {
        byte[] issuerNameHash = CertIdHasher.hashIssuerName(issuerDer, hlen);
        byte[] issuerKeyHash = CertIdHasher.hashIssuerPublicKey(issuerDer, hlen);

        byte[] hashAlg = buildStreebogAlgorithmId(hlen);
        byte[] nameHash = DerCodec.encodeOctetString(issuerNameHash);
        byte[] keyHash = DerCodec.encodeOctetString(issuerKeyHash);
        byte[] serial = extractSerialTlv(certDer);

        return DerCodec.encodeSequence(hashAlg, nameHash, keyHash, serial);
    }

    /**
     * Извлекает полный TLV serialNumber (включая 02 LL) для bit-exact копирования.
     */
    private static byte[] extractSerialTlv(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        int tlvStart = pos;
        int[] serialTlv = GostDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, tlvStart, serialTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = GostDerParser.readTlv(der, 0);
        int[] tbsTlv = GostDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    /**
     * AlgorithmIdentifier для хэш-алгоритма CertID: SEQUENCE { OID, NULL }
     */
    private static byte[] buildStreebogAlgorithmId(int hlen) {
        String digestOid =
                hlen == GostOids.STREEBOG_512_HASH_LEN ? GostOids.DIGEST_512 : GostOids.DIGEST_256;
        return DerCodec.encodeSequence(DerCodec.encodeOid(digestOid), DerCodec.encodeNull());
    }

    /**
     * Строит запрос с подписью (RFC 9215 §4.2).
     */
    private static byte[] buildSignedRequest(
            byte[] tbsDer, PrivateKeyParameters signKey, ECParameters params) {
        int hlen = params.hlen;

        byte[] hash = GostSignatureHelper.doHash(tbsDer, hlen);
        byte[] sig = Signature.signHash(hash, signKey);

        byte[] sigAlg = GostSignatureHelper.buildAlgId(params);
        byte[] signature = DerCodec.encodeSequence(sigAlg, DerCodec.encodeBitString(sig));
        byte[] optSig = DerCodec.encodeContextConstructed(0, signature);
        return DerCodec.encodeSequence(tbsDer, optSig);
    }
}
