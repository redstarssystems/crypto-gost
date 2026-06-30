package org.rssys.gost.jsse.ocsp;

import org.rssys.gost.pkix.cert.GostOcspRequestBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Построитель DER-закодированного OCSPRequest (RFC 6960 §4.1) с поддержкой nonce (RFC 8954).
 *
 * <p>Делегирует построение DER в {@link GostOcspRequestBuilder} из модуля pkix.
 *
 * <p>Fluent API:
 * <pre>
 * OcspRequest req = OcspRequestBuilder.create()
 *     .targetCert(certDer)
 *     .issuerCert(issuerDer)
 *     .build();
 * </pre>
 *
 * <p>С подписью:
 * <pre>
 * OcspRequest req = OcspRequestBuilder.create()
 *     .targetCert(certDer)
 *     .issuerCert(issuerDer)
 *     .signKey(signKey)
 *     .params(ecParams)
 *     .build();
 * </pre>
 *
 * <p>Размер хэша CertID: {@code .hashLen(32)} (Streebog-256, по умолчанию) или
 * {@code .hashLen(64)} (Streebog-512).
 */
public final class OcspRequestBuilder {

    private byte[] targetCert;
    private byte[] issuerCert;
    private int hashLen = TlsConstants.STREEBOG_256_HASH_LEN;
    private PrivateKeyParameters signKey;
    private ECParameters params;

    private OcspRequestBuilder() {}

    /**
     * Создаёт построитель OCSP-запроса.
     */
    public static OcspRequestBuilder create() {
        return new OcspRequestBuilder();
    }

    /**
     * Проверяемый сертификат (DER).
     */
    public OcspRequestBuilder targetCert(byte[] certDer) {
        this.targetCert = certDer;
        return this;
    }

    /**
     * Сертификат издателя (DER).
     */
    public OcspRequestBuilder issuerCert(byte[] issuerDer) {
        this.issuerCert = issuerDer;
        return this;
    }

    /**
     * Длина хэша CertID в байтах (32 = Streebog-256, 64 = Streebog-512).
     * По умолчанию 32. При наличии {@link #signKey} приоритет имеет {@code params.hlen}.
     */
    public OcspRequestBuilder hashLen(int hlen) {
        this.hashLen = hlen;
        return this;
    }

    /**
     * Закрытый ключ для подписи запроса. Если не задан — запрос без подписи.
     */
    public OcspRequestBuilder signKey(PrivateKeyParameters key) {
        this.signKey = key;
        return this;
    }

    /**
     * Параметры эллиптической кривой для подписи (только с {@link #signKey}).
     */
    public OcspRequestBuilder params(ECParameters params) {
        this.params = params;
        return this;
    }

    /**
     * Собирает OCSPRequest (RFC 6960 §4.1). Делегирует в {@link GostOcspRequestBuilder}.
     *
     * @return OcspRequest с DER-байтами и nonce
     */
    public OcspRequest build() {
        if (targetCert == null) throw new IllegalStateException("targetCert must be set");
        if (issuerCert == null) throw new IllegalStateException("issuerCert must be set");

        GostOcspRequestBuilder pkixBuilder =
                GostOcspRequestBuilder.create().targetCert(targetCert).issuerCert(issuerCert);

        if (signKey != null) {
            pkixBuilder.signKey(signKey).params(params);
        } else {
            pkixBuilder.hashLen(hashLen);
        }

        byte[] der = pkixBuilder.build();
        byte[] nonce = pkixBuilder.getNonce();
        return new OcspRequest(der, nonce);
    }
}
