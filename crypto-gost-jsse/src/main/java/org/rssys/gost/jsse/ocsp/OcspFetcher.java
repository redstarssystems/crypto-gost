package org.rssys.gost.jsse.ocsp;

/**
 * Интерфейс для OCSP-запросов.
 * <p>
 * Фазы 1-4: OCSP-степплинг предоставляется вручную через конфигурацию.
 * Фаза 5: дефолтная реализация на JDK HttpClient.
 */
public interface OcspFetcher {

    /**
     * Запрашивает OCSP-ответ для сертификата.
     *
     * @param certDer     DER-encoded сертификат
     * @param issuerDer   DER-encoded сертификат issuer'а
     * @param ocspResponderUri URI OCSP-responder (из AIA-расширения сертификата)
     * @return raw DER-encoded OCSPResponse или null при ошибке
     */
    byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri);

    /**
     * Запрашивает OCSP-ответ с nonce (RFC 8954).
     * <p>
     * Дефолтная реализация вызывает {@link #fetch(byte[], byte[], String)}
     * и возвращает nonce=null. Реализации, поддерживающие nonce, должны
     * переопределить этот метод.
     *
     * @param certDer     DER-encoded сертификат
     * @param issuerDer   DER-encoded сертификат issuer'а
     * @param ocspResponderUri URI OCSP-responder
     * @return OcspFetchResult с OCSP-ответом и nonce
     */
    default OcspFetchResult fetchWithNonce(
            byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
        return new OcspFetchResult(fetch(certDer, issuerDer, ocspResponderUri), null);
    }
}
