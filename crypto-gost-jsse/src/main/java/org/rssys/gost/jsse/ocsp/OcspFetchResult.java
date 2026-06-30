package org.rssys.gost.jsse.ocsp;

/**
 * Результат OCSP-запроса с опциональным nonce (RFC 8954).
 *
 * @param response DER-encoded OCSPResponse (null при ошибке)
 * @param nonce    nonce из запроса (null если nonce не использовался)
 */
public record OcspFetchResult(byte[] response, byte[] nonce) {}
