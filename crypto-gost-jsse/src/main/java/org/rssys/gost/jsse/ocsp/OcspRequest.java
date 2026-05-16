package org.rssys.gost.jsse.ocsp;

/**
 * Результат сборки OCSP-запроса с nonce (RFC 8954).
 *
 * @param der   DER-encoded OCSPRequest
 * @param nonce случайный nonce (16 байт) для проверки в ответе
 */
public record OcspRequest(byte[] der, byte[] nonce) {
}
