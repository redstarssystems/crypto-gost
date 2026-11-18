package org.rssys.gost.jsse.ocsp;

/**
 * Результат сборки OCSP-запроса с nonce (RFC 8954).
 *
 * @param der   DER-encoded OCSPRequest
 * @param nonce сырые байты nonce для проверки в ответе (билдер генерирует 32 байта)
 */
public record OcspRequest(byte[] der, byte[] nonce) {}
