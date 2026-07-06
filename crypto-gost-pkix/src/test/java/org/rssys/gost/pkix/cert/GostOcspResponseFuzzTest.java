package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тест для {@link GostOcspResponse#GostOcspResponse(byte[])}.
 *
 * <p>Конструктор OCSP-ответа принимает полностью недоверенные DER-байты из сети (RFC 6960).
 * Внутри: {@code parseSequence}, {@code readTlv}, парсинг ENUMERATED responseStatus,
 * BasicOCSPResponse, tbsResponseData, SingleResponse, nonce, delegatedCertificates —
 * весь стек через {@code GostDerParser} с прямым доступом к массиву.</p>
 *
 * <p>Проверяет DoS-фиксы 0.6.2:
 * <ul>
 *   <li>{@code MAX_OCSP_RESPONSE_SIZE} = 256 КБ — размер DER до парсинга</li>
 *   <li>ENUMERATED responseStatus &le; 1 байт — CPU DoS через побитовый сдвиг</li>
 *   <li>{@code MAX_SINGLE_RESPONSES} = 256 — DoS через неограниченные SingleResponse</li>
 *   <li>Non-canonical constructed тег good-статуса {@code 0xA0} — DER malleability</li>
 * </ul>
 *
 * <p>Конструктор оборачивает {@code IllegalArgumentException | ArrayIndexOutOfBoundsException}
 * в {@code PkixException("Malformed OCSP response DER")} — ожидаемая реакция на битый DER.
 * {@code PkixException} — fail-closed, ожидаемо. AIOOBE / NPE — баг.</p>
 */
class GostOcspResponseFuzzTest {

    @FuzzTest
    void fuzzConstructor(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            new GostOcspResponse(der);
        } catch (PkixException e) {
            // Ожидаемо: битый DER, структурная ошибка, превышение лимитов
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверный тег, выход за границы структуры
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Проверяет {@link GostOcspResponse#getNonce()} на распарсенном ответе.
     * Nonce извлекается через единый парсер (0.6.2 — устранение дублирующего парсера).
     */
    @FuzzTest
    void fuzzGetNonce(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        GostOcspResponse resp;
        try {
            resp = new GostOcspResponse(der);
        } catch (PkixException | IllegalArgumentException e) {
            return;
        } catch (RuntimeException e) {
            rethrowIfBug(e);
            return;
        }
        try {
            resp.getNonce();
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
