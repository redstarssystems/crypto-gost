package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тест для {@link GostOcspRequest#fromDer}.
 *
 * <p>Парсер OCSP-запроса принимает недоверенные DER-байты из сети (RFC 6960 §4.1).
 * Внутри: {@code GostOcspRequest(der)} -> {@code parseSequence/readTlv/parseCertId/parseNonce}
 * — все статические методы {@code GostDerParser} с прямым доступом к массиву без проверки границ.
 *
 * <p>Конструктор оборачивает {@code IllegalArgumentException | ArrayIndexOutOfBoundsException}
 * в {@code PkixException("Malformed OCSP request DER")} — это ожидаемая реакция на битый DER.
 * {@code NullPointerException} и {@code NegativeArraySizeException} не оборачиваются и
 * долетают как {@code RuntimeException} — их {@code rethrowIfBug} перебрасывает как баги.
 *
 * <p>ПОЧЕМУ rethrowIfBug локально, а не import из другого модуля:
 * crypto-gost-core не публикует test-jar — кросс-модульный импорт невозможен.
 */
class GostOcspRequestFuzzTest {

    @FuzzTest
    void fuzzFromDer(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            GostOcspRequest.fromDer(der);
        } catch (PkixException e) {
            // Ожидаемо: битый DER, структурная ошибка
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Перебрасывает RuntimeException, если это баг (AIOOBE, NPE,
     * NegativeArraySizeException). Иначе — проглатывает.
     */
    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException) {
            throw e;
        }
    }
}
