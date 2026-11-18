package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.util.FuzzTestUtils;

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
 * долетают как {@code RuntimeException} — их {@code FuzzTestUtils.rethrowIfBug}
 * перебрасывает как баги.
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
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
