package org.rssys.gost.pkix.tsp;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.cert.PkixException;

/**
 * Fuzz-тесты для {@link TspResponse}.
 *
 * <p>{@code TspResponse.parse()} принимает недоверенный сетевой ввод (TimeStampResp DER),
 * {@code TspResponse.parseTimeStampToken()} — встроенный TimeStampToken из unsignedAttrs
 * CAdES-T подписи. Оба парсят глубоко вложенные ASN.1-структуры без защитных проверок
 * на каждом уровне.
 *
 * <p>ПОЧЕМУ два метода: {@code parse()} и {@code parseTimeStampToken()} парсят разные
 * ASN.1-структуры (TimeStampResp с PKIStatusInfo vs TimeStampToken = CMS SignedData
 * напрямую) — разные кодовые пути.
 *
 * <p>ПОЧЕМУ rethrowIfBug локально: пакет {@code tsp} не видит package-private
 * {@code FuzzTestUtils} из {@code cms}.
 */
class TspResponseFuzzTest {

    @FuzzTest
    void fuzzParseTspResponse(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            TspResponse.fromDer(der);
        } catch (PkixException e) {
            // ожидаемо: битый DER, неверная структура
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    @FuzzTest
    void fuzzParseTimeStampToken(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            TspResponse.parseTimeStampToken(der);
        } catch (PkixException e) {
            // ожидаемо: битый DER, неверная структура
        } catch (RuntimeException e) {
            rethrowIfBug(e);
        }
    }

    /**
     * Перебрасывает RuntimeException, если это баг (AIOOBE, NPE,
     * NegativeArraySizeException, IndexOutOfBoundsException,
     * ClassCastException, ArithmeticException, BufferOverflowException).
     * Иначе — проглатывает (ожидаемо для DER-парсинга на битом входе).
     */
    private static void rethrowIfBug(RuntimeException e) {
        if (e instanceof ArrayIndexOutOfBoundsException
                || e instanceof IndexOutOfBoundsException
                || e instanceof NegativeArraySizeException
                || e instanceof NullPointerException
                || e instanceof ClassCastException
                || e instanceof ArithmeticException
                || e instanceof java.nio.BufferOverflowException) {
            throw e;
        }
    }
}
