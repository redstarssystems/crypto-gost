package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тест для {@link GostCrl#GostCrl(byte[])}.
 *
 * <p>Конструктор принимает недоверенные DER-байты из сети (CRL, RFC 5280 §5).
 * Внутри: ~15 вызовов {@code GostDerParser.readTlv/parseSequence/parseTime}
 * и прямых обращений к массиву без проверки границ.
 *
 * <p>ПОЧЕМУ прямой фаззинг конструктора, а не через {@link CrlVerifier}:
 * {@code CrlVerifier.verify()} оборачивает {@code new GostCrl(der)} в
 * {@code catch (RuntimeException e) -> PkixException}. AIOOBE из конструктора
 * поглощается и до Jazzer не долетает.
 *
 * <p>ПОЧЕМУ нет метода fuzzVerify: fail-closed инвариант проверяет подпись
 * до парсинга revoked-списка. {@code PublicKeyParameters} из фаззера не построить —
 * подпись всегда невалидна, до revoked-зоны управление не доходит.
 *
 * <p>ПОЧЕМУ rethrowIfBug локально, а не import из другого модуля:
 * crypto-gost-core не публикует test-jar — кросс-модульный импорт невозможен.
 */
class GostCrlFuzzTest {

    @FuzzTest
    void fuzzConstructor(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            new GostCrl(der);
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
