package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz-тест для {@link GostCsrParser#fromDer}.
 * <p>
 * CSR-парсер принимает недоверенные DER-байты из сети (PKCS#10).
 * Внутри: {@code new GostCsrParser(der)} -> {@code parseCsr()} ->
 * {@code GostDerParser.readTlv/parseSequence/parseTime} без проверки границ.
 * <p>
 * ПОЧЕМУ ловим RuntimeException: конструктор не валидирует границы
 * DER-массива. На битом DER может выбросить любое непроверяемое исключение
 * (AIOOBE, IllegalArgumentException), как документировано в Javadoc класса.
 * <p>
 * ПОЧЕМУ rethrowIfBug локально, а не import из org.rssys.gost.util:
 * crypto-gost-core не публикует test-jar — кросс-модульный импорт невозможен.
 */
class GostCsrParserFuzzTest {

    @FuzzTest
    void fuzzParseCsr(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            GostCsrParser.fromDer(der);
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
