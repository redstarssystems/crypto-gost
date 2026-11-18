package org.rssys.gost.pkix.cert;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.pkix.util.FuzzTestUtils;

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
 */
class GostCsrParserFuzzTest {

    @FuzzTest
    void fuzzParseCsr(FuzzedDataProvider data) {
        byte[] der = data.consumeRemainingAsBytes();
        if (der.length == 0) return;
        try {
            GostCsrParser.fromDer(der);
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
