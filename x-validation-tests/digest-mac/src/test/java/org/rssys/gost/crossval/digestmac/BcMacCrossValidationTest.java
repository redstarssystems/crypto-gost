package org.rssys.gost.crossval.digestmac;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.CrossValUtils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация хэшей и MAC: crypto-gost vs BouncyCastle.
 *
 * Для каждого размера из SIZES и каждого алгоритма:
 * обе библиотеки вычисляют хэш/MAC на одних и тех же данных,
 * затем результаты сравниваются.
 * Ключи для HMAC/CMAC фиксированные (32 байта).
 */
class BcMacCrossValidationTest {

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.digestmac.TestData#macParams")
    @DisplayName("BC-кросс-валидация MAC/хэш: {0} size={1}")
    void crossValidate(TestData.Algo algo, int size) {
        byte[] data = TestData.msg(size);
        byte[] key  = algo.needKey() ? TestData.testKey() : null;

        String keyHex = key != null ? " key=" + CrossValUtils.toHex(key) : "";
        byte[] expected = TestData.computeGost(algo, key, data);
        byte[] actual   = TestData.computeBc(algo, key, data);

        assertArrayEquals(expected, actual,
                () -> "Несовпадение с BC: algo=" + algo + " size=" + size
                        + " " + CrossValUtils.diffContext(expected, actual) + keyHex);
    }
}
