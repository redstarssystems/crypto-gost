package org.rssys.gost.crossval.digestmac;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация хэшей и MAC: crypto-gost vs OpenSSL (GOST-провайдер).
 *
 * Тест пропускается, если OpenSSL недоступен или собран без поддержки
 * Streebog и CMAC-Kuznyechik.
 */
class OpenSslMacCrossValidationTest {

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeStreebog();
        OpenSslChecker.assumeCmacKuznyechik();
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.digestmac.TestData#macParams")
    @DisplayName("OpenSSL-кросс-валидация MAC/хэш: {0} size={1}")
    void crossValidate(TestData.Algo algo, int size) {
        byte[] data = TestData.msg(size);
        byte[] key  = algo.needKey() ? TestData.testKey() : null;

        String keyHex = key != null ? " key=" + CrossValUtils.toHex(key) : "";
        byte[] expected = TestData.computeGost(algo, key, data);
        try {
            byte[] actual = computeOpenSsl(algo, key, data);
            assertArrayEquals(expected, actual,
                    () -> "Несовпадение с OpenSSL: algo=" + algo + " size=" + size
                            + " " + CrossValUtils.diffContext(expected, actual) + keyHex);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Исключение при вычислении OpenSSL: algo=" + algo + " size=" + size, e);
        }
    }

    private static byte[] computeOpenSsl(TestData.Algo algo, byte[] key, byte[] data) throws Exception {
        switch (algo) {
            case STREEBOG256: return OpenSslMacHelper.opensslDgst256(data);
            case STREEBOG512: return OpenSslMacHelper.opensslDgst512(data);
            case HMAC256:     return OpenSslMacHelper.opensslHmac256(key, data);
            case HMAC512:     return OpenSslMacHelper.opensslHmac512(key, data);
            case CMAC:        return OpenSslMacHelper.opensslCmac(key, data);
            default: throw new IllegalArgumentException("Неизвестный алгоритм: " + algo);
        }
    }
}
