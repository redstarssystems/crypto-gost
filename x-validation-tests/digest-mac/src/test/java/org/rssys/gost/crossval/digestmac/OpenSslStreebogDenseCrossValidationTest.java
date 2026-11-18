package org.rssys.gost.crossval.digestmac;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация Стрибога против OpenSSL на разреженном наборе длин, но на всех трёх наборах
 * данных, включая «все 0xFF».
 *
 * OpenSSL — единственный эталон, не выведенный из BouncyCastle, поэтому перенос в сумме блоков
 * проверяется и на нём. Каждый вызов — отдельный процесс, поэтому длины разрежены, а вход цельный:
 * буферизацию покрывает плотный тест против BC.
 */
class OpenSslStreebogDenseCrossValidationTest {

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeStreebog();
    }

    static Stream<Integer> sparseLengths() {
        return Arrays.stream(StreebogInputs.SPARSE_LENGTHS).boxed();
    }

    @ParameterizedTest(name = "длина {0}")
    @MethodSource("sparseLengths")
    @DisplayName("OpenSSL: Стрибог-256 и -512, три набора данных, длина {0}")
    void digestMatchesOpenSsl(int length) throws Exception {
        for (StreebogInputs.Pattern pattern : StreebogInputs.Pattern.values()) {
            byte[] data = StreebogInputs.data(pattern, length);
            for (int sizeBits : new int[]{256, 512}) {
                Digest digest = sizeBits == 256 ? new Streebog256() : new Streebog512();
                digest.update(data, 0, data.length);
                byte[] expected = new byte[digest.getDigestSize()];
                digest.doFinal(expected, 0);
                byte[] actual = sizeBits == 256
                        ? OpenSslMacHelper.opensslDgst256(data)
                        : OpenSslMacHelper.opensslDgst512(data);
                assertArrayEquals(expected, actual,
                        () -> "Несовпадение с OpenSSL: размер=" + sizeBits + " набор=" + pattern
                                + " длина=" + length + " " + CrossValUtils.diffContext(expected, actual));
            }
        }
    }
}
