package org.rssys.gost.signature;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link SignatureCodec#decode}.
 * <p>
 * ПОЧЕМУ напрямую, а не через {@code GostSignatureSpi.engineVerify}:
 * GostSignatureSpi использует {@code catch (Exception e)} в engineVerify,
 * который маскирует NPE/AIOOBE из SignatureCodec.decode (аналогично
 * GostKeyFactorySpi). Прямой фаззинг decode позволяет Jazzer детектировать
 * баги в разборе подписи.
 */
class SignatureCodecFuzzTest {

    private static final ECParameters PARAMS_256 = ECParameters.cryptoProA();
    private static final ECParameters PARAMS_512 = ECParameters.tc26a512();

    /**
     * Декодирует подпись с 256-битными параметрами (ожидаемая длина 64 байта).
     * {@link SignatureCodec#decode} проверяет длину и вызывает
     * {@code Arrays.copyOfRange} — потенциальный AIOOBE при битом входе.
     */
    @FuzzTest
    void fuzzDecode256(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            SignatureCodec.decode(input, PARAMS_256);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверная длина подписи (должна быть 64 байта)
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Декодирует подпись с 512-битными параметрами (ожидаемая длина 128 байт).
     */
    @FuzzTest
    void fuzzDecode512(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            SignatureCodec.decode(input, PARAMS_512);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: неверная длина подписи (должна быть 128 байт)
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
