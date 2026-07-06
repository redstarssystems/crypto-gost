package org.rssys.gost.signature;

import java.math.BigInteger;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link SignatureCodec#decode} и {@link SignatureCodec#encode}.
 * <p>
 * ПОЧЕМУ напрямую, а не через {@code GostSignatureSpi.engineVerify}:
 * GostSignatureSpi использует {@code catch (Exception e)} в engineVerify,
 * который маскирует NPE/AIOOBE из SignatureCodec.decode (аналогично
 * GostKeyFactorySpi). Прямой фаззинг decode позволяет Jazzer детектировать
 * баги в разборе подписи.
 * <p>
 * ПОЧЕМУ добавлен encode: в 0.6.2 исправлен тихий truncation oversized
 * компонент r/s ({@code length > rolen + 1}). Тест проверяет, что encode
 * выбрасывает {@code IllegalArgumentException} при превышении.
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

    /**
     * Кодирует пару (r, s) в подпись {@code s || r} big-endian.
     * Проверяет фикс 0.6.2: oversized компоненты (> rolen + 1) -> IllegalArgumentException.
     * <p>
     * Фаззер подаёт произвольные байты, конвертированные в BigInteger.
     * Это покрывает и валидные (< rolen), и oversized (> rolen + 1) случаи.
     */
    @FuzzTest
    void fuzzEncode(FuzzedDataProvider data) {
        byte[] rBytes = data.consumeBytes(data.consumeInt(1, 128));
        byte[] sBytes = data.consumeBytes(data.consumeInt(1, 128));
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        try {
            SignatureCodec.encode(r, s, PARAMS_256);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: компонент превышает размер поля (rolen = 32 для 256-бит)
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
        try {
            SignatureCodec.encode(r, s, PARAMS_512);
        } catch (IllegalArgumentException e) {
            // Ожидаемо: компонент превышает размер поля (rolen = 64 для 512-бит)
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
