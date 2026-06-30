package org.rssys.gost.jca.spec;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.rssys.gost.util.FuzzTestUtils;

/**
 * Fuzz-тесты для {@link GostDerCodec}.
 * <p>
 * Проверяет напрямую {@link GostDerCodec#decodePublicKey}, {@link GostDerCodec#decodePrivateKey}
 * и {@link GostDerCodec#checkNotMasked} без обёртки через JCA KeyFactory SPI.
 * <p>
 * ПОЧЕМУ отдельно от {@code GostKeyFactorySpiFuzzTest}: GostKeyFactorySpi использует
 * {@code catch (Exception e)}, который перехватывает NPE/AIOOBE из GostDerCodec/DerCodec
 * и заворачивает в InvalidKeySpecException. Фаззер не видит эти баги. Прямой вызов
 * GostDerCodec.* без SPI-обёртки позволяет Jazzer детектировать их.
 */
class GostDerCodecFuzzTest {

    /**
     * Декодирует открытый ключ из произвольных DER-байт SubjectPublicKeyInfo.
     * {@link GostDerCodec#decodePublicKey} вызывает {@code DerCodec.parseSequenceContents},
     * {@code DerCodec.parseBitString}, {@code DerCodec.parseOctetString} и
     * {@code GostCurves.byName} — все на недоверенном входе.
     */
    @FuzzTest
    void fuzzDecodePublicKey(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostDerCodec.decodePublicKey(input);
        } catch (IllegalArgumentException e) {
            // Ожидаемо для битого DER — неверная структура, неизвестная кривая
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Декодирует закрытый ключ из произвольных DER-байт PrivateKeyInfo.
     * Вызывает тот же стек: {@code DerCodec.parseSequenceContents} ->
     * {@code DerCodec.parseOid} -> {@code DerCodec.parseOctetString}.
     */
    @FuzzTest
    void fuzzDecodePrivateKey(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostDerCodec.decodePrivateKey(input);
        } catch (IllegalArgumentException e) {
            // Ожидаемо для битого DER
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }

    /**
     * Проверяет, что ключ не замаскирован, из произвольных DER-байт.
     * Вызывает {@code DerCodec.parseSequenceContents} + {@code DerCodec.parseOctetString}.
     * Может бросить {@code UnsupportedOperationException} на маскированном ключе.
     */
    @FuzzTest
    void fuzzCheckNotMasked(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        try {
            GostDerCodec.checkNotMasked(input);
        } catch (IllegalArgumentException | UnsupportedOperationException e) {
            // Ожидаемо для битого DER или маскированного ключа
        } catch (RuntimeException e) {
            FuzzTestUtils.rethrowIfBug(e);
        }
    }
}
