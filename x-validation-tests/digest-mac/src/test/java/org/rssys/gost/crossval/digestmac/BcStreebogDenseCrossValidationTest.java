package org.rssys.gost.crossval.digestmac;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;

import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Плотная кросс-валидация Стрибога против BouncyCastle: все длины 0..300 и окрестности границ
 * блока, три набора данных, разные способы подачи входа.
 *
 * Эталон BC всегда считается цельным, поэтому каждый способ подачи на стороне crypto-gost
 * (по одному байту, кусками, с пустыми вызовами) проверяет буферизацию. Один и тот же объект
 * Digest переиспользуется для всех подач, а между ними иногда вызывается destroy() посреди потока:
 * остаток состояния от прежнего сообщения дал бы расхождение.
 */
class BcStreebogDenseCrossValidationTest {

    private static final int[] CHUNK_SIZES = {1, 17, 53, 64};
    private static final int[] HMAC_MESSAGE_LENGTHS = {0, 1, 63, 64, 65, 200};

    static Stream<Integer> denseLengths() {
        return Arrays.stream(StreebogInputs.DENSE_LENGTHS).boxed();
    }

    static Stream<Integer> hmacKeyLengths() {
        return Arrays.stream(StreebogInputs.HMAC_KEY_LENGTHS).boxed();
    }

    private static Digest newDigest(int sizeBits) {
        return sizeBits == 256 ? new Streebog256() : new Streebog512();
    }

    private static byte[] bc(int sizeBits, byte[] data) {
        return sizeBits == 256 ? BcMacHelper.bcDigest256(data) : BcMacHelper.bcDigest512(data);
    }

    private static byte[] finish(Digest digest) {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    @ParameterizedTest(name = "длина {0}")
    @MethodSource("denseLengths")
    @DisplayName("BC: Стрибог-256 и -512, все наборы и способы подачи, длина {0}")
    void digestMatchesBc(int length) {
        for (int sizeBits : new int[]{256, 512}) {
            Digest reused = newDigest(sizeBits);
            for (StreebogInputs.Pattern pattern : StreebogInputs.Pattern.values()) {
                byte[] data = StreebogInputs.data(pattern, length);
                byte[] expected = bc(sizeBits, data);
                String where = "размер=" + sizeBits + " набор=" + pattern + " длина=" + length;

                // Остаток от «чужого» сообщения: destroy() посреди потока обязан его стереть.
                reused.update(data, 0, Math.min(length, 70));
                reused.update((byte) 0x7E);
                reused.destroy();

                reused.update(data, 0, length);
                assertSame(expected, finish(reused), "цельный вход, " + where);

                for (byte b : data) {
                    reused.update(b);
                }
                assertSame(expected, finish(reused), "побайтно, " + where);

                for (int chunk : CHUNK_SIZES) {
                    for (int offset = 0; offset < length; offset += chunk) {
                        reused.update(data, offset, Math.min(chunk, length - offset));
                    }
                    assertSame(expected, finish(reused), "куски по " + chunk + ", " + where);
                }

                reused.update(data, 0, 0);
                reused.update(data, 0, length / 2);
                reused.update(data, length / 2, 0);
                reused.update(data, length / 2, length - length / 2);
                assertSame(expected, finish(reused), "с пустыми вызовами, " + where);
            }
        }
    }

    @ParameterizedTest(name = "ключ {0} байт")
    @MethodSource("hmacKeyLengths")
    @DisplayName("BC: HMAC-Стрибог-256 и -512 с ключом {0} байт (в том числе длиннее блока)")
    void hmacMatchesBc(int keyLength) {
        byte[] key = StreebogInputs.data(StreebogInputs.Pattern.PSEUDO, keyLength);
        for (int size : new int[]{256, 512}) {
            Hmac hmac = new Hmac(newDigest(size));
            for (int messageLength : HMAC_MESSAGE_LENGTHS) {
                byte[] message = StreebogInputs.data(StreebogInputs.Pattern.COUNTER, messageLength);
                hmac.init(key);
                hmac.update(message, 0, message.length);
                byte[] actual = new byte[hmac.getMacSize()];
                hmac.doFinal(actual, 0);
                byte[] expected = size == 256
                        ? BcMacHelper.bcHmac256(key, message)
                        : BcMacHelper.bcHmac512(key, message);
                assertSame(expected, actual,
                        "HMAC размер=" + size + " ключ=" + keyLength + " сообщение=" + messageLength);
            }
        }
    }

    private static void assertSame(byte[] expected, byte[] actual, String where) {
        assertArrayEquals(expected, actual,
                () -> "Несовпадение с BC: " + where + " " + CrossValUtils.diffContext(expected, actual));
    }
}
