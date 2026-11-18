package org.rssys.gost.digest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Тесты хэш-функции Стрибог (ГОСТ Р 34.11-2012): буферизация, способы подачи входа, повторное
 * использование объекта, границы аргументов и сложение по модулю 2⁵¹².
 *
 * <p>Эталоны RFC 6986 §10 лежат в {@code HMacTest}. Замороженные значения сняты с реализации до
 * перехода на слова {@code long} и подтверждены кросс-валидацией с BouncyCastle и OpenSSL
 * ({@code x-validation-tests/digest-mac}).
 */
@DisplayName("Стрибог: буферизация, подача входа, сложение по модулю 2^512")
class StreebogTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String FROZEN_RESOURCE = "streebog-frozen.txt";
    private static final String ALL_LENGTHS = "ALL";
    private static final int MAX_FROZEN_LENGTH = 300;
    private static final int WORD_COUNT = 8;
    private static final int[] CHUNK_SIZES = {1, 17, 53, 64};
    private static final int[] BOUNDARY_LENGTHS = {0, 1, 17, 53, 63, 64, 65, 127, 128, 129, 300};

    /** Наборы данных: счётчик, псевдослучайный и все 0xFF (проверка переноса в сумме блоков). */
    private enum Pattern {
        COUNTER,
        PSEUDO,
        FF;

        byte[] data(int length) {
            byte[] data = new byte[length];
            switch (this) {
                case COUNTER:
                    for (int i = 0; i < length; i++) {
                        data[i] = (byte) i;
                    }
                    break;
                case FF:
                    Arrays.fill(data, (byte) 0xFF);
                    break;
                default:
                    // xorshift64 с фиксированным зерном: значения не зависят от версии JDK.
                    long state = 0x9E3779B97F4A7C15L;
                    for (int i = 0; i < length; i++) {
                        state ^= state << 13;
                        state ^= state >>> 7;
                        state ^= state << 17;
                        data[i] = (byte) (state >>> 32);
                    }
            }
            return data;
        }
    }

    private static Digest newDigest(int sizeBits) {
        return sizeBits == 256 ? new Streebog256() : new Streebog512();
    }

    private static byte[] hashAtOnce(int sizeBits, byte[] data) {
        Digest digest = newDigest(sizeBits);
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    // =========================================================================
    // Замороженные эталоны
    // =========================================================================

    private record Frozen(int sizeBits, Pattern pattern, String length, String hex) {
        @Override
        public String toString() {
            return sizeBits + " " + pattern + " " + length;
        }
    }

    private static Stream<Frozen> frozenVectors() throws IOException {
        List<Frozen> result = new ArrayList<>();
        try (InputStream in = StreebogTest.class.getResourceAsStream(FROZEN_RESOURCE)) {
            if (in == null) {
                throw new IOException("Не найден ресурс " + FROZEN_RESOURCE);
            }
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.trim().split(" ");
                result.add(
                        new Frozen(
                                Integer.parseInt(fields[0]),
                                Pattern.valueOf(fields[1]),
                                fields[2],
                                fields[3]));
            }
        }
        return result.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("frozenVectors")
    @DisplayName("Замороженный эталон: хэш совпадает с прежней реализацией")
    void frozenVectorsMatch(Frozen vector) throws IOException {
        byte[] actual;
        if (ALL_LENGTHS.equals(vector.length())) {
            // Сводный эталон: хэши длин 0..300 подряд склеены и захэшированы ещё раз. Он покрывает
            // все переходы через границу блока, а сбой отдельной длины покажет кросс-валидация.
            ByteArrayOutputStream concatenated = new ByteArrayOutputStream();
            for (int length = 0; length <= MAX_FROZEN_LENGTH; length++) {
                concatenated.write(hashAtOnce(vector.sizeBits(), vector.pattern().data(length)));
            }
            actual = hashAtOnce(vector.sizeBits(), concatenated.toByteArray());
        } else {
            actual =
                    hashAtOnce(
                            vector.sizeBits(),
                            vector.pattern().data(Integer.parseInt(vector.length())));
        }
        assertEquals(
                vector.hex(), HEX.formatHex(actual), "хэш отличается от замороженного эталона");
    }

    // =========================================================================
    // Способы подачи входа
    // =========================================================================

    private static Stream<Integer> boundaryLengths() {
        return Arrays.stream(BOUNDARY_LENGTHS).boxed();
    }

    @ParameterizedTest(name = "длина {0}")
    @MethodSource("boundaryLengths")
    @DisplayName("update(byte) побайтно даёт тот же хэш, что и цельный вход")
    void byteWiseUpdateMatchesAtOnce(int length) {
        for (Pattern pattern : Pattern.values()) {
            for (int sizeBits : new int[] {256, 512}) {
                byte[] data = pattern.data(length);
                Digest digest = newDigest(sizeBits);
                for (byte b : data) {
                    digest.update(b);
                }
                byte[] out = new byte[digest.getDigestSize()];
                digest.doFinal(out, 0);
                assertArrayEquals(
                        hashAtOnce(sizeBits, data),
                        out,
                        "побайтовая подача: " + pattern + " " + sizeBits + " длина " + length);
            }
        }
    }

    @ParameterizedTest(name = "длина {0}")
    @MethodSource("boundaryLengths")
    @DisplayName("Подача кусками по 1, 17, 53 и 64 байта даёт тот же хэш, что и цельный вход")
    void chunkedUpdateMatchesAtOnce(int length) {
        for (Pattern pattern : Pattern.values()) {
            for (int sizeBits : new int[] {256, 512}) {
                byte[] data = pattern.data(length);
                byte[] expected = hashAtOnce(sizeBits, data);
                for (int chunk : CHUNK_SIZES) {
                    Digest digest = newDigest(sizeBits);
                    for (int offset = 0; offset < length; offset += chunk) {
                        digest.update(data, offset, Math.min(chunk, length - offset));
                    }
                    byte[] out = new byte[digest.getDigestSize()];
                    digest.doFinal(out, 0);
                    assertArrayEquals(
                            expected,
                            out,
                            "куски по "
                                    + chunk
                                    + ": "
                                    + pattern
                                    + " "
                                    + sizeBits
                                    + " длина "
                                    + length);
                }
            }
        }
    }

    @Test
    @DisplayName("Пустые вызовы update(x, 0, 0) и смесь update(byte) с блоками не меняют хэш")
    void emptyAndMixedUpdatesDoNotChangeHash() {
        byte[] data = Pattern.PSEUDO.data(200);
        for (int sizeBits : new int[] {256, 512}) {
            Digest digest = newDigest(sizeBits);
            digest.update(data, 0, 0);
            digest.update(data[0]);
            digest.update(data, 1, 0);
            digest.update(data, 1, 62);
            digest.update(data, 63, 0);
            digest.update(data, 63, 100);
            digest.update(data[163]);
            digest.update(data, 164, 36);
            digest.update(data, 200, 0);
            byte[] out = new byte[digest.getDigestSize()];
            digest.doFinal(out, 0);
            assertArrayEquals(
                    hashAtOnce(sizeBits, data), out, "смешанная подача, размер " + sizeBits);
        }
    }

    // =========================================================================
    // Повторное использование объекта
    // =========================================================================

    @Test
    @DisplayName("Один объект на подряд идущие сообщения: каждый хэш равен хэшу свежего объекта")
    void reusedInstanceGivesFreshResults() {
        int[] lengths = {0, 1, 63, 64, 65, 200, 64, 0, 129};
        for (int sizeBits : new int[] {256, 512}) {
            Digest reused = newDigest(sizeBits);
            for (int length : lengths) {
                byte[] data = Pattern.PSEUDO.data(length);
                reused.update(data, 0, length);
                byte[] out = new byte[reused.getDigestSize()];
                reused.doFinal(out, 0);
                assertArrayEquals(
                        hashAtOnce(sizeBits, data),
                        out,
                        "повторное использование: размер " + sizeBits + " длина " + length);
            }
        }
    }

    @ParameterizedTest(name = "после {0} байт")
    @ValueSource(ints = {0, 1, 40, 64, 70, 128})
    @DisplayName("reset() и destroy() посреди потока сбрасывают незавершённое сообщение")
    void resetAndDestroyDiscardPartialMessage(int consumedBytes) {
        byte[] noise = Pattern.COUNTER.data(consumedBytes);
        byte[] data = Pattern.PSEUDO.data(100);
        for (int sizeBits : new int[] {256, 512}) {
            byte[] expected = hashAtOnce(sizeBits, data);
            List<Supplier<Digest>> abandoners = new ArrayList<>();
            abandoners.add(
                    () -> {
                        Digest d = newDigest(sizeBits);
                        d.update(noise, 0, noise.length);
                        d.reset();
                        return d;
                    });
            abandoners.add(
                    () -> {
                        Digest d = newDigest(sizeBits);
                        d.update(noise, 0, noise.length);
                        d.destroy();
                        return d;
                    });
            for (Supplier<Digest> abandoner : abandoners) {
                Digest digest = abandoner.get();
                digest.update(data, 0, data.length);
                byte[] out = new byte[digest.getDigestSize()];
                digest.doFinal(out, 0);
                assertArrayEquals(
                        expected,
                        out,
                        "после сброса остался хвост прежнего сообщения: " + sizeBits);
            }
        }
    }

    // =========================================================================
    // Границы аргументов
    // =========================================================================

    @Test
    @DisplayName("update с неверными границами бросает IndexOutOfBoundsException")
    void updateRejectsBadBounds() {
        Digest digest = new Streebog256();
        byte[] data = new byte[16];
        assertThrows(IndexOutOfBoundsException.class, () -> digest.update(data, -1, 4));
        assertThrows(IndexOutOfBoundsException.class, () -> digest.update(data, 0, -1));
        assertThrows(IndexOutOfBoundsException.class, () -> digest.update(data, 10, 7));
        assertThrows(IndexOutOfBoundsException.class, () -> digest.update(data, 17, 0));
        assertThrows(NullPointerException.class, () -> digest.update(null, 0, 0));
    }

    @Test
    @DisplayName("doFinal в короткий массив бросает исключение и не портит состояние")
    void doFinalRejectsShortOutputAndKeepsState() {
        byte[] data = Pattern.COUNTER.data(70);
        for (int sizeBits : new int[] {256, 512}) {
            Digest digest = newDigest(sizeBits);
            digest.update(data, 0, data.length);
            int size = digest.getDigestSize();
            assertThrows(
                    IndexOutOfBoundsException.class, () -> digest.doFinal(new byte[size - 1], 0));
            assertThrows(IndexOutOfBoundsException.class, () -> digest.doFinal(new byte[size], 1));
            assertThrows(IndexOutOfBoundsException.class, () -> digest.doFinal(new byte[size], -1));
            byte[] out = new byte[size];
            digest.doFinal(out, 0);
            assertArrayEquals(
                    hashAtOnce(sizeBits, data),
                    out,
                    "неудачный doFinal изменил состояние хэша, размер " + sizeBits);
        }
    }

    @Test
    @DisplayName("doFinal пишет с указанного смещения и не трогает остальные байты")
    void doFinalWritesAtOffsetOnly() {
        byte[] data = Pattern.PSEUDO.data(10);
        for (int sizeBits : new int[] {256, 512}) {
            Digest digest = newDigest(sizeBits);
            digest.update(data, 0, data.length);
            int size = digest.getDigestSize();
            byte[] out = new byte[size + 6];
            Arrays.fill(out, (byte) 0x5A);
            assertEquals(size, digest.doFinal(out, 3));
            assertArrayEquals(hashAtOnce(sizeBits, data), Arrays.copyOfRange(out, 3, 3 + size));
            for (int i : new int[] {0, 1, 2, size + 3, size + 4, size + 5}) {
                assertEquals((byte) 0x5A, out[i], "затронут байт вне диапазона вывода: " + i);
            }
        }
    }

    @Test
    @DisplayName("Размеры и имена: блок 64 байта, дайджест 32 и 64 байта")
    void metadata() {
        assertEquals(64, new Streebog256().getByteLength());
        assertEquals(64, new Streebog512().getByteLength());
        assertEquals(32, new Streebog256().getDigestSize());
        assertEquals(64, new Streebog512().getDigestSize());
    }

    // =========================================================================
    // Сложение по модулю 2^512
    // =========================================================================

    private static final BigInteger MODULUS = BigInteger.ONE.shiftLeft(512);

    private static BigInteger toNumber(long[] words) {
        BigInteger result = BigInteger.ZERO;
        for (int i = WORD_COUNT - 1; i >= 0; i--) {
            result =
                    result.shiftLeft(Long.SIZE).or(new BigInteger(Long.toUnsignedString(words[i])));
        }
        return result;
    }

    private static long[] filled(long word) {
        long[] words = new long[WORD_COUNT];
        Arrays.fill(words, word);
        return words;
    }

    /** Простой детерминированный генератор слов для проверки против BigInteger. */
    private static long[] pseudoWords(long seed) {
        long[] words = new long[WORD_COUNT];
        long state = seed;
        for (int i = 0; i < WORD_COUNT; i++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            words[i] = state;
        }
        return words;
    }

    @Test
    @DisplayName("Счётчик N: перенос из младшего слова проходит через все 8 слов")
    void counterCarryPropagatesThroughAllWords() {
        long[] counter = filled(-1L);
        Streebog.addToCounter(counter, 512);
        assertEquals(
                BigInteger.valueOf(511), toNumber(counter), "перенос через все слова теряется");

        long[] oneWord = new long[WORD_COUNT];
        oneWord[0] = -1L;
        Streebog.addToCounter(oneWord, 1);
        assertEquals(BigInteger.ONE.shiftLeft(64), toNumber(oneWord), "перенос в слово 1 теряется");

        long[] wrapAtTop = new long[WORD_COUNT];
        Arrays.fill(wrapAtTop, 1, WORD_COUNT, -1L);
        wrapAtTop[0] = -512;
        Streebog.addToCounter(wrapAtTop, 512);
        assertEquals(BigInteger.ZERO, toNumber(wrapAtTop), "результат не сведён по модулю 2^512");
    }

    @Test
    @DisplayName(
            "Счётчик N: результат совпадает с BigInteger на краевых и псевдослучайных значениях")
    void counterMatchesBigInteger() {
        long[] values = {0, 1, 8, 504, 512, Long.MAX_VALUE, Long.MAX_VALUE - 7};
        for (long seed = 1; seed <= 200; seed++) {
            long[] counter = pseudoWords(seed * 0x9E3779B97F4A7C15L);
            if (seed % 3 == 0) {
                counter[0] = -1L - (seed % 5);
            }
            for (long value : values) {
                BigInteger expected = toNumber(counter).add(BigInteger.valueOf(value)).mod(MODULUS);
                long[] actual = counter.clone();
                Streebog.addToCounter(actual, value);
                assertEquals(expected, toNumber(actual), "N + " + value + ", seed " + seed);
            }
        }
    }

    @Test
    @DisplayName("Сумма Σ: перенос проходит через все слова и сводится по модулю 2^512")
    void sigmaCarryPropagatesThroughAllWords() {
        long[] accumulator = filled(-1L);
        long[] one = new long[WORD_COUNT];
        one[0] = 1;
        Streebog.addMod512(accumulator, one);
        assertEquals(BigInteger.ZERO, toNumber(accumulator), "0xFF…FF + 1 должно давать 0");

        long[] allOnes = filled(-1L);
        long[] other = filled(-1L);
        Streebog.addMod512(allOnes, other);
        assertEquals(
                MODULUS.subtract(BigInteger.TWO),
                toNumber(allOnes),
                "0xFF…FF + 0xFF…FF должно давать 2^512 - 2");
    }

    @Test
    @DisplayName("Сумма Σ: результат совпадает с BigInteger на краевых и псевдослучайных значениях")
    void sigmaMatchesBigInteger() {
        for (long seed = 1; seed <= 500; seed++) {
            long[] a = pseudoWords(seed * 0xD1B54A32D192ED03L);
            long[] b = pseudoWords(seed * 0x9E3779B97F4A7C15L + 7);
            // Каждое слово то целиком из единиц, то нулевое: перенос гарантированно цепочкой.
            for (int i = 0; i < WORD_COUNT; i++) {
                long selector = seed >>> i;
                if ((selector & 3) == 0) {
                    a[i] = -1L;
                } else if ((selector & 3) == 1) {
                    b[i] = 0L;
                }
            }
            BigInteger expected = toNumber(a).add(toNumber(b)).mod(MODULUS);
            long[] actual = a.clone();
            Streebog.addMod512(actual, b);
            assertEquals(expected, toNumber(actual), "Σ + m, seed " + seed);
        }
    }
}
