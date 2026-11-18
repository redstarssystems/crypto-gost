package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Матрица нарезки для JCA-шифров Кузнечика: результат не должен зависеть от того, как вход
 * разбит на порции {@code update}, и повтор после {@link ShortBufferException} обязан давать
 * тот же результат, что вызов без ошибки.
 */
@DisplayName("GostCipherSpi/GostMgmCipherSpi — нарезка входа и ShortBufferException")
@ExtendWith(JcaTestSupport.class)
class GostCipherSpiChunkingTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final int[] CHUNK_SIZES = {1, 5, 15, 16, 17, 31};
    private static final int[] DATA_LENGTHS = {1, 5, 15, 16, 17, 31, 32, 33, 100};

    /** Алгоритм JCA, длина IV в байтах и признак того, что вход должен быть кратен блоку. */
    private record Algorithm(String name, int ivLength, boolean blockAligned) {
        @Override
        public String toString() {
            return name;
        }
    }

    private static final Algorithm[] ALGORITHMS = {
        new Algorithm("Kuznyechik/CTR/NoPadding", 8, false),
        new Algorithm("Kuznyechik/CFB/NoPadding", 16, false),
        new Algorithm("Kuznyechik/OFB/NoPadding", 16, false),
        new Algorithm("Kuznyechik/CBC/PKCS7Padding", 16, false),
        new Algorithm("Kuznyechik/CBC/ISO7816-4", 16, false),
        new Algorithm("Kuznyechik/CBC/NoPadding", 16, true),
        new Algorithm("Kuznyechik/MGM/NoPadding", 16, false)
    };

    /** Все сочетания «алгоритм x длина данных x размер порции» с учётом выравнивания CBC/NoPadding. */
    static Stream<Arguments> matrix() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (Algorithm algorithm : ALGORITHMS) {
            for (int dataLength : DATA_LENGTHS) {
                if (algorithm.blockAligned() && dataLength % 16 != 0) {
                    continue;
                }
                for (int chunk : CHUNK_SIZES) {
                    builder.add(Arguments.of(algorithm, dataLength, chunk));
                }
            }
        }
        return builder.build();
    }

    private static GostSecretKey newKey() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        return new GostSecretKey("Kuznyechik", key);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    /** MGM требует ICN со старшим битом 0 (RFC 9058 §3). */
    private static byte[] newIv(Algorithm algorithm) {
        byte[] iv = randomBytes(algorithm.ivLength());
        if (algorithm.name().contains("MGM")) {
            iv[0] &= 0x7F;
        }
        return iv;
    }

    private static Cipher newCipher(Algorithm algorithm, int opmode, GostSecretKey key, byte[] iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm.name(), PROVIDER);
        cipher.init(opmode, key, new IvParameterSpec(iv));
        return cipher;
    }

    /** Прогоняет вход через update порциями {@code chunk} байт и завершает doFinal. */
    private static byte[] runChunked(Cipher cipher, byte[] input, int chunk) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        while (input.length - offset > chunk) {
            byte[] part = cipher.update(input, offset, chunk);
            if (part != null) {
                out.write(part);
            }
            offset += chunk;
        }
        out.write(cipher.doFinal(input, offset, input.length - offset));
        return out.toByteArray();
    }

    @ParameterizedTest(name = "{0}, данных {1} байт, порция {2}")
    @MethodSource("matrix")
    @DisplayName(
            "шифртекст порциями равен шифртексту одним куском, расшифрование порциями возвращает исходник")
    void chunkedEqualsWholeAndRoundtrips(Algorithm algorithm, int dataLength, int chunk)
            throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(dataLength);

        byte[] whole = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);
        byte[] chunked =
                runChunked(newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv), plaintext, chunk);
        assertArrayEquals(
                whole, chunked, "Шифртекст по порциям должен совпасть с шифртекстом одним куском");

        byte[] decrypted =
                runChunked(newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv), whole, chunk);
        assertArrayEquals(
                plaintext,
                decrypted,
                "Расшифрование по порциям должно вернуть исходный открытый текст без дополнения");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("streamAlgorithms")
    @DisplayName("потоковый режим: вывод update равен длине ввода, без буферизации")
    void streamModeEmitsEveryByteImmediately(Algorithm algorithm) throws Exception {
        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, newKey(), newIv(algorithm));
        for (int length : new int[] {1, 5, 15, 17}) {
            byte[] part = cipher.update(randomBytes(length));
            assertNotNull(part, "Потоковый режим должен вернуть байты сразу");
            assertEquals(length, part.length, "Длина вывода update должна равняться длине ввода");
        }
    }

    static Stream<Arguments> streamAlgorithms() {
        return Stream.of(ALGORITHMS)
                .filter(
                        a ->
                                a.name().contains("/CTR/")
                                        || a.name().contains("/CFB/")
                                        || a.name().contains("/OFB/"))
                .map(Arguments::of);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("streamAlgorithms")
    @DisplayName("повтор update после ShortBufferException даёт тот же шифртекст")
    void updateRetryAfterShortBuffer(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(37);
        byte[] expected = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        byte[] tooSmall = new byte[plaintext.length - 1];
        assertThrows(
                ShortBufferException.class,
                () -> cipher.update(plaintext, 0, plaintext.length, tooSmall, 0),
                "Буфер короче вывода должен вызвать ShortBufferException");

        byte[] exact = new byte[plaintext.length];
        int written = cipher.update(plaintext, 0, plaintext.length, exact, 0);
        assertEquals(plaintext.length, written, "Должны быть записаны все байты");
        assertArrayEquals(
                expected, exact, "Повтор после ShortBufferException должен дать тот же шифртекст");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("streamAlgorithms")
    @DisplayName("повтор doFinal после ShortBufferException даёт тот же шифртекст")
    void doFinalRetryAfterShortBuffer(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(37);
        byte[] expected = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        byte[] tooSmall = new byte[plaintext.length - 1];
        assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(plaintext, 0, plaintext.length, tooSmall, 0),
                "Буфер короче вывода должен вызвать ShortBufferException");

        byte[] exact = new byte[plaintext.length];
        int written = cipher.doFinal(plaintext, 0, plaintext.length, exact, 0);
        assertEquals(plaintext.length, written, "Должны быть записаны все байты");
        assertArrayEquals(
                expected, exact, "Повтор после ShortBufferException должен дать тот же шифртекст");
    }

    @Test
    @DisplayName(
            "CBC с padding: буфер ровно под фактический вывод update не вызывает ShortBufferException")
    void cbcUpdateExactBufferIsEnough() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40); // 2 полных блока + 8 байт хвоста

        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        byte[] exact = new byte[32];
        int written = cipher.update(plaintext, 0, plaintext.length, exact, 0);
        assertEquals(32, written, "CBC должен выдать только полные блоки");

        byte[] tooSmall = new byte[16];
        Cipher second = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        assertThrows(
                ShortBufferException.class,
                () -> second.update(plaintext, 0, plaintext.length, tooSmall, 0),
                "Буфер меньше числа полных блоков должен вызвать ShortBufferException");
        byte[] retry = new byte[32];
        assertEquals(32, second.update(plaintext, 0, plaintext.length, retry, 0));
        assertArrayEquals(
                exact, retry, "Повтор после ShortBufferException должен дать тот же результат");
    }

    @Test
    @DisplayName("CBC-расшифрование с padding: update удерживает последний блок до doFinal")
    void cbcDecryptHoldsLastBlockUntilDoFinal() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext =
                randomBytes(32); // кратно блоку -> шифртекст 48 байт, последний блок — padding
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);
        assertEquals(48, ciphertext.length, "Ожидается 48 байт шифртекста с полным блоком padding");

        Cipher decryptor = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] early = decryptor.update(ciphertext);
        assertEquals(
                32,
                early.length,
                "update не должен выдавать последний блок, в котором лежит padding");
        byte[] rest = decryptor.doFinal();
        assertEquals(0, rest.length, "doFinal должен снять padding и ничего не добавить");
        assertArrayEquals(plaintext, early, "Открытый текст не должен содержать байт padding");
    }

    @Test
    @DisplayName(
            "CBC-расшифрование с padding: граница буфера update — ровно (всего - 1) / 16 блоков")
    void cbcDecryptUpdateBoundaryIsExact() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(32); // шифртекст 48 байт, последний блок — padding
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        // Буфер ровно под удерживаемую границу (два блока) достаточен
        Cipher exactCipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] exact = new byte[32];
        assertEquals(
                32,
                exactCipher.update(ciphertext, 0, ciphertext.length, exact, 0),
                "update должен записать два блока без ShortBufferException");
        assertArrayEquals(plaintext, exact, "Открытый текст после update");

        // Буфер на байт меньше недостаточен, повтор с нужным размером даёт тот же результат
        for (int tooSmallLength : new int[] {31, 16}) {
            Cipher cipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
            byte[] tooSmall = new byte[tooSmallLength];
            assertThrows(
                    ShortBufferException.class,
                    () -> cipher.update(ciphertext, 0, ciphertext.length, tooSmall, 0),
                    "Буфер " + tooSmallLength + " байт короче границы update");
            byte[] retry = new byte[32];
            assertEquals(32, cipher.update(ciphertext, 0, ciphertext.length, retry, 0));
            assertArrayEquals(
                    plaintext,
                    retry,
                    "Повтор после ShortBufferException должен дать тот же результат");
            assertEquals(0, cipher.doFinal().length, "doFinal должен снять padding");
        }
    }

    @Test
    @DisplayName(
            "CBC-расшифрование с padding: буфер ровно под открытый текст принимается в doFinal")
    void cbcDecryptDoFinalAcceptsExactPlaintextBuffer() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(20);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher cipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        // getOutputSize даёт верхнюю оценку (32), но фактический открытый текст — 20 байт
        assertEquals(32, cipher.getOutputSize(ciphertext.length), "Верхняя оценка размера");
        byte[] exact = new byte[plaintext.length];
        assertEquals(
                plaintext.length,
                cipher.doFinal(ciphertext, 0, ciphertext.length, exact, 0),
                "Буфер ровно под открытый текст не должен вызывать ShortBufferException");
        assertArrayEquals(plaintext, exact, "Расшифрованный текст");
    }

    @Test
    @DisplayName(
            "CBC-расшифрование с padding: заведомо малый буфер отвергается до обработки, повтор проходит")
    void cbcDecryptDoFinalRejectsHopelessBufferRecoverably() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(20);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher cipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] hopeless = new byte[3]; // даже минимум (длина - 16 = 16 байт) не помещается
        assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(ciphertext, 0, ciphertext.length, hopeless, 0),
                "Буфер короче минимально возможного открытого текста");
        byte[] retry = new byte[plaintext.length];
        assertEquals(
                plaintext.length,
                cipher.doFinal(ciphertext, 0, ciphertext.length, retry, 0),
                "Повтор с достаточным буфером должен пройти");
        assertArrayEquals(plaintext, retry, "Расшифрованный текст после повтора");
    }

    @ParameterizedTest(name = "открытый текст {0} байт, первый буфер {1}")
    @org.junit.jupiter.params.provider.CsvSource({"20, 19", "40, 39", "31, 30", "5, 3"})
    @DisplayName(
            "CBC-расшифрование одним вызовом: поздний ShortBufferException восстановим, повтор даёт верный результат")
    void cbcDecryptLateShortBufferOneShotIsRecoverable(int plaintextLength, int firstBufferLength)
            throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(plaintextLength);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        // Буфер не меньше «длина - 16», но меньше открытого текста: отказ возможен только после
        // расшифрования; пока update не двигал регистр, состояние возвращается к исходному
        Cipher cipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] firstBuffer = new byte[firstBufferLength];
        assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(ciphertext, 0, ciphertext.length, firstBuffer, 0),
                "Буфер короче открытого текста должен вызвать ShortBufferException");

        byte[] retryBuffer = new byte[ciphertext.length];
        int written = cipher.doFinal(ciphertext, 0, ciphertext.length, retryBuffer, 0);
        assertEquals(plaintext.length, written, "Повтор должен вернуть весь открытый текст");
        assertArrayEquals(
                plaintext,
                Arrays.copyOf(retryBuffer, written),
                "Повтор после ShortBufferException должен дать верный результат");
    }

    @Test
    @DisplayName(
            "CBC-расшифрование после update: поздний ShortBufferException блокирует шифр до нового init")
    void cbcDecryptLateShortBufferAfterUpdateBlocksUntilReinit() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);
        assertEquals(48, ciphertext.length, "Для 40 байт ожидается 48 байт шифртекста");

        Cipher cipher = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        // update пропускает два блока через шифр (33 байта: 32 обработано, 1 удержан),
        // регистр CBC сдвинут, и состояние до doFinal уже не восстановить
        byte[] firstPart = cipher.update(ciphertext, 0, 33);
        assertEquals(32, firstPart.length, "update должен выдать два блока");

        // Остаток расшифруется в 8 байт, буфер на 7 байт не меньше минимума (16 - 16 = 0)
        byte[] tooSmall = new byte[7];
        assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(ciphertext, 33, 15, tooSmall, 0),
                "Буфер короче остатка открытого текста должен вызвать ShortBufferException");

        // Повтор не должен молча вернуть данные, расшифрованные «с середины» цепочки
        byte[] retryBuffer = new byte[16];
        assertThrows(
                IllegalStateException.class,
                () -> cipher.doFinal(ciphertext, 33, 15, retryBuffer, 0),
                "Повтор без init после потери состояния должен бросать IllegalStateException");

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        assertArrayEquals(
                plaintext,
                cipher.doFinal(ciphertext),
                "После нового init расшифрование должно вернуть исходный текст");
    }

    @Test
    @DisplayName("MGM: повтор doFinal после ShortBufferException даёт тот же шифртекст и тег")
    void mgmDoFinalRetryAfterShortBuffer() throws Exception {
        Algorithm algorithm = ALGORITHMS[6];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(20);
        byte[] expected = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        byte[] tooSmall = new byte[expected.length - 1];
        assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(plaintext, 0, plaintext.length, tooSmall, 0),
                "Буфер короче шифртекста с тегом должен вызвать ShortBufferException");

        byte[] exact = new byte[expected.length];
        assertEquals(expected.length, cipher.doFinal(plaintext, 0, plaintext.length, exact, 0));
        assertArrayEquals(
                expected, exact, "Повтор после ShortBufferException должен дать тот же результат");

        // Расшифрование: буфер под открытый текст точный, под него — тоже без отказа
        Cipher decryptor = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        byte[] shortPlain = new byte[plaintext.length - 1];
        assertThrows(
                ShortBufferException.class,
                () -> decryptor.doFinal(expected, 0, expected.length, shortPlain, 0),
                "Буфер короче открытого текста должен вызвать ShortBufferException");
        byte[] plain = new byte[plaintext.length];
        assertEquals(plaintext.length, decryptor.doFinal(expected, 0, expected.length, plain, 0));
        assertArrayEquals(plaintext, plain, "Расшифрованный текст должен совпасть с исходным");
        assertFalse(
                Arrays.equals(expected, plaintext),
                "Шифртекст не должен совпадать с открытым текстом");
    }

    // -----------------------------------------------------------------------
    // Сверка с независимой реализацией и эталонными векторами
    // -----------------------------------------------------------------------

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }

    /**
     * Эталонные векторы для сверки JCA целиком и порциями. CTR — вектор ГОСТ Р 34.13-2015 (§А.2.5,
     * синхропосылка 8 байт). CBC — не вектор стандарта: у стандарта синхропосылка 32 байта (m = 2n),
     * а JCA принимает ровно 16, поэтому значение получено расчётом по §4.2 с синхропосылкой,
     * усечённой до 16 байт (как в ModesTest), и независимо подтверждено сверкой с OpenSSL.
     * CFB и OFB в стандарте тоже заданы 32-байтной синхропосылкой, их векторы проверяются на
     * уровне режимов в ModesTest; через JCA они сверяются с api.Cipher и с OpenSSL.
     */
    private static final String STANDARD_KEY =
            "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";

    private static final String STANDARD_PLAIN =
            "1122334455667700ffeeddccbbaa9988"
                    + "00112233445566778899aabbcceeff0a"
                    + "112233445566778899aabbcceeff0a00"
                    + "2233445566778899aabbcceeff0a0011";

    private static final String STANDARD_CTR_IV = "1234567890abcdef";
    private static final String STANDARD_CTR_CIPHER =
            "db46342940acfb01fd7fddd98a2d5de8"
                    + "f9f014c644b982bbb16c22b9b3cbec70"
                    + "7a8b3ca84156936481a175108b94261c"
                    + "60fed990f34d3e239ef8d4ac20ae8a83";

    /** Расчётный вектор (синхропосылка усечена до 16 байт), не вектор стандарта. */
    private static final String STANDARD_CBC_IV = "1234567890abcef0a1b2c3d4e5f00112";

    private static final String STANDARD_CBC_CIPHER =
            "689972d4a085fa4d90e52e3d6d7dcc27"
                    + "abf170b2b226c3010ccfa136d659cdaa"
                    + "ca719272ab1d438e15507d521ecd5522"
                    + "e01108ff8d9d3a6d8ca2a533fa614e71";

    @ParameterizedTest(name = "{0} (порция {1})")
    @MethodSource("standardVectors")
    @DisplayName(
            "JCA воспроизводит эталонные векторы (CTR — ГОСТ Р 34.13-2015, CBC — расчётный) целиком и порциями")
    void jcaMatchesStandardVector(String algorithm, int chunk, String iv, String expected)
            throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", new SymmetricKey(hex(STANDARD_KEY)));
        byte[] plain = hex(STANDARD_PLAIN);

        Cipher encryptor = Cipher.getInstance(algorithm, PROVIDER);
        encryptor.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(hex(iv)));
        assertArrayEquals(
                hex(expected),
                runChunked(encryptor, plain, chunk),
                "Шифртекст должен совпасть с эталонным вектором");

        Cipher decryptor = Cipher.getInstance(algorithm, PROVIDER);
        decryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(hex(iv)));
        assertArrayEquals(
                plain,
                runChunked(decryptor, hex(expected), chunk),
                "Расшифрование эталонного шифртекста должно вернуть открытый текст");
    }

    static Stream<Arguments> standardVectors() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (int chunk : CHUNK_SIZES) {
            builder.add(
                    Arguments.of(
                            "Kuznyechik/CTR/NoPadding",
                            chunk,
                            STANDARD_CTR_IV,
                            STANDARD_CTR_CIPHER));
            builder.add(
                    Arguments.of(
                            "Kuznyechik/CBC/NoPadding",
                            chunk,
                            STANDARD_CBC_IV,
                            STANDARD_CBC_CIPHER));
        }
        return builder.build();
    }

    static Stream<Arguments> nonMgmAlgorithms() {
        return Stream.of(ALGORITHMS).filter(a -> !a.name().contains("MGM")).map(Arguments::of);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonMgmAlgorithms")
    @DisplayName("JCA даёт тот же шифртекст, что api.Cipher, при любой нарезке")
    void jcaMatchesApiCipher(Algorithm algorithm) throws Exception {
        byte[] rawKey = randomBytes(32);
        GostSecretKey key = new GostSecretKey("Kuznyechik", new SymmetricKey(rawKey));
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(algorithm.blockAligned() ? 96 : 100);

        org.rssys.gost.api.Cipher.Mode mode =
                algorithm.name().contains("/CTR/")
                        ? org.rssys.gost.api.Cipher.Mode.CTR
                        : algorithm.name().contains("/CFB/")
                                ? org.rssys.gost.api.Cipher.Mode.CFB
                                : algorithm.name().contains("/OFB/")
                                        ? org.rssys.gost.api.Cipher.Mode.OFB
                                        : org.rssys.gost.api.Cipher.Mode.CBC;
        org.rssys.gost.api.Cipher.Padding padding =
                algorithm.name().endsWith("PKCS7Padding")
                        ? org.rssys.gost.api.Cipher.Padding.PKCS7
                        : algorithm.name().endsWith("ISO7816-4")
                                ? org.rssys.gost.api.Cipher.Padding.ISO7816_4
                                : org.rssys.gost.api.Cipher.Padding.NONE;
        byte[] expected =
                org.rssys.gost.api.Cipher.encrypt(
                        plaintext, new SymmetricKey(rawKey), iv, mode, padding);

        for (int chunk : CHUNK_SIZES) {
            byte[] actual =
                    runChunked(
                            newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv), plaintext, chunk);
            assertArrayEquals(
                    expected,
                    actual,
                    "Шифртекст JCA должен совпасть с api.Cipher, порция " + chunk);
        }
    }

    // -----------------------------------------------------------------------
    // Пересечение входного и выходного буферов
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonMgmAlgorithms")
    @DisplayName(
            "update и doFinal безопасны, когда вход и выход — один массив (в том же месте и со сдвигом)")
    void overlappingInputAndOutputAreSafe(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] data = randomBytes(64);
        byte[] expected = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(data);

        // doFinal: сдвиг вывода вправо на 8 байт и запись на то же место
        for (int shift : new int[] {0, 8}) {
            byte[] buf = Arrays.copyOf(data, 64 + 32);
            Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
            int written = cipher.doFinal(buf, 0, 64, buf, shift);
            assertEquals(expected.length, written, "Длина вывода doFinal, сдвиг " + shift);
            assertArrayEquals(
                    expected,
                    Arrays.copyOfRange(buf, shift, shift + written),
                    "Результат doFinal при пересечении буферов, сдвиг " + shift);
        }

        // update: для потоковых режимов вывод равен вводу, для CBC — все полные блоки (64 байта)
        for (int shift : new int[] {0, 8}) {
            byte[] buf = Arrays.copyOf(data, 64 + 32);
            Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
            int written = cipher.update(buf, 0, 64, buf, shift);
            assertEquals(64, written, "Длина вывода update, сдвиг " + shift);
            assertArrayEquals(
                    Arrays.copyOf(expected, 64),
                    Arrays.copyOfRange(buf, shift, shift + written),
                    "Результат update при пересечении буферов, сдвиг " + shift);
        }
    }

    // -----------------------------------------------------------------------
    // CipherInputStream / CipherOutputStream
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("matrixAlgorithms")
    @DisplayName(
            "CipherOutputStream -> CipherInputStream возвращает исходные данные, шифртекст равен одному куску")
    void cipherStreamsRoundtrip(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(algorithm.blockAligned() ? 96 : 100);
        byte[] expected = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (CipherOutputStream out =
                new CipherOutputStream(sink, newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv))) {
            for (int offset = 0; offset < plaintext.length; offset += 7) {
                out.write(plaintext, offset, Math.min(7, plaintext.length - offset));
            }
        }
        assertArrayEquals(expected, sink.toByteArray(), "Шифртекст CipherOutputStream");

        try (CipherInputStream in =
                new CipherInputStream(
                        new ByteArrayInputStream(expected),
                        newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv))) {
            assertArrayEquals(plaintext, in.readAllBytes(), "Открытый текст из CipherInputStream");
        }
    }

    static Stream<Arguments> matrixAlgorithms() {
        return Stream.of(ALGORITHMS).map(Arguments::of);
    }

    @Test
    @DisplayName(
            "CipherInputStream: CBC/PKCS7 выдаёт 20 байт, а не 32 с padding, и отвергает испорченный padding")
    void cipherInputStreamStripsAndChecksPadding() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(20);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);
        assertEquals(32, ciphertext.length, "Для 20 байт ожидается 32 байта шифртекста");

        try (CipherInputStream in =
                new CipherInputStream(
                        new ByteArrayInputStream(ciphertext),
                        newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv))) {
            assertArrayEquals(
                    plaintext,
                    in.readAllBytes(),
                    "CipherInputStream должен вернуть 20 байт без padding");
        }

        // Бит в последнем байте предпоследнего блока меняет последний байт открытого текста
        // детерминированно: padding перестаёт быть корректным
        byte[] corrupted = ciphertext.clone();
        corrupted[ciphertext.length - 17] ^= 1;
        IOException failure =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (CipherInputStream in =
                                    new CipherInputStream(
                                            new ByteArrayInputStream(corrupted),
                                            newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv))) {
                                in.readAllBytes();
                            }
                        },
                        "Испорченный padding должен привести к ошибке чтения");
        assertInstanceOf(
                BadPaddingException.class,
                failure.getCause(),
                "Причиной должна быть BadPaddingException");
    }

    @Test
    @DisplayName(
            "CBC: update с испорченным padding не принимается молча, ошибка приходит на doFinal")
    void cbcDecryptWithCorruptedPaddingFailsOnDoFinal() throws Exception {
        Algorithm algorithm = ALGORITHMS[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] ciphertext =
                newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(randomBytes(20));
        ciphertext[ciphertext.length - 17] ^= 1;

        Cipher decryptor = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        decryptor.update(ciphertext);
        assertThrows(
                BadPaddingException.class,
                decryptor::doFinal,
                "Испорченный padding должен быть обнаружен на doFinal");
    }
}
