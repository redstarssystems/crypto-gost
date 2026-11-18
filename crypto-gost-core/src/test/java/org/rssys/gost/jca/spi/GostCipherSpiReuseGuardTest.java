package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Защита от повтора пары (ключ, IV/ICN/UKM) при шифровании в JCA")
@ExtendWith(JcaTestSupport.class)
class GostCipherSpiReuseGuardTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    /** Трансформация, длина IV и признак MGM (ICN со старшим битом 0, тег всегда). */
    private record Algorithm(String name, int ivLength) {
        boolean isMgm() {
            return name.contains("MGM");
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static final Algorithm CTR = new Algorithm("Kuznyechik/CTR/NoPadding", 8);
    private static final Algorithm CBC = new Algorithm("Kuznyechik/CBC/PKCS7Padding", 16);
    private static final Algorithm CBC_NO_PADDING = new Algorithm("Kuznyechik/CBC/NoPadding", 16);
    private static final Algorithm MGM = new Algorithm("Kuznyechik/MGM/NoPadding", 16);

    private static final Algorithm[] GUARDED = {
        CTR,
        new Algorithm("Kuznyechik/CFB/NoPadding", 16),
        new Algorithm("Kuznyechik/OFB/NoPadding", 16),
        CBC,
        MGM
    };

    static Stream<Arguments> guarded() {
        return Stream.of(GUARDED).map(Arguments::of);
    }

    private static GostSecretKey newKey() {
        return new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    /** Новый nonce; для MGM старший бит ICN равен 0 (RFC 9058 §3). */
    private static byte[] newIv(Algorithm algorithm) {
        byte[] iv = randomBytes(algorithm.ivLength());
        if (algorithm.isMgm()) {
            iv[0] &= 0x7F;
        }
        return iv;
    }

    private static Cipher newCipher(Algorithm algorithm) throws Exception {
        return Cipher.getInstance(algorithm.name(), PROVIDER);
    }

    private static void encryptOnce(Cipher cipher, GostSecretKey key, byte[] iv, byte[] plaintext)
            throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        assertTrue(cipher.doFinal(plaintext).length > 0, "шифртекст должен быть выдан");
    }

    // -----------------------------------------------------------------------
    // Основное правило
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName(
            "та же пара после выданного шифртекста отвергается, с другим ключом или IV допускается")
    void samePairIsRejectedAfterCiphertextIssued(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40);
        Cipher cipher = newCipher(algorithm);
        encryptOnce(cipher, key, iv, plaintext);

        InvalidAlgorithmParameterException failure =
                assertThrows(
                        InvalidAlgorithmParameterException.class,
                        () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                        "повтор пары должен отвергаться");
        assertTrue(
                failure.getMessage().startsWith("Cannot reuse key and "),
                "сообщение: " + failure.getMessage());

        // Другой ключ при том же IV и тот же ключ при другом IV допускаются
        GostSecretKey otherKey = newKey();
        cipher.init(Cipher.ENCRYPT_MODE, otherKey, new IvParameterSpec(iv));
        assertTrue(cipher.doFinal(plaintext).length > 0, "другой ключ при том же IV");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(newIv(algorithm)));
        assertTrue(cipher.doFinal(plaintext).length > 0, "тот же ключ при другом IV");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName(
            "сгенерированный IV входит в пару: init без параметров -> getIV -> init с тем же IV отвергается")
    void generatedIvIsPartOfThePair(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        Cipher cipher = newCipher(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.doFinal(randomBytes(20));
        byte[] generatedIv = cipher.getIV();

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(generatedIv)),
                "обход через getIV() должен быть закрыт");

        // Шифрование без параметров дважды допустимо: IV разные
        cipher.init(Cipher.ENCRYPT_MODE, key);
        assertTrue(cipher.doFinal(randomBytes(20)).length > 0, "новый случайный IV");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName("цикл из десяти сообщений с константным IV на одном экземпляре падает на втором")
    void constantIvLoopFailsOnSecondMessage(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        Cipher cipher = newCipher(algorithm);
        int succeeded = 0;
        for (int i = 0; i < 10; i++) {
            try {
                encryptOnce(cipher, key, iv, randomBytes(30));
                succeeded++;
            } catch (InvalidAlgorithmParameterException expected) {
                break;
            }
        }
        assertEquals(1, succeeded, "только первое сообщение должно пройти");
    }

    // -----------------------------------------------------------------------
    // Расшифрование и режим WRAP
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName(
            "encrypt -> decrypt -> encrypt с той же парой отвергается, расшифровывать той же парой можно многократно")
    void decryptionDoesNotResetUsedPair(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40);
        Cipher cipher = newCipher(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        for (int i = 0; i < 3; i++) {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            assertArrayEquals(plaintext, cipher.doFinal(ciphertext), "расшифрование " + i);
        }
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "использованная пара переживает init на расшифрование");
    }

    // -----------------------------------------------------------------------
    // Ожидающая и использованная пара
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName(
            "init без выданного шифртекста пару не расходует: повторный init с той же парой допустим")
    void pendingPairMayBeReinitialized(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        Cipher cipher = newCipher(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        assertDoesNotThrow(
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "шифртекст не выдавался, гамма не использована");
        assertTrue(cipher.doFinal(randomBytes(20)).length > 0, "шифр работает");
    }

    static Stream<Arguments> streamModes() {
        return Stream.of(GUARDED[0], GUARDED[1], GUARDED[2]).map(Arguments::of);
    }

    // -----------------------------------------------------------------------
    // Пути с буфером вызывающего и ByteBuffer: пара фиксируется и здесь
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("streamModes")
    @DisplayName("update в буфер вызывающего (горячий путь и вход = выход) расходует пару")
    void updateIntoCallerBufferUsesThePair(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] plaintext = randomBytes(40);

        // Вход и выход - разные массивы: гамма пишется прямо в буфер вызывающего
        byte[] ivSeparate = newIv(algorithm);
        Cipher separate = newCipher(algorithm);
        separate.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivSeparate));
        byte[] out = new byte[plaintext.length];
        assertEquals(plaintext.length, separate.update(plaintext, 0, plaintext.length, out, 0));
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> separate.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivSeparate)),
                "гамма вышла в буфер вызывающего");

        // Вход и выход - один массив: идёт через промежуточный массив
        byte[] ivInPlace = newIv(algorithm);
        Cipher inPlace = newCipher(algorithm);
        inPlace.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivInPlace));
        byte[] shared = plaintext.clone();
        assertEquals(shared.length, inPlace.update(shared, 0, shared.length, shared, 0));
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> inPlace.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivInPlace)),
                "тот же результат при совпадающих входе и выходе");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName("doFinal в буфер вызывающего расходует пару")
    void doFinalIntoCallerBufferUsesThePair(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40);
        Cipher cipher = newCipher(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
        assertTrue(cipher.doFinal(plaintext, 0, plaintext.length, out, 0) > 0, "вывод выдан");

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "пара использована при записи в буфер вызывающего");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName("update и doFinal через ByteBuffer расходуют пару")
    void byteBufferPathsUseThePair(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(40);
        Cipher cipher = newCipher(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(cipher.getOutputSize(80));
        cipher.update(java.nio.ByteBuffer.wrap(plaintext), out);
        cipher.doFinal(java.nio.ByteBuffer.wrap(randomBytes(40)), out);
        assertTrue(out.position() > 0, "вывод выдан");

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "пара использована при работе через ByteBuffer");
    }

    @Test
    @DisplayName("update с выданным шифртекстом (без doFinal) расходует пару")
    void updateIssuingCiphertextUsesThePair() throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(CTR);
        Cipher cipher = newCipher(CTR);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        assertEquals(10, cipher.update(randomBytes(10)).length, "update выдал шифртекст");

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "гамма уже вышла наружу");
    }

    @Test
    @DisplayName(
            "doFinal без вывода (пустое сообщение в CTR) гамму не расходует, пара остаётся доступной")
    void emptyMessageDoesNotUseThePair() throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(CTR);
        Cipher cipher = newCipher(CTR);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        assertEquals(0, cipher.doFinal().length, "пустое сообщение даёт пустой шифртекст");

        assertDoesNotThrow(
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "гамма не использовалась");
    }

    @Test
    @DisplayName(
            "doFinal упал до выдачи вывода (CBC/NoPadding, хвост не кратен блоку): та же пара допускается")
    void failureBeforeAnyOutputKeepsThePairAvailable() throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(CBC_NO_PADDING);
        Cipher cipher = newCipher(CBC_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        assertThrows(
                javax.crypto.IllegalBlockSizeException.class,
                () -> cipher.doFinal(new byte[17]),
                "длина не кратна блоку");

        assertDoesNotThrow(
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "шифртекст не выдавался");
        assertEquals(32, cipher.doFinal(new byte[32]).length, "исправленный вход проходит");
    }

    @Test
    @DisplayName("MGM: пустые открытый текст и AAD отвергаются и пару не расходуют")
    void mgmRefusalOfEmptyMessageKeepsThePairAvailable() throws Exception {
        GostSecretKey key = newKey();
        byte[] icn = newIv(MGM);
        Cipher cipher = newCipher(MGM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn));
        assertThrows(IllegalArgumentException.class, cipher::doFinal, "пустые P и A");

        assertDoesNotThrow(
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(icn)),
                "тег не выдавался, ICN не использован");
        assertEquals(36, cipher.doFinal(new byte[20]).length, "тег и шифртекст");
    }

    /**
     * SPI напрямую (тест в том же пакете): {@code javax.crypto.Cipher} сам делает шифр
     * неинициализированным при любом отказе init, поэтому состояние SPI через публичный API не
     * проверить.
     */
    private interface SpiHandle {
        void init(GostSecretKey key, byte[] iv) throws Exception;

        byte[] doFinal(byte[] input) throws Exception;
    }

    private static SpiHandle newSpi(Algorithm algorithm) throws Exception {
        if (algorithm.isMgm()) {
            GostMgmCipherSpi spi = new GostMgmCipherSpi();
            return new SpiHandle() {
                @Override
                public void init(GostSecretKey key, byte[] iv) throws Exception {
                    spi.engineInit(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), null);
                }

                @Override
                public byte[] doFinal(byte[] input) throws Exception {
                    return spi.engineDoFinal(input, 0, input.length);
                }
            };
        }
        GostCipherSpi spi = new GostCipherSpi();
        String[] parts = algorithm.name().split("/");
        spi.engineSetMode(parts[1]);
        spi.engineSetPadding(parts[2]);
        return new SpiHandle() {
            @Override
            public void init(GostSecretKey key, byte[] iv) throws Exception {
                spi.engineInit(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), null);
            }

            @Override
            public byte[] doFinal(byte[] input) throws Exception {
                return spi.engineDoFinal(input, 0, input.length);
            }
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName("отказ init не портит ни текущую операцию SPI, ни запомненные пары")
    void rejectedInitKeepsSpiState(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] ivA = newIv(algorithm);
        byte[] ivB = newIv(algorithm);
        byte[] plaintext = randomBytes(40);

        Cipher reference = newCipher(algorithm);
        reference.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivB));
        byte[] expectedForB = reference.doFinal(plaintext);

        SpiHandle spi = newSpi(algorithm);
        spi.init(key, ivA);
        spi.doFinal(plaintext); // A использована
        spi.init(key, ivB); // B ожидает
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> spi.init(key, ivA),
                "A уже использована");

        // Текущая операция SPI с B не пострадала, а обе пары на месте
        assertArrayEquals(
                expectedForB, spi.doFinal(plaintext), "операция с B должна завершиться как обычно");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> spi.init(key, ivB),
                "теперь использована B");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("guarded")
    @DisplayName(
            "помнится только последняя пара: A -> B -> A проходит (документированное ограничение)")
    void onlyTheLastUsedPairIsRemembered(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] ivA = newIv(algorithm);
        byte[] ivB = newIv(algorithm);
        Cipher cipher = newCipher(algorithm);
        encryptOnce(cipher, key, ivA, randomBytes(30));
        encryptOnce(cipher, key, ivB, randomBytes(30));

        assertDoesNotThrow(
                () -> encryptOnce(cipher, key, ivA, randomBytes(30)),
                "пара A забыта после использования пары B");
    }

    @Test
    @DisplayName(
            "детерминированное CBC через новый экземпляр Cipher работает: уникальность между экземплярами — на вызывающем")
    void deterministicCbcViaNewInstanceStillWorks() throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(CBC);
        byte[] plaintext = randomBytes(40);

        Cipher first = newCipher(CBC);
        first.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = first.doFinal(plaintext);
        Cipher second = newCipher(CBC);
        second.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        assertArrayEquals(
                ciphertext, second.doFinal(plaintext), "тот же результат у нового экземпляра");
    }

    // -----------------------------------------------------------------------
    // CTR-ACPKM: эффективный nonce
    // -----------------------------------------------------------------------

    private static final String ACPKM = "Kuznyechik/CTR-ACPKM/NoPadding";
    private static final String ACPKM_OMAC = "Kuznyechik/CTR-ACPKM-OMAC/NoPadding";

    @Test
    @DisplayName(
            "CTR-ACPKM без OMAC: UKM X и X ‖ Y дают одну гамму, поэтому вторая пара отвергается")
    void acpkmUkmSharingFirstEightBytesIsTheSamePair() throws Exception {
        GostSecretKey key = newKey();
        byte[] x = randomBytes(8);
        byte[] xy = Arrays.copyOf(x, 12);
        System.arraycopy(randomBytes(4), 0, xy, 8, 4);

        Cipher cipher = Cipher.getInstance(ACPKM, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(x));
        assertTrue(cipher.doFinal(randomBytes(20)).length > 0, "шифртекст выдан");

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(xy)),
                "счётчик строится из первых 8 байт UKM: гамма повторилась бы");
    }

    @Test
    @DisplayName(
            "CTR-ACPKM-OMAC: UKM с тем же началом и другим seed допускается, тот же UKM отвергается")
    void acpkmOmacUsesTheWholeUkm() throws Exception {
        GostSecretKey key = newKey();
        byte[] ukm = randomBytes(16);
        byte[] otherSeed = ukm.clone();
        otherSeed[15] ^= 1;

        Cipher cipher = Cipher.getInstance(ACPKM_OMAC, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm));
        assertTrue(cipher.doFinal(randomBytes(20)).length > 0, "шифртекст выдан");

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ukm)),
                "тот же UKM");
        // Другой seed даёт другие ключи KDF_TREE: гамма не повторяется
        assertDoesNotThrow(
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(otherSeed)),
                "другой seed");
    }
}
