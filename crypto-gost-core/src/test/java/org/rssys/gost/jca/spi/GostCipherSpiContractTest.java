package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
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

/**
 * Контракт JCA-шифров Кузнечика: IV при расшифровании, состояние после {@code doFinal},
 * допустимость padding по режимам, пустые данные в MGM.
 */
@DisplayName("GostCipherSpi/GostMgmCipherSpi — контракт CipherSpi")
@ExtendWith(JcaTestSupport.class)
class GostCipherSpiContractTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    /** Трансформация и длина IV; MGM требует ICN со старшим битом 0. */
    private record Algorithm(String name, int ivLength) {
        boolean isMgm() {
            return name.contains("MGM");
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static final Algorithm[] STREAM_AND_CBC = {
        new Algorithm("Kuznyechik/CTR/NoPadding", 8),
        new Algorithm("Kuznyechik/CFB/NoPadding", 16),
        new Algorithm("Kuznyechik/OFB/NoPadding", 16),
        new Algorithm("Kuznyechik/CBC/PKCS7Padding", 16),
        new Algorithm("Kuznyechik/CBC/ISO7816-4", 16),
        new Algorithm("Kuznyechik/CBC/NoPadding", 16)
    };

    private static final Algorithm MGM = new Algorithm("Kuznyechik/MGM/NoPadding", 16);

    static Stream<Arguments> nonMgm() {
        return Stream.of(STREAM_AND_CBC).map(Arguments::of);
    }

    static Stream<Arguments> allAlgorithms() {
        return Stream.concat(Stream.of(STREAM_AND_CBC), Stream.of(MGM)).map(Arguments::of);
    }

    private static GostSecretKey newKey() {
        return new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
    }

    private static byte[] newIv(Algorithm algorithm) {
        byte[] iv = new byte[algorithm.ivLength()];
        CryptoRandom.INSTANCE.nextBytes(iv);
        if (algorithm.isMgm()) {
            iv[0] &= 0x7F;
        }
        return iv;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    /** Открытый текст нужной длины: CBC/NoPadding требует кратности блоку. */
    private static byte[] plaintextFor(Algorithm algorithm) {
        return randomBytes(algorithm.name().endsWith("CBC/NoPadding") ? 48 : 50);
    }

    private static Cipher newCipher(Algorithm algorithm, int opmode, GostSecretKey key, byte[] iv)
            throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm.name(), PROVIDER);
        cipher.init(opmode, key, new IvParameterSpec(iv));
        return cipher;
    }

    // -----------------------------------------------------------------------
    // IV при расшифровании
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allAlgorithms")
    @DisplayName("расшифрование без IV отвергается (случайный IV дал бы мусор без ошибки)")
    void decryptionWithoutIvIsRejected(Algorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm.name(), PROVIDER);
        GostSecretKey key = newKey();

        assertThrows(
                InvalidKeyException.class,
                () -> cipher.init(Cipher.DECRYPT_MODE, key),
                "init(DECRYPT, key) без параметров должен бросать исключение");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.DECRYPT_MODE, key, (IvParameterSpec) null),
                "init(DECRYPT, key, null) должен бросать исключение");
        // Шифрование без IV по-прежнему допустимо: IV генерируется и доступен через getIV()
        cipher.init(Cipher.ENCRYPT_MODE, key);
        assertNotNull(cipher.getIV(), "При шифровании без IV он должен быть сгенерирован");
    }

    // -----------------------------------------------------------------------
    // Состояние после doFinal
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allAlgorithms")
    @DisplayName("шифрование блокируется после doFinal до нового init; getIV остаётся доступным")
    void encryptionIsBlockedAfterDoFinal(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = plaintextFor(algorithm);
        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);

        byte[] first = cipher.doFinal(plaintext);
        assertArrayEquals(iv, cipher.getIV(), "getIV() после doFinal должен вернуть IV");

        assertThrows(
                IllegalStateException.class,
                () -> cipher.doFinal(plaintext),
                "Повторный doFinal без init повторил бы гамму");
        assertThrows(
                IllegalStateException.class,
                () -> cipher.update(plaintext),
                "update после doFinal без init должен бросать исключение");

        // Новый init с той же парой (ключ, IV) повторил бы гамму: отвергается
        assertThrows(
                java.security.InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "Та же пара (ключ, IV) после выданного шифртекста должна отвергаться");

        byte[] freshIv = newIv(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(freshIv));
        byte[] second = cipher.doFinal(plaintext);
        assertEquals(first.length, second.length, "Длина шифртекста та же");
        // Мусор на выходе длину бы прошёл: проверяем расшифрованием
        assertArrayEquals(
                plaintext,
                newCipher(algorithm, Cipher.DECRYPT_MODE, key, freshIv).doFinal(second),
                "После init с новым IV шифр работает как прежде");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonMgm")
    @DisplayName("расшифрование возвращается в состояние после init: повтор даёт тот же результат")
    void decryptionIsResetAfterDoFinal(Algorithm algorithm) throws Exception {
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = plaintextFor(algorithm);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);

        Cipher decryptor = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        assertArrayEquals(plaintext, decryptor.doFinal(ciphertext), "Первое расшифрование");
        assertArrayEquals(
                plaintext, decryptor.doFinal(ciphertext), "Повторное расшифрование без init");
    }

    @Test
    @DisplayName("CBC: после BadPaddingException шифр возвращается в состояние после init")
    void cbcDecryptionIsResetAfterBadPadding() throws Exception {
        Algorithm algorithm = STREAM_AND_CBC[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        byte[] plaintext = randomBytes(20);
        byte[] ciphertext = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext);
        byte[] corrupted = ciphertext.clone();
        corrupted[ciphertext.length - 17] ^= 1; // детерминированно ломает padding

        Cipher decryptor = newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        assertThrows(
                BadPaddingException.class,
                () -> decryptor.doFinal(corrupted),
                "Испорченный padding должен быть обнаружен");
        assertArrayEquals(
                plaintext,
                decryptor.doFinal(ciphertext),
                "После ошибки шифр не должен хранить накопленный шифртекст и сдвинутый регистр");
    }

    @Test
    @DisplayName(
            "CBC/NoPadding: отказ из-за длины не кратной блоку отбрасывает вход и не блокирует шифр")
    void cbcEncryptionRejectedBeforeProcessingDiscardsInput() throws Exception {
        Algorithm algorithm = STREAM_AND_CBC[5];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);

        assertThrows(
                javax.crypto.IllegalBlockSizeException.class,
                () -> cipher.doFinal(new byte[17]),
                "Длина не кратная блоку должна отвергаться");
        byte[] plaintext = randomBytes(32);
        assertArrayEquals(
                newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plaintext),
                cipher.doFinal(plaintext),
                "Отказ до обработки не должен блокировать шифр");
    }

    @Test
    @DisplayName(
            "CBC-расшифрование без единого байта шифртекста возвращает пустой результат, как SunJCE")
    void cbcDecryptionOfEmptyInputReturnsEmpty() throws Exception {
        Algorithm algorithm = STREAM_AND_CBC[3];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);

        assertEquals(
                0,
                newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv).doFinal().length,
                "doFinal() без данных должен вернуть пустой результат");
        try (javax.crypto.CipherInputStream in =
                new javax.crypto.CipherInputStream(
                        new java.io.ByteArrayInputStream(new byte[0]),
                        newCipher(algorithm, Cipher.DECRYPT_MODE, key, iv))) {
            assertEquals(
                    0,
                    in.readAllBytes().length,
                    "Чтение пустого потока не должно завершаться ошибкой");
        }
    }

    @Test
    @DisplayName("CBC/NoPadding: отказ из-за длины после update блокирует шифр до нового init")
    void cbcEncryptionRejectedAfterUpdateBlocksUntilReinit() throws Exception {
        Algorithm algorithm = STREAM_AND_CBC[5];
        GostSecretKey key = newKey();
        byte[] iv = newIv(algorithm);
        Cipher cipher = newCipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);

        // update пропустил блок через регистр цепочки: отбросить хвост и продолжить нельзя,
        // иначе сообщение молча потеряло бы середину
        assertEquals(16, cipher.update(randomBytes(16)).length, "update должен выдать блок");
        assertThrows(
                javax.crypto.IllegalBlockSizeException.class,
                () -> cipher.doFinal(new byte[1]),
                "Длина не кратная блоку должна отвергаться");
        assertThrows(
                IllegalStateException.class,
                () -> cipher.doFinal(new byte[16]),
                "После отказа при сдвинутом регистре шифр требует нового init");

        // update уже выдал шифртекст, поэтому пара использована, хотя doFinal потом упал:
        // commit не откатывается при последующей ошибке
        assertThrows(
                java.security.InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)),
                "Пара с выданным update шифртекстом остаётся использованной");

        byte[] freshIv = newIv(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(freshIv));
        byte[] message = randomBytes(32);
        byte[] ciphertext = cipher.doFinal(message);
        // Мусор на выходе длину бы прошёл: проверяем расшифрованием
        assertArrayEquals(
                message,
                newCipher(algorithm, Cipher.DECRYPT_MODE, key, freshIv).doFinal(ciphertext),
                "После init с новым IV шифр работает");
    }

    // -----------------------------------------------------------------------
    // MGM
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "MGM: расшифрование тоже требует нового init после doFinal, в том числе после ошибки тега")
    void mgmRequiresInitAfterAnyOutcome() throws Exception {
        GostSecretKey key = newKey();
        byte[] icn = newIv(MGM);
        byte[] plaintext = randomBytes(20);
        byte[] ciphertext = newCipher(MGM, Cipher.ENCRYPT_MODE, key, icn).doFinal(plaintext);

        Cipher decryptor = newCipher(MGM, Cipher.DECRYPT_MODE, key, icn);
        assertArrayEquals(plaintext, decryptor.doFinal(ciphertext), "Первое расшифрование");
        assertThrows(
                IllegalStateException.class,
                () -> decryptor.doFinal(ciphertext),
                "Повторное расшифрование MGM без init не допускается");

        byte[] corrupted = ciphertext.clone();
        corrupted[0] ^= 1;
        Cipher failing = newCipher(MGM, Cipher.DECRYPT_MODE, key, icn);
        assertThrows(
                AEADBadTagException.class,
                () -> failing.doFinal(corrupted),
                "Испорченный шифртекст должен давать ошибку тега");
        assertThrows(
                IllegalStateException.class,
                () -> failing.doFinal(ciphertext),
                "После ошибки тега шифр требует нового init");
    }

    @Test
    @DisplayName("MGM: update после doFinal сразу бросает, а не копит данные до следующего doFinal")
    void mgmUpdateAfterDoFinalFailsImmediately() throws Exception {
        GostSecretKey key = newKey();
        byte[] icn = newIv(MGM);
        Cipher cipher = newCipher(MGM, Cipher.ENCRYPT_MODE, key, icn);
        cipher.doFinal(randomBytes(20));

        assertThrows(
                IllegalStateException.class,
                () -> cipher.update(randomBytes(20)),
                "update после завершения должен бросать исключение немедленно");
    }

    @Test
    @DisplayName(
            "MGM: пустые открытый текст и AAD отвергаются, пустой открытый текст с AAD работает")
    void mgmEmptyPlaintextAndEmptyAad() throws Exception {
        GostSecretKey key = newKey();
        byte[] icn = newIv(MGM);

        Cipher encryptor = newCipher(MGM, Cipher.ENCRYPT_MODE, key, icn);
        assertThrows(
                IllegalArgumentException.class,
                encryptor::doFinal,
                "Пустые P и A одновременно должны отвергаться (RFC 9058 §6)");

        // Перехваченный тег пустого сообщения не должен приниматься ни под каким ICN
        Cipher decryptor = newCipher(MGM, Cipher.DECRYPT_MODE, key, icn);
        assertThrows(
                AEADBadTagException.class,
                () -> decryptor.doFinal(new byte[16]),
                "Пустое сообщение без AAD не должно аутентифицироваться");

        byte[] aad = {1, 2, 3};
        Cipher withAad = newCipher(MGM, Cipher.ENCRYPT_MODE, key, icn);
        withAad.updateAAD(aad);
        byte[] tagOnly = withAad.doFinal();
        assertEquals(16, tagOnly.length, "Только тег");
        Cipher verifier = newCipher(MGM, Cipher.DECRYPT_MODE, key, icn);
        verifier.updateAAD(aad);
        assertEquals(0, verifier.doFinal(tagOnly).length, "Пустой открытый текст с AAD проходит");
    }

    @Test
    @DisplayName(
            "MGM: CipherOutputStream без данных и без AAD бросает IllegalArgumentException при close()")
    void mgmCipherOutputStreamWithoutDataFailsLoudly() throws Exception {
        GostSecretKey key = newKey();
        byte[] icn = newIv(MGM);
        java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
        Cipher encryptor = newCipher(MGM, Cipher.ENCRYPT_MODE, key, icn);

        // Проверяемые исключения close() проглатывает молча, а это нет: пустое сообщение
        // без AAD не должно превращаться в «успешно зашифрованный» пустой вывод
        javax.crypto.CipherOutputStream stream =
                new javax.crypto.CipherOutputStream(sink, encryptor);
        try {
            assertThrows(
                    IllegalArgumentException.class,
                    stream::close,
                    "close() пустого MGM-потока без AAD должен бросать исключение");
        } finally {
            // Нижний поток при такой ошибке закрывает вызывающий; судить, закрыл ли его JDK,
            // тест не должен: это деталь реализации конкретной версии JDK
            sink.close();
        }
        assertEquals(0, sink.size(), "В нижний поток ничего не должно быть записано");
    }

    // -----------------------------------------------------------------------
    // Padding только для CBC
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @org.junit.jupiter.params.provider.ValueSource(strings = {"CTR", "CFB", "OFB"})
    @DisplayName("padding для потокового режима отвергается при getInstance")
    void paddingIsRejectedForStreamModesByGetInstance(String mode) {
        for (String padding : new String[] {"PKCS5Padding", "PKCS7Padding", "ISO7816-4"}) {
            assertThrows(
                    NoSuchPaddingException.class,
                    () -> Cipher.getInstance("Kuznyechik/" + mode + "/" + padding, PROVIDER),
                    "Kuznyechik/" + mode + "/" + padding + " не должен создаваться");
        }
        assertDoesNotThrow(() -> Cipher.getInstance("Kuznyechik/" + mode + "/NoPadding", PROVIDER));
    }

    @Test
    @DisplayName("setMode и setPadding в любом порядке: несовместимое сочетание отвергается")
    void paddingAndModeOrderDoesNotMatter() throws Exception {
        GostSecretKey key = newKey();

        // Режим выбран раньше padding: отказ сразу
        GostCipherSpi modeFirst = new GostCipherSpi();
        modeFirst.engineSetMode("CTR");
        assertThrows(
                NoSuchPaddingException.class,
                () -> modeFirst.engineSetPadding("PKCS5Padding"),
                "CTR + PKCS5Padding должно отвергаться при setPadding");

        // Padding выбран раньше режима: отказ в init (точка использования)
        GostCipherSpi paddingFirst = new GostCipherSpi();
        paddingFirst.engineSetPadding("PKCS5Padding");
        paddingFirst.engineSetMode("CTR");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                        paddingFirst.engineInit(
                                Cipher.ENCRYPT_MODE,
                                key,
                                new IvParameterSpec(new byte[8]),
                                CryptoRandom.INSTANCE),
                "CTR + PKCS5Padding должно отвергаться при init");

        // Совместимый порядок: padding, затем CBC
        GostCipherSpi cbc = new GostCipherSpi();
        cbc.engineSetPadding("PKCS5Padding");
        cbc.engineSetMode("CBC");
        assertDoesNotThrow(
                () ->
                        cbc.engineInit(
                                Cipher.ENCRYPT_MODE,
                                key,
                                new IvParameterSpec(new byte[16]),
                                CryptoRandom.INSTANCE),
                "PKCS5Padding + CBC допустимо");
    }
}
