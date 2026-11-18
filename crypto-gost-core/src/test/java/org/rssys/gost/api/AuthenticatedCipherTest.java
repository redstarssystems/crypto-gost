package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.TestHex;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты для AuthenticatedCipher.
 *
 * <p>Тест-векторы для OpenSSL-совместимости вычислены и верифицированы через:
 * <pre>
 *   openssl enc -kuznyechik-ctr -nosalt -nopad -d -K &lt;key&gt; -iv &lt;iv&gt; ...
 *   openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc -macopt hexkey:&lt;key&gt; ...
 * </pre>
 */
@DisplayName("AuthenticatedCipher: тесты")
class AuthenticatedCipherTest {

    /** Ключ для тестов: байты 0x01..0x20 */
    private static final byte[] KEY_BYTES = new byte[32];

    static {
        for (int i = 0; i < 32; i++) KEY_BYTES[i] = (byte) (i + 1);
    }

    private static SymmetricKey testKey() {
        return new SymmetricKey(KEY_BYTES);
    }

    private static final int VERSION_LEN = 1;
    private static final int SALT_LEN = 16;
    private static final int TAG_LEN = 16;
    private static final int TAG_OFFSET = VERSION_LEN + SALT_LEN;
    private static final int CIPHERTEXT_OFFSET = TAG_OFFSET + TAG_LEN;
    private static final byte[] PLAINTEXT = "integrity test".getBytes(StandardCharsets.UTF_8);

    private static byte[] fromHex(String hex) {
        return TestHex.bytes(hex);
    }

    // -----------------------------------------------------------------------
    // Roundtrip
    // -----------------------------------------------------------------------

    /** Эталонные оболочки над диапазонными помощниками пакета: целый массив на входе и выходе. */
    private static byte[] ctr(byte[] data, SymmetricKey key, byte[] iv) {
        byte[] out = new byte[data.length];
        AuthenticatedCipher.ctrEncrypt(data, 0, data.length, out, 0, key, iv);
        return out;
    }

    private static byte[] cmac(byte[] aad, byte[] data, SymmetricKey key) {
        byte[] tag = new byte[TAG_LEN];
        AuthenticatedCipher.computeCmac(
                aad, aad == null ? 0 : aad.length, data, 0, data.length, key, tag, 0);
        return tag;
    }

    @Test
    @DisplayName("seal/open: круговая проверка")
    void testSealOpenRoundtrip() throws Exception {
        byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes("UTF-8");
        SymmetricKey key = testKey();

        byte[] packet = AuthenticatedCipher.seal(plaintext, key);
        byte[] restored = AuthenticatedCipher.open(packet, key);

        assertArrayEquals(plaintext, restored);
    }

    @Test
    @DisplayName("seal: каждый вызов даёт разный пакет (случайная соль)")
    void testSealRandomSalt() {
        SymmetricKey key = testKey();

        byte[] p1 = AuthenticatedCipher.seal(PLAINTEXT, key);
        byte[] p2 = AuthenticatedCipher.seal(PLAINTEXT, key);

        assertFalse(Arrays.equals(p1, p2), "Соль случайна — пакеты должны отличаться");
        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(p1, VERSION_LEN, TAG_OFFSET),
                        Arrays.copyOfRange(p2, VERSION_LEN, TAG_OFFSET)),
                "Соли двух сообщений должны отличаться");
    }

    @Test
    @DisplayName("seal: шифртексты одного открытого текста различаются (гамма зависит от соли)")
    void testCiphertextDiffersForSamePlaintext() {
        SymmetricKey key = testKey();

        byte[] p1 = AuthenticatedCipher.seal(PLAINTEXT, key);
        byte[] p2 = AuthenticatedCipher.seal(PLAINTEXT, key);

        byte[] ct1 = Arrays.copyOfRange(p1, CIPHERTEXT_OFFSET, p1.length);
        byte[] ct2 = Arrays.copyOfRange(p2, CIPHERTEXT_OFFSET, p2.length);
        assertFalse(
                Arrays.equals(ct1, ct2),
                "При одном ключе и одинаковом открытом тексте шифртексты должны различаться:"
                        + " иначе гамма повторяется");
    }

    @Test
    @DisplayName("seal: версия 0x01, длина пакета = MIN_PACKET_LEN + длина открытого текста")
    void testPacketLayout() {
        byte[] plaintext = new byte[43];
        byte[] packet = AuthenticatedCipher.seal(plaintext, testKey());

        assertEquals(0x01, packet[0], "Первый байт пакета — версия формата");
        assertEquals(
                AuthenticatedCipher.MIN_PACKET_LEN + 43,
                packet.length,
                "overhead = версия(1) + соль(16) + тег(16)");
        assertEquals(33, AuthenticatedCipher.MIN_PACKET_LEN);
    }

    @Test
    @DisplayName("seal/open: пустые данные, пакет ровно минимальной длины")
    void testEmptyPlaintext() throws Exception {
        byte[] packet = AuthenticatedCipher.seal(new byte[0], testKey());
        assertEquals(AuthenticatedCipher.MIN_PACKET_LEN, packet.length);

        byte[] restored = AuthenticatedCipher.open(packet, testKey());

        assertArrayEquals(new byte[0], restored);
    }

    @Test
    @DisplayName("seal не изменяет ключ вызывающего")
    void testSealDoesNotDestroyCallerKey() throws Exception {
        SymmetricKey key = testKey();
        AuthenticatedCipher.seal(PLAINTEXT, key);

        assertArrayEquals(KEY_BYTES, key.getKey(), "Мастер-ключ должен остаться нетронутым");
        assertArrayEquals(
                PLAINTEXT, AuthenticatedCipher.open(AuthenticatedCipher.seal(PLAINTEXT, key), key));
    }

    // -----------------------------------------------------------------------
    // Обнаружение нарушений целостности
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("open: изменение любого байта пакета -> AuthenticationException")
    void testChangeAnyByte() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());

        for (int i = 0; i < packet.length; i++) {
            byte[] corrupted = packet.clone();
            corrupted[i] ^= 0x01;
            int position = i;
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(corrupted, testKey()),
                    "Изменение байта " + position + " должно обнаруживаться");
        }
    }

    @Test
    @DisplayName("open: изменение версии -> отказ без разбора пакета")
    void testChangedVersion() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());
        packet[0] = 0x02;

        AuthenticationException e =
                assertThrows(
                        AuthenticationException.class,
                        () -> AuthenticatedCipher.open(packet, testKey()));

        assertTrue(e.getMessage().contains("version"), "Причина отказа — версия формата");
    }

    @Test
    @DisplayName("open: изменение соли -> отказ (другие ключи, CMAC не совпадает)")
    void testChangedSalt() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());
        packet[VERSION_LEN] ^= 0x01;

        assertThrows(
                AuthenticationException.class, () -> AuthenticatedCipher.open(packet, testKey()));
    }

    @Test
    @DisplayName("open: изменение тега -> отказ")
    void testChangedTag() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());
        packet[TAG_OFFSET] ^= 0x01;

        assertThrows(
                AuthenticationException.class, () -> AuthenticatedCipher.open(packet, testKey()));
    }

    @Test
    @DisplayName("open: изменение шифртекста -> отказ до расшифрования")
    void testChangedCiphertext() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());
        packet[CIPHERTEXT_OFFSET] ^= 0x42;

        assertThrows(
                AuthenticationException.class, () -> AuthenticatedCipher.open(packet, testKey()));
    }

    @Test
    @DisplayName("seal и open: мастер-ключ не 32 байта -> IllegalArgumentException")
    void testWrongKeyLengthRejected() throws Exception {
        byte[] validPacket = AuthenticatedCipher.seal(PLAINTEXT, testKey());

        for (int length : new int[] {1, 16, 31, 33, 64}) {
            SymmetricKey badKey = new SymmetricKey(new byte[length]);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AuthenticatedCipher.seal(PLAINTEXT, badKey),
                    "seal принял ключ длиной " + length + " байт");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AuthenticatedCipher.seal(new byte[0], badKey),
                    "seal пустого текста принял ключ длиной " + length + " байт");
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AuthenticatedCipher.open(validPacket, badKey),
                    "open принял ключ длиной " + length + " байт");
        }
        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(validPacket, testKey()),
                "Ключ в 32 байта должен продолжать работать");
    }

    @Test
    @DisplayName("seal: уничтоженный ключ -> IllegalStateException, как и раньше")
    void testDestroyedKeyRejected() {
        SymmetricKey key = testKey();
        key.destroy();

        assertThrows(IllegalStateException.class, () -> AuthenticatedCipher.seal(PLAINTEXT, key));
    }

    @Test
    @DisplayName("open: перестановка тега, соли или шифртекста между валидными пакетами -> отказ")
    void testFieldSwapBetweenValidPackets() {
        SymmetricKey key = testKey();
        byte[] a = AuthenticatedCipher.seal(PLAINTEXT, key);
        byte[] b = AuthenticatedCipher.seal(PLAINTEXT, key);

        byte[] withTagOfB = a.clone();
        System.arraycopy(b, TAG_OFFSET, withTagOfB, TAG_OFFSET, TAG_LEN);
        byte[] withSaltOfB = a.clone();
        System.arraycopy(b, VERSION_LEN, withSaltOfB, VERSION_LEN, SALT_LEN);
        byte[] withCiphertextOfB = a.clone();
        System.arraycopy(
                b,
                CIPHERTEXT_OFFSET,
                withCiphertextOfB,
                CIPHERTEXT_OFFSET,
                b.length - CIPHERTEXT_OFFSET);

        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(withTagOfB, key),
                "Тег другого пакета должен быть отвергнут");
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(withSaltOfB, key),
                "Соль другого пакета должна быть отвергнута");
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(withCiphertextOfB, key),
                "Шифртекст другого пакета должен быть отвергнут");
    }

    @Test
    @DisplayName("open: неверный ключ -> AuthenticationException")
    void testWrongKey() {
        byte[] packet = AuthenticatedCipher.seal("secret message".getBytes(), testKey());

        SymmetricKey wrongKey = KeyGenerator.generateSymmetricKey();
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(packet, wrongKey),
                "Неверный ключ -> CMAC не совпадёт");
        wrongKey.destroy();
    }

    @Test
    @DisplayName("open: пустой пакет -> AuthenticationException")
    void testEmptyPacket() {
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(new byte[0], testKey()));
    }

    @Test
    @DisplayName("seal и open: null вместо данных или ключа -> NullPointerException")
    void testNullArgumentsRejected() {
        byte[] packet = AuthenticatedCipher.seal(new byte[16], testKey());
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedCipher.open(null, testKey()),
                "open: пакет null это ошибка вызова, а не нарушение целостности");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedCipher.open(packet, null),
                "open: ключ null");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedCipher.seal(null, testKey()),
                "seal: открытый текст null");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedCipher.seal(new byte[16], null),
                "seal: ключ null");
    }

    @Test
    @DisplayName("open: пакет короче минимального на байт -> AuthenticationException")
    void testPacketOneByteBelowMinimum() {
        byte[] shortPacket = new byte[AuthenticatedCipher.MIN_PACKET_LEN - 1];
        shortPacket[0] = AuthenticatedCipher.VERSION;

        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(shortPacket, testKey()));
    }

    @Test
    @DisplayName("open: усечение пакета на каждом поле -> AuthenticationException")
    void testTruncationAtEveryField() {
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey());
        // версия, середина соли, середина тега, середина шифртекста, последний байт
        int[] lengths = {
            VERSION_LEN,
            VERSION_LEN + SALT_LEN / 2,
            TAG_OFFSET + TAG_LEN / 2,
            CIPHERTEXT_OFFSET + PLAINTEXT.length / 2,
            packet.length - 1
        };
        for (int length : lengths) {
            byte[] truncated = Arrays.copyOf(packet, length);
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(truncated, testKey()),
                    "Усечение до " + length + " байт должно отвергаться");
        }
    }

    @Test
    @DisplayName("open: пакет прежнего формата (IV 8 + тег 16 + шифртекст) не принимается")
    void testLegacyFormatRejected() {
        byte[] legacy = new byte[8 + 16 + 20];
        // Ни при каком значении первого байта прежний пакет не должен открыться.
        for (int first = 0; first < 256; first++) {
            legacy[0] = (byte) first;
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(legacy, testKey()),
                    "Пакет прежнего формата с первым байтом " + first);
        }
    }

    @Test
    @DisplayName("open: настоящий пакет формата 0.7.1 (один ключ, IV 8) не принимается")
    void testRealLegacyPacketRejected() {
        SymmetricKey key = testKey();
        // Алгоритм 0.7.1: CTR на мастер-ключе со случайным IV, CMAC(IV ‖ шифртекст) на том же
        // ключе, пакет [IV(8)] [CMAC(16)] [шифртекст]. Первый байт IV перебирается, включая
        // значение версии 0x01: такой пакет должен отвергаться тегом, а не разбором.
        for (int first = 0; first < 256; first++) {
            byte[] iv = fromHex("0102030405060708");
            iv[0] = (byte) first;
            byte[] ciphertext = ctr(PLAINTEXT, key, iv);
            byte[] tag = cmac(iv, ciphertext, key);

            byte[] legacy = new byte[8 + TAG_LEN + ciphertext.length];
            System.arraycopy(iv, 0, legacy, 0, 8);
            System.arraycopy(tag, 0, legacy, 8, TAG_LEN);
            System.arraycopy(ciphertext, 0, legacy, 8 + TAG_LEN, ciphertext.length);

            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(legacy, testKey()),
                    "Настоящий пакет 0.7.1 с первым байтом IV " + first + " не должен открываться");
        }
    }

    // -----------------------------------------------------------------------
    // Инварианты конструкции
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("deriveKeyPair: ключи CMAC и CTR различны и зависят от соли")
    void testDerivedKeysDiffer() {
        byte[] label = "auth-cipher-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] saltA = new byte[SALT_LEN];
        byte[] saltB = new byte[SALT_LEN];
        saltB[0] = 1;
        SymmetricKey[] a = new SymmetricKey[2];
        SymmetricKey[] b = new SymmetricKey[2];

        AuthenticatedCipher.deriveKeyPair(testKey(), label, saltA, a);
        AuthenticatedCipher.deriveKeyPair(testKey(), label, saltB, b);

        assertFalse(Arrays.equals(a[0].getKey(), a[1].getKey()), "Ключи CMAC и CTR совпали");
        assertFalse(Arrays.equals(a[0].getKey(), b[0].getKey()), "Ключ CMAC не зависит от соли");
        assertFalse(Arrays.equals(a[1].getKey(), b[1].getKey()), "Ключ CTR не зависит от соли");
        assertFalse(Arrays.equals(a[0].getKey(), KEY_BYTES), "Ключ CMAC совпал с мастер-ключом");
        assertFalse(Arrays.equals(a[1].getKey(), KEY_BYTES), "Ключ CTR совпал с мастер-ключом");
    }

    @Test
    @DisplayName("deriveKeyPair: метка KDF разделяет назначения (AuthenticatedStream и Cipher)")
    void testLabelSeparatesKeys() {
        byte[] salt = new byte[SALT_LEN];
        SymmetricKey[] cipherKeys = new SymmetricKey[2];
        SymmetricKey[] streamKeys = new SymmetricKey[2];

        // Метки берутся из рабочих констант: при смене метки тест продолжает проверять настоящую
        AuthenticatedCipher.deriveKeyPair(
                testKey(),
                AuthenticatedCipher.KDF_LABEL_NAME.getBytes(StandardCharsets.US_ASCII),
                salt,
                cipherKeys);
        AuthenticatedCipher.deriveKeyPair(
                testKey(),
                AuthenticatedStream.KDF_LABEL_NAME.getBytes(StandardCharsets.US_ASCII),
                salt,
                streamKeys);

        assertFalse(
                Arrays.equals(cipherKeys[0].getKey(), streamKeys[0].getKey()),
                "Одинаковая затравка с разными метками не должна давать одинаковые ключи");
    }

    // -----------------------------------------------------------------------
    // Независимая сборка пакета из примитивов (формат и вывод ключей)
    // -----------------------------------------------------------------------

    /**
     * Пакет текущего формата без внешнего AAD, снятый рабочим {@code seal} до появления AAD
     * (ревизия 6aea5404): ключ - байты 0x01..0x20, открытый текст - "integrity test". Закрепляет,
     * что пакеты без AAD по-прежнему читаются.
     */
    private static final String PACKET_OF_CURRENT_FORMAT =
            "01df5930e31fb2db33a367a4bc2ff6c29bbbf693d619ecfd01e641c4aef86bf8023795508675885cdeb31d58"
                    + "ed941b";

    /**
     * Эталонный пакет с внешним AAD: ключ 0x01..0x20, соль 00..0f, открытый текст "integrity
     * test", AAD - ASCII-строка "invoice-2026-0417". Собран {@link #assemblePacket} из
     * примитивов, затравка KDF - {@code соль ‖ aad}.
     */
    private static final String FROZEN_PACKET_WITH_AAD =
            "01000102030405060708090a0b0c0d0e0f567420e291f7178c80c7d14e428cdbc63044043db0ad0c"
                    + "a7f0403feced19";

    private static final byte[] FROZEN_AAD =
            "invoice-2026-0417".getBytes(StandardCharsets.US_ASCII);

    /**
     * Собирает пакет по описанию формата: вывод ключей через KDF_TREE от затравки {@code соль ‖
     * aad} независим от кода {@code AuthenticatedCipher}, сборка пакета тоже. {@code ctr} и
     * {@code cmac} - обёртки над кодом {@code AuthenticatedCipher}: они закрыты векторами OpenSSL
     * ниже. Внешний AAD в пакет и в тег не попадает.
     */
    private static byte[] assemblePacket(byte[] salt, byte[] aad, byte[] plaintext) {
        byte[] header = new byte[VERSION_LEN + SALT_LEN];
        header[0] = 0x01;
        System.arraycopy(salt, 0, header, VERSION_LEN, SALT_LEN);

        byte[] seed = Arrays.copyOf(salt, salt.length + aad.length);
        System.arraycopy(aad, 0, seed, salt.length, aad.length);
        byte[] material =
                KdfTreeGostR3411_2012_256.generate(
                        KEY_BYTES,
                        "auth-cipher-v1".getBytes(StandardCharsets.US_ASCII),
                        seed,
                        2,
                        32);
        SymmetricKey cmacKey = new SymmetricKey(Arrays.copyOfRange(material, 0, 32));
        SymmetricKey ctrKey = new SymmetricKey(Arrays.copyOfRange(material, 32, 64));

        byte[] ciphertext = ctr(plaintext, ctrKey, new byte[8]);
        byte[] tag = cmac(header, ciphertext, cmacKey);

        byte[] packet = new byte[CIPHERTEXT_OFFSET + ciphertext.length];
        System.arraycopy(header, 0, packet, 0, header.length);
        System.arraycopy(tag, 0, packet, TAG_OFFSET, TAG_LEN);
        System.arraycopy(ciphertext, 0, packet, CIPHERTEXT_OFFSET, ciphertext.length);
        return packet;
    }

    @Test
    @DisplayName("формат: пакет, собранный из примитивов без AAD, открывается всеми формами open")
    void testPacketAssembledFromPrimitives() throws Exception {
        byte[] salt = fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] packet = assemblePacket(salt, new byte[0], PLAINTEXT);

        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(packet, testKey()),
                "Пакет, собранный из примитивов по описанию формата, должен открываться");
        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(packet, testKey(), new byte[0]),
                "Пустой AAD равнозначен короткой форме");
        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(packet, testKey(), null),
                "null вместо AAD равнозначен пустому");
    }

    @Test
    @DisplayName("формат: пакет, собранный из примитивов с AAD, открывается только с тем же AAD")
    void testPacketWithAadAssembledFromPrimitives() throws Exception {
        byte[] salt = fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] packet = assemblePacket(salt, FROZEN_AAD, PLAINTEXT);

        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(packet, testKey(), FROZEN_AAD),
                "Пакет с AAD должен открываться с тем же AAD");
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(packet, testKey()),
                "Без AAD пакет с AAD открываться не должен");
    }

    @Test
    @DisplayName("замороженный пакет текущего формата без AAD читается всеми формами open")
    void testPacketOfCurrentFormatIsStillReadable() throws Exception {
        byte[] packet = fromHex(PACKET_OF_CURRENT_FORMAT);

        assertArrayEquals(PLAINTEXT, AuthenticatedCipher.open(packet, testKey()), "короткая форма");
        assertArrayEquals(
                PLAINTEXT, AuthenticatedCipher.open(packet, testKey(), new byte[0]), "пустой AAD");
        assertArrayEquals(
                PLAINTEXT, AuthenticatedCipher.open(packet, testKey(), null), "null вместо AAD");
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(packet, testKey(), FROZEN_AAD),
                "Непустой AAD у читателя пакета без AAD: отказ");
    }

    @Test
    @DisplayName(
            "замороженный пакет с AAD: эталон совпадает с записью, open читает, чужой AAD отвергает")
    void testFrozenPacketWithAad() throws Exception {
        byte[] salt = fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] reference = assemblePacket(salt, FROZEN_AAD, PLAINTEXT);
        assertEquals(
                FROZEN_PACKET_WITH_AAD,
                TestHex.string(reference),
                "эталонная сборка с AAD изменилась");

        byte[] frozen = fromHex(FROZEN_PACKET_WITH_AAD);
        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(frozen, testKey(), FROZEN_AAD),
                "открытый текст замороженного пакета");
        byte[] otherAad = "invoice-2026-0418".getBytes(StandardCharsets.US_ASCII);
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(frozen, testKey(), otherAad),
                "Другой AAD: отказ");
    }

    @Test
    @DisplayName("seal с AAD: пакет побайтно совпадает с эталонной сборкой по той же соли")
    void testSealMatchesReferenceAssembly() {
        int[] aadLengths = {0, 1, 16, 100};
        for (int aadLength : aadLengths) {
            byte[] aad = new byte[aadLength];
            for (int i = 0; i < aadLength; i++) aad[i] = (byte) (0x30 + i);

            byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey(), aad);
            byte[] salt = Arrays.copyOfRange(packet, VERSION_LEN, VERSION_LEN + SALT_LEN);

            assertArrayEquals(
                    assemblePacket(salt, aad, PLAINTEXT),
                    packet,
                    "пакет seal при длине AAD " + aadLength + " должен совпасть с эталоном");
        }
        // null равнозначен пустому AAD: тот же эталон без AAD
        byte[] withNull = AuthenticatedCipher.seal(PLAINTEXT, testKey(), null);
        byte[] salt = Arrays.copyOfRange(withNull, VERSION_LEN, VERSION_LEN + SALT_LEN);
        assertArrayEquals(
                assemblePacket(salt, new byte[0], PLAINTEXT), withNull, "null вместо AAD");
    }

    @Test
    @DisplayName("open: неверный AAD даёт AuthenticationException, в том числе при пустом тексте")
    void testWrongAadIsRejected() throws Exception {
        byte[] aad = "context-A".getBytes(StandardCharsets.US_ASCII);
        byte[] otherAad = "context-B".getBytes(StandardCharsets.US_ASCII);
        for (byte[] plaintext : new byte[][] {new byte[0], PLAINTEXT}) {
            byte[] withAad = AuthenticatedCipher.seal(plaintext, testKey(), aad);
            byte[] withoutAad = AuthenticatedCipher.seal(plaintext, testKey());
            String where = "длина текста " + plaintext.length;

            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(withAad, testKey(), otherAad),
                    "другой AAD, " + where);
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(withAad, testKey(), new byte[0]),
                    "пустой вместо заданного, " + where);
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(withAad, testKey()),
                    "короткая форма вместо заданного, " + where);
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedCipher.open(withoutAad, testKey(), aad),
                    "заданный вместо пустого, " + where);
            assertArrayEquals(
                    plaintext,
                    AuthenticatedCipher.open(withAad, testKey(), aad),
                    "верный AAD, " + where);
        }
    }

    @Test
    @DisplayName("seal и open: null и пустой AAD взаимозаменяемы")
    void testNullAndEmptyAadAreInterchangeable() throws Exception {
        byte[] sealedWithNull = AuthenticatedCipher.seal(PLAINTEXT, testKey(), null);
        byte[] sealedWithEmpty = AuthenticatedCipher.seal(PLAINTEXT, testKey(), new byte[0]);
        byte[] sealedShort = AuthenticatedCipher.seal(PLAINTEXT, testKey());

        for (byte[] packet : new byte[][] {sealedWithNull, sealedWithEmpty, sealedShort}) {
            assertArrayEquals(PLAINTEXT, AuthenticatedCipher.open(packet, testKey(), null), "null");
            assertArrayEquals(
                    PLAINTEXT, AuthenticatedCipher.open(packet, testKey(), new byte[0]), "пустой");
            assertArrayEquals(PLAINTEXT, AuthenticatedCipher.open(packet, testKey()), "короткая");
        }
    }

    @Test
    @DisplayName("seal: правка массива AAD после вызова не влияет на пакет")
    void testAadArrayChangeAfterSealIsIgnored() throws Exception {
        byte[] aad = "original".getBytes(StandardCharsets.US_ASCII);
        byte[] original = aad.clone();
        byte[] packet = AuthenticatedCipher.seal(PLAINTEXT, testKey(), aad);
        Arrays.fill(aad, (byte) 'X');

        assertArrayEquals(
                PLAINTEXT,
                AuthenticatedCipher.open(packet, testKey(), original),
                "исходный AAD открывает пакет");
        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedCipher.open(packet, testKey(), aad),
                "изменённый AAD: отказ");
    }

    @Test
    @DisplayName("seal и open с AAD: круговая проверка для разных длин текста и AAD")
    void testRoundtripWithAad() throws Exception {
        int[] textLengths = {0, 1, 15, 16, 17, 100, 1000};
        int[] aadLengths = {1, 16, 17, 300};
        for (int textLength : textLengths) {
            for (int aadLength : aadLengths) {
                byte[] plaintext = new byte[textLength];
                byte[] aad = new byte[aadLength];
                CryptoRandom.INSTANCE.nextBytes(plaintext);
                CryptoRandom.INSTANCE.nextBytes(aad);

                byte[] packet = AuthenticatedCipher.seal(plaintext, testKey(), aad);
                assertEquals(
                        AuthenticatedCipher.MIN_PACKET_LEN + textLength,
                        packet.length,
                        "AAD не должен увеличивать пакет");
                assertArrayEquals(
                        plaintext,
                        AuthenticatedCipher.open(packet, testKey(), aad),
                        "текст " + textLength + ", AAD " + aadLength);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Совместимость примитивов с OpenSSL (golden vector test)
    //
    // Тест-вектор вычислен и верифицирован через:
    //   key = 0x0102...20 (32 байта)
    //   openssl enc -kuznyechik-ctr -nosalt -nopad -d -K <key> -iv <iv> < ct > pt
    //   openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc -macopt hexkey:<key> pt
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("OpenSSL совместимость примитивов: CTR и CMAC — golden vectors")
    void testOpenSslCompatibilityGoldenVector() throws Exception {
        SymmetricKey key = testKey();
        byte[] plaintext = "The quick brown fox".getBytes("UTF-8");
        byte[] iv = fromHex("0102030405060708");

        // Ожидаемый шифртекст (верифицирован через openssl enc -kuznyechik-ctr -K <key> -iv <iv>)
        byte[] expectedCt = fromHex("7169cd162a3c2f04a8fe48df31958f6b9803dd");
        // Ожидаемый CMAC (верифицирован через openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc
        // -macopt hexkey:<key>)
        byte[] expectedCmac = fromHex("89425a02b25cf9a380b22b89ed1e74de");

        assertArrayEquals(
                expectedCt,
                ctr(plaintext, key, iv),
                "CTR шифртекст должен совпасть с openssl enc -kuznyechik-ctr");
        assertArrayEquals(
                expectedCmac,
                cmac(null, plaintext, key),
                "CMAC должен совпасть с openssl dgst -mac cmac -macopt cipher:kuznyechik-cbc");

        key.destroy();
    }
}
