package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.TestHex;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.kdf.KdfTreeGostR3411_2012_256;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.AuthenticationIOException;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("AuthenticatedStream: раскладка формата, эталонная сборка и непрерывная гамма")
class AuthenticatedStreamFormatTest {

    private static final int KEY_LEN = 32;
    private static final int NONCE_LEN = 16;
    private static final int STREAM_HEADER_LEN = 21;
    private static final int CHUNK_HEADER_LEN = 21;
    private static final byte[] KDF_LABEL = "auth-stream".getBytes(StandardCharsets.US_ASCII);

    /**
     * Поток, записанный выпущенной версией 0.7.1: версия 0x02, nonce 8 байт. Ключ 00..1f, открытый
     * текст 00..27, размер чанка 17. Получен сборкой 0.7.1.
     */
    private static final String STREAM_OF_RELEASED_VERSION =
            "9267d0059766bbdb02000000110000001100fbf7a0ee2ccc7fdf7d9670b90960699cf0ab50e17b821528d4"
                    + "d19dbbd847e164e7ae40318e72b36c5c00000011001253f3593025ce2977c79251029a5939ac5"
                    + "e81481ac6991bb32e151cf34b17240b123421d5225622660000000601637e24329d175e9951f9"
                    + "6ce375553e8b0fc5c41a8783cd917694c14489cd";

    /**
     * Поток раскладки, где версия 0x03 стояла после nonce: nonce 16 байт, версия на смещении 16.
     * Ключ 00..1f, открытый текст 00..27, размер чанка 17. Получен кодом до смены порядка полей.
     */
    private static final String STREAM_OF_PREVIOUS_LAYOUT =
            "3e75e014f4950f6ffc81821faab266de0300000011000000110087ade0ca1155e1e6fd8aa601656b0e09c9"
                    + "7ee889dc0e4b03dcd9478c2eb4633826fd98e2161a8bac4b0000001100e787047b54bd8ad81e1"
                    + "7d252ac7419595e298389412632c2d2b8426a2fd722fe5939b37ad33633b37a00000006011cad"
                    + "1711fb0b49b7f48749114288cba6deb80384179eaf278d54a8d46f0d";

    /**
     * Эталонный поток: ключ 00..1f, nonce a0..af, открытый текст 00..27, размер чанка 17. Собран
     * {@link #referenceStream} из примитивов, не рабочим кодом потока.
     */
    private static final String FROZEN_STREAM =
            "03a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000110000001100471c9245852186b489a7d12a5462"
                    + "05335146dfb1a9a89c253f8f85a329a9c5f06c0000001100cf31cc17cfa156189ae55bcaac1cf1b4"
                    + "f82792980303b23df7f960d8a13f98ff09000000060191cc1e9410c069b2cc1f249b734d90c710b1"
                    + "4337c6f9";

    /**
     * Эталонный поток с внешним AAD: ключ 00..1f, nonce a0..af, открытый текст 00..27, размер
     * чанка 17, AAD - ASCII-строка "report-2026.pdf". Собран {@link #referenceStream} из
     * примитивов, затравка KDF - {@code nonce ‖ aad}.
     */
    private static final String FROZEN_STREAM_WITH_AAD =
            "03a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000110000001100b9d6e20f718a9b6b6688071462ec"
                    + "33b977a75ba502d88f3429279040fe80c16530000000110059eb782151d0a33aaf29ae6fb566bf3a"
                    + "244b5b750f03667a419a1486aaa412540c00000006014f6aebb329043292154338cf2f306ed95307"
                    + "12e7e326";

    private static final byte[] FROZEN_AAD = "report-2026.pdf".getBytes(StandardCharsets.US_ASCII);

    private static byte[] sequentialBytes(int from, int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (from + i);
        }
        return bytes;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    /**
     * Собирает поток по описанию формата только из KDF_TREE, Ctr и Cmac: вспомогательные методы
     * потока не вызываются, иначе эталон проверял бы код сам собой. Гамма берётся одним проходом
     * по всему открытому тексту, чанки нарезаются из готового шифртекста.
     */
    private static byte[] referenceStream(
            byte[] masterKey, byte[] nonce, byte[] plaintext, int chunkSize) {
        return referenceStream(masterKey, nonce, plaintext, chunkSize, new byte[0]);
    }

    /**
     * То же, что четырёхаргументная форма, но внешний AAD входит в затравку KDF: {@code nonce ‖
     * aad}. В заголовок потока и в CMAC он не попадает.
     */
    private static byte[] referenceStream(
            byte[] masterKey, byte[] nonce, byte[] plaintext, int chunkSize, byte[] aad) {
        byte[] seed = Arrays.copyOf(nonce, nonce.length + aad.length);
        System.arraycopy(aad, 0, seed, nonce.length, aad.length);
        byte[] derived = KdfTreeGostR3411_2012_256.generate(masterKey, KDF_LABEL, seed, 2, KEY_LEN);
        SymmetricKey cmacKey = new SymmetricKey(Arrays.copyOfRange(derived, 0, KEY_LEN));
        SymmetricKey ctrKey = new SymmetricKey(Arrays.copyOfRange(derived, KEY_LEN, 2 * KEY_LEN));

        Ctr ctr = new Ctr(new Kuznyechik());
        ctr.init(true, new ParametersWithIV(ctrKey, new byte[8]));
        byte[] ciphertext = new byte[plaintext.length];
        ctr.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

        byte[] header = new byte[STREAM_HEADER_LEN];
        header[0] = 0x03;
        System.arraycopy(nonce, 0, header, 1, NONCE_LEN);
        ByteBuffer.wrap(header).putInt(1 + NONCE_LEN, chunkSize);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.writeBytes(header);
        // Чанк уходит, как только набрал chunkSize байт, поэтому последний (возможно пустой)
        // чанк всегда есть: при кратном объёме он пустой
        int chunkCount = plaintext.length / chunkSize + 1;
        for (int seqNo = 0; seqNo < chunkCount; seqNo++) {
            boolean last = seqNo == chunkCount - 1;
            int offset = seqNo * chunkSize;
            int length = last ? plaintext.length - offset : chunkSize;
            byte flags = last ? (byte) 1 : (byte) 0;

            ByteBuffer chunkAad = ByteBuffer.allocate(9 + (seqNo == 0 ? STREAM_HEADER_LEN : 0));
            chunkAad.putLong(seqNo).put(flags);
            if (seqNo == 0) {
                chunkAad.put(header);
            }
            Cmac cmac = new Cmac(new Kuznyechik());
            cmac.init(cmacKey);
            cmac.update(chunkAad.array(), 0, chunkAad.capacity());
            cmac.update(ciphertext, offset, length);
            byte[] tag = new byte[16];
            cmac.doFinal(tag, 0);

            stream.writeBytes(ByteBuffer.allocate(4).putInt(length).array());
            stream.write(flags);
            stream.writeBytes(tag);
            stream.write(ciphertext, offset, length);
        }
        return stream.toByteArray();
    }

    private static byte[] seal(byte[] plaintext, SymmetricKey key, int chunkSize)
            throws IOException {
        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sealed, key, chunkSize)) {
            out.write(plaintext);
        }
        return sealed.toByteArray();
    }

    private static byte[] sealWithAad(byte[] plaintext, SymmetricKey key, int chunkSize, byte[] aad)
            throws IOException {
        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sealed, key, chunkSize, aad)) {
            out.write(plaintext);
        }
        return sealed.toByteArray();
    }

    /**
     * Открывает поток с заданным AAD и читает до конца. Сам {@code opening} из-за AAD не бросает
     * исключение: читается только заголовок, отказ приходит при первом чтении.
     */
    private static byte[] openWithAad(byte[] stream, SymmetricKey key, byte[] aad)
            throws IOException, AuthenticationException {
        try (InputStream in =
                AuthenticatedStream.opening(new ByteArrayInputStream(stream), key, aad)) {
            return in.readAllBytes();
        }
    }

    /** Проверяет, что чтение с данным AAD отвергнуто по целостности на чанке 0. */
    private static void assertRejectedAtFirstChunk(
            byte[] stream, SymmetricKey key, byte[] aad, String message)
            throws IOException, AuthenticationException {
        InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(stream), key, aad);
        try (in) {
            AuthenticationIOException failure =
                    assertThrows(AuthenticationIOException.class, in::readAllBytes, message);
            assertTrue(
                    failure.getMessage().contains("chunk 0, plaintext offset 0"),
                    message + ": отказ должен указывать чанк 0, а не " + failure.getMessage());
        }
    }

    private static void assertRejected(byte[] stream, SymmetricKey key, String message) {
        Exception failure =
                assertThrows(
                        Exception.class,
                        () -> {
                            try (InputStream in =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(stream), key)) {
                                in.readAllBytes();
                            }
                        },
                        message);
        assertTrue(
                failure instanceof AuthenticationException
                        || failure instanceof AuthenticationIOException,
                message + ": отказ должен быть по целостности, а не " + failure);
    }

    // -----------------------------------------------------------------------
    // Раскладка и эталон
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Рабочий поток побайтно совпадает с эталонной сборкой по тому же nonce")
    void productionStreamMatchesReference() throws Exception {
        int[][] cases = {
            {17, 40}, {16, 32}, {16, 0}, {16, 1}, {31, 100}, {1000, 2500}, {64, 320}, {17, 17}
        };
        for (int[] c : cases) {
            int chunkSize = c[0];
            int length = c[1];
            byte[] masterKey = randomBytes(KEY_LEN);
            byte[] plaintext = randomBytes(length);

            byte[] sealed = seal(plaintext, new SymmetricKey(masterKey), chunkSize);
            byte[] nonce = Arrays.copyOfRange(sealed, 1, 1 + NONCE_LEN);

            assertArrayEquals(
                    referenceStream(masterKey, nonce, plaintext, chunkSize),
                    sealed,
                    "поток для chunkSize=" + chunkSize + ", длина=" + length);
        }
    }

    @Test
    @DisplayName(
            "Замороженный вектор: эталон совпадает с записью, читатель возвращает открытый текст")
    void frozenVectorIsStable() throws Exception {
        byte[] masterKey = sequentialBytes(0, KEY_LEN);
        byte[] nonce = sequentialBytes(0xA0, NONCE_LEN);
        byte[] plaintext = sequentialBytes(0, 40);

        byte[] reference = referenceStream(masterKey, nonce, plaintext, 17);
        assertEquals(FROZEN_STREAM, TestHex.string(reference), "эталонная сборка изменилась");

        byte[] frozen = TestHex.bytes(FROZEN_STREAM);
        try (InputStream in =
                AuthenticatedStream.opening(
                        new ByteArrayInputStream(frozen), new SymmetricKey(masterKey))) {
            assertArrayEquals(plaintext, in.readAllBytes(), "открытый текст замороженного потока");
        }
    }

    // -----------------------------------------------------------------------
    // Внешний AAD: входит в затравку KDF, в поток не пишется
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "С внешним AAD рабочий поток побайтно совпадает с эталонной сборкой по тому же nonce")
    void productionStreamWithAadMatchesReference() throws Exception {
        int[][] cases = {{17, 40}, {16, 0}, {31, 100}, {1000, 2500}, {17, 17}};
        int[] aadLengths = {1, 16, 40, 300};
        for (int[] c : cases) {
            for (int aadLength : aadLengths) {
                int chunkSize = c[0];
                int length = c[1];
                byte[] masterKey = randomBytes(KEY_LEN);
                byte[] plaintext = randomBytes(length);
                byte[] aad = randomBytes(aadLength);

                byte[] sealed = sealWithAad(plaintext, new SymmetricKey(masterKey), chunkSize, aad);
                byte[] nonce = Arrays.copyOfRange(sealed, 1, 1 + NONCE_LEN);

                assertArrayEquals(
                        referenceStream(masterKey, nonce, plaintext, chunkSize, aad),
                        sealed,
                        "поток для chunkSize="
                                + chunkSize
                                + ", длина="
                                + length
                                + ", AAD="
                                + aadLength);
            }
        }
    }

    @Test
    @DisplayName("Пустой и null AAD дают тот же поток, что эталон без AAD по тому же nonce")
    void emptyAndNullAadMatchReferenceWithoutAad() throws Exception {
        for (byte[] aad : new byte[][] {new byte[0], null}) {
            byte[] masterKey = randomBytes(KEY_LEN);
            byte[] plaintext = randomBytes(100);

            byte[] sealed = sealWithAad(plaintext, new SymmetricKey(masterKey), 31, aad);
            byte[] nonce = Arrays.copyOfRange(sealed, 1, 1 + NONCE_LEN);

            assertArrayEquals(
                    referenceStream(masterKey, nonce, plaintext, 31),
                    sealed,
                    "поток с пустым AAD (null="
                            + (aad == null)
                            + ") не должен отличаться от прежнего");
        }
    }

    @Test
    @DisplayName("Замороженный вектор с AAD: эталон совпадает с записью, читатель возвращает текст")
    void frozenVectorWithAadIsStable() throws Exception {
        byte[] masterKey = sequentialBytes(0, KEY_LEN);
        byte[] nonce = sequentialBytes(0xA0, NONCE_LEN);
        byte[] plaintext = sequentialBytes(0, 40);

        byte[] reference = referenceStream(masterKey, nonce, plaintext, 17, FROZEN_AAD);
        assertEquals(
                FROZEN_STREAM_WITH_AAD,
                TestHex.string(reference),
                "эталонная сборка с AAD изменилась");

        SymmetricKey key = new SymmetricKey(masterKey);
        byte[] frozen = TestHex.bytes(FROZEN_STREAM_WITH_AAD);
        assertArrayEquals(
                plaintext,
                openWithAad(frozen, key, FROZEN_AAD),
                "открытый текст замороженного потока");
        assertRejectedAtFirstChunk(
                frozen, key, "report-2026.pdx".getBytes(StandardCharsets.US_ASCII), "другой AAD");
        assertRejectedAtFirstChunk(frozen, key, new byte[0], "пустой AAD вместо заданного");
    }

    @Test
    @DisplayName("Прежний поток без AAD с непустым AAD у читателя отвергается на чанке 0")
    void frozenStreamWithoutAadIsRejectedWithNonEmptyAad() throws Exception {
        SymmetricKey key = new SymmetricKey(sequentialBytes(0, KEY_LEN));
        assertRejectedAtFirstChunk(
                TestHex.bytes(FROZEN_STREAM), key, FROZEN_AAD, "поток без AAD, читатель с AAD");
    }

    @Test
    @DisplayName("Разный AAD при одном nonce даёт разный шифртекст и разные теги")
    void differentAadWithSameNonceGivesDifferentStreams() {
        byte[] masterKey = randomBytes(KEY_LEN);
        byte[] nonce = randomBytes(NONCE_LEN);
        byte[] plaintext = randomBytes(17);

        byte[] first = referenceStream(masterKey, nonce, plaintext, 17, new byte[] {1});
        byte[] second = referenceStream(masterKey, nonce, plaintext, 17, new byte[] {2});
        byte[] none = referenceStream(masterKey, nonce, plaintext, 17);

        int body = STREAM_HEADER_LEN + CHUNK_HEADER_LEN;
        assertArrayEquals(
                Arrays.copyOf(first, STREAM_HEADER_LEN),
                Arrays.copyOf(second, STREAM_HEADER_LEN),
                "заголовок потока от AAD не зависит");
        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(first, body, body + 17),
                        Arrays.copyOfRange(second, body, body + 17)),
                "шифртекст при разном AAD должен различаться: ключ CTR зависит от AAD");
        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(first, body, body + 17),
                        Arrays.copyOfRange(none, body, body + 17)),
                "шифртекст с AAD и без него должен различаться");
        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(first, STREAM_HEADER_LEN + 5, STREAM_HEADER_LEN + 21),
                        Arrays.copyOfRange(second, STREAM_HEADER_LEN + 5, STREAM_HEADER_LEN + 21)),
                "теги при разном AAD должны различаться");
    }

    @Test
    @DisplayName("Неверный AAD отвергается на чанке 0, в том числе у пустого потока")
    void wrongAadIsRejectedAtFirstChunk() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] aad = "context-A".getBytes(StandardCharsets.US_ASCII);
        for (int length : new int[] {0, 5, 100}) {
            byte[] plaintext = randomBytes(length);
            byte[] withAad = sealWithAad(plaintext, key, 17, aad);
            byte[] withoutAad = seal(plaintext, key, 17);
            String where = "длина=" + length;

            assertRejectedAtFirstChunk(
                    withAad,
                    key,
                    "context-B".getBytes(StandardCharsets.US_ASCII),
                    "другой AAD, " + where);
            assertRejectedAtFirstChunk(
                    withAad, key, new byte[0], "пустой вместо заданного, " + where);
            assertRejectedAtFirstChunk(withAad, key, null, "null вместо заданного, " + where);
            assertRejectedAtFirstChunk(withoutAad, key, aad, "заданный вместо пустого, " + where);
            assertArrayEquals(plaintext, openWithAad(withAad, key, aad), "верный AAD, " + where);
        }
    }

    @Test
    @DisplayName("null и пустой AAD взаимозаменяемы между sealing и opening")
    void nullAndEmptyAadAreInterchangeable() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(100);
        byte[] sealedWithNull = sealWithAad(plaintext, key, 31, null);
        byte[] sealedWithEmpty = sealWithAad(plaintext, key, 31, new byte[0]);

        for (byte[] sealed : new byte[][] {sealedWithNull, sealedWithEmpty}) {
            assertArrayEquals(plaintext, openWithAad(sealed, key, null), "читатель с null");
            assertArrayEquals(
                    plaintext, openWithAad(sealed, key, new byte[0]), "читатель с пустым");
            try (InputStream in =
                    AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                assertArrayEquals(plaintext, in.readAllBytes(), "читатель короткой формой");
            }
        }
    }

    @Test
    @DisplayName("sealing(out, key, aad) использует размер чанка по умолчанию и не теряет AAD")
    void sealingWithAadUsesDefaultChunkSize() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] aad = "context".getBytes(StandardCharsets.US_ASCII);
        byte[] plaintext = randomBytes(100);

        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sealed, key, aad)) {
            out.write(plaintext);
        }
        byte[] stream = sealed.toByteArray();

        assertEquals(
                AuthenticatedStream.DEFAULT_CHUNK_SIZE,
                ByteBuffer.wrap(stream).getInt(1 + NONCE_LEN),
                "размер чанка в заголовке");
        assertArrayEquals(plaintext, openWithAad(stream, key, aad), "верный AAD");
        assertRejectedAtFirstChunk(stream, key, new byte[0], "AAD не должен теряться");
    }

    @Test
    @DisplayName("Правка массива AAD после создания потока не меняет результат")
    void aadArrayChangeAfterSealingIsIgnored() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] aad = "original".getBytes(StandardCharsets.US_ASCII);
        byte[] original = aad.clone();
        byte[] plaintext = randomBytes(100);

        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sealed, key, 17, aad)) {
            Arrays.fill(aad, (byte) 'X');
            out.write(plaintext);
        }
        byte[] stream = sealed.toByteArray();

        assertArrayEquals(plaintext, openWithAad(stream, key, original), "исходный AAD");
        assertRejectedAtFirstChunk(stream, key, aad, "изменённый AAD");
    }

    @Test
    @DisplayName("Запись и чтение с AAD туда и обратно для разных размеров чанка и данных")
    void roundtripWithAad() throws Exception {
        int[] chunkSizes = {16, 17, 1000};
        int[] lengths = {0, 1, 16, 17, 100, 2500};
        for (int chunkSize : chunkSizes) {
            for (int length : lengths) {
                SymmetricKey key = KeyGenerator.generateSymmetricKey();
                byte[] plaintext = randomBytes(length);
                byte[] aad = randomBytes(chunkSize % 5 + 1);
                byte[] sealed = sealWithAad(plaintext, key, chunkSize, aad);
                assertArrayEquals(
                        plaintext,
                        openWithAad(sealed, key, aad),
                        "chunkSize=" + chunkSize + ", длина=" + length);
            }
        }
    }

    @Test
    @DisplayName("Накладные расходы: 21 байт на поток и 21 байт на чанк")
    void overheadIsTwentyOneBytesPerStreamAndChunk() throws Exception {
        // 100 байт при чанке 40: два полных чанка и последний из 20 байт
        byte[] sealed = seal(randomBytes(100), KeyGenerator.generateSymmetricKey(), 40);
        assertEquals(21 + 3 * 21 + 100, sealed.length, "заголовок потока, три чанка и данные");
        assertEquals(STREAM_HEADER_LEN, AuthenticatedStream.HEADER_SIZE);
        assertEquals(CHUNK_HEADER_LEN, AuthenticatedStream.CHUNK_HEADER_SIZE);
    }

    // -----------------------------------------------------------------------
    // Непрерывная гамма
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "Два чанка с одинаковым открытым текстом дают разный шифртекст: гамма не сбрасывается")
    void identicalChunksGiveDifferentCiphertext() throws Exception {
        byte[] plaintext = new byte[64];
        Arrays.fill(plaintext, (byte) 0x5A);
        byte[] sealed = seal(plaintext, KeyGenerator.generateSymmetricKey(), 32);

        int firstChunkBody = STREAM_HEADER_LEN + CHUNK_HEADER_LEN;
        int secondChunkBody = firstChunkBody + 32 + CHUNK_HEADER_LEN;
        byte[] first = Arrays.copyOfRange(sealed, firstChunkBody, firstChunkBody + 32);
        byte[] second = Arrays.copyOfRange(sealed, secondChunkBody, secondChunkBody + 32);
        assertFalse(
                Arrays.equals(first, second),
                "одинаковые чанки с одним ключом потока не должны давать одну гамму");
    }

    @Test
    @DisplayName("Размер чанка не кратен 16 (17, 31, 1000): запись и чтение туда и обратно")
    void roundtripWithChunkSizeNotMultipleOfBlock() throws Exception {
        int[] chunkSizes = {17, 31, 1000};
        int[] lengths = {0, 1, 16, 17, 34, 35, 100, 2500, 3000};
        for (int chunkSize : chunkSizes) {
            for (int length : lengths) {
                SymmetricKey key = KeyGenerator.generateSymmetricKey();
                byte[] plaintext = randomBytes(length);
                byte[] sealed = seal(plaintext, key, chunkSize);
                String where = "chunkSize=" + chunkSize + ", длина=" + length;

                try (InputStream in =
                        AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                    assertArrayEquals(plaintext, in.readAllBytes(), "буфером: " + where);
                }
                ByteArrayOutputStream byteByByte = new ByteArrayOutputStream();
                try (InputStream in =
                        AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                    int b;
                    while ((b = in.read()) >= 0) {
                        byteByByte.write(b);
                    }
                }
                assertArrayEquals(plaintext, byteByByte.toByteArray(), "по байту: " + where);
                ByteArrayOutputStream smallBuffer = new ByteArrayOutputStream();
                try (InputStream in =
                        AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                    byte[] buf = new byte[5];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        smallBuffer.write(buf, 0, n);
                    }
                }
                assertArrayEquals(plaintext, smallBuffer.toByteArray(), "малым буфером: " + where);
            }
        }
    }

    @Test
    @DisplayName("Объём кратен размеру чанка: последний чанк пустой и читается без ошибок")
    void emptyLastChunkWhenLengthIsMultipleOfChunkSize() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(64);
        byte[] sealed = seal(plaintext, key, 32);

        assertEquals(
                STREAM_HEADER_LEN + 2 * (CHUNK_HEADER_LEN + 32) + CHUNK_HEADER_LEN,
                sealed.length,
                "два полных чанка и пустой последний");
        int lastChunkStart = STREAM_HEADER_LEN + 2 * (CHUNK_HEADER_LEN + 32);
        assertEquals(0, ByteBuffer.wrap(sealed).getInt(lastChunkStart), "длина последнего чанка");
        assertEquals(AuthenticatedStream.FLAG_LAST, sealed[lastChunkStart + 4], "флаг последнего");
        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            assertArrayEquals(plaintext, in.readAllBytes(), "открытый текст");
        }
    }

    // -----------------------------------------------------------------------
    // Привязка чанка к месту: единственная защита от обмена чанков равной длины
    // -----------------------------------------------------------------------

    /** Четыре полных чанка по 32 байта с разным содержимым и неполный последний из 8 байт. */
    private static final int MIDDLE_CHUNK_SIZE = 32;

    private static final int MIDDLE_CHUNK_TOTAL = CHUNK_HEADER_LEN + MIDDLE_CHUNK_SIZE;

    private static int middleChunkStart(int index) {
        return STREAM_HEADER_LEN + index * MIDDLE_CHUNK_TOTAL;
    }

    private static byte[] middleChunk(byte[] stream, int index) {
        return Arrays.copyOfRange(
                stream, middleChunkStart(index), middleChunkStart(index) + MIDDLE_CHUNK_TOTAL);
    }

    @Test
    @DisplayName("Перестановка двух полных средних чанков равной длины отвергается")
    void swapOfMiddleChunksIsRejected() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(4 * MIDDLE_CHUNK_SIZE + 8), key, MIDDLE_CHUNK_SIZE);

        byte[] swapped = sealed.clone();
        System.arraycopy(
                middleChunk(sealed, 2), 0, swapped, middleChunkStart(1), MIDDLE_CHUNK_TOTAL);
        System.arraycopy(
                middleChunk(sealed, 1), 0, swapped, middleChunkStart(2), MIDDLE_CHUNK_TOTAL);

        assertRejected(
                swapped, key, "чанки 1 и 2 одной длины, без seqNo в AAD обмен прошёл бы по тегу");
    }

    @Test
    @DisplayName("Повтор полного среднего чанка (замена и вставка копии) отвергается")
    void duplicateOfMiddleChunkIsRejected() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(4 * MIDDLE_CHUNK_SIZE + 8), key, MIDDLE_CHUNK_SIZE);

        byte[] replaced = sealed.clone();
        System.arraycopy(
                middleChunk(sealed, 1), 0, replaced, middleChunkStart(2), MIDDLE_CHUNK_TOTAL);
        assertRejected(replaced, key, "копия чанка 1 на месте чанка 2");

        ByteArrayOutputStream inserted = new ByteArrayOutputStream();
        inserted.write(sealed, 0, middleChunkStart(2));
        inserted.writeBytes(middleChunk(sealed, 1));
        inserted.write(sealed, middleChunkStart(2), sealed.length - middleChunkStart(2));
        assertRejected(inserted.toByteArray(), key, "копия чанка 1 вставлена перед чанком 2");
    }

    // -----------------------------------------------------------------------
    // Прежние форматы
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Поток выпущенной версии 0.7.1 (0x02, nonce 8 байт) отвергается")
    void streamOfReleasedVersionIsRejected() {
        SymmetricKey key = new SymmetricKey(sequentialBytes(0, KEY_LEN));
        assertRejected(
                TestHex.bytes(STREAM_OF_RELEASED_VERSION),
                key,
                "поток прежнего выпуска не читается: откатов на старые форматы нет");
    }

    @Test
    @DisplayName("Поток прежней раскладки (версия после nonce) отвергается")
    void streamOfPreviousLayoutIsRejected() {
        SymmetricKey key = new SymmetricKey(sequentialBytes(0, KEY_LEN));
        assertRejected(
                TestHex.bytes(STREAM_OF_PREVIOUS_LAYOUT),
                key,
                "байт 0 старой раскладки - байт nonce, отказ может прийти позже версии");
    }

    // -----------------------------------------------------------------------
    // null
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("sealing и opening: null вместо потока или ключа -> NullPointerException")
    void nullArgumentsAreRejected() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedStream.sealing(null, key),
                "sealing: нижний поток null");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedStream.sealing(OutputStream.nullOutputStream(), null),
                "sealing: ключ null");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedStream.sealing(null, key, 0),
                "sealing: null проверяется раньше размера чанка");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedStream.opening(null, key),
                "opening: нижний поток null");
        assertThrows(
                NullPointerException.class,
                () -> AuthenticatedStream.opening(new ByteArrayInputStream(new byte[0]), null),
                "opening: ключ null");
    }
}
