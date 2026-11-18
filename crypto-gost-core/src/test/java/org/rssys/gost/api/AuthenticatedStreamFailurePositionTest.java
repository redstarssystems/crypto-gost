package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.AuthenticationIOException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Позиция отказа в сообщении AuthenticatedStream: номер чанка с нуля и смещение его открытого
 * текста от начала данных. Значения проверяются точно, а не подстрокой «chunk»: ошибка на единицу
 * (номер после инкремента счётчика, смещение с заголовком потока) иначе прошла бы незамеченной.
 */
@DisplayName("AuthenticatedStream: позиция отказа в сообщении")
class AuthenticatedStreamFailurePositionTest {

    private static final int STREAM_HEADER = AuthenticatedStream.HEADER_SIZE;
    private static final int CHUNK_HEADER = AuthenticatedStream.CHUNK_HEADER_SIZE;

    /** Размер чанка в тестах: 200 байт данных дают чанки 64, 64, 64 и 8 (последний, номер 3). */
    private static final int CHUNK_SIZE = 64;

    private static final int PLAINTEXT_LENGTH = 200;

    /** Полный размер записанного обычного чанка: заголовок чанка и шифртекст. */
    private static final int FULL_CHUNK = CHUNK_HEADER + CHUNK_SIZE;

    /** Результат чтения до отказа: сколько байт открытого текста выдано и чем всё закончилось. */
    private record Outcome(long delivered, Throwable failure) {}

    private static byte[] sealed(SymmetricKey key) throws Exception {
        byte[] plaintext = new byte[PLAINTEXT_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(plaintext);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sink, key, CHUNK_SIZE)) {
            out.write(plaintext);
        }
        return sink.toByteArray();
    }

    /** Смещение первого байта чанка (его заголовка) в записанном потоке. */
    private static int chunkStart(int chunkIndex) {
        return STREAM_HEADER + chunkIndex * FULL_CHUNK;
    }

    /** Читает поток порциями, пока не случится отказ, и считает выданные байты. */
    private static Outcome readUntilFailure(byte[] sealed, SymmetricKey key) throws Exception {
        long delivered = 0;
        byte[] buffer = new byte[16];
        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            while (true) {
                int read = in.read(buffer);
                if (read < 0) {
                    return new Outcome(delivered, null);
                }
                delivered += read;
            }
        } catch (AuthenticationIOException failure) {
            return new Outcome(delivered, failure);
        }
    }

    private static String message(Outcome outcome) {
        assertInstanceOf(
                AuthenticationIOException.class, outcome.failure(), "ожидался отказ целостности");
        assertInstanceOf(
                AuthenticationException.class,
                outcome.failure().getCause(),
                "причиной должна быть AuthenticationException");
        return outcome.failure().getMessage();
    }

    @Test
    @DisplayName("несовпадение CMAC в третьем чанке: номер 2, смещение 128, выдано ровно 128 байт")
    void cmacMismatchNamesChunkAndOffset() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = sealed(key);
        sealed[chunkStart(2) + CHUNK_HEADER + 3] ^= 1; // байт шифртекста чанка 2

        Outcome outcome = readUntilFailure(sealed, key);

        String message = message(outcome);
        assertTrue(message.contains("CMAC mismatch"), "причина отказа: " + message);
        assertTrue(
                message.endsWith("[chunk 2, plaintext offset 128]"),
                "позиция в конце сообщения: " + message);
        assertEquals(
                128,
                outcome.delivered(),
                "смещение должно совпадать с числом уже выданных байт открытого текста");
    }

    @Test
    @DisplayName(
            "несовпадение CMAC в первом чанке: номер 0, смещение 0, заголовок потока не входит")
    void firstChunkOffsetExcludesStreamHeader() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = sealed(key);
        sealed[chunkStart(0) + CHUNK_HEADER + 3] ^= 1;

        Outcome outcome = readUntilFailure(sealed, key);

        assertTrue(
                message(outcome).endsWith("[chunk 0, plaintext offset 0]"),
                "позиция первого чанка: " + message(outcome));
        assertEquals(0, outcome.delivered(), "до отказа ничего выдано быть не должно");
    }

    @Test
    @DisplayName("несовпадение CMAC в последнем чанке: номер 3, смещение 192")
    void cmacMismatchInLastChunk() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = sealed(key);
        sealed[chunkStart(3) + CHUNK_HEADER + 1] ^= 1;

        Outcome outcome = readUntilFailure(sealed, key);

        assertTrue(
                message(outcome).endsWith("[chunk 3, plaintext offset 192]"),
                "позиция последнего чанка: " + message(outcome));
        assertEquals(192, outcome.delivered(), "выданы три полных чанка");
    }

    @Test
    @DisplayName("усечение на границе чанков: потерян чанк 2, смещение 128")
    void truncationAtBoundaryNamesMissingChunk() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = Arrays.copyOf(sealed(key), chunkStart(2));

        Outcome outcome = readUntilFailure(sealed, key);

        String message = message(outcome);
        assertTrue(message.contains("last chunk not found"), "причина отказа: " + message);
        assertTrue(
                message.endsWith("[chunk 2, plaintext offset 128]"),
                "позиция первого отсутствующего чанка: " + message);
        assertEquals(128, outcome.delivered(), "два полных чанка уже выданы");
    }

    @Test
    @DisplayName("усечение внутри заголовка чанка: позиция того же чанка")
    void truncationInsideChunkHeader() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = Arrays.copyOf(sealed(key), chunkStart(1) + 5);

        String message = message(readUntilFailure(sealed, key));

        assertTrue(
                message.endsWith("[chunk 1, plaintext offset 64]"),
                "позиция оборванного чанка: " + message);
    }

    @Test
    @DisplayName("усечение внутри шифртекста последнего чанка: номер 3, смещение 192")
    void truncationInsideChunkBody() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = Arrays.copyOf(sealed(key), chunkStart(3) + CHUNK_HEADER + 2);

        String message = message(readUntilFailure(sealed, key));

        assertTrue(message.contains("chunk is incomplete"), "причина отказа: " + message);
        assertTrue(
                message.endsWith("[chunk 3, plaintext offset 192]"),
                "позиция оборванного чанка: " + message);
    }

    @Test
    @DisplayName("недопустимые флаги и длина чанка 1: позиция чанка 1, смещение 64")
    void malformedChunkHeaderNamesChunk() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();

        byte[] badFlags = sealed(key);
        badFlags[chunkStart(1) + 4] = 0x02;
        String flagsMessage = message(readUntilFailure(badFlags, key));
        assertTrue(flagsMessage.contains("Invalid chunk flags"), "причина: " + flagsMessage);
        assertTrue(flagsMessage.endsWith("[chunk 1, plaintext offset 64]"), flagsMessage);

        byte[] shortNonFinal = sealed(key);
        shortNonFinal[chunkStart(1) + 3] = (byte) (CHUNK_SIZE - 1); // длина младшим байтом
        String lengthMessage = message(readUntilFailure(shortNonFinal, key));
        assertTrue(lengthMessage.contains("non-final chunk"), "причина: " + lengthMessage);
        assertTrue(lengthMessage.endsWith("[chunk 1, plaintext offset 64]"), lengthMessage);
    }

    @Test
    @DisplayName("позиция есть при повторном обращении к уже отказавшему потоку")
    void positionIsKeptOnRepeatedRead() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = sealed(key);
        sealed[chunkStart(2) + CHUNK_HEADER + 3] ^= 1;
        byte[] buffer = new byte[16];

        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            in.readNBytes(128);
            IOException first =
                    assertThrows(AuthenticationIOException.class, () -> in.read(buffer));
            IOException again =
                    assertThrows(AuthenticationIOException.class, () -> in.read(buffer));
            assertEquals(first.getMessage(), again.getMessage(), "сообщение повтора");
            assertTrue(again.getMessage().contains("[chunk 2, plaintext offset 128]"));
        }
    }

    @Test
    @DisplayName("неполный заголовок потока: чанков ещё нет, позиции в сообщении нет")
    void incompleteStreamHeaderHasNoPosition() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();

        AuthenticationException failure =
                assertThrows(
                        AuthenticationException.class,
                        () ->
                                AuthenticatedStream.opening(
                                        new ByteArrayInputStream(new byte[STREAM_HEADER - 1]),
                                        key));

        assertFalse(
                failure.getMessage().contains("chunk "),
                "до первого чанка позиции нет: " + failure.getMessage());
    }
}
