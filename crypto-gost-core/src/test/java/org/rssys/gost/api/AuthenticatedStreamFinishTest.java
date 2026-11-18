package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("AuthenticatedStream: finish(), flush() и затирание ключей потока")
class AuthenticatedStreamFinishTest {

    private static final int HEADER = AuthenticatedStream.HEADER_SIZE;
    private static final int CHUNK_HEADER = AuthenticatedStream.CHUNK_HEADER_SIZE;

    private final SymmetricKey key = KeyGenerator.generateSymmetricKey();

    /** Нижний выходной поток, который запоминает записанное, считает flush и close и умеет отказывать. */
    private static final class RecordingOutput extends OutputStream {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int flushCount;
        int closeCount;
        boolean failWrites;

        @Override
        public void write(int b) throws IOException {
            if (failWrites) throw new IOException("запись отклонена");
            bytes.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (failWrites) throw new IOException("запись отклонена");
            bytes.write(b, off, len);
        }

        @Override
        public void flush() {
            flushCount++;
        }

        @Override
        public void close() {
            closeCount++;
        }

        int size() {
            return bytes.size();
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(data);
        return data;
    }

    /** Флаги чанков записанного потока: разбор идёт по длинам, как у читателя. */
    private static List<Byte> chunkFlags(byte[] stream) {
        List<Byte> flags = new ArrayList<>();
        int pos = HEADER;
        while (pos < stream.length) {
            int length =
                    ((stream[pos] & 0xFF) << 24)
                            | ((stream[pos + 1] & 0xFF) << 16)
                            | ((stream[pos + 2] & 0xFF) << 8)
                            | (stream[pos + 3] & 0xFF);
            flags.add(stream[pos + 4]);
            pos += CHUNK_HEADER + length;
        }
        assertEquals(stream.length, pos, "поток должен состоять из целых чанков");
        return flags;
    }

    /**
     * Состояние ключей потока через рефлексию: у потока нет публичного способа его узнать. Ключи
     * живут только в раундовых ключах {@code Kuznyechik} внутри {@code Ctr} и {@code Cmac}, поэтому
     * смотрим флаг инициализации обоих шифров: вызывать у них операции нельзя, они сдвинули бы
     * гамму и состояние CMAC потока.
     */
    private static boolean keysDestroyed(Object stream) throws Exception {
        Object crypto = fieldOf(stream, "crypto");
        Object ctrCipher = fieldOf(fieldOf(crypto, "ctr"), "kuz");
        Object cmacCipher = fieldOf(fieldOf(fieldOf(crypto, "cmac"), "cipher"), "cipher");
        boolean ctr = !(boolean) fieldOf(ctrCipher, "keyInitialized");
        boolean cmac = !(boolean) fieldOf(cmacCipher, "keyInitialized");
        assertEquals(cmac, ctr, "ключи CMAC и CTR затираются вместе");
        return cmac;
    }

    private static Object fieldOf(Object owner, String name) throws Exception {
        for (Class<?> type = owner.getClass(); type != null; type = type.getSuperclass()) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(owner);
            } catch (NoSuchFieldException notHere) {
                // поле может быть объявлено в суперклассе
            }
        }
        throw new NoSuchFieldException(name);
    }

    // -----------------------------------------------------------------------
    // finish()
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "finish() пишет последний чанк и оставляет нижний поток открытым для дальнейших данных")
    void finishLeavesUnderlyingOpenAndReaderStopsAtLastChunk() throws Exception {
        RecordingOutput target = new RecordingOutput();
        byte[] plain = randomBytes(100);
        byte[] trailer = randomBytes(30);

        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 64);
        sealing.write(plain);
        sealing.finish();
        assertEquals(0, target.closeCount, "finish() не закрывает нижний поток");
        assertTrue(keysDestroyed(sealing), "после finish() ключи потока затёрты");
        target.write(trailer);

        byte[] all = target.bytes.toByteArray();
        ByteArrayInputStream source = new ByteArrayInputStream(all);
        try (InputStream opening = AuthenticatedStream.opening(source, key)) {
            assertArrayEquals(plain, opening.readAllBytes(), "открытый текст защищённой части");
        }
        assertEquals(
                trailer.length,
                source.available(),
                "читатель остановился на последнем чанке и не тронул данные за ним");
    }

    @Test
    @DisplayName("Повторный finish() ничего не пишет")
    void finishIsIdempotent() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.write(randomBytes(10));
        sealing.finish();
        int sizeAfterFirst = target.size();
        sealing.finish();
        assertEquals(sizeAfterFirst, target.size(), "второй finish() не должен писать чанк");
        assertEquals(1, chunkFlags(target.bytes.toByteArray()).size(), "ровно один чанк");
    }

    @Test
    @DisplayName("write после finish() и finish() после close() дают IOException")
    void writeAfterFinishAndFinishAfterCloseAreRejected() throws Exception {
        AuthenticatedStream.SealingStream sealing =
                AuthenticatedStream.sealing(new RecordingOutput(), key);
        sealing.finish();
        IOException afterFinish =
                assertThrows(
                        IOException.class, () -> sealing.write(1), "write(int) после finish()");
        assertTrue(afterFinish.getMessage().contains("finished"), afterFinish.getMessage());
        assertThrows(
                IOException.class,
                () -> sealing.write(new byte[4], 0, 4),
                "write(byte[]) после finish()");

        sealing.close();
        IOException afterClose =
                assertThrows(IOException.class, sealing::finish, "finish() после close()");
        assertTrue(afterClose.getMessage().contains("closed"), afterClose.getMessage());
    }

    @Test
    @DisplayName("close() после finish() закрывает нижний поток один раз и не пишет второй чанк")
    void closeAfterFinishOnlyClosesUnderlying() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.write(randomBytes(10));
        sealing.finish();
        int sizeAfterFinish = target.size();
        sealing.close();
        sealing.close();
        assertEquals(sizeAfterFinish, target.size(), "close() после finish() не пишет чанков");
        assertEquals(1, target.closeCount, "нижний поток закрыт один раз");
    }

    @Test
    @DisplayName("finish() на пустом потоке пишет валидный пустой последний чанк")
    void finishOnEmptyStreamWritesEmptyLastChunk() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.sealing(target, key).finish();
        byte[] stream = target.bytes.toByteArray();
        assertEquals(HEADER + CHUNK_HEADER, stream.length, "заголовок потока и пустой чанк");
        assertEquals(List.of(AuthenticatedStream.FLAG_LAST), chunkFlags(stream));

        try (InputStream opening =
                AuthenticatedStream.opening(new ByteArrayInputStream(stream), key)) {
            assertEquals(-1, opening.read(), "пустой поток читается как конец");
        }
    }

    @Test
    @DisplayName(
            "Полные чанки и неполный хвост: ровно один последний чанк, круговой проход сохраняет данные")
    void fullChunksAndPartialTail() throws Exception {
        RecordingOutput target = new RecordingOutput();
        byte[] plain = randomBytes(40);
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 16);
        sealing.write(plain);
        sealing.finish();

        byte[] stream = target.bytes.toByteArray();
        assertEquals(
                List.of(
                        AuthenticatedStream.FLAG_NORMAL,
                        AuthenticatedStream.FLAG_NORMAL,
                        AuthenticatedStream.FLAG_LAST),
                chunkFlags(stream),
                "два полных чанка и один последний с хвостом");
        try (InputStream opening =
                AuthenticatedStream.opening(new ByteArrayInputStream(stream), key)) {
            assertArrayEquals(plain, opening.readAllBytes(), "открытый текст");
        }
    }

    // -----------------------------------------------------------------------
    // flush()
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("flush() доводит полные чанки до нижнего потока, не завершая поток")
    void flushReachesUnderlyingAndKeepsStreamOpen() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 16);
        sealing.write(randomBytes(16));
        int beforeFlush = target.flushCount;
        sealing.flush();
        assertEquals(beforeFlush + 1, target.flushCount, "flush() должен дойти до нижнего потока");
        assertEquals(HEADER + CHUNK_HEADER + 16, target.size(), "полный чанк уже записан");
        assertDoesNotThrow(() -> sealing.write(1), "поток после flush() не завершён");
    }

    @Test
    @DisplayName("flush() не выталкивает неполный буфер как обычный чанк")
    void flushDoesNotPushPartialChunk() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 16);
        sealing.write(randomBytes(5));
        int sizeBefore = target.size();
        sealing.flush();
        assertEquals(sizeBefore, target.size(), "неполный буфер остаётся до finish() или close()");
    }

    @Test
    @DisplayName("flush() после finish() допустим, после close() даёт IOException")
    void flushAfterFinishAndClose() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.finish();
        assertDoesNotThrow(sealing::flush, "flush() после finish()");
        sealing.close();
        assertThrows(IOException.class, sealing::flush, "flush() после close()");
    }

    @Test
    @DisplayName("flush() после сбоя записи чанка даёт IOException")
    void flushAfterWriteFailureIsRejected() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 16);
        target.failWrites = true;
        assertThrows(IOException.class, () -> sealing.write(randomBytes(16)), "сбой записи чанка");
        target.failWrites = false;

        int flushesBefore = target.flushCount;
        IOException unusable =
                assertThrows(IOException.class, sealing::flush, "flush() на непригодном потоке");
        assertTrue(unusable.getMessage().contains("unusable"), unusable.getMessage());
        assertEquals(flushesBefore, target.flushCount, "нижний поток не должен получать flush()");
    }

    // -----------------------------------------------------------------------
    // Сбой записи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "Сбой записи в finish(): ключи затёрты, второй последний чанк не появляется, close() закрывает поток")
    void finishFailureIsFailClosed() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key);
        sealing.write(randomBytes(10));
        int sizeBefore = target.size();
        target.failWrites = true;

        assertThrows(IOException.class, sealing::finish, "сбой записи доходит до вызывающего");
        assertTrue(keysDestroyed(sealing), "ключи затёрты и после сбоя");
        assertThrows(IOException.class, sealing::finish, "повторный finish() после сбоя");

        target.failWrites = false;
        sealing.close();
        assertEquals(sizeBefore, target.size(), "после сбоя второй последний чанк не пишется");
        assertEquals(1, target.closeCount, "close() всё равно закрывает нижний поток");
    }

    @Test
    @DisplayName("Сбой записи полного чанка делает поток непригодным и затирает ключи")
    void chunkWriteFailureMakesStreamUnusable() throws Exception {
        RecordingOutput target = new RecordingOutput();
        AuthenticatedStream.SealingStream sealing = AuthenticatedStream.sealing(target, key, 16);
        target.failWrites = true;
        assertThrows(IOException.class, () -> sealing.write(randomBytes(16)), "сбой записи чанка");
        target.failWrites = false;

        assertTrue(keysDestroyed(sealing), "ключи затёрты после сбоя");
        IOException unusable =
                assertThrows(IOException.class, () -> sealing.write(1), "write после сбоя");
        assertTrue(unusable.getMessage().contains("unusable"), unusable.getMessage());
        sealing.close();
        assertEquals(1, target.closeCount, "close() закрывает нижний поток");
    }

    @Test
    @DisplayName("Сбой записи заголовка потока доходит до вызывающего из sealing()")
    void headerWriteFailureThrowsFromFactory() {
        RecordingOutput target = new RecordingOutput();
        target.failWrites = true;
        assertThrows(
                IOException.class,
                () -> AuthenticatedStream.sealing(target, key),
                "sealing() сообщает о сбое записи заголовка");
    }

    // -----------------------------------------------------------------------
    // Читающая сторона
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Читатель затирает ключи потока после последнего чанка без close()")
    void readerDestroysKeysAfterLastChunk() throws Exception {
        RecordingOutput target = new RecordingOutput();
        byte[] plain = randomBytes(40);
        try (OutputStream sealing = AuthenticatedStream.sealing(target, key, 16)) {
            sealing.write(plain);
        }

        InputStream opening =
                AuthenticatedStream.opening(
                        new ByteArrayInputStream(target.bytes.toByteArray()), key);
        byte[] first = new byte[16];
        assertEquals(16, opening.read(first), "первый чанк");
        assertFalse(keysDestroyed(opening), "ключи нужны, пока последний чанк не прочитан");

        assertEquals(24, opening.readAllBytes().length, "остальные данные");
        assertTrue(keysDestroyed(opening), "после последнего чанка ключи затёрты без close()");
        assertEquals(-1, opening.read(), "поток дочитан до конца");
    }

    @Test
    @DisplayName("Читатель затирает ключи потока при ошибке чтения")
    void readerDestroysKeysOnFailure() throws Exception {
        RecordingOutput target = new RecordingOutput();
        try (OutputStream sealing = AuthenticatedStream.sealing(target, key, 16)) {
            sealing.write(randomBytes(20));
        }
        byte[] stream = target.bytes.toByteArray();
        stream[HEADER + CHUNK_HEADER] ^= 0x01; // шифртекст первого чанка

        InputStream opening = AuthenticatedStream.opening(new ByteArrayInputStream(stream), key);
        assertThrows(IOException.class, opening::readAllBytes, "ошибка целостности");
        assertTrue(keysDestroyed(opening), "поток непригоден, ключи затёрты");
    }
}
