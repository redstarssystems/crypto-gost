package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

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

@DisplayName("AuthenticatedStream: границы, типизированные ошибки, строгий разбор")
class AuthenticatedStreamFailClosedTest {

    /** Размер заголовка потока и заголовка чанка (см. AuthenticatedStream). */
    private static final int STREAM_HEADER = AuthenticatedStream.HEADER_SIZE;

    private static final int CHUNK_HEADER = AuthenticatedStream.CHUNK_HEADER_SIZE;

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    private static byte[] seal(byte[] plaintext, SymmetricKey key, int chunkSize)
            throws IOException {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sink, key, chunkSize)) {
            out.write(plaintext);
        }
        return sink.toByteArray();
    }

    /** Читает весь поток; возвращает исключение, которым чтение завершилось. */
    private static Throwable readAllExpectingFailure(byte[] sealed, SymmetricKey key) {
        return assertThrows(
                Exception.class,
                () -> {
                    try (InputStream in =
                            AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                        in.readAllBytes();
                    }
                },
                "чтение должно завершиться ошибкой");
    }

    // -----------------------------------------------------------------------
    // Границы размера чанка
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("sealing: размер чанка вне [16, 1 МиБ] отвергается при создании, а не при чтении")
    void sealingRejectsChunkSizeOutsideReadableRange() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        for (int chunkSize :
                new int[] {
                    15,
                    0,
                    -1,
                    AuthenticatedStream.MAX_CHUNK_SIZE + 1,
                    2 * 1024 * 1024,
                    Integer.MAX_VALUE
                }) {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AuthenticatedStream.sealing(sink, key, chunkSize),
                    "размер чанка " + chunkSize + " должен отвергаться");
            assertEquals(0, sink.size(), "заголовок не должен быть записан, размер " + chunkSize);
        }
    }

    @Test
    @DisplayName("sealing: границы диапазона 16 байт и 1 МиБ принимаются и читаются обратно")
    void sealingAcceptsRangeBoundaries() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(40);
        for (int chunkSize : new int[] {16, AuthenticatedStream.MAX_CHUNK_SIZE}) {
            byte[] sealed = seal(plaintext, key, chunkSize);
            try (InputStream in =
                    AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                assertArrayEquals(plaintext, in.readAllBytes(), "размер чанка " + chunkSize);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Типизированные ошибки
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "подмена шифртекста при чтении -> AuthenticationIOException с причиной AuthenticationException")
    void tamperingIsReportedAsAuthenticationIoException() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(100), key, 64);
        sealed[STREAM_HEADER + CHUNK_HEADER + 3] ^= 1; // байт шифртекста первого чанка

        Throwable failure = readAllExpectingFailure(sealed, key);

        assertInstanceOf(
                AuthenticationIOException.class,
                failure,
                "подмена должна отличаться от ошибки ввода-вывода");
        assertInstanceOf(
                AuthenticationException.class,
                failure.getCause(),
                "причиной должна быть AuthenticationException");
    }

    @Test
    @DisplayName("усечение посреди чанка -> AuthenticationIOException, а не обычный IOException")
    void truncationInsideChunkIsAuthenticationFailure() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        byte[] truncated = Arrays.copyOf(sealed, STREAM_HEADER + CHUNK_HEADER + 10);

        assertInstanceOf(
                AuthenticationIOException.class,
                readAllExpectingFailure(truncated, key),
                "обрыв внутри шифртекста чанка — нарушение целостности");
    }

    @Test
    @DisplayName("усечение на границе чанков (нет последнего чанка) -> AuthenticationIOException")
    void truncationAtChunkBoundaryIsAuthenticationFailure() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        int firstChunkEnd = STREAM_HEADER + CHUNK_HEADER + 64;

        assertInstanceOf(
                AuthenticationIOException.class,
                readAllExpectingFailure(Arrays.copyOf(sealed, firstChunkEnd), key),
                "поток без чанка с флагом последнего");
    }

    @Test
    @DisplayName("усечение и пустой поток в заголовке -> AuthenticationException из opening")
    void incompleteStreamHeaderIsAuthenticationFailure() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        for (int length : new int[] {0, 5, STREAM_HEADER - 1}) {
            byte[] truncated = new byte[length];
            assertThrows(
                    AuthenticationException.class,
                    () -> AuthenticatedStream.opening(new ByteArrayInputStream(truncated), key),
                    "заголовок из " + length + " байт неполный");
        }
    }

    @Test
    @DisplayName("ошибка ввода-вывода нижнего потока остаётся обычным IOException")
    void transientIoErrorIsNotReportedAsAttack() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        int failAfter = STREAM_HEADER + CHUNK_HEADER + 10;
        InputStream flaky =
                new InputStream() {
                    private int position = 0;

                    @Override
                    public int read() throws IOException {
                        if (position >= failAfter) {
                            throw new IOException("сетевой сбой");
                        }
                        return sealed[position++] & 0xFF;
                    }

                    @Override
                    public int read(byte[] buf, int off, int len) throws IOException {
                        if (len == 0) {
                            return 0;
                        }
                        int b = read();
                        buf[off] = (byte) b;
                        return 1;
                    }
                };

        IOException failure =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream in = AuthenticatedStream.opening(flaky, key)) {
                                in.readAllBytes();
                            }
                        },
                        "сбой нижнего потока должен приходить как IOException");
        assertFalse(
                failure instanceof AuthenticationIOException,
                "обрыв сети не должен выдаваться за атаку");
        assertEquals("сетевой сбой", failure.getMessage(), "исходное исключение без обёрток");
    }

    // -----------------------------------------------------------------------
    // Состояние после ошибки
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "после ошибки аутентификации повторный read бросает исключение, а не возвращает конец потока")
    void readAfterAuthenticationFailureDoesNotReportEndOfStream() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        sealed[STREAM_HEADER + CHUNK_HEADER + 3] ^= 1;

        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            assertThrows(
                    AuthenticationIOException.class,
                    () -> in.read(new byte[100]),
                    "первое чтение должно сообщить о подмене");
            // Вызывающий, проигнорировавший ошибку, не должен увидеть -1: это выглядело бы как
            // чистый конец потока и скрыло бы усечение
            AuthenticationIOException again =
                    assertThrows(
                            AuthenticationIOException.class,
                            () -> in.read(new byte[100]),
                            "повторное чтение должно снова бросать исключение");
            assertInstanceOf(AuthenticationException.class, again.getCause(), "причина сохранена");
            assertThrows(AuthenticationIOException.class, in::read, "read() по байту — так же");
        }
    }

    @Test
    @DisplayName(
            "после сбоя нижнего потока повторный read бросает исключение, а не читает с середины чанка")
    void readAfterTransientFailureDoesNotContinueMidStructure() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        int failAt = STREAM_HEADER + CHUNK_HEADER + 10;
        boolean[] failed = {false};
        InputStream flaky =
                new InputStream() {
                    private int position = 0;

                    @Override
                    public int read() throws IOException {
                        if (position >= failAt && !failed[0]) {
                            failed[0] = true;
                            throw new IOException("сетевой сбой");
                        }
                        // После одного сбоя источник «восстанавливается» и отдаёт остаток потока
                        return position < sealed.length ? sealed[position++] & 0xFF : -1;
                    }

                    @Override
                    public int read(byte[] buf, int off, int len) throws IOException {
                        if (len == 0) {
                            return 0;
                        }
                        int b = read();
                        if (b < 0) {
                            return -1;
                        }
                        buf[off] = (byte) b;
                        return 1;
                    }
                };

        try (InputStream in = AuthenticatedStream.opening(flaky, key)) {
            IOException first = assertThrows(IOException.class, () -> in.read(new byte[100]));
            assertEquals("сетевой сбой", first.getMessage(), "исходное исключение без обёрток");

            IOException second = assertThrows(IOException.class, () -> in.read(new byte[100]));
            assertFalse(
                    second instanceof AuthenticationIOException,
                    "сбой сети не должен превращаться в обвинение в подмене");
            assertSame(first, second.getCause(), "повторная ошибка ссылается на первую причину");
        }
    }

    @Test
    @DisplayName(
            "read с нулевой длиной возвращает 0 в любом состоянии, неверные границы отвергаются")
    void zeroLengthReadFollowsInputStreamContract() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(10);
        byte[] sealed = seal(plaintext, key, 64);
        byte[] buf = new byte[8];

        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            assertEquals(0, in.read(buf, 0, 0), "до чтения");
            assertThrows(
                    IndexOutOfBoundsException.class,
                    () -> in.read(buf, 5, 4),
                    "выход за границы массива");
            assertArrayEquals(plaintext, in.readAllBytes(), "данные не пострадали");
            assertEquals(0, in.read(buf, 0, 0), "после конца потока");
            assertEquals(-1, in.read(buf, 0, 1), "конец потока при непустом запросе");
        }

        byte[] tampered = sealed.clone();
        tampered[STREAM_HEADER + CHUNK_HEADER + 3] ^= 1;
        try (InputStream in =
                AuthenticatedStream.opening(new ByteArrayInputStream(tampered), key)) {
            assertThrows(AuthenticationIOException.class, () -> in.read(buf));
            assertEquals(0, in.read(buf, 0, 0), "после ошибки нулевой запрос ничего не читает");
            assertThrows(
                    AuthenticationIOException.class,
                    () -> in.read(buf),
                    "непустой запрос по-прежнему бросает исключение");
        }
    }

    // -----------------------------------------------------------------------
    // Строгий разбор чанков
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("флаги чанка кроме 0x00 и 0x01 отвергаются до чтения шифртекста")
    void nonCanonicalFlagsAreRejected() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(100), key, 64);
        sealed[STREAM_HEADER + 4] = 0x02; // флаги первого чанка

        Throwable failure = readAllExpectingFailure(sealed, key);

        assertInstanceOf(AuthenticationIOException.class, failure, "тип ошибки");
        assertTrue(
                failure.getMessage().contains("Invalid chunk flags"),
                "причина должна называть флаги: " + failure.getMessage());
    }

    @Test
    @DisplayName(
            "не последний чанк неполной длины отвергается (иначе пустой чанк читался как конец потока)")
    void shortNonFinalChunkIsRejected() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] sealed = seal(randomBytes(200), key, 64);
        // Длина шифртекста первого (обычного) чанка: 64 -> 0
        sealed[STREAM_HEADER] = 0;
        sealed[STREAM_HEADER + 1] = 0;
        sealed[STREAM_HEADER + 2] = 0;
        sealed[STREAM_HEADER + 3] = 0;

        Throwable failure = readAllExpectingFailure(sealed, key);

        assertInstanceOf(AuthenticationIOException.class, failure, "тип ошибки");
        assertTrue(
                failure.getMessage().contains("non-final chunk"),
                "причина должна называть неполный не последний чанк: " + failure.getMessage());
    }

    @Test
    @DisplayName("данные после последнего чанка не читаются и не мешают чтению защищённого потока")
    void bytesAfterLastChunkAreNotConsumed() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(100);
        byte[] sealed = seal(plaintext, key, 64);
        byte[] trailer = randomBytes(50);
        byte[] embedded = Arrays.copyOf(sealed, sealed.length + trailer.length);
        System.arraycopy(trailer, 0, embedded, sealed.length, trailer.length);
        ByteArrayInputStream raw = new ByteArrayInputStream(embedded);

        try (InputStream in = AuthenticatedStream.opening(raw, key)) {
            assertArrayEquals(plaintext, in.readAllBytes(), "защищённый поток читается целиком");
        }
        assertEquals(
                trailer.length, raw.available(), "данные за последним чанком остались нетронутыми");
    }
}
