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
import org.rssys.gost.util.CryptoRandom;

@DisplayName("AuthenticatedStream Tests")
class AuthenticatedStreamTest {

    private static SymmetricKey newKey() {
        return KeyGenerator.generateSymmetricKey();
    }

    /** Полный roundtrip: seal -> open, возвращает расшифрованные данные. */
    private byte[] roundtrip(byte[] plaintext, SymmetricKey key) throws Exception {
        return roundtrip(plaintext, key, AuthenticatedStream.DEFAULT_CHUNK_SIZE);
    }

    private byte[] roundtrip(byte[] plaintext, SymmetricKey key, int chunkSize) throws Exception {
        // Шифрование
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, chunkSize)) {
            seal.write(plaintext);
        }

        // Расшифрование
        ByteArrayOutputStream decBuf = new ByteArrayOutputStream();
        try (InputStream open =
                AuthenticatedStream.opening(new ByteArrayInputStream(encBuf.toByteArray()), key)) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = open.read(buf)) > 0) decBuf.write(buf, 0, n);
        }
        return decBuf.toByteArray();
    }

    // -----------------------------------------------------------------------
    // Roundtrip — разные размеры данных
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Roundtrip: 1 байт")
    void testRoundtrip1Byte() throws Exception {
        byte[] data = {0x42};
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: пустые данные")
    void testRoundtripEmpty() throws Exception {
        assertArrayEquals(new byte[0], roundtrip(new byte[0], newKey()));
    }

    @Test
    @DisplayName("Roundtrip: 1 КБ данных (один чанк)")
    void testRoundtrip1KB() throws Exception {
        byte[] data = new byte[1024];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: ровно один полный чанк (64 КБ)")
    void testRoundtripExactlyOneChunk() throws Exception {
        byte[] data = new byte[AuthenticatedStream.DEFAULT_CHUNK_SIZE];
        CryptoRandom.INSTANCE.nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: 100 КБ (один с половиной чанка)")
    void testRoundtrip100KB() throws Exception {
        byte[] data = new byte[100 * 1024];
        CryptoRandom.INSTANCE.nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: 200 КБ (три чанка)")
    void testRoundtrip200KB() throws Exception {
        byte[] data = new byte[200 * 1024];
        CryptoRandom.INSTANCE.nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: кастомный chunkSize = 100 байт")
    void testRoundtripCustomChunkSize() throws Exception {
        byte[] data = new byte[550]; // 5.5 чанков по 100 байт
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i % 256);
        assertArrayEquals(data, roundtrip(data, newKey(), 100));
    }

    @Test
    @DisplayName("Roundtrip: запись по байту — тот же результат что и за один вызов")
    void testRoundtripByteByByte() throws Exception {
        byte[] data = "The quick brown fox jumps over the lazy dog".getBytes("UTF-8");
        SymmetricKey key = newKey();

        // Запись одним write()
        byte[] r1 = roundtrip(data, key);

        // Запись по байту
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, 100)) {
            for (byte b : data) seal.write(b & 0xFF);
        }
        ByteArrayOutputStream decBuf = new ByteArrayOutputStream();
        try (InputStream open =
                AuthenticatedStream.opening(new ByteArrayInputStream(encBuf.toByteArray()), key)) {
            int b;
            while ((b = open.read()) >= 0) decBuf.write(b);
        }
        assertArrayEquals(
                r1, decBuf.toByteArray(), "Побайтовая запись должна давать тот же plaintext");
    }

    // -----------------------------------------------------------------------
    // Заголовок потока
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Заголовок потока: nonce[8] случайный, version=0x02, chunkSize")
    void testStreamHeader() throws Exception {
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey(), 1024)) {
            seal.write("hello".getBytes());
        }
        byte[] bytes = encBuf.toByteArray();

        // nonce[8] — случайные байты, не должны быть нулями (вероятность ~2^-64)
        boolean allZeros = true;
        for (int i = 0; i < 8; i++) {
            if (bytes[i] != 0) {
                allZeros = false;
                break;
            }
        }
        assertFalse(allZeros, "nonce не должен быть нулевым");
        // version = 0x02
        assertEquals(0x02, bytes[8] & 0xFF, "version");
        // chunkSize = 1024 (big-endian) на позициях 9..12
        assertEquals(0x00, bytes[9] & 0xFF);
        assertEquals(0x00, bytes[10] & 0xFF);
        assertEquals(0x04, bytes[11] & 0xFF);
        assertEquals(0x00, bytes[12] & 0xFF);
    }

    @Test
    @DisplayName("Последний чанк: флаг FLAG_LAST = 0x01")
    void testLastChunkFlag() throws Exception {
        byte[] data = "short".getBytes("UTF-8");
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey())) {
            seal.write(data);
        }
        byte[] bytes = encBuf.toByteArray();
        // Заголовок потока = 13 байт, затем чанк: chunkLen(4) + flags(1) + ...
        // Для одного чанка flags должен быть FLAG_LAST = 0x01
        int flagPos = AuthenticatedStream.HEADER_SIZE + 4; // после chunkLen
        assertEquals(
                AuthenticatedStream.FLAG_LAST,
                bytes[flagPos],
                "Единственный чанк должен иметь флаг FLAG_LAST");
    }

    // -----------------------------------------------------------------------
    // Обнаружение нарушений целостности
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "opening: подмена байта в CMAC чанка -> IOException (причина: AuthenticationException)")
    void testTamperedChunkCmac() throws Exception {
        byte[] data = "data to protect".getBytes("UTF-8");
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        SymmetricKey key = newKey();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key)) {
            seal.write(data);
        }

        byte[] packet = encBuf.toByteArray();
        // Портим CMAC в чанке: заголовок(13) + chunkLen(4) + flags(1) + IV(8) = позиция 26
        int cmacPos = AuthenticatedStream.HEADER_SIZE + 4 + 1 + 8;
        packet[cmacPos] ^= 0xFF;

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(packet), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Причина IOException должна быть AuthenticationException");
    }

    @Test
    @DisplayName("opening: подмена байта в шифртексте -> IOException")
    void testTamperedCiphertext() throws Exception {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0xAB);
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        SymmetricKey key = newKey();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, 64)) {
            seal.write(data);
        }

        byte[] packet = encBuf.toByteArray();
        // Портим шифртекст первого чанка: после заголовка потока + заголовка чанка
        int ctPos = AuthenticatedStream.HEADER_SIZE + AuthenticatedStream.CHUNK_HEADER_SIZE;
        packet[ctPos] ^= 0x01;

        assertThrows(
                IOException.class,
                () -> {
                    try (InputStream open =
                            AuthenticatedStream.opening(new ByteArrayInputStream(packet), key)) {
                        byte[] buf = new byte[256];
                        //noinspection StatementWithEmptyBody
                        while (open.read(buf) > 0)
                            ;
                    }
                });
    }

    @Test
    @DisplayName("opening: усечённый поток (нет последнего чанка) -> AuthenticationException")
    void testTruncatedStream() throws Exception {
        byte[] data = new byte[200 * 1024]; // два чанка по 64 КБ + остаток
        Arrays.fill(data, (byte) 0x55);
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        SymmetricKey key = newKey();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key)) {
            seal.write(data);
        }

        // Обрезаем поток — оставляем только половину
        byte[] full = encBuf.toByteArray();
        byte[] truncated = Arrays.copyOf(full, full.length / 2);

        assertThrows(
                IOException.class,
                () -> {
                    try (InputStream open =
                            AuthenticatedStream.opening(new ByteArrayInputStream(truncated), key)) {
                        byte[] buf = new byte[4096];
                        //noinspection StatementWithEmptyBody
                        while (open.read(buf) > 0)
                            ;
                    }
                },
                "Усечённый поток должен обнаруживаться");
    }

    @Test
    @DisplayName("opening: неверный ключ -> IOException")
    void testWrongKey() throws Exception {
        byte[] data = "secret".getBytes("UTF-8");
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey())) {
            seal.write(data);
        }

        assertThrows(
                IOException.class,
                () -> {
                    try (InputStream open =
                            AuthenticatedStream.opening(
                                    new ByteArrayInputStream(encBuf.toByteArray()), newKey())) {
                        byte[] buf = new byte[256];
                        //noinspection StatementWithEmptyBody
                        while (open.read(buf) > 0)
                            ;
                    }
                },
                "Неверный ключ -> CMAC не совпадёт");
    }

    @Test
    @DisplayName("opening: неверная версия заголовка -> AuthenticationException")
    void testInvalidVersion() {
        // Заголовок: nonce[8] + version[1] + chunkSize[4]
        // version != 0x02 -> отказ
        byte[] badHeader = new byte[50];
        badHeader[8] = 0x01; // VERSION=0x01, не 0x02

        assertThrows(
                AuthenticationException.class,
                () -> AuthenticatedStream.opening(new ByteArrayInputStream(badHeader), newKey()));
    }

    @Test
    @DisplayName("chunkSize < 16 -> IllegalArgumentException")
    void testInvalidChunkSize() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AuthenticatedStream.sealing(new ByteArrayOutputStream(), newKey(), 8));
    }

    // -----------------------------------------------------------------------
    // Структура: несколько чанков
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Два чанка: данные точно 2 * chunkSize")
    void testExactlyTwoChunks() throws Exception {
        int cs = 512;
        byte[] data = new byte[2 * cs];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i % 251);

        byte[] restored = roundtrip(data, newKey(), cs);
        assertArrayEquals(data, restored);
    }

    @Test
    @DisplayName("Разные ключи для шифрования и открытия -> IOException")
    void testDifferentKeysForSealAndOpen() {
        assertThrows(
                IOException.class,
                () -> {
                    byte[] data = "hello world".getBytes("UTF-8");
                    ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
                    try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey())) {
                        seal.write(data);
                    }
                    try (InputStream open =
                            AuthenticatedStream.opening(
                                    new ByteArrayInputStream(encBuf.toByteArray()), newKey())) {
                        byte[] buf = new byte[256];
                        //noinspection StatementWithEmptyBody
                        while (open.read(buf) > 0)
                            ;
                    }
                });
    }

    // -----------------------------------------------------------------------
    // Защита от OOM через chunkLen
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("opening: chunkLen превышает chunkSize -> AuthenticationException")
    void testChunkLenExceedsChunkSize() throws Exception {
        byte[] data = new byte[100];
        SymmetricKey key = newKey();
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, 128)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // chunkLen — первые 4 байта после заголовка потока (HEADER_SIZE = 13)
        int chunkLenPos = AuthenticatedStream.HEADER_SIZE;
        packet[chunkLenPos] = (byte) 0x00;
        packet[chunkLenPos + 1] = (byte) 0x00;
        packet[chunkLenPos + 2] = (byte) 0x0F;
        packet[chunkLenPos + 3] = (byte) 0xA0; // 4000 > 128

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(packet), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "chunkLen > chunkSize должен вызывать AuthenticationException");
    }

    @Test
    @DisplayName("opening: chunkSize в заголовке > MAX_CHUNK_SIZE -> AuthenticationException")
    void testHeaderChunkSizeTooLarge() throws Exception {
        byte[] data = new byte[16];
        SymmetricKey key = newKey();
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, 256)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // chunkSize — байты 9..12 (после nonce[8] + VERSION[1])
        packet[9] = (byte) 0x7F;
        packet[10] = (byte) 0xFF;
        packet[11] = (byte) 0xFF;
        packet[12] = (byte) 0xFF; // > MAX_CHUNK_SIZE (1_048_576)

        AuthenticationException ex =
                assertThrows(
                        AuthenticationException.class,
                        () -> AuthenticatedStream.opening(new ByteArrayInputStream(packet), key));
        assertTrue(
                ex.getMessage().contains("Invalid chunk size"),
                "Сообщение должно указывать на некорректный chunkSize");
    }

    // -----------------------------------------------------------------------
    // Защита от reorder/duplicate через seqNo в AAD
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("opening: перестановка чанков -> AuthenticationException")
    void testChunkReorderDetected() throws Exception {
        int chunkSize = 32;
        byte[] data = new byte[chunkSize + 1]; // 33 байта — два чанка: 32 + 1
        Arrays.fill(data, (byte) 0x42);
        SymmetricKey key = newKey();

        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, chunkSize)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // Чанк 0: HEADER_SIZE..HEADER_SIZE+CHUNK_HEADER_SIZE+chunkSize-1
        int hdr = AuthenticatedStream.HEADER_SIZE;
        int chunk0total = AuthenticatedStream.CHUNK_HEADER_SIZE + chunkSize;

        // Собираем пакет с перестановкой: Header + Chunk1 + Chunk0
        ByteArrayOutputStream reordered = new ByteArrayOutputStream();
        reordered.write(packet, 0, hdr); // header
        reordered.write(
                packet,
                hdr + chunk0total, // Chunk1
                packet.length - hdr - chunk0total);
        reordered.write(packet, hdr, chunk0total); // Chunk0

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(reordered.toByteArray()),
                                            key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Перестановка чанков должна обнаруживаться через seqNo в AAD");
    }

    @Test
    @DisplayName("opening: дубликат чанка -> AuthenticationException")
    void testChunkDuplicateDetected() throws Exception {
        int chunkSize = 32;
        byte[] data = new byte[chunkSize + 1]; // 33 байта — два чанка: 32 + 1
        Arrays.fill(data, (byte) 0x42);
        SymmetricKey key = newKey();

        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, chunkSize)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        int hdr = AuthenticatedStream.HEADER_SIZE;
        int chunk0total = AuthenticatedStream.CHUNK_HEADER_SIZE + chunkSize;

        // Собираем пакет с дубликатом: Header + Chunk0 + Chunk0_copy + Chunk1
        ByteArrayOutputStream dup = new ByteArrayOutputStream();
        dup.write(packet, 0, hdr); // header
        dup.write(packet, hdr, chunk0total); // Chunk0
        dup.write(packet, hdr, chunk0total); // Chunk0 (дубликат)
        dup.write(
                packet,
                hdr + chunk0total, // Chunk1
                packet.length - hdr - chunk0total);

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(dup.toByteArray()), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Дубликат чанка должен обнаруживаться через seqNo в AAD");
    }

    // -----------------------------------------------------------------------
    // Защита от подмены флага через AAD
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("opening: FLAG_NORMAL -> FLAG_LAST (раннее завершение) -> AuthenticationException")
    void testEarlyLastFlagDetected() throws Exception {
        int chunkSize = 32;
        byte[] data = new byte[chunkSize + 1]; // 33 байта — два чанка
        SymmetricKey key = newKey();

        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key, chunkSize)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // flags — 5-й байт заголовка первого чанка (HEADER_SIZE + chunkLen[4])
        int flagPos = AuthenticatedStream.HEADER_SIZE + 4;
        packet[flagPos] = AuthenticatedStream.FLAG_LAST;

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(packet), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Подмена FLAG_NORMAL -> FLAG_LAST должна обнаруживаться через AAD");
    }

    @Test
    @DisplayName("opening: FLAG_LAST -> FLAG_NORMAL (бесконечный поток) -> AuthenticationException")
    void testRemovedLastFlagDetected() throws Exception {
        byte[] data = new byte[16];
        SymmetricKey key = newKey();

        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // flags — 5-й байт заголовка первого (и единственного) чанка
        int flagPos = AuthenticatedStream.HEADER_SIZE + 4;
        packet[flagPos] = AuthenticatedStream.FLAG_NORMAL;

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(packet), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Удаление FLAG_LAST должно обнаруживаться через AAD");
    }

    // -----------------------------------------------------------------------
    // Header integrity: заголовок в AAD первого чанка
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("opening: подмена nonce в заголовке -> AuthenticationException на первом чанке")
    void testTamperedHeaderNonce() throws Exception {
        byte[] data = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey key = newKey();

        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, key)) {
            seal.write(data);
        }
        byte[] packet = encBuf.toByteArray();

        // Меняем байт в nonce (byte[3]), версия и chunkSize остаются валидными
        packet[3] ^= 0xFF;

        IOException ex =
                assertThrows(
                        IOException.class,
                        () -> {
                            try (InputStream open =
                                    AuthenticatedStream.opening(
                                            new ByteArrayInputStream(packet), key)) {
                                byte[] buf = new byte[256];
                                //noinspection StatementWithEmptyBody
                                while (open.read(buf) > 0)
                                    ;
                            }
                        });
        assertInstanceOf(
                AuthenticationException.class,
                ex.getCause(),
                "Подмена nonce в заголовке должна обнаруживаться через AAD первого чанка");
    }

    @Test
    @DisplayName("opening: VERSION=0x01 -> AuthenticationException при чтении заголовка")
    void testOldVersionRejected() {
        byte[] header = new byte[50];
        // Заполняем nonce[8] случайными байтами — версия на byte[8] должна быть 0x01
        CryptoRandom.INSTANCE.nextBytes(header);
        header[8] = 0x01; // VERSION = 0x01 (старый формат)

        AuthenticationException ex =
                assertThrows(
                        AuthenticationException.class,
                        () ->
                                AuthenticatedStream.opening(
                                        new ByteArrayInputStream(header), newKey()));
        assertTrue(
                ex.getMessage().contains("Unsupported format version"),
                "Должно быть сообщение о неподдерживаемой версии");
    }
}
