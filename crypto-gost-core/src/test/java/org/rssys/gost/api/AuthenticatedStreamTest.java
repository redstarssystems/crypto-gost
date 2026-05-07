package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuthenticatedStream Tests")
class AuthenticatedStreamTest {

    private static SymmetricKey newKey() {
        return KeyGenerator.generateSymmetricKey();
    }

    /** Полный roundtrip: seal → open, возвращает расшифрованные данные. */
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
        try (InputStream open = AuthenticatedStream.opening(
                new ByteArrayInputStream(encBuf.toByteArray()), key)) {
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
        new java.security.SecureRandom().nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: 100 КБ (один с половиной чанка)")
    void testRoundtrip100KB() throws Exception {
        byte[] data = new byte[100 * 1024];
        new java.security.SecureRandom().nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: 200 КБ (три чанка)")
    void testRoundtrip200KB() throws Exception {
        byte[] data = new byte[200 * 1024];
        new java.security.SecureRandom().nextBytes(data);
        assertArrayEquals(data, roundtrip(data, newKey()));
    }

    @Test
    @DisplayName("Roundtrip: кастомный chunkSize = 100 байт")
    void testRoundtripCustomChunkSize() throws Exception {
        byte[] data = new byte[550]; // 5.5 чанков по 100 байт
        for (int i = 0; i < data.length; i++) data[i] = (byte)(i % 256);
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
        try (InputStream open = AuthenticatedStream.opening(
                new ByteArrayInputStream(encBuf.toByteArray()), key)) {
            int b;
            while ((b = open.read()) >= 0) decBuf.write(b);
        }
        assertArrayEquals(r1, decBuf.toByteArray(),
            "Побайтовая запись должна давать тот же plaintext");
    }

    // -----------------------------------------------------------------------
    // Заголовок потока
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Заголовок потока: magic, version, chunkSize")
    void testStreamHeader() throws Exception {
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(
                encBuf, newKey(), 1024)) {
            seal.write("hello".getBytes());
        }
        byte[] bytes = encBuf.toByteArray();

        // magic = "GOST"
        assertEquals(0x47, bytes[0] & 0xFF, "magic[0]");
        assertEquals(0x4F, bytes[1] & 0xFF, "magic[1]");
        assertEquals(0x53, bytes[2] & 0xFF, "magic[2]");
        assertEquals(0x54, bytes[3] & 0xFF, "magic[3]");
        // version = 1
        assertEquals(0x01, bytes[4] & 0xFF, "version");
        // chunkSize = 1024 (big-endian)
        assertEquals(0x00, bytes[5] & 0xFF);
        assertEquals(0x00, bytes[6] & 0xFF);
        assertEquals(0x04, bytes[7] & 0xFF);
        assertEquals(0x00, bytes[8] & 0xFF);
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
        assertEquals(AuthenticatedStream.FLAG_LAST, bytes[flagPos],
            "Единственный чанк должен иметь флаг FLAG_LAST");
    }

    // -----------------------------------------------------------------------
    // Обнаружение нарушений целостности
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("opening: подмена байта в CMAC чанка → IOException (причина: AuthenticationException)")
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

        IOException ex = assertThrows(IOException.class, () -> {
            try (InputStream open = AuthenticatedStream.opening(
                    new ByteArrayInputStream(packet), key)) {
                byte[] buf = new byte[256];
                //noinspection StatementWithEmptyBody
                while (open.read(buf) > 0) ;
            }
        });
        assertInstanceOf(AuthenticationException.class, ex.getCause(),
            "Причина IOException должна быть AuthenticationException");
    }

    @Test
    @DisplayName("opening: подмена байта в шифртексте → IOException")
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

        assertThrows(IOException.class, () -> {
            try (InputStream open = AuthenticatedStream.opening(
                    new ByteArrayInputStream(packet), key)) {
                byte[] buf = new byte[256];
                //noinspection StatementWithEmptyBody
                while (open.read(buf) > 0) ;
            }
        });
    }

    @Test
    @DisplayName("opening: усечённый поток (нет последнего чанка) → AuthenticationException")
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

        assertThrows(IOException.class, () -> {
            try (InputStream open = AuthenticatedStream.opening(
                    new ByteArrayInputStream(truncated), key)) {
                byte[] buf = new byte[4096];
                //noinspection StatementWithEmptyBody
                while (open.read(buf) > 0) ;
            }
        }, "Усечённый поток должен обнаруживаться");
    }

    @Test
    @DisplayName("opening: неверный ключ → IOException")
    void testWrongKey() throws Exception {
        byte[] data = "secret".getBytes("UTF-8");
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey())) {
            seal.write(data);
        }

        assertThrows(IOException.class, () -> {
            try (InputStream open = AuthenticatedStream.opening(
                    new ByteArrayInputStream(encBuf.toByteArray()), newKey())) {
                byte[] buf = new byte[256];
                //noinspection StatementWithEmptyBody
                while (open.read(buf) > 0) ;
            }
        }, "Неверный ключ → CMAC не совпадёт");
    }

    @Test
    @DisplayName("opening: неверный magic → AuthenticationException")
    void testInvalidMagic() {
        byte[] badHeader = new byte[50];
        badHeader[0] = 0x00; // не GOST

        assertThrows(AuthenticationException.class, () ->
            AuthenticatedStream.opening(new ByteArrayInputStream(badHeader), newKey()));
    }

    @Test
    @DisplayName("chunkSize < 16 → IllegalArgumentException")
    void testInvalidChunkSize() {
        assertThrows(IllegalArgumentException.class, () ->
            AuthenticatedStream.sealing(new ByteArrayOutputStream(), newKey(), 8));
    }

    // -----------------------------------------------------------------------
    // Структура: несколько чанков
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Два чанка: данные точно 2 * chunkSize")
    void testExactlyTwoChunks() throws Exception {
        int cs = 512;
        byte[] data = new byte[2 * cs];
        for (int i = 0; i < data.length; i++) data[i] = (byte)(i % 251);

        byte[] restored = roundtrip(data, newKey(), cs);
        assertArrayEquals(data, restored);
    }

    @Test
    @DisplayName("Разные ключи для шифрования и открытия → IOException")
    void testDifferentKeysForSealAndOpen() {
        assertThrows(IOException.class, () -> {
            byte[] data = "hello world".getBytes("UTF-8");
            ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
            try (OutputStream seal = AuthenticatedStream.sealing(encBuf, newKey())) {
                seal.write(data);
            }
            try (InputStream open = AuthenticatedStream.opening(
                    new ByteArrayInputStream(encBuf.toByteArray()), newKey())) {
                byte[] buf = new byte[256];
                //noinspection StatementWithEmptyBody
                while (open.read(buf) > 0) ;
            }
        });
    }
}
