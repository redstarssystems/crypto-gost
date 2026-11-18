package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Рабочие буферы {@code AuthenticatedStream} переиспользуются между чанками: данные не должны
 * зависеть от нарезки чтения и записи, а открытый текст не должен оставаться в буферах после
 * конца потока.
 */
@DisplayName("AuthenticatedStream: переиспользование буферов чанка")
class AuthenticatedStreamBufferReuseTest {

    private static final int CHUNK = 16;

    private static byte[] seal(byte[] plain, SymmetricKey key) throws Exception {
        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        try (OutputStream out = AuthenticatedStream.sealing(sealed, key, CHUNK)) {
            out.write(plain);
        }
        return sealed.toByteArray();
    }

    private static byte[] readAll(InputStream in, int bufferSize) throws Exception {
        ByteArrayOutputStream collected = new ByteArrayOutputStream();
        if (bufferSize == 1) {
            int b;
            while ((b = in.read()) >= 0) {
                collected.write(b);
            }
        } else {
            byte[] buffer = new byte[bufferSize];
            int n;
            while ((n = in.read(buffer, 0, bufferSize)) > 0) {
                collected.write(buffer, 0, n);
            }
        }
        return collected.toByteArray();
    }

    @Test
    @DisplayName("Чтение по байту, малым и большим буфером на длинах вокруг границы чанка")
    void readingPatternsDoNotChangeResult() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        for (int length : new int[] {0, 1, 15, 16, 17, 31, 32, 33, 100}) {
            byte[] plain = new byte[length];
            CryptoRandom.INSTANCE.nextBytes(plain);
            byte[] sealed = seal(plain, key);
            for (int bufferSize : new int[] {1, 7, 4096}) {
                try (InputStream in =
                        AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
                    assertArrayEquals(
                            plain,
                            readAll(in, bufferSize),
                            "длина " + length + ", буфер чтения " + bufferSize);
                }
            }
        }
    }

    @Test
    @DisplayName("После конца потока буфер читателя, державший открытый текст, обнулён")
    void readerBufferIsWipedAfterEnd() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plain = new byte[3 * CHUNK + 5];
        Arrays.fill(plain, (byte) 0x7B);
        byte[] sealed = seal(plain, key);

        try (InputStream in = AuthenticatedStream.opening(new ByteArrayInputStream(sealed), key)) {
            assertEquals(0x7B, in.read(), "первый байт открытого текста");
            Field field = in.getClass().getDeclaredField("plainBuf");
            field.setAccessible(true);
            byte[] held = (byte[]) field.get(in);
            assertTrue(held.length >= CHUNK, "буфер должен вместить чанк");
            assertEquals(plain.length - 1, readAll(in, 7).length, "остаток потока");
            for (byte b : held) {
                assertEquals(0, b, "открытый текст остался в буфере читателя после конца потока");
            }
        }
    }

    @Test
    @DisplayName("После finish() буфер писателя обнулён: ни открытого текста, ни шифртекста")
    void writerBufferIsWipedAfterFinish() throws Exception {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        ByteArrayOutputStream sealed = new ByteArrayOutputStream();
        AuthenticatedStream.SealingStream out = AuthenticatedStream.sealing(sealed, key, CHUNK);
        byte[] plain = new byte[CHUNK + 3];
        Arrays.fill(plain, (byte) 0x7B);
        out.write(plain);
        Field field = AuthenticatedStream.SealingStream.class.getDeclaredField("chunkBuf");
        field.setAccessible(true);
        byte[] buffer = (byte[]) field.get(out);
        out.finish();
        for (byte b : buffer) {
            assertEquals(0, b, "в буфере писателя остались данные после finish()");
        }
    }
}
