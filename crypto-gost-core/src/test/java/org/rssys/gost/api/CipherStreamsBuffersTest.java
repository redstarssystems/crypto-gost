package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Потоковые обёртки {@code Cipher}: шифртекст не зависит от того, как данные нарезаны на записи
 * и чтения (в том числе длиннее внутреннего буфера), входной массив вызывающего при шифровании
 * не меняется, а расшифрование идёт прямо в буфере чтения.
 */
@DisplayName("Cipher: потоки шифруют и расшифровывают независимо от нарезки данных")
class CipherStreamsBuffersTest {

    private static final int LENGTH = 20_000;

    private static byte[] iv(Cipher.Mode mode) {
        byte[] iv = new byte[mode == Cipher.Mode.CTR ? 8 : 16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        return iv;
    }

    @Test
    @DisplayName("Запись одним куском и по частям даёт тот же шифртекст, вход не меняется")
    void encryptingStreamMatchesOneShot() throws IOException {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plain = new byte[LENGTH];
        CryptoRandom.INSTANCE.nextBytes(plain);
        byte[] original = plain.clone();
        for (Cipher.Mode mode :
                new Cipher.Mode[] {Cipher.Mode.CTR, Cipher.Mode.CFB, Cipher.Mode.OFB}) {
            byte[] iv = iv(mode);
            byte[] expected = Cipher.encrypt(plain, key, iv, mode);

            ByteArrayOutputStream whole = new ByteArrayOutputStream();
            try (OutputStream out = Cipher.encryptingStream(whole, key, iv, mode)) {
                out.write(plain, 0, plain.length);
            }
            ByteArrayOutputStream pieces = new ByteArrayOutputStream();
            try (OutputStream out = Cipher.encryptingStream(pieces, key, iv, mode)) {
                out.write(plain, 0, 1);
                out.write(plain, 1, 8191);
                out.write(plain, 8192, 3);
                out.write(plain, 8195, LENGTH - 8195);
            }
            assertArrayEquals(expected, whole.toByteArray(), "одной записью, режим " + mode);
            assertArrayEquals(expected, pieces.toByteArray(), "по частям, режим " + mode);
            assertArrayEquals(original, plain, "входной массив изменился, режим " + mode);
        }
    }

    @Test
    @DisplayName("Чтение буферами разного размера и со смещением возвращает открытый текст")
    void decryptingStreamReadsAnyBufferSize() throws IOException {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plain = new byte[LENGTH];
        CryptoRandom.INSTANCE.nextBytes(plain);
        for (Cipher.Mode mode :
                new Cipher.Mode[] {Cipher.Mode.CTR, Cipher.Mode.CFB, Cipher.Mode.OFB}) {
            byte[] iv = iv(mode);
            byte[] cipherText = Cipher.encrypt(plain, key, iv, mode);
            for (int bufferSize : new int[] {1, 7, 16, 4096, 30_000}) {
                ByteArrayOutputStream collected = new ByteArrayOutputStream();
                try (InputStream in =
                        Cipher.decryptingStream(
                                new ByteArrayInputStream(cipherText), key, iv, mode)) {
                    byte[] buffer = new byte[bufferSize + 5];
                    int n;
                    while ((n = in.read(buffer, 5, bufferSize)) > 0) {
                        collected.write(buffer, 5, n);
                    }
                }
                assertArrayEquals(
                        plain, collected.toByteArray(), "режим " + mode + ", буфер " + bufferSize);
            }
        }
    }

    @Test
    @DisplayName("Запись с неверными границами отвергается и ничего не передаёт вниз")
    void writeRejectsBadBounds() throws IOException {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (OutputStream out =
                Cipher.encryptingStream(sink, key, iv(Cipher.Mode.CTR), Cipher.Mode.CTR)) {
            byte[] data = new byte[10];
            assertThrows(
                    IndexOutOfBoundsException.class,
                    () -> out.write(data, 5, 6),
                    "хвост за границей");
            assertThrows(
                    IndexOutOfBoundsException.class,
                    () -> out.write(data, -1, 2),
                    "отрицательное смещение");
            assertThrows(
                    IndexOutOfBoundsException.class,
                    () -> out.write(data, 0, -1),
                    "отрицательная длина");
        }
        assertArrayEquals(new byte[0], sink.toByteArray(), "при отказе вниз ничего не уходит");
    }
}
