package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Cipher: потоковый API не трогает потоки вызывающего при отказе")
class CipherStreamsFailClosedTest {

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    @Test
    @DisplayName("encryptingStream(CBC) бросает исключение, не записав в поток ни байта")
    void encryptingStreamCbcWritesNothing() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SymmetricKey key = KeyGenerator.generateSymmetricKey();

        assertThrows(
                UnsupportedOperationException.class,
                () -> Cipher.encryptingStream(out, key, Cipher.Mode.CBC),
                "CBC не поддерживает потоковый режим");
        assertEquals(0, out.size(), "IV не должен попасть в поток до отказа");
    }

    @Test
    @DisplayName("encryptingStream с ключом неверной длины не записывает IV")
    void encryptingStreamWrongKeyWritesNothing() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SymmetricKey shortKey = new SymmetricKey(randomBytes(16));

        assertThrows(
                IllegalArgumentException.class,
                () -> Cipher.encryptingStream(out, shortKey, Cipher.Mode.CTR),
                "ключ 16 байт не подходит Кузнечику");
        assertEquals(0, out.size(), "IV не должен попасть в поток до отказа");
    }

    @Test
    @DisplayName("decryptingStream(CBC) бросает исключение, не прочитав из потока ни байта")
    void decryptingStreamCbcConsumesNothing() {
        byte[] data = randomBytes(64);
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        SymmetricKey key = KeyGenerator.generateSymmetricKey();

        assertThrows(
                UnsupportedOperationException.class,
                () -> Cipher.decryptingStream(in, key, Cipher.Mode.CBC),
                "CBC не поддерживает потоковый режим");
        assertEquals(data.length, in.available(), "IV не должен быть изъят из потока до отказа");
    }

    @Test
    @DisplayName("decryptingStream с ключом неверной длины не читает IV")
    void decryptingStreamWrongKeyConsumesNothing() {
        byte[] data = randomBytes(64);
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        SymmetricKey shortKey = new SymmetricKey(randomBytes(16));

        assertThrows(
                IllegalArgumentException.class,
                () -> Cipher.decryptingStream(in, shortKey, Cipher.Mode.CTR),
                "ключ 16 байт не подходит Кузнечику");
        assertEquals(data.length, in.available(), "IV не должен быть изъят из потока до отказа");
    }

    @Test
    @DisplayName(
            "штатный путь: IV записывается первым и читается обратно, roundtrip для CTR, CFB, OFB")
    void roundtripStillWorks() throws IOException {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] plaintext = randomBytes(1000);
        for (Cipher.Mode mode :
                new Cipher.Mode[] {Cipher.Mode.CTR, Cipher.Mode.CFB, Cipher.Mode.OFB}) {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            try (var out = Cipher.encryptingStream(sink, key, mode)) {
                out.write(plaintext);
            }
            int ivLength = (mode == Cipher.Mode.CTR) ? 8 : 16;
            assertEquals(
                    ivLength + plaintext.length, sink.size(), "[IV | шифртекст], режим " + mode);
            try (var in =
                    Cipher.decryptingStream(
                            new ByteArrayInputStream(sink.toByteArray()), key, mode)) {
                assertArrayEquals(
                        plaintext, in.readAllBytes(), "расшифрованный текст, режим " + mode);
            }
        }
    }

    @Test
    @DisplayName("ISO 7816-4 в Cipher.decrypt: дополнение длиннее блока отвергается")
    void isoPaddingLongerThanBlockIsRejected() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        byte[] iv = randomBytes(16);
        // Открытый текст из двух блоков: 0x80 в начале первого блока и 29 нулей. Без проверки
        // границ блока он принимался как дополнение в 30 байт и отрезался
        byte[] crafted = new byte[32];
        crafted[2] = (byte) 0x80;
        byte[] ciphertext = Cipher.encrypt(crafted, key, iv, Cipher.Mode.CBC, Cipher.Padding.NONE);

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Cipher.decrypt(
                                ciphertext, key, iv, Cipher.Mode.CBC, Cipher.Padding.ISO7816_4),
                "дополнение вне последнего блока должно отвергаться");

        byte[] valid = randomBytes(20);
        byte[] validCiphertext =
                Cipher.encrypt(valid, key, iv, Cipher.Mode.CBC, Cipher.Padding.ISO7816_4);
        assertArrayEquals(
                valid,
                Cipher.decrypt(validCiphertext, key, iv, Cipher.Mode.CBC, Cipher.Padding.ISO7816_4),
                "корректное дополнение снимается");
        assertFalse(Arrays.equals(valid, crafted), "предусловие теста");
    }
}
