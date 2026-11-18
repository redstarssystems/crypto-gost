package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Шифры, которые копят сообщение до {@code doFinal} (MGM и CTR-ACPKM-OMAC), на больших данных:
 * результат не зависит от нарезки {@code update}, а тег остаётся последними 16 байтами, хотя
 * ёмкость буфера больше размера сообщения.
 */
@DisplayName("MGM и CTR-ACPKM-OMAC: накопление большого сообщения порциями")
@ExtendWith(JcaTestSupport.class)
class GostBufferedCipherGrowthTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final int TAG_LEN = 16;

    static Stream<Arguments> matrix() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (String algorithm :
                new String[] {"Kuznyechik/MGM/NoPadding", "Kuznyechik/CTR-ACPKM-OMAC/NoPadding"}) {
            // 70001 не кратно степени двойки: ёмкость заведомо больше размера
            for (int length : new int[] {1, 63, 64, 65, 8192, 70_001}) {
                for (int chunk : new int[] {1, 7, 4096, 8192}) {
                    builder.add(Arguments.of(algorithm, length, chunk));
                }
            }
        }
        return builder.build();
    }

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        CryptoRandom.INSTANCE.nextBytes(b);
        return b;
    }

    private static Cipher cipher(String algorithm, int mode, GostSecretKey key, byte[] iv)
            throws Exception {
        Cipher c = Cipher.getInstance(algorithm, PROVIDER);
        c.init(mode, key, new IvParameterSpec(iv));
        return c;
    }

    private static byte[] runChunked(Cipher cipher, byte[] input, int chunk) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        while (input.length - offset > chunk) {
            byte[] part = cipher.update(input, offset, chunk);
            if (part != null) {
                out.write(part);
            }
            offset += chunk;
        }
        out.write(cipher.doFinal(input, offset, input.length - offset));
        return out.toByteArray();
    }

    @ParameterizedTest(name = "{0}, данных {1} байт, порция {2}")
    @MethodSource("matrix")
    @DisplayName(
            "шифртекст порциями равен шифртексту одним куском, расшифрование возвращает исходник")
    void chunkedEqualsWholeAndRoundtrips(String algorithm, int length, int chunk) throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
        byte[] iv = random(16);
        iv[0] &= 0x7F; // ICN для MGM: старший бит 0 (RFC 9058 §3)
        byte[] plain = random(length);

        byte[] whole = cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plain);
        byte[] chunked = runChunked(cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv), plain, chunk);
        assertArrayEquals(whole, chunked, "шифртекст по порциям совпадает с шифртекстом целиком");
        assertEquals(length + TAG_LEN, whole.length, "шифртекст длиннее открытого на тег");

        assertArrayEquals(
                plain,
                runChunked(cipher(algorithm, Cipher.DECRYPT_MODE, key, iv), whole, chunk),
                "расшифрование по порциям возвращает исходные данные");
    }

    @ParameterizedTest(name = "{0}, порция {1}")
    @MethodSource("corruptionMatrix")
    @DisplayName("искажённый тег после накопления большого сообщения отвергается")
    void corruptedTagRejected(String algorithm, int chunk) throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
        byte[] iv = random(16);
        iv[0] &= 0x7F;
        byte[] encrypted = cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(random(70_001));
        // Тег - последние 16 байт; ёмкость буфера при приёме больше размера, и тег не должен
        // читаться из «хвоста» ёмкости
        encrypted[encrypted.length - 1] ^= 1;

        Cipher decryptor = cipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        assertThrows(
                AEADBadTagException.class,
                () -> runChunked(decryptor, encrypted, chunk),
                "искажённый тег должен быть отвергнут");
    }

    static Stream<Arguments> corruptionMatrix() {
        return Stream.of(
                Arguments.of("Kuznyechik/MGM/NoPadding", 4096),
                Arguments.of("Kuznyechik/MGM/NoPadding", 8192),
                Arguments.of("Kuznyechik/CTR-ACPKM-OMAC/NoPadding", 4096),
                Arguments.of("Kuznyechik/CTR-ACPKM-OMAC/NoPadding", 8192));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("algorithms")
    @DisplayName("ввод короче тега после нескольких update отвергается, лишняя ёмкость не читается")
    void inputShorterThanTagRejected(String algorithm) throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
        byte[] iv = random(16);
        iv[0] &= 0x7F;
        // ёмкость после первого update уже 64 байта, а размер всего 15
        Cipher decryptor = cipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        decryptor.update(random(5));
        decryptor.update(random(5));
        assertThrows(
                AEADBadTagException.class,
                () -> decryptor.doFinal(random(5)),
                "15 байт не вмещают тег в 16 байт");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("algorithms")
    @DisplayName("getOutputSize не переполняется на огромной длине ввода")
    void outputSizeDoesNotOverflow(String algorithm) throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
        byte[] iv = random(16);
        iv[0] &= 0x7F;
        Cipher encryptor = cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv);
        encryptor.update(random(100));
        assertTrue(
                encryptor.getOutputSize(Integer.MAX_VALUE) > 0,
                "размер выхода при шифровании положителен");
        Cipher decryptor = cipher(algorithm, Cipher.DECRYPT_MODE, key, iv);
        decryptor.update(random(100));
        assertTrue(
                decryptor.getOutputSize(Integer.MAX_VALUE) > 0,
                "размер выхода при расшифровании положителен");
        assertEquals(
                100 + 5 + TAG_LEN,
                encryptor.getOutputSize(5),
                "точный размер для малого ввода: накопленное + ввод + тег");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("algorithms")
    @DisplayName("CipherOutputStream блоками по 8 КиБ даёт тот же шифртекст, что doFinal")
    void cipherStreamsMatchDoFinal(String algorithm) throws Exception {
        GostSecretKey key = new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey());
        byte[] iv = random(16);
        iv[0] &= 0x7F;
        byte[] plain = random(70_001);
        byte[] whole = cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv).doFinal(plain);

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (CipherOutputStream out =
                new CipherOutputStream(sink, cipher(algorithm, Cipher.ENCRYPT_MODE, key, iv))) {
            writeInBlocks(out, plain);
        }
        assertArrayEquals(whole, sink.toByteArray(), "шифртекст потока совпадает с doFinal");

        try (CipherInputStream in =
                new CipherInputStream(
                        new ByteArrayInputStream(whole),
                        cipher(algorithm, Cipher.DECRYPT_MODE, key, iv))) {
            assertArrayEquals(plain, in.readAllBytes(), "расшифрование потоком");
        }
    }

    private static void writeInBlocks(CipherOutputStream out, byte[] data) throws IOException {
        final int block = 8192;
        for (int off = 0; off < data.length; off += block) {
            out.write(data, off, Math.min(block, data.length - off));
        }
    }

    static Stream<Arguments> algorithms() {
        return Stream.of(
                Arguments.of("Kuznyechik/MGM/NoPadding"),
                Arguments.of("Kuznyechik/CTR-ACPKM-OMAC/NoPadding"));
    }
}
