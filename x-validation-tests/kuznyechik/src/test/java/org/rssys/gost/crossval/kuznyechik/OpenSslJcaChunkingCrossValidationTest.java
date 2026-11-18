package org.rssys.gost.crossval.kuznyechik;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Кросс-валидация JCA-пути Кузнечика (CTR/CFB/OFB/CBC) с OpenSSL при разной нарезке входа.
 * <p>
 * OpenSSL здесь — независимый эталон: {@code org.rssys.gost.api.Cipher} и JCA-шифр используют
 * одни и те же классы режимов, поэтому сверка между ними не доказывает корректность
 * потокового {@code update}. Шифртекст JCA, полученный порциями через {@code update},
 * {@link CipherOutputStream} и {@link CipherInputStream}, обязан совпасть с тем, что даёт OpenSSL
 * за один вызов, а шифртекст OpenSSL обязан расшифровываться JCA при любой нарезке.
 * Тест пропускается, если OpenSSL недоступен или собран без Кузнечика.
 */
class OpenSslJcaChunkingCrossValidationTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final int[] DATA_SIZES = {1, 15, 16, 17, 33, 100};
    private static final int[] CHUNK_SIZES = {1, 5, 16, 17, 31};

    @BeforeAll
    static void prepare() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeKuznyechikCipher();
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    /** Режим OpenSSL, JCA-трансформация и длина IV (у CTR 8 байт, у остальных 16). */
    private record Case(org.rssys.gost.api.Cipher.Mode mode, String transformation, int ivLength) {
        @Override
        public String toString() {
            return transformation;
        }
    }

    private static final Case[] CASES = {
        new Case(org.rssys.gost.api.Cipher.Mode.CTR, "Kuznyechik/CTR/NoPadding", 8),
        new Case(org.rssys.gost.api.Cipher.Mode.CFB, "Kuznyechik/CFB/NoPadding", 16),
        new Case(org.rssys.gost.api.Cipher.Mode.OFB, "Kuznyechik/OFB/NoPadding", 16),
        // OpenSSL по умолчанию использует PKCS#7
        new Case(org.rssys.gost.api.Cipher.Mode.CBC, "Kuznyechik/CBC/PKCS7Padding", 16)
    };

    static Stream<Arguments> cases() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (Case current : CASES) {
            for (int size : DATA_SIZES) {
                builder.add(Arguments.of(current, size));
            }
        }
        return builder.build();
    }

    @ParameterizedTest(name = "{0}, {1} байт")
    @MethodSource("cases")
    @DisplayName("JCA при любой нарезке совпадает с OpenSSL в обе стороны")
    void jcaChunkedMatchesOpenSsl(Case current, int size) throws Exception {
        byte[] rawKey = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(rawKey);
        byte[] iv = new byte[current.ivLength()];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = new byte[size];
        CryptoRandom.INSTANCE.nextBytes(plaintext);
        String context =
                "key=" + CrossValUtils.toHex(rawKey) + " iv=" + CrossValUtils.toHex(iv);

        byte[] expected = CompatHelper.opensslOp(current.mode(), "-e", rawKey, iv, plaintext);

        GostSecretKey key = new GostSecretKey("Kuznyechik", new SymmetricKey(rawKey));
        for (int chunk : CHUNK_SIZES) {
            Cipher encryptor = Cipher.getInstance(current.transformation(), PROVIDER);
            encryptor.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ciphertext = runChunked(encryptor, plaintext, chunk);
            assertArrayEquals(
                    expected,
                    ciphertext,
                    () ->
                            "JCA update по "
                                    + chunk
                                    + " байт не совпал с OpenSSL: "
                                    + current
                                    + " size="
                                    + size
                                    + " "
                                    + CrossValUtils.diffContext(expected, ciphertext)
                                    + " "
                                    + context);

            Cipher decryptor = Cipher.getInstance(current.transformation(), PROVIDER);
            decryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = runChunked(decryptor, expected, chunk);
            assertArrayEquals(
                    plaintext,
                    decrypted,
                    () ->
                            "JCA не расшифровал шифртекст OpenSSL порциями по "
                                    + chunk
                                    + ": "
                                    + current
                                    + " size="
                                    + size
                                    + " "
                                    + CrossValUtils.diffContext(plaintext, decrypted)
                                    + " "
                                    + context);
        }

        // Потоки JCE работают поверх update/doFinal и ловят ошибки буферизации и снятия padding
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        Cipher streamEncryptor = Cipher.getInstance(current.transformation(), PROVIDER);
        streamEncryptor.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        try (CipherOutputStream out = new CipherOutputStream(sink, streamEncryptor)) {
            for (int offset = 0; offset < plaintext.length; offset += 7) {
                out.write(plaintext, offset, Math.min(7, plaintext.length - offset));
            }
        }
        assertArrayEquals(
                expected,
                sink.toByteArray(),
                () -> "CipherOutputStream не совпал с OpenSSL: " + current + " size=" + size);

        Cipher streamDecryptor = Cipher.getInstance(current.transformation(), PROVIDER);
        streamDecryptor.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        try (CipherInputStream in =
                new CipherInputStream(new ByteArrayInputStream(expected), streamDecryptor)) {
            assertArrayEquals(
                    plaintext,
                    in.readAllBytes(),
                    () ->
                            "CipherInputStream не расшифровал шифртекст OpenSSL: "
                                    + current
                                    + " size="
                                    + size);
        }
    }

    /** Прогоняет вход через update порциями {@code chunk} байт и завершает doFinal. */
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
}
