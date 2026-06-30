package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;

@DisplayName("Digest Tests")
class DigestTest {

    private static final byte[] MSG = "hello gost".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEY_BYTES = new byte[32];

    static {
        Arrays.fill(KEY_BYTES, (byte) 0x42);
    }

    private static final SymmetricKey KEY = new SymmetricKey(KEY_BYTES);

    // -----------------------------------------------------------------------
    // Статические методы — совпадение с низкоуровневым API
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("digest256: совпадает с низкоуровневым Streebog256")
    void testDigest256MatchesLowLevel() {
        Streebog256 d = new Streebog256();
        d.update(MSG, 0, MSG.length);
        byte[] expected = new byte[32];
        d.doFinal(expected, 0);

        assertArrayEquals(expected, Digest.digest256(MSG));
    }

    @Test
    @DisplayName("digest512: совпадает с низкоуровневым Streebog512")
    void testDigest512MatchesLowLevel() {
        Streebog512 d = new Streebog512();
        d.update(MSG, 0, MSG.length);
        byte[] expected = new byte[64];
        d.doFinal(expected, 0);

        assertArrayEquals(expected, Digest.digest512(MSG));
    }

    @Test
    @DisplayName("hmac256: совпадает с низкоуровневым Hmac(Streebog256)")
    void testHmac256MatchesLowLevel() {
        Hmac h = new Hmac(new Streebog256());
        h.init(KEY);
        h.update(MSG, 0, MSG.length);
        byte[] expected = new byte[32];
        h.doFinal(expected, 0);

        assertArrayEquals(expected, Digest.hmac256(MSG, KEY));
    }

    @Test
    @DisplayName("hmac512: совпадает с низкоуровневым Hmac(Streebog512)")
    void testHmac512MatchesLowLevel() {
        Hmac h = new Hmac(new Streebog512());
        h.init(KEY);
        h.update(MSG, 0, MSG.length);
        byte[] expected = new byte[64];
        h.doFinal(expected, 0);

        assertArrayEquals(expected, Digest.hmac512(MSG, KEY));
    }

    // -----------------------------------------------------------------------
    // Длины вывода
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("digest256: длина 32 байта")
    void testDigest256Length() {
        assertEquals(32, Digest.digest256(MSG).length);
    }

    @Test
    @DisplayName("digest512: длина 64 байта")
    void testDigest512Length() {
        assertEquals(64, Digest.digest512(MSG).length);
    }

    @Test
    @DisplayName("hmac256: длина 32 байта")
    void testHmac256Length() {
        assertEquals(32, Digest.hmac256(MSG, KEY).length);
    }

    @Test
    @DisplayName("hmac512: длина 64 байта")
    void testHmac512Length() {
        assertEquals(64, Digest.hmac512(MSG, KEY).length);
    }

    // -----------------------------------------------------------------------
    // Потоковый инстанс — совпадение с порциями и цельным вводом
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Digest инстанс STREEBOG_256: update по частям = update целиком")
    void testStreamingDigest256() {
        byte[] expected = Digest.digest256(MSG);

        byte[] actual =
                new Digest(Digest.Algorithm.STREEBOG_256)
                        .update(Arrays.copyOfRange(MSG, 0, 5))
                        .update(Arrays.copyOfRange(MSG, 5, MSG.length))
                        .digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Digest инстанс STREEBOG_512: update по частям = update целиком")
    void testStreamingDigest512() {
        byte[] expected = Digest.digest512(MSG);

        byte[] actual =
                new Digest(Digest.Algorithm.STREEBOG_512)
                        .update(MSG, 0, 3)
                        .update(MSG, 3, MSG.length - 3)
                        .digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Digest инстанс HMAC_256: update по частям = статический метод")
    void testStreamingHmac256() {
        byte[] expected = Digest.hmac256(MSG, KEY);

        byte[] actual = new Digest(Digest.Algorithm.HMAC_256, KEY).update(MSG).digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Digest инстанс HMAC_512: update по частям = статический метод")
    void testStreamingHmac512() {
        byte[] expected = Digest.hmac512(MSG, KEY);

        byte[] actual =
                new Digest(Digest.Algorithm.HMAC_512, KEY)
                        .update(Arrays.copyOfRange(MSG, 0, 4))
                        .update(Arrays.copyOfRange(MSG, 4, MSG.length))
                        .digest();

        assertArrayEquals(expected, actual);
    }

    @Test
    @DisplayName("Digest инстанс: повторное использование после digest()")
    void testStreamingReuseAfterDigest() {
        Digest h = new Digest(Digest.Algorithm.STREEBOG_256);
        byte[] r1 = h.update(MSG).digest();
        byte[] r2 = h.update(MSG).digest();
        assertArrayEquals(
                r1, r2, "После digest() инстанс должен быть готов к повторному использованию");
    }

    // -----------------------------------------------------------------------
    // Конструктор с неправильными аргументами
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Digest(HMAC_256) без ключа -> IllegalArgumentException")
    void testStreamingMacWithoutKey() {
        assertThrows(IllegalArgumentException.class, () -> new Digest(Digest.Algorithm.HMAC_256));
    }

    @Test
    @DisplayName("Digest(STREEBOG_256, key) с ключом -> IllegalArgumentException")
    void testStreamingDigestWithKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Digest(Digest.Algorithm.STREEBOG_256, KEY));
    }

    // -----------------------------------------------------------------------
    // Чувствительность к данным
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("digest256: разные данные -> разные хэши")
    void testDigest256Sensitivity() {
        byte[] h1 = Digest.digest256("hello".getBytes(StandardCharsets.UTF_8));
        byte[] h2 = Digest.digest256("world".getBytes(StandardCharsets.UTF_8));
        assertFalse(Arrays.equals(h1, h2));
    }

    @Test
    @DisplayName("hmac256: разные ключи -> разные теги")
    void testHmac256KeySensitivity() {
        SymmetricKey key2 = new SymmetricKey(new byte[32]);
        byte[] m1 = Digest.hmac256(MSG, KEY);
        byte[] m2 = Digest.hmac256(MSG, key2);
        assertFalse(Arrays.equals(m1, m2));
    }
}
