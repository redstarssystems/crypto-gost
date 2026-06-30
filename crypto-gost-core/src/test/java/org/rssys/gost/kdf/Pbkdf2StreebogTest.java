package org.rssys.gost.kdf;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.mac.Hmac;

/**
 * Тесты PBKDF2-HMAC-Streebog (RFC 9337 §4, RFC 2898 §5.2).
 *
 * <p>Тест-векторы: RFC 9337 Appendix A (PBKDF2 HMAC_GOSTR3411).
 */
@DisplayName("Pbkdf2Streebog — RFC 9337 Appendix A")
class Pbkdf2StreebogTest {

    private static byte[] hex(String s) {
        s = s.replaceAll("\\s+", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(s.charAt(i), 16) << 4)
                                    | Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // ========================================================================
    // RFC 9337 Appendix A — тест-векторы
    // ========================================================================

    @Test
    @DisplayName("Вектор 1: P=password, S=salt, c=1, dkLen=64")
    void testVector1() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII),
                        "salt".getBytes(StandardCharsets.US_ASCII),
                        1,
                        64);
        byte[] expected =
                hex(
                        "64 77 0a f7 f7 48 c3 b1 c9 ac 83 1d bc fd 85 c2 "
                                + "61 11 b3 0a 8a 65 7d dc 30 56 b8 0c a7 3e 04 0d "
                                + "28 54 fd 36 81 1f 6d 82 5c c4 ab 66 ec 0a 68 a4 "
                                + "90 a9 e5 cf 51 56 b3 a2 b7 ee cd db f9 a1 6b 47");
        assertArrayEquals(expected, dk);
    }

    @Test
    @DisplayName("Вектор 2: P=password, S=salt, c=2, dkLen=64")
    void testVector2() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII),
                        "salt".getBytes(StandardCharsets.US_ASCII),
                        2,
                        64);
        byte[] expected =
                hex(
                        "5a 58 5b af df bb 6e 88 30 d6 d6 8a a3 b4 3a c0 "
                                + "0d 2e 4a eb ce 01 c9 b3 1c 2c ae d5 6f 02 36 d4 "
                                + "d3 4b 2b 8f bd 2c 4e 89 d5 4d 46 f5 0e 47 d4 5b "
                                + "ba c3 01 57 17 43 11 9e 8d 3c 42 ba 66 d3 48 de");
        assertArrayEquals(expected, dk);
    }

    @Test
    @DisplayName("Вектор 3: P=password, S=salt, c=4096, dkLen=64")
    void testVector3() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII),
                        "salt".getBytes(StandardCharsets.US_ASCII),
                        4096,
                        64);
        byte[] expected =
                hex(
                        "e5 2d eb 9a 2d 2a af f4 e2 ac 9d 47 a4 1f 34 c2 "
                                + "03 76 59 1c 67 80 7f 04 77 e3 25 49 dc 34 1b c7 "
                                + "86 7c 09 84 1b 6d 58 e2 9d 03 47 c9 96 30 1d 55 "
                                + "df 0d 34 e4 7c f6 8f 4e 3c 2c da f1 d9 ab 86 c3");
        assertArrayEquals(expected, dk);
    }

    @Test
    @DisplayName("Вектор 4: P=passwordPASSWORDpassword, S=saltSALT(36), c=4096, dkLen=100 (l=2)")
    void testVector4() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "passwordPASSWORDpassword".getBytes(StandardCharsets.US_ASCII),
                        "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(StandardCharsets.US_ASCII),
                        4096,
                        100);
        byte[] expected =
                hex(
                        "b2 d8 f1 24 5f c4 d2 92 74 80 20 57 e4 b5 4e 0a "
                                + "07 53 aa 22 fc 53 76 0b 30 1c f0 08 67 9e 58 fe "
                                + "4b ee 9a dd ca e9 9b a2 b0 b2 0f 43 1a 9c 5e 50 "
                                + "f3 95 c8 93 87 d0 94 5a ed ec a6 eb 40 15 df c2 "
                                + "bd 24 21 ee 9b b7 11 83 ba 88 2c ee bf ef 25 9f "
                                + "33 f9 e2 7d c6 17 8c b8 9d c3 74 28 cf 9c c5 2a "
                                + "2b aa 2d 3a");
        assertArrayEquals(expected, dk);
    }

    @Test
    @DisplayName("Вектор 5: P=pass\\0word, S=sa\\0lt, c=4096, dkLen=64")
    void testVector5() {
        byte[] password = new byte[] {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'};
        byte[] salt = new byte[] {'s', 'a', 0, 'l', 't'};
        byte[] dk = Pbkdf2Streebog.generate(password, salt, 4096, 64);
        byte[] expected =
                hex(
                        "50 df 06 28 85 b6 98 01 a3 c1 02 48 eb 0a 27 ab "
                                + "6e 52 2f fe b2 0c 99 1c 66 0f 00 14 75 d7 3a 4e "
                                + "16 7f 78 2c 18 e9 7e 92 97 6d 9c 1d 97 08 31 ea "
                                + "78 cc b8 79 f6 70 68 cd ac 19 10 74 08 44 e8 30");
        assertArrayEquals(expected, dk);
    }

    // ========================================================================
    // Разные PRF: HMAC-Streebog-256 через Mac-перегрузку
    // ========================================================================

    @Test
    @DisplayName("HMAC-Streebog-256 как PRF: детерминизм")
    void testPrf256Determinism() {
        Hmac hmac = new Hmac(new Streebog256());
        hmac.init("password".getBytes(StandardCharsets.US_ASCII));

        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        byte[] r1 = Pbkdf2Streebog.generate(hmac, salt, 1, 32);
        byte[] r2 = Pbkdf2Streebog.generate(hmac, salt, 1, 32);
        assertArrayEquals(r1, r2);
        assertFalse(allZero(r1));
    }

    @Test
    @DisplayName("HMAC-Streebog-256 и HMAC-Streebog-512 дают разные ключи")
    void test256vs512() {
        byte[] password = "password".getBytes(StandardCharsets.US_ASCII);
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);

        byte[] dk512 = Pbkdf2Streebog.generate(password, salt, 1, 32);

        Hmac hmac256 = new Hmac(new Streebog256());
        hmac256.init(password);
        byte[] dk256 = Pbkdf2Streebog.generate(hmac256, salt, 1, 32);

        assertFalse(java.util.Arrays.equals(dk512, dk256));
    }

    // ========================================================================
    // Граничные случаи
    // ========================================================================

    @Test
    @DisplayName("dkLen=1: берётся первый байт от HMAC")
    void testDkLenMin() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII),
                        "salt".getBytes(StandardCharsets.US_ASCII),
                        1,
                        1);
        assertEquals(1, dk.length);
        byte[] full =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII),
                        "salt".getBytes(StandardCharsets.US_ASCII),
                        1,
                        64);
        assertEquals(full[0], dk[0]);
    }

    @Test
    @DisplayName("Пустая соль: легитимна по RFC 2898")
    void testEmptySalt() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        "password".getBytes(StandardCharsets.US_ASCII), new byte[0], 1, 32);
        assertEquals(32, dk.length);
    }

    @Test
    @DisplayName("Пустой пароль: допустимо по RFC 2104 §2, RFC 8018")
    void testEmptyPassword() {
        byte[] dk =
                Pbkdf2Streebog.generate(
                        new byte[0], "salt".getBytes(StandardCharsets.US_ASCII), 1, 32);
        assertEquals(32, dk.length);
        boolean allZero = true;
        for (byte b : dk) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        assertFalse(allZero, "PBKDF2 с пустым паролем не должен давать нулевой ключ");
    }

    // ========================================================================
    // Исключения
    // ========================================================================

    @Test
    @DisplayName("c=0 -> IllegalArgumentException")
    void testCIllegal() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Pbkdf2Streebog.generate(
                                "p".getBytes(StandardCharsets.US_ASCII),
                                "s".getBytes(StandardCharsets.US_ASCII),
                                0,
                                32));
    }

    @Test
    @DisplayName("c=-1 -> IllegalArgumentException")
    void testCNegative() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Pbkdf2Streebog.generate(
                                "p".getBytes(StandardCharsets.US_ASCII),
                                "s".getBytes(StandardCharsets.US_ASCII),
                                -1,
                                32));
    }

    @Test
    @DisplayName("dkLen=0 -> IllegalArgumentException")
    void testDkLenZero() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Pbkdf2Streebog.generate(
                                "p".getBytes(StandardCharsets.US_ASCII),
                                "s".getBytes(StandardCharsets.US_ASCII),
                                1,
                                0));
    }

    @Test
    @DisplayName("dkLen=-1 -> IllegalArgumentException")
    void testDkLenNegative() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Pbkdf2Streebog.generate(
                                "p".getBytes(StandardCharsets.US_ASCII),
                                "s".getBytes(StandardCharsets.US_ASCII),
                                1,
                                -1));
    }

    // ========================================================================
    // helpers
    // ========================================================================

    private static boolean allZero(byte[] data) {
        for (byte b : data) if (b != 0) return false;
        return true;
    }
}
