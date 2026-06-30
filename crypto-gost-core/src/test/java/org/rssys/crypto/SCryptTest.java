package org.rssys.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.crypto.util.SCrypt;

/**
 * Тесты корректности реализации SCrypt (RFC 7914).
 *
 * <p>Тест-векторы взяты из RFC 7914 §12:
 * https://www.rfc-editor.org/rfc/rfc7914#section-12
 *
 * <p>Вектор 3 (N=1024, r=8, p=16) пропущен из-за объёма памяти (~128 МБ),
 * необходимого для выполнения в стандартном тестовом окружении.
 */
@DisplayName("SCrypt (RFC 7914) Tests")
class SCryptTest {

    /** Вспомогательный метод: hex-строка -> byte[]. */
    private static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    // -----------------------------------------------------------------------
    // RFC 7914 §12 — тест-вектор 1
    //
    // scrypt("", "", 16, 1, 1, 64)
    //
    // Ожидаемый результат:
    //   77d6576238657b203b19ca42c18a0497
    //   f16b4844e3074ae8dfdffa3fede21442
    //   fcd0069ded0948f8326a753a0fc81f17
    //   e8d3e0fb2e0d3628cf35e20c38d18906
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("RFC 7914 §12 вектор 1: scrypt(\"\", \"\", N=16, r=1, p=1, dkLen=64)")
    void testVector1() throws Exception {
        byte[] passwd = "".getBytes("UTF-8");
        byte[] salt = "".getBytes("UTF-8");

        byte[] expected =
                fromHex(
                        "77d6576238657b203b19ca42c18a0497"
                                + "f16b4844e3074ae8dfdffa3fede21442"
                                + "fcd0069ded0948f8326a753a0fc81f17"
                                + "e8d3e0fb2e0d3628cf35e20c38d18906");

        byte[] actual = SCrypt.generate(passwd, salt, 16, 1, 1, 64);

        assertArrayEquals(
                expected, actual, "RFC 7914 вектор 1: scrypt(\"\", \"\", 16, 1, 1, 64) не совпал");
    }

    // -----------------------------------------------------------------------
    // RFC 7914 §12 — тест-вектор 2
    //
    // scrypt("password", "NaCl", 1024, 8, 16, 64)
    //
    // Ожидаемый результат:
    //   fdbabe1c9d3472007856e7190d01e9fe
    //   7c6ad7cbc8237830e77376634b373162
    //   2eaf30d92e22a3886ff109279d9830da
    //   c727afb94a83ee6d8360cbdfa2cc0640
    //
    // Примечание: требует ~128 МБ памяти (N=1024, r=8 -> V = 128·8·1024 = 1 МБ на блок × 16).
    // Выполняется несколько секунд.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "RFC 7914 §12 вектор 2: scrypt(\"password\", \"NaCl\", N=1024, r=8, p=16, dkLen=64)")
    void testVector2() throws Exception {
        byte[] passwd = "password".getBytes("UTF-8");
        byte[] salt = "NaCl".getBytes("UTF-8");

        byte[] expected =
                fromHex(
                        "fdbabe1c9d3472007856e7190d01e9fe"
                                + "7c6ad7cbc8237830e77376634b373162"
                                + "2eaf30d92e22a3886ff109279d9830da"
                                + "c727afb94a83ee6d8360cbdfa2cc0640");

        byte[] actual = SCrypt.generate(passwd, salt, 1024, 8, 16, 64);

        assertArrayEquals(
                expected,
                actual,
                "RFC 7914 вектор 2: scrypt(\"password\", \"NaCl\", 1024, 8, 16, 64) не совпал");
    }

    // -----------------------------------------------------------------------
    // RFC 7914 §12 — тест-вектор 3 (облегчённый)
    //
    // scrypt("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64)
    //
    // Ожидаемый результат:
    //   7023bdcb3afd7348461c06cd81fd38eb
    //   fda8fbba904f8e3ea9b543f6545da1f2
    //   d5432955613f0fcf62d49705242a9af9
    //   e61e85dc0d651e40dfcf017b45575887
    //
    // Облегчённый вариант вектора 3 из RFC (p=1 вместо p=1, N=16384 вместо N=1048576).
    // Требует ~128 МБ памяти.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "RFC 7914 §12 вектор 3: scrypt(\"pleaseletmein\", \"SodiumChloride\", N=16384, r=8, p=1, dkLen=64)")
    void testVector3() throws Exception {
        byte[] passwd = "pleaseletmein".getBytes("UTF-8");
        byte[] salt = "SodiumChloride".getBytes("UTF-8");

        byte[] expected =
                fromHex(
                        "7023bdcb3afd7348461c06cd81fd38eb"
                                + "fda8fbba904f8e3ea9b543f6545da1f2"
                                + "d5432955613f0fcf62d49705242a9af9"
                                + "e61e85dc0d651e40dfcf017b45575887");

        byte[] actual = SCrypt.generate(passwd, salt, 16384, 8, 1, 64);

        assertArrayEquals(
                expected,
                actual,
                "RFC 7914 вектор 3: scrypt(\"pleaseletmein\", ..., 16384, 8, 1, 64) не совпал");
    }

    // -----------------------------------------------------------------------
    // Проверка детерминированности: один и тот же вход -> один и тот же выход
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Детерминированность: одинаковые параметры дают одинаковый ключ")
    void testDeterministic() throws Exception {
        byte[] passwd = "test-password".getBytes("UTF-8");
        byte[] salt = "test-salt-16byt".getBytes("UTF-8");

        byte[] dk1 = SCrypt.generate(passwd, salt, 16, 1, 1, 32);
        byte[] dk2 = SCrypt.generate(passwd, salt, 16, 1, 1, 32);

        assertArrayEquals(dk1, dk2, "SCrypt должен быть детерминированным");
    }

    // -----------------------------------------------------------------------
    // Проверка чувствительности: разные пароли дают разные ключи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Чувствительность к паролю: разные пароли -> разные ключи")
    void testPasswordSensitivity() throws Exception {
        byte[] salt = "same-salt".getBytes("UTF-8");
        byte[] dk1 = SCrypt.generate("password1".getBytes("UTF-8"), salt, 16, 1, 1, 32);
        byte[] dk2 = SCrypt.generate("password2".getBytes("UTF-8"), salt, 16, 1, 1, 32);

        assertFalse(
                Arrays.equals(dk1, dk2), "Разные пароли должны давать разные производные ключи");
    }

    // -----------------------------------------------------------------------
    // Проверка чувствительности: разные соли дают разные ключи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Чувствительность к соли: разные соли -> разные ключи")
    void testSaltSensitivity() throws Exception {
        byte[] passwd = "samepassword".getBytes("UTF-8");
        byte[] dk1 = SCrypt.generate(passwd, "salt1".getBytes("UTF-8"), 16, 1, 1, 32);
        byte[] dk2 = SCrypt.generate(passwd, "salt2".getBytes("UTF-8"), 16, 1, 1, 32);

        assertFalse(Arrays.equals(dk1, dk2), "Разные соли должны давать разные производные ключи");
    }

    // -----------------------------------------------------------------------
    // Проверка dkLen: выходной массив имеет правильную длину
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Длина вывода соответствует dkLen")
    void testOutputLength() throws Exception {
        byte[] passwd = "p".getBytes("UTF-8");
        byte[] salt = "s".getBytes("UTF-8");

        for (int dkLen : new int[] {1, 16, 32, 64, 100}) {
            byte[] dk = SCrypt.generate(passwd, salt, 16, 1, 1, dkLen);
            assertEquals(dkLen, dk.length, "Длина вывода должна быть равна dkLen=" + dkLen);
        }
    }

    // -----------------------------------------------------------------------
    // Проверка валидации параметров
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Валидация: passwd = null -> IllegalArgumentException")
    void testNullPasswd() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(null, new byte[16], 16, 1, 1, 32),
                "null passwd должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: salt = null -> IllegalArgumentException")
    void testNullSalt() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], null, 16, 1, 1, 32),
                "null salt должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: N не степень 2 -> IllegalArgumentException")
    void testNNotPowerOf2() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], 15, 1, 1, 32),
                "N=15 не является степенью 2");
    }

    @Test
    @DisplayName("Валидация: N = 1 -> IllegalArgumentException")
    void testNEquals1() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], 1, 1, 1, 32),
                "N=1 должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: r = 0 -> IllegalArgumentException")
    void testRZero() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], 16, 0, 1, 32),
                "r=0 должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: p = 0 -> IllegalArgumentException")
    void testPZero() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], 16, 1, 0, 32),
                "p=0 должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: dkLen = 0 -> IllegalArgumentException")
    void testDkLenZero() {
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], 16, 1, 1, 0),
                "dkLen=0 должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Валидация: N слишком большой -> IllegalArgumentException")
    void testNTooLarge() {
        // N > Integer.MAX_VALUE / 128 / r при r=1 -> N > 16777215
        assertThrows(
                IllegalArgumentException.class,
                () -> SCrypt.generate(new byte[8], new byte[8], Integer.MAX_VALUE, 1, 1, 32),
                "Слишком большой N должен бросать IllegalArgumentException");
    }
}
