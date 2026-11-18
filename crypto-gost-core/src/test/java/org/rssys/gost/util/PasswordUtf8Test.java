package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PasswordUtf8 — кодирование пароля в UTF-8")
class PasswordUtf8Test {

    @Test
    @DisplayName(
            "ASCII, кириллица, символ из трёх байт и суррогатная пара кодируются как стандартный UTF-8")
    void encodesLikeStandardUtf8() {
        assertArrayEquals(
                "password".getBytes(StandardCharsets.UTF_8),
                PasswordUtf8.encode("password".toCharArray()),
                "ASCII");
        assertArrayEquals(
                new byte[] {
                    (byte) 0xD0, (byte) 0xBF, (byte) 0xD0, (byte) 0xB0, (byte) 0xD1, (byte) 0x80
                },
                PasswordUtf8.encode("\u043F\u0430\u0440".toCharArray()),
                "кириллица: по два байта");
        assertArrayEquals(
                new byte[] {(byte) 0xE2, (byte) 0x82, (byte) 0xAC},
                PasswordUtf8.encode("\u20AC".toCharArray()),
                "евро: три байта");
        // U+1F600: пара D83D DE00 -> одна 4-байтовая последовательность F0 9F 98 80, а не два по 3
        // байта
        assertArrayEquals(
                new byte[] {(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80},
                PasswordUtf8.encode("\uD83D\uDE00".toCharArray()),
                "суррогатная пара: четыре байта");
    }

    @Test
    @DisplayName("null и пустой пароль дают пустой результат")
    void emptyPassword() {
        assertEquals(0, PasswordUtf8.encode(null).length, "null");
        assertEquals(0, PasswordUtf8.encode(new char[0]).length, "пустой массив");
    }

    @Test
    @DisplayName("непарный суррогат отвергается без подстановки «?», сообщение не содержит пароль")
    void unpairedSurrogateIsRejected() {
        String[] malformed = {
            "ab\uD800", // высокий в конце
            "\uDC00ab", // низкий в начале
            "a\uD800b", // высокий без пары
            "\uD800\uD800", // два высоких подряд
            "\uDE00\uD83D" // порядок пары нарушен
        };
        for (String password : malformed) {
            IllegalArgumentException failure =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> PasswordUtf8.encode(password.toCharArray()),
                            "должен отвергаться: " + password.length() + " символов");
            assertFalse(failure.getMessage().contains("ab"), "в сообщении не должно быть пароля");
        }
    }

    @Test
    @DisplayName(
            "результат совпадает с String.getBytes(UTF_8) на случайных допустимых строках, длина точная")
    void matchesStandardEncoderOnRandomStrings() {
        Random random = new Random(20261104L);
        for (int iteration = 0; iteration < 2000; iteration++) {
            StringBuilder builder = new StringBuilder();
            int codePoints = random.nextInt(40);
            for (int i = 0; i < codePoints; i++) {
                int cp;
                do {
                    cp = random.nextInt(0x110000);
                } while (cp >= 0xD800 && cp <= 0xDFFF);
                builder.appendCodePoint(cp);
            }
            String password = builder.toString();
            byte[] expected = password.getBytes(StandardCharsets.UTF_8);
            byte[] actual = PasswordUtf8.encode(password.toCharArray());
            assertArrayEquals(expected, actual, "итерация " + iteration);
        }
    }

    @Test
    @DisplayName("пароль в char[] вызывающего не изменяется")
    void inputIsNotModified() {
        char[] password = "\u043F\uD83D\uDE00x".toCharArray();
        char[] copy = password.clone();
        PasswordUtf8.encode(password);
        assertArrayEquals(copy, password, "исходный массив не должен меняться");
    }
}
