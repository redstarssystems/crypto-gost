package org.rssys.gost.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SafeText: вывод недоверенных адресов и текста без секретов и управляющих символов")
class SafeTextTest {

    @Test
    @DisplayName("Адрес выводится как схема://хост:порт/путь без учётных данных и параметров")
    void uriWithoutCredentialsAndQuery() {
        String text =
                SafeText.uri(URI.create("https://user:pass@crl.example:8443/a/b.crl?token=s#f"));

        assertEquals("https://crl.example:8443/a/b.crl", text);
    }

    @Test
    @DisplayName("Порт не выводится, если не задан; IPv6-адрес выводится в скобках")
    void portAndIpv6() {
        assertEquals("http://crl.example/x", SafeText.uri(URI.create("http://crl.example/x")));
        assertEquals("http://[::1]:80/x", SafeText.uri(URI.create("http://[::1]:80/x")));
    }

    @Test
    @DisplayName("Строка-адрес с учётными данными и параметрами очищается так же")
    void stringOverload() {
        String text = SafeText.uri("http://u:p@ocsp.example/r?key=secret");

        assertEquals("http://ocsp.example/r", text);
        assertFalse(text.contains("secret") || text.contains("u:p"), "секреты в выводе: " + text);
    }

    @Test
    @DisplayName("Не разбираемая строка заменяется заглушкой и не бросает исключение")
    void malformedUriIsReplaced() {
        String raw = "http://[bad?token=secret";

        assertEquals(SafeText.MALFORMED_URI, SafeText.uri(raw));
        assertEquals(SafeText.MALFORMED_URI, SafeText.uri((String) null));
        assertEquals(SafeText.MALFORMED_URI, SafeText.uri((URI) null));
    }

    @Test
    @DisplayName(
            "Адрес без разбираемого хоста не выводит authority (там могут быть учётные данные)")
    void authorityWithoutHostIsNotPrinted() {
        // Имя хоста с подчёркиванием не разбирается как хост: getHost() возвращает null
        URI uri = URI.create("http://user:pass@bad_host/x");

        assertEquals(SafeText.MALFORMED_URI, SafeText.uri(uri));
    }

    @Test
    @DisplayName("Текст усекается до предела и заменяет всё, кроме печатных ASCII")
    void printableAsciiOnly() {
        byte[] body = "ok\r\nINJECT\u0001éz".getBytes(StandardCharsets.UTF_8);

        assertEquals("ok??INJECT??z", SafeText.printableAscii(body));
        assertEquals(
                SafeText.MAX_HEADER_CHARS,
                SafeText.printableAscii("x".repeat(1000)).length(),
                "предел длины");
        assertTrue(SafeText.printableAscii(new byte[] {(byte) 0xFF, (byte) 0xFE}).matches("\\?+"));
    }

    @Test
    @DisplayName("null вместо текста не бросает исключение и даёт отличимую заглушку")
    void nullTextIsSafe() {
        assertEquals(SafeText.NULL_TEXT, SafeText.printableAscii((String) null));
        assertEquals(SafeText.NULL_TEXT, SafeText.printableAscii((byte[]) null));
        assertEquals(SafeText.NULL_TEXT, SafeText.printableAscii(null, 10));
    }

    @Test
    @DisplayName("Перегрузка с пределом усекает по заданной длине и так же заменяет символы")
    void explicitLimit() {
        assertEquals("ab", SafeText.printableAscii("abcdef", 2));
        assertEquals("", SafeText.printableAscii("abcdef", 0));
        assertEquals("a?c", SafeText.printableAscii("a\nc", 255));
        assertEquals(
                255, SafeText.printableAscii("x".repeat(1000), 255).length(), "предел 255 не 128");
        assertEquals(
                SafeText.printableAscii("x".repeat(1000)),
                SafeText.printableAscii("x".repeat(1000), SafeText.MAX_HEADER_CHARS),
                "перегрузка без предела должна совпадать с пределом по умолчанию");
    }

    @Test
    @DisplayName("Отрицательный предел длины отвергается")
    void negativeLimitIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> SafeText.printableAscii("abc", -1));
    }
}
