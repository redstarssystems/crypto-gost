package org.rssys.gost.pkix.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HttpValidators: допустимый Last-Modified")
class HttpValidatorsTest {

    private static final String VALID = "Sun, 08 Nov 2026 03:08:46 GMT";

    @Test
    @DisplayName("Дата IMF-fixdate принимается как есть")
    void validDate() {
        assertEquals(VALID, HttpValidators.acceptLastModified(VALID));
    }

    @Test
    @DisplayName("null, пустая строка, пробелы по краям, не дата, слишком длинная отвергаются")
    void invalidValues() {
        assertNull(HttpValidators.acceptLastModified(null));
        assertNull(HttpValidators.acceptLastModified(""));
        assertNull(HttpValidators.acceptLastModified(" " + VALID));
        assertNull(HttpValidators.acceptLastModified(VALID + " "));
        assertNull(HttpValidators.acceptLastModified("yesterday"));
        assertNull(HttpValidators.acceptLastModified("x".repeat(65)));
        assertNull(
                HttpValidators.acceptLastModified(
                        VALID + " ".repeat(HttpValidators.MAX_LAST_MODIFIED_CHARS)));
    }

    @Test
    @DisplayName("Управляющие и не-ASCII символы (CR, LF, NUL, юникод) отвергаются")
    void controlCharacters() {
        assertNull(HttpValidators.acceptLastModified(VALID + "\r\nX-Injected: 1"));
        assertNull(HttpValidators.acceptLastModified("Sun, 08 Nov 2026 03:08:46\u0000GMT"));
        assertNull(HttpValidators.acceptLastModified("Sun, 08 Nov 2026 03:08:46 é"));
    }

    @Test
    @DisplayName("Несуществующая дата и неверный день недели отвергаются")
    void impossibleDate() {
        assertNull(HttpValidators.acceptLastModified("Sun, 31 Feb 2026 03:08:46 GMT"));
        assertNull(HttpValidators.acceptLastModified("Mon, 08 Nov 2026 03:08:46 GMT"));
    }
}
