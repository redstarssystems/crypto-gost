package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Коды {@code max_fragment_length} (RFC 6066 §4) и размеры фрагмента, которые им соответствуют. */
@DisplayName("TlsUtils: max_fragment_length")
class TlsUtilsMaxFragmentLengthTest {

    @Test
    @DisplayName("коды 1..4 дают 512, 1024, 2048, 4096 байт")
    void codesMapToSizes() {
        assertEquals(512, TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512));
        assertEquals(1024, TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_1024));
        assertEquals(2048, TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_2048));
        assertEquals(4096, TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_4096));
    }

    @Test
    @DisplayName("ноль и недопустимые коды дают полный размер фрагмента, без исключений")
    void invalidCodesFallBackToFullFragment() {
        for (int code : new int[] {0, -1, 5, 255, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
            assertEquals(
                    TlsConstants.MAX_PLAINTEXT_LENGTH,
                    TlsUtils.maxFragmentLength(code),
                    "Код " + code + " не должен уменьшать фрагмент или падать");
        }
    }

    @Test
    @DisplayName("допустимыми считаются только коды 1..4")
    void validRangeIsOneToFour() {
        for (int code = 1; code <= 4; code++) {
            assertTrue(TlsUtils.isMaxFragmentLengthCode(code), "Код " + code);
        }
        for (int code : new int[] {0, -1, 5, 255}) {
            assertFalse(TlsUtils.isMaxFragmentLengthCode(code), "Код " + code);
        }
    }
}
