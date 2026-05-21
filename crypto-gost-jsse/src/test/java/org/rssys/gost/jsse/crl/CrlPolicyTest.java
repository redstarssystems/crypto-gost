package org.rssys.gost.jsse.crl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit-тесты для {@link CrlPolicy}.
 */
@DisplayName("CrlPolicy: значения политики CRL")
class CrlPolicyTest {

    @Test
    @DisplayName("DISABLED — CRL не проверяется")
    void testDisabled() {
        assertEquals(CrlPolicy.DISABLED, CrlPolicy.valueOf("DISABLED"));
    }

    @Test
    @DisplayName("IF_CDP_PRESENT — CRL если есть CDP, нет CDP — OK")
    void testIfCdpPresent() {
        assertEquals(CrlPolicy.IF_CDP_PRESENT, CrlPolicy.valueOf("IF_CDP_PRESENT"));
    }

    @Test
    @DisplayName("REQUIRE — CRL обязателен при наличии CDP")
    void testRequire() {
        assertEquals(CrlPolicy.REQUIRE, CrlPolicy.valueOf("REQUIRE"));
    }

    @Test
    @DisplayName("Три значения в enum")
    void testEnumSize() {
        assertEquals(3, CrlPolicy.values().length);
    }
}
