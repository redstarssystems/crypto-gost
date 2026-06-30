package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TstInfo: equals и hashCode для record с byte[] компонентом")
class TstInfoTest {

    @Test
    @DisplayName("equals возвращает true при идентичных полях (включая byte[])")
    void equalsReturnsTrueForIdenticalFields() {
        byte[] hash = {1, 2, 3, 4, 5};
        TstInfo a =
                new TstInfo(
                        "1.2.3",
                        hash,
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        TstInfo b =
                new TstInfo(
                        "1.2.3",
                        new byte[] {1, 2, 3, 4, 5},
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        assertEquals(a, b, "Два TstInfo с идентичными данными должны быть равны");
    }

    @Test
    @DisplayName("equals возвращает false при разном messageImprintHash")
    void equalsReturnsFalseForDifferentHash() {
        TstInfo a =
                new TstInfo(
                        "1.2.3",
                        new byte[] {1, 2, 3},
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        TstInfo b =
                new TstInfo(
                        "1.2.3",
                        new byte[] {4, 5, 6},
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        assertNotEquals(a, b, "Разный хэш — TstInfo должны быть не равны");
    }

    @Test
    @DisplayName("hashCode совпадает при идентичных полях")
    void hashCodeEqualForIdenticalFields() {
        byte[] hash = {10, 20, 30};
        TstInfo a =
                new TstInfo(
                        "1.2.3",
                        hash,
                        "1.2.3.4",
                        BigInteger.TWO,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        TstInfo b =
                new TstInfo(
                        "1.2.3",
                        new byte[] {10, 20, 30},
                        "1.2.3.4",
                        BigInteger.TWO,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        assertEquals(
                a.hashCode(), b.hashCode(), "Идентичные TstInfo должны иметь одинаковый hashCode");
    }

    @Test
    @DisplayName("hashCode разный при разном messageImprintHash")
    void hashCodeDifferentForDifferentHash() {
        TstInfo a =
                new TstInfo(
                        "1.2.3",
                        new byte[] {1, 2, 3},
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        TstInfo b =
                new TstInfo(
                        "1.2.3",
                        new byte[] {4, 5, 6},
                        "1.2.3.4",
                        BigInteger.ONE,
                        "20250101000000Z",
                        null,
                        null,
                        false,
                        null);
        assertNotEquals(a.hashCode(), b.hashCode(), "Разный хэш — hashCode должны различаться");
    }
}
