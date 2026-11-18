package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostCurves;

@DisplayName("ECParameters: структурное равенство и согласованность с кривой точки")
class ECParametersEqualsTest {

    /** Копия параметров по значению; cofactorOverride меняет единственный параметр для проверки равенства. */
    private static ECParameters copyOf(ECParameters src, int cofactor) {
        return new ECParameters(
                src.p.toString(16),
                src.a.toString(16),
                src.b.toString(16),
                src.gx.toString(16),
                src.gy.toString(16),
                src.n.toString(16),
                src.hlen,
                cofactor);
    }

    @Test
    @DisplayName("Рефлексивность и равенство копии по значению с одинаковым hashCode")
    void equalByValue() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters copy = copyOf(original, original.cofactor);

        assertEquals(original, original, "объект равен самому себе");
        assertEquals(original, copy, "копия по значению равна оригиналу");
        assertEquals(copy, original, "равенство симметрично");
        assertEquals(original.hashCode(), copy.hashCode(), "hashCode согласован с equals");
    }

    @Test
    @DisplayName("Разные кривые и null не равны")
    void differentCurvesAreNotEqual() {
        assertNotEquals(
                ECParameters.cryptoProA(), ECParameters.tc26a256(), "разные кривые 256 бит");
        assertNotEquals(ECParameters.tc26a512(), ECParameters.tc26c512(), "разные кривые 512 бит");
        assertNotEquals(null, ECParameters.cryptoProA(), "null не равен параметрам");
        assertNotEquals("строка", ECParameters.cryptoProA(), "объект другого типа не равен");
    }

    @Test
    @DisplayName("Кривая с теми же p, n, hlen, но другим кофактором не равна оригиналу")
    void sameFieldAndOrderButDifferentCofactor() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters tampered = copyOf(original, original.cofactor + 1);

        assertEquals(original.p, tampered.p, "модуль поля совпадает");
        assertEquals(original.n, tampered.n, "порядок подгруппы совпадает");
        assertNotEquals(original, tampered, "полное равенство должно различать кофактор");
    }

    @Test
    @DisplayName("Равенство учитывает каждый параметр: a, b, gx, gy при тех же p, n, hlen")
    void everyConstructorParameterParticipates() {
        ECParameters o = ECParameters.cryptoProA();
        String p = o.p.toString(16);
        String a = o.a.toString(16);
        String b = o.b.toString(16);
        String gx = o.gx.toString(16);
        String gy = o.gy.toString(16);
        String n = o.n.toString(16);
        String other = "7";

        assertNotEquals(
                o, new ECParameters(p, other, b, gx, gy, n, o.hlen, o.cofactor), "другой a");
        assertNotEquals(
                o, new ECParameters(p, a, other, gx, gy, n, o.hlen, o.cofactor), "другой b");
        assertNotEquals(
                o, new ECParameters(p, a, b, other, gy, n, o.hlen, o.cofactor), "другой gx");
        assertNotEquals(
                o, new ECParameters(p, a, b, gx, other, n, o.hlen, o.cofactor), "другой gy");
    }

    @Test
    @DisplayName("oidOf по ссылке: копия по значению не получает стандартный OID")
    void oidOfStaysIdentityBased() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters copy = copyOf(original, original.cofactor);

        assertEquals(GostCurves.OID_CRYPTOPRO_A, GostCurves.oidOf(original), "синглтон имеет OID");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCurves.oidOf(copy),
                "самодельная value-equal кривая не должна получать канонический OID");
    }
}
