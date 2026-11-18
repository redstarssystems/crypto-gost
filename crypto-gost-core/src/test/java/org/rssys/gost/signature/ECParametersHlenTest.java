package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * {@code hlen} задаёт длину координат, скаляров и общего секрета: несовпадение с длиной поля или
 * порядка раньше приводило к молчаливому усечению старших байт.
 */
@DisplayName("ECParameters: hlen согласован с длиной поля и порядка")
class ECParametersHlenTest {

    private static ECParameters build(ECParameters o, int hlen) {
        return new ECParameters(
                o.p.toString(16),
                o.a.toString(16),
                o.b.toString(16),
                o.gx.toString(16),
                o.gy.toString(16),
                o.n.toString(16),
                hlen,
                o.cofactor);
    }

    @ParameterizedTest(name = "hlen = {0}")
    @ValueSource(ints = {-32, 0, 1, 31, 33, 63, 65, 128})
    @DisplayName("Недопустимое значение hlen отвергается")
    void invalidHlenRejected(int hlen) {
        ECParameters o = ECParameters.cryptoProA();
        assertThrows(IllegalArgumentException.class, () -> build(o, hlen));
    }

    @Test
    @DisplayName("hlen = 64 на 256-битной кривой и hlen = 32 на 512-битной отвергаются")
    void hlenMismatchWithFieldRejected() {
        assertThrows(IllegalArgumentException.class, () -> build(ECParameters.tc26a256(), 64));
        assertThrows(IllegalArgumentException.class, () -> build(ECParameters.tc26c512(), 32));
        assertThrows(IllegalArgumentException.class, () -> build(ECParameters.tc26a512(), 32));
    }

    @Test
    @DisplayName("Поле шире hlen при верной длине порядка отвергается (расходится только p)")
    void hlenMismatchOnlyWithFieldRejected() {
        ECParameters narrow = ECParameters.cryptoProA();
        ECParameters wide = ECParameters.tc26a512();
        // порядок 256 бит и hlen = 32 согласованы между собой; расходится только модуль поля
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new ECParameters(
                                wide.p.toString(16),
                                narrow.a.toString(16),
                                narrow.b.toString(16),
                                narrow.gx.toString(16),
                                narrow.gy.toString(16),
                                narrow.n.toString(16),
                                narrow.hlen,
                                narrow.cofactor));
    }

    @Test
    @DisplayName("Порядок короче поля при верном hlen поля отвергается (расходится только n)")
    void hlenMismatchWithOrderRejected() {
        ECParameters o = ECParameters.cryptoProA();
        BigInteger shortOrder = BigInteger.ONE.shiftLeft(200).add(BigInteger.valueOf(7));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new ECParameters(
                                o.p.toString(16),
                                o.a.toString(16),
                                o.b.toString(16),
                                o.gx.toString(16),
                                o.gy.toString(16),
                                shortOrder.toString(16),
                                o.hlen,
                                o.cofactor));
    }

    @Test
    @DisplayName("Все зарегистрированные кривые проходят проверку hlen")
    void registeredCurvesAccepted() {
        for (ECParameters curve :
                new ECParameters[] {
                    ECParameters.tc26a256(),
                    ECParameters.cryptoProA(),
                    ECParameters.cryptoProB(),
                    ECParameters.cryptoProC(),
                    ECParameters.tc26a512(),
                    ECParameters.tc26b512(),
                    ECParameters.tc26c512()
                }) {
            assertDoesNotThrow(() -> build(curve, curve.hlen));
            assertEquals(
                    (curve.p.bitLength() + 7) / 8, curve.hlen, "hlen равен длине поля в байтах");
        }
    }
}
