package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.spec.GostDerCodec;

@DisplayName("PublicKeyParameters: кривая точки совпадает с объявленными параметрами")
class PublicKeyParametersCurveTest {

    private static ECPoint basePoint(ECParameters params) {
        return ECPoint.affine(params.gx, params.gy, params);
    }

    @Test
    @DisplayName("Точка и параметры одной кривой принимаются")
    void matchingCurveIsAccepted() {
        for (ECParameters p :
                new ECParameters[] {
                    ECParameters.cryptoProA(), ECParameters.tc26a256(), ECParameters.tc26c512()
                }) {
            assertDoesNotThrow(
                    () -> new PublicKeyParameters(basePoint(p), p),
                    "штатный ключ должен приниматься: " + p.n);
        }
    }

    @Test
    @DisplayName("Точка одной кривой с параметрами другой -> IllegalArgumentException")
    void mixedCurvesAreRejected() {
        ECPoint pointOnA = basePoint(ECParameters.cryptoProA());
        assertThrows(
                IllegalArgumentException.class,
                () -> new PublicKeyParameters(pointOnA, ECParameters.tc26a256()),
                "точка CryptoPro-A с параметрами TC26-A-256 должна быть отвергнута");

        ECPoint pointOn512 = basePoint(ECParameters.tc26c512());
        assertThrows(
                IllegalArgumentException.class,
                () -> new PublicKeyParameters(pointOn512, ECParameters.cryptoProA()),
                "точка 512-битной кривой с параметрами 256-битной должна быть отвергнута");
    }

    @Test
    @DisplayName("Точка и value-equal копия параметров принимаются (структурное равенство)")
    void valueEqualCopyIsAccepted() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters copy =
                new ECParameters(
                        original.p.toString(16),
                        original.a.toString(16),
                        original.b.toString(16),
                        original.gx.toString(16),
                        original.gy.toString(16),
                        original.n.toString(16),
                        original.hlen,
                        original.cofactor);
        assertDoesNotThrow(
                () -> new PublicKeyParameters(basePoint(original), copy),
                "копия параметров по значению описывает ту же кривую");
    }

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
    @DisplayName(
            "Точка настоящей кривой с параметрами-двойником (другой кофактор) -> IllegalArgumentException")
    void lookalikeParametersAreRejectedByConstructor() {
        ECParameters real = ECParameters.cryptoProA();
        ECParameters lookalike = copyOf(real, real.cofactor + 1);

        assertThrows(
                IllegalArgumentException.class,
                () -> new PublicKeyParameters(basePoint(real), lookalike),
                "параметры с теми же p, n, hlen, но другим кофактором - другая кривая");
    }

    @Test
    @DisplayName(
            "Ключ с value-equal копией параметров пригоден для вычислений, но не кодируется в DER")
    void valueEqualCopyIsNotEncodable() {
        ECParameters original = ECParameters.cryptoProA();
        ECParameters copy = copyOf(original, original.cofactor);
        PublicKeyParameters key = new PublicKeyParameters(basePoint(original), copy);

        // GostCurves.oidOf работает по ссылке: канонический OID получают только зарегистрированные
        // кривые
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.encodePublicKey(key),
                "кодирование ключа с незарегистрированными параметрами не поддерживается");
        assertNull(
                new GostECPublicKey(key).getEncoded(),
                "getEncoded() по контракту Key возвращает null, если кодирование недоступно");
    }
}
