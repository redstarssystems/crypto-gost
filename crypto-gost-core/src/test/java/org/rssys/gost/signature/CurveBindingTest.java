package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Идентификатор кривой в затравке нонса: каноническая запись параметров и её хэш.
 *
 * <p>Замороженные значения сняты с независимой реализации ({@code NonceOracle} в
 * {@code x-validation-tests/sign}, на BouncyCastle и своём Стрибоге-256), а не с кода библиотеки:
 * иначе ошибка в записи или в кодировании {@code BigInteger} попала бы и в «замороженное».
 * Значения идентификатора проверяются здесь же, потому что {@code ECParameters.curveBinding()}
 * виден только внутри пакета, а эталон на BouncyCastle лежит в другом модуле.
 */
@DisplayName("ECParameters: идентификатор кривой для затравки нонса")
class CurveBindingTest {

    private static final HexFormat HEX = HexFormat.of();

    private static Stream<Arguments> registeredCurves() {
        return Stream.of(
                Arguments.of(
                        "tc26a256",
                        "1d3e9865f55e569ae38bc5de0d8df268e7af5501714c190caa89eb8f01cc2a78"),
                Arguments.of(
                        "tc26a512",
                        "a367c5537069ee8605d1161d43951a35596af379f951fc4e905a4e7e8630ecfe"),
                Arguments.of(
                        "tc26b512",
                        "4703a0b5c551d603b56b318433268314ad0614a72d4bf297fb92997a14ed86d1"),
                Arguments.of(
                        "tc26c512",
                        "42675c6ef0248ba14b323f3738bc7bf0f738f675c2a943cfa51a803b8e3c69b1"),
                Arguments.of(
                        "cryptoProA",
                        "ccbecb0e3e30e82b86be0cc29ad58f6906be00bcfd6231c57774856b1abd9807"),
                Arguments.of(
                        "cryptoProB",
                        "dcb23588f815a7bbf8b0e3e4f66d6e4fa3e09ded0e8a97391567226251e718af"),
                Arguments.of(
                        "cryptoProC",
                        "04ce4ae2dcac5d7967273cedbbc2294e1fa8de3e9e4d6c7b517b89b940173f71"));
    }

    private static ECParameters curveByName(String name) {
        return switch (name) {
            case "tc26a256" -> ECParameters.tc26a256();
            case "tc26a512" -> ECParameters.tc26a512();
            case "tc26b512" -> ECParameters.tc26b512();
            case "tc26c512" -> ECParameters.tc26c512();
            case "cryptoProA" -> ECParameters.cryptoProA();
            case "cryptoProB" -> ECParameters.cryptoProB();
            case "cryptoProC" -> ECParameters.cryptoProC();
            default -> throw new IllegalArgumentException("неизвестная кривая " + name);
        };
    }

    private static List<ECParameters> allCurves() {
        return List.of(
                ECParameters.tc26a256(),
                ECParameters.tc26a512(),
                ECParameters.tc26b512(),
                ECParameters.tc26c512(),
                ECParameters.cryptoProA(),
                ECParameters.cryptoProB(),
                ECParameters.cryptoProC());
    }

    /** Копия по значению через открытый конструктор; {@code a} подменяется, если задан. */
    private static ECParameters copyOf(ECParameters source, BigInteger a, int cofactor) {
        return new ECParameters(
                source.p.toString(16),
                a.toString(16),
                source.b.toString(16),
                source.gx.toString(16),
                source.gy.toString(16),
                source.n.toString(16),
                source.hlen,
                cofactor);
    }

    private static String bindingHex(ECParameters params) {
        return HEX.formatHex(params.curveBinding());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("registeredCurves")
    @DisplayName("Идентификатор зарегистрированной кривой равен значению независимой реализации")
    void registeredCurveBindingMatchesFrozenValue(String name, String expectedHex) {
        assertEquals(
                expectedHex,
                bindingHex(curveByName(name)),
                name + ": идентификатор кривой не совпал с эталоном");
    }

    @Test
    @DisplayName("Идентификаторы семи зарегистрированных кривых попарно различны")
    void registeredCurveBindingsAreDistinct() {
        Set<String> seen = new HashSet<>();
        for (ECParameters params : allCurves()) {
            assertTrue(
                    seen.add(bindingHex(params)),
                    "две кривые дали один идентификатор: общий нонс между ними возможен");
        }
    }

    @Test
    @DisplayName(
            "Кривая, записанная другим объектом с теми же параметрами, даёт тот же идентификатор")
    void equalParametersGiveEqualBinding() {
        for (ECParameters original : allCurves()) {
            ECParameters copy = copyOf(original, original.a, original.cofactor);
            assertArrayEquals(
                    original.curveBinding(),
                    copy.curveBinding(),
                    "равные по значению кривые обязаны давать равный идентификатор");
        }
    }

    @Test
    @DisplayName("Кривые, различающиеся одним параметром, дают разный идентификатор")
    void anySingleParameterChangesBinding() {
        ECParameters o = ECParameters.cryptoProA();
        String p = o.p.toString(16);
        String a = o.a.toString(16);
        String b = o.b.toString(16);
        String gx = o.gx.toString(16);
        String gy = o.gy.toString(16);
        String n = o.n.toString(16);
        String other = "7";
        // p меняется на другое нечётное число той же длины: hlen обязан сходиться с длиной p
        String otherP = o.p.subtract(BigInteger.TWO).toString(16);

        List<ECParameters> variants = new ArrayList<>();
        variants.add(new ECParameters(otherP, a, b, gx, gy, n, o.hlen, o.cofactor));
        variants.add(new ECParameters(p, other, b, gx, gy, n, o.hlen, o.cofactor));
        variants.add(new ECParameters(p, a, other, gx, gy, n, o.hlen, o.cofactor));
        variants.add(new ECParameters(p, a, b, other, gy, n, o.hlen, o.cofactor));
        variants.add(new ECParameters(p, a, b, gx, other, n, o.hlen, o.cofactor));
        variants.add(
                new ECParameters(
                        p,
                        a,
                        b,
                        gx,
                        gy,
                        o.n.subtract(BigInteger.TWO).toString(16),
                        o.hlen,
                        o.cofactor));
        variants.add(new ECParameters(p, a, b, gx, gy, n, o.hlen, o.cofactor + 1));

        Set<String> seen = new HashSet<>();
        seen.add(bindingHex(o));
        for (int i = 0; i < variants.size(); i++) {
            assertTrue(
                    seen.add(bindingHex(variants.get(i))),
                    "вариант " + i + " дал идентификатор, уже встречавшийся");
        }
    }

    @Test
    @DisplayName("Крайние значения a (0, p, -3, p-3) кодируются как в независимой реализации")
    void edgeCoefficientValuesMatchFrozenBindings() {
        ECParameters o = ECParameters.cryptoProA();
        BigInteger minusThree = BigInteger.valueOf(-3);
        assertEquals(
                "ebccd4f4c91806e08d244c7b3b7466c9a35f7551b79755d0c9a8d717f6455c34",
                bindingHex(copyOf(o, BigInteger.ZERO, o.cofactor)),
                "a = 0");
        assertEquals(
                "8f71999378b02ef389640eb071a21d1de0fe68b036d4bd633c2f31897d49c84c",
                bindingHex(copyOf(o, o.p, o.cofactor)),
                "a = p: не должно совпадать с a = 0");
        assertEquals(
                "7a7b10d711ab9d3738104c944fdad12f4088e528505ac757c0dfa66e8b9aab6d",
                bindingHex(copyOf(o, minusThree, o.cofactor)),
                "a = -3: не должно совпадать с p - 3");
        assertEquals(
                "ccbecb0e3e30e82b86be0cc29ad58f6906be00bcfd6231c57774856b1abd9807",
                bindingHex(copyOf(o, o.p.subtract(BigInteger.valueOf(3)), o.cofactor)),
                "a = p - 3 (так задана cryptoProA)");
    }
}
