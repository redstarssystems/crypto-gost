package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;

/**
 * {@link PrivateKeyParameters#derivePublicKey()} считает {@code d·G} сам и на зарегистрированных
 * кривых не повторяет проверку подгруппы: для них порядок G равен n. Для самодельной кривой и
 * равной по значению копии такой гарантии нет, поэтому проверка остаётся полной.
 */
@DisplayName("PrivateKeyParameters.derivePublicKey: доверие только зарегистрированным кривым")
class DerivePublicKeyTest {

    static Stream<Arguments> curves() {
        return Stream.of(
                Arguments.of("TC26-A-256", ECParameters.tc26a256()),
                Arguments.of("CryptoPro-A", ECParameters.cryptoProA()),
                Arguments.of("CryptoPro-B", ECParameters.cryptoProB()),
                Arguments.of("CryptoPro-C", ECParameters.cryptoProC()),
                Arguments.of("TC26-A-512", ECParameters.tc26a512()),
                Arguments.of("TC26-B-512", ECParameters.tc26b512()),
                Arguments.of("TC26-C-512", ECParameters.tc26c512()));
    }

    private static ECParameters copyOf(ECParameters o, ECPoint generator) {
        return new ECParameters(
                o.p.toString(16),
                o.a.toString(16),
                o.b.toString(16),
                generator.getX().toString(16),
                generator.getY().toString(16),
                o.n.toString(16),
                o.hlen,
                o.cofactor);
    }

    /** Точка на кривой с кофактором 4, не входящая в подгруппу порядка n (p = 3 mod 4). */
    private static ECPoint pointOutsideSubgroup(ECParameters params) {
        BigInteger p = params.p;
        assertEquals(3, p.mod(BigInteger.valueOf(4)).intValue(), "ожидается p = 3 (mod 4)");
        BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
        for (BigInteger x = BigInteger.ONE; x.bitLength() < 32; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(p);
            BigInteger y = rhs.modPow(exponent, p);
            if (!y.multiply(y).mod(p).equals(rhs)) {
                continue;
            }
            ECPoint candidate = ECPoint.affine(x, y, params);
            if (!candidate.multiply(params.n).isInfinity()) {
                return candidate.normalize();
            }
        }
        fail("точка вне подгруппы n не найдена");
        return null;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Одиночный экземпляр зарегистрирован, а его равная по значению копия нет")
    void onlySingletonsAreRegistered(String name, ECParameters params) {
        ECParameters copy = copyOf(params, ECPoint.affine(params.gx, params.gy, params));
        assertEquals(params, copy, "предусловие: копия равна по значению");
        assertTrue(params.isRegistered(), "одиночный экземпляр должен быть зарегистрирован");
        assertFalse(copy.isRegistered(), "копия не должна получать доверия");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Порядок базовой точки зарегистрированной кривой равен n: основание для доверия")
    void registeredGeneratorHasOrderN(String name, ECParameters params) {
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        assertTrue(g.multiply(params.n).isInfinity(), "n·G должно быть точкой на бесконечности");
        assertFalse(
                g.multiply(params.n.subtract(BigInteger.ONE)).isInfinity(), "порядок G меньше n");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Выведенный ключ равен d·G и проходит полную проверку подгруппы")
    void derivedKeyEqualsScalarMultiple(String name, ECParameters params) {
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        for (BigInteger d :
                new BigInteger[] {
                    BigInteger.ONE,
                    BigInteger.valueOf(2),
                    BigInteger.valueOf(0x1234567L),
                    params.n.subtract(BigInteger.ONE)
                }) {
            PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
            PublicKeyParameters pub = priv.derivePublicKey();
            ECPoint expected = g.multiply(d).normalize();
            assertEquals(expected.getX(), pub.getQ().getX(), "x выведенного ключа, d = " + d);
            assertEquals(expected.getY(), pub.getQ().getY(), "y выведенного ключа, d = " + d);
            assertTrue(
                    pub.getQ().isValidPublicKey(),
                    "выведенный ключ не прошёл полную проверку, d = " + d);
            assertEquals(params, pub.getParams(), "параметры ключа");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Signature.derivePublicKey даёт тот же ключ")
    void signatureDelegates(String name, ECParameters params) {
        PrivateKeyParameters priv =
                new PrivateKeyParameters(BigInteger.valueOf(987654321L), params);
        ECPoint viaSignature = Signature.derivePublicKey(priv).getQ();
        ECPoint direct = priv.derivePublicKey().getQ();
        assertEquals(direct.getX(), viaSignature.getX(), "x");
        assertEquals(direct.getY(), viaSignature.getY(), "y");
    }

    @Test
    @DisplayName("Равная по значению копия кривой даёт тот же ключ")
    void valueEqualCopyWorks() {
        ECParameters registered = ECParameters.tc26a256();
        ECParameters copy =
                copyOf(registered, ECPoint.affine(registered.gx, registered.gy, registered));
        assertEquals(registered, copy, "предусловие: копия равна по значению");
        BigInteger d = BigInteger.valueOf(31337);
        ECPoint expected = new PrivateKeyParameters(d, registered).derivePublicKey().getQ();
        ECPoint actual = new PrivateKeyParameters(d, copy).derivePublicKey().getQ();
        assertEquals(expected.getX(), actual.getX(), "x");
        assertEquals(expected.getY(), actual.getY(), "y");
    }

    @Test
    @DisplayName("Самодельная кривая, у которой G вне подгруппы n, отвергается (кофактор 4)")
    void customCurveWithGeneratorOutsideSubgroupRejected() {
        // Кофактор 4 обязателен: при h = 1 isValidPublicKey() завершается на isOnCurve() и
        // multiply(n) не вызывается, тест прошёл бы вхолостую
        ECParameters base = ECParameters.tc26a256();
        ECPoint badGenerator = pointOutsideSubgroup(base);
        ECParameters custom = copyOf(base, badGenerator);
        // d = 1 нечётное: при d, кратном 4, d·G для G порядка 4n попало бы в подгруппу
        // и было бы принято; здесь Q = G, то есть вне подгруппы
        PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.ONE, custom);
        assertThrows(
                IllegalArgumentException.class,
                priv::derivePublicKey,
                "ключ вне подгруппы n принят без полной проверки");
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.derivePublicKey(priv),
                "Signature.derivePublicKey принял ключ вне подгруппы n");
    }

    @Test
    @DisplayName("Подгруппа проверяется по объявленному кофактору: при h = 1 только кривая")
    void subgroupIsCheckedByDeclaredCofactor() {
        ECParameters base = ECParameters.tc26a256();
        ECPoint outside = pointOutsideSubgroup(base);
        // тот же набор, но с объявленным h = 1: проверка подгруппы по замыслу не выполняется.
        // Тест закрепляет это как осознанное поведение: ECParameters не вычисляет порядок
        // группы, кофактор принимается как часть объявленных параметров (от них зависит и
        // ECDH), а самодельные параметры библиотека из внешнего ввода не строит
        ECParameters declaredCofactorOne =
                new ECParameters(
                        base.p.toString(16),
                        base.a.toString(16),
                        base.b.toString(16),
                        outside.getX().toString(16),
                        outside.getY().toString(16),
                        base.n.toString(16),
                        base.hlen,
                        1);
        PrivateKeyParameters priv = new PrivateKeyParameters(BigInteger.ONE, declaredCofactorOne);
        assertEquals(
                outside.getX(),
                priv.derivePublicKey().getQ().getX(),
                "при объявленном h = 1 подгруппа не проверяется");
    }

    @Test
    @DisplayName("Публичный конструктор по-прежнему проверяет подгруппу у внешней точки")
    void publicConstructorStillChecksSubgroup() {
        ECParameters params = ECParameters.tc26a256();
        ECPoint outside = pointOutsideSubgroup(params);
        assertThrows(
                IllegalArgumentException.class,
                () -> new PublicKeyParameters(outside, params),
                "внешняя точка вне подгруппы принята");
    }

    @Test
    @DisplayName("Уничтоженный закрытый ключ не выводит открытый")
    void destroyedKeyRejected() {
        PrivateKeyParameters priv =
                new PrivateKeyParameters(BigInteger.valueOf(5), ECParameters.cryptoProA());
        priv.destroy();
        assertThrows(IllegalStateException.class, priv::derivePublicKey, "ключ уничтожен");
    }
}
