package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.util.Pack;

/**
 * Зависимость нонса {@code k} от закрытого ключа {@code d} и от числа {@code e}.
 *
 * <p>Нонс обязан быть функцией тройки {@code (d, e, кривая)}; здесь кривая постоянна, зависимость
 * от неё проверяют {@code SignatureSecurityPropertiesTest} и {@code CurveBindingTest}. Если {@code d}
 * выпадет из затравки, два ключа получат один {@code k} на одном хэше, и из {@code s1 - s2 = r·(d1 - d2)} при известном одном
 * ключе вычисляется второй. Если в затравку попадёт лишь часть {@code d} (например, младшие 32
 * байта 64-байтного ключа), ключи, различающиеся только в старшей половине, получат общий
 * {@code k}. Подпись при этом остаётся верной, поэтому проверки свойств («подпись верна»,
 * «подпись детерминирована») такую ошибку не замечают.
 *
 * <p>{@code k} читается не из приватного {@code generateK}, а восстанавливается из подписи:
 * {@code k = (s - r·d)·e⁻¹ mod n}. Перед этим подпись проверяется открытым ключом и
 * проверяется диапазон {@code 0 < k < n}: иначе тест мог бы пройти или упасть из-за невалидной
 * подписи, а не из-за зависимости {@code k} от {@code d}.
 */
@DisplayName("Нонс k: зависимость от закрытого ключа d и от числа e")
class NonceDerivationTest {

    private static Stream<ECParameters> allCurves() {
        return Stream.of(
                ECParameters.tc26a256(),
                ECParameters.tc26a512(),
                ECParameters.tc26b512(),
                ECParameters.tc26c512(),
                ECParameters.cryptoProA(),
                ECParameters.cryptoProB(),
                ECParameters.cryptoProC());
    }

    private static Supplier<Digest> digestFactory(ECParameters params) {
        return params.hlen == Streebog256.DIGEST_SIZE ? Streebog256::new : Streebog512::new;
    }

    private static int keyLength(ECParameters params) {
        return (params.n.bitLength() + 7) / 8;
    }

    /**
     * Ключ с нулевым старшим байтом: он заведомо меньше порядка кривой (n &gt; 2²⁵⁴ у 256-битных и
     * &gt; 2⁵¹⁰ у 512-битных кривых, а ключ короче на байт), поэтому любое изменение
     * остальных байт оставляет ключ допустимым. Наивное изменение старшего байта у tc26a256 и
     * tc26c512 вывело бы ключ за порядок кривой.
     */
    private static BigInteger baseKey(ECParameters params) {
        int length = keyLength(params);
        byte[] bytes = new byte[length];
        for (int i = 1; i < length; i++) {
            bytes[i] = (byte) (i * 29 + 7);
        }
        return new BigInteger(1, bytes);
    }

    /** Ключ, отличающийся от базового ровно одним байтом на позиции {@code index} (0 - старший). */
    private static BigInteger keyWithChangedByte(ECParameters params, BigInteger base, int index) {
        int length = keyLength(params);
        assertTrue(index >= 1 && index < length, "позиция вне ключа или старший байт");
        BigInteger delta = BigInteger.valueOf(0x5A).shiftLeft(8 * (length - 1 - index));
        BigInteger changed = base.xor(delta);
        assertNotEquals(base, changed, "ключ обязан отличаться");
        assertTrue(
                changed.signum() > 0 && changed.compareTo(params.n) < 0,
                "изменённый ключ обязан оставаться в [1, n-1]");
        return changed;
    }

    private static byte[] hash(ECParameters params, int seed) {
        byte[] hash = new byte[params.hlen];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) (i * 7 + seed);
        }
        return hash;
    }

    private static BigInteger eOf(byte[] hash, ECParameters params) {
        BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(params.n);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    /** Подпись и нонс, восстановленный из неё. */
    private record Signed(BigInteger r, BigInteger s, BigInteger k) {}

    /**
     * Подписывает хэш ключом {@code d}, проверяет подпись открытым ключом и восстанавливает
     * нонс. Проверка подписи и диапазона нонса стоит до любых сравнений в тестах.
     */
    private static Signed signAndRecoverNonce(ECParameters params, BigInteger d, byte[] hash) {
        PrivateKeyParameters key = new PrivateKeyParameters(d, params);
        ECDSASigner signer = new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
        signer.init(true, key);
        BigInteger[] signature;
        try {
            signature = signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }

        ECDSASigner verifier =
                new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
        verifier.init(false, key.derivePublicKey());
        assertTrue(
                verifier.verifySignature(hash, signature[0], signature[1]),
                "подпись обязана проверяться: иначе восстановленный нонс не имеет смысла");

        BigInteger n = params.n;
        BigInteger e = eOf(hash, params);
        BigInteger k =
                signature[1]
                        .subtract(signature[0].multiply(d))
                        .mod(n)
                        .multiply(e.modInverse(n))
                        .mod(n);
        assertTrue(k.signum() > 0 && k.compareTo(n) < 0, "нонс обязан лежать в [1, n-1]");
        return new Signed(signature[0], signature[1], k);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Ключи, различающиеся одним байтом (старшим, средним, младшим), дают разные k")
    void keysDifferingInOneByteGiveDifferentNonces(ECParameters params) {
        int length = keyLength(params);
        BigInteger base = baseKey(params);
        byte[] hash = hash(params, 3);
        Signed reference = signAndRecoverNonce(params, base, hash);

        // Старший значащий байт, середина и младший байт. У 512-битных кривых середина лежит
        // за пределами младших 32 байт: затравка из усечённого ключа дала бы общий k
        int[] positions = {1, length / 2, length - 1};
        for (int index : positions) {
            Signed changed =
                    signAndRecoverNonce(params, keyWithChangedByte(params, base, index), hash);
            assertNotEquals(
                    reference.k(),
                    changed.k(),
                    "ключи, различающиеся байтом " + index + ", обязаны давать разные k");
            assertNotEquals(
                    reference.r(),
                    changed.r(),
                    "разные k обязаны давать разные r (байт " + index + ")");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Разные закрытые ключи при одном хэше дают разные k")
    void differentKeysOnSameHashGiveDifferentNonces(ECParameters params) {
        byte[] hash = hash(params, 11);
        BigInteger one = BigInteger.ONE;
        BigInteger small = BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(7));
        BigInteger base = baseKey(params);
        BigInteger nearOrder = params.n.subtract(BigInteger.ONE);

        Signed[] results = {
            signAndRecoverNonce(params, one, hash),
            signAndRecoverNonce(params, small, hash),
            signAndRecoverNonce(params, base, hash),
            signAndRecoverNonce(params, nearOrder, hash)
        };
        for (int i = 0; i < results.length; i++) {
            for (int j = i + 1; j < results.length; j++) {
                assertNotEquals(
                        results[i].k(),
                        results[j].k(),
                        "разные ключи (" + i + " и " + j + ") обязаны давать разные k");
            }
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Равные (d, хэш) дают равные k, разные хэши при одном d дают разные k")
    void nonceIsFunctionOfKeyAndHash(ECParameters params) {
        BigInteger key = baseKey(params);
        byte[] hash = hash(params, 5);

        Signed first = signAndRecoverNonce(params, key, hash);
        Signed second = signAndRecoverNonce(params, key, hash);
        assertEquals(first.k(), second.k(), "равные (d, хэш) обязаны давать равный k");
        assertEquals(first.r(), second.r(), "равные (d, хэш) обязаны давать равный r");
        assertEquals(first.s(), second.s(), "равные (d, хэш) обязаны давать равный s");

        for (int seed = 6; seed < 12; seed++) {
            byte[] other = hash(params, seed);
            assertNotEquals(
                    eOf(hash, params),
                    eOf(other, params),
                    "для теста значения e обязаны различаться");
            Signed otherSigned = signAndRecoverNonce(params, key, other);
            assertNotEquals(
                    first.k(),
                    otherSigned.k(),
                    "разные e при одном d обязаны давать разные k (seed " + seed + ")");
        }
    }
}
