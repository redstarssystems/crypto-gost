package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.util.FixedSecureRandom;
import org.rssys.gost.util.Pack;

/**
 * Привязка детерминированного нонса к числу {@code e} из уравнения подписи.
 *
 * <p>Нонс обязан быть функцией {@code (d, e, кривая)}; привязка к кривой проверяется в
 * {@code SignatureSecurityPropertiesTest} и {@code CurveBindingTest}. Если два разных хэша дают одинаковый {@code k} при
 * разных {@code e}, то по двум подписям {@code s1 = r·d + k·e1}, {@code s2 = r·d + k·e2}
 * восстанавливается закрытый ключ. Кросс-валидация такой дефект не видит: подпись с повторным
 * {@code k} проверяется верно. Поэтому защита закреплена здесь прямыми проверками.
 *
 * <p>Здесь же собраны проверки соответствия размера дайджеста кривой, в том числе в гибридном
 * режиме: там важно, что несоответствие отвергается раньше обращения к источнику случайности.
 */
@DisplayName("ECDSASigner: нонс k привязан к e (RFC 6979 для ГОСТ Р 34.10-2012)")
class DeterministicNonceTest {

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

    private static ECDSASigner newSigner(ECParameters params) {
        return new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
    }

    private static java.util.function.Supplier<Digest> digestFactory(ECParameters params) {
        return params.hlen == Streebog256.DIGEST_SIZE ? Streebog256::new : Streebog512::new;
    }

    private static PrivateKeyParameters fixedKey(ECParameters params) {
        // Фиксированный d воспроизводим и заведомо меньше n на любой кривой (n > 2^254)
        BigInteger d =
                BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567));
        return new PrivateKeyParameters(d, params);
    }

    /**
     * Хэш, у которого число {@code e = LE(hash)} равно {@code value} до приведения по модулю n:
     * ГОСТ читает хэш младшим байтом вперёд, поэтому массив - это развёрнутая big-endian запись.
     */
    private static byte[] hashWithLittleEndianValue(BigInteger value, int hlen) {
        return Pack.reverseBytes(Pack.toFixedLengthBigEndian(value, hlen));
    }

    /** Хэш, у которого число {@code BE(hash)} равно {@code value}: так его читает RFC 6979. */
    private static byte[] hashWithBigEndianValue(BigInteger value, int hlen) {
        return Pack.toFixedLengthBigEndian(value, hlen);
    }

    private static BigInteger[] sign(ECParameters params, byte[] hash) {
        ECDSASigner signer = newSigner(params);
        signer.init(true, fixedKey(params));
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    private static BigInteger eOf(byte[] hash, ECParameters params) {
        BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(params.n);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Хэши с одинаковой прежней затравкой и разными e дают разные r")
    void sameLegacySeedDifferentEGivesDifferentR(ECParameters params) {
        int drop = 8 * params.hlen - params.n.bitLength();
        // bits2int(H1) mod n == bits2int(H2) mod n == 1: прежняя затравка k у обоих одинакова
        byte[] h1 = hashWithBigEndianValue(BigInteger.ONE.shiftLeft(drop), params.hlen);
        byte[] h2 =
                hashWithBigEndianValue(BigInteger.ONE.add(params.n).shiftLeft(drop), params.hlen);

        BigInteger e1 = eOf(h1, params);
        BigInteger e2 = eOf(h2, params);
        assertNotEquals(e1, e2, "для атаки значения e обязаны различаться");

        BigInteger[] sig1 = sign(params, h1);
        BigInteger[] sig2 = sign(params, h2);

        assertNotEquals(
                sig1[0],
                sig2[0],
                "разные e обязаны давать разные k, иначе по двум подписям восстанавливается d");

        // Восстановление по формулам атаки не должно давать закрытый ключ
        BigInteger n = params.n;
        BigInteger kGuess =
                sig1[1].subtract(sig2[1])
                        .mod(n)
                        .multiply(e1.subtract(e2).mod(n).modInverse(n))
                        .mod(n);
        BigInteger dGuess =
                sig1[1].subtract(kGuess.multiply(e1)).mod(n).multiply(sig1[0].modInverse(n)).mod(n);
        assertNotEquals(
                fixedKey(params).getD(),
                dGuess,
                "закрытый ключ не должен восстанавливаться по двум подписям");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Хэши с одинаковым e (0, 1, n) дают побайтно равные подписи")
    void sameEGivesIdenticalSignature(ECParameters params) {
        // e = 0 заменяется на 1, а n сводится к 0 и тоже к 1: все три хэша задают одно e
        byte[] zero = hashWithLittleEndianValue(BigInteger.ZERO, params.hlen);
        byte[] one = hashWithLittleEndianValue(BigInteger.ONE, params.hlen);
        byte[] modulus = hashWithLittleEndianValue(params.n, params.hlen);

        BigInteger[] sigZero = sign(params, zero);
        BigInteger[] sigOne = sign(params, one);
        BigInteger[] sigModulus = sign(params, modulus);

        assertEquals(sigOne[0], sigZero[0], "e = 0 и e = 1 обязаны давать одинаковый r");
        assertEquals(sigOne[1], sigZero[1], "e = 0 и e = 1 обязаны давать одинаковый s");
        assertEquals(sigOne[0], sigModulus[0], "LE = n и e = 1 обязаны давать одинаковый r");
        assertEquals(sigOne[1], sigModulus[1], "LE = n и e = 1 обязаны давать одинаковый s");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Хэши LE(h) и LE(h) + n дают побайтно равные подписи")
    void sameEAfterAddingModulusGivesIdenticalSignature(ECParameters params) {
        BigInteger base = BigInteger.valueOf(0x5A5A5A5AL);
        BigInteger shifted = base.add(params.n);
        // Условие построения пары: сумма должна помещаться в hlen байт
        assertTrue(
                shifted.bitLength() <= 8 * params.hlen,
                "LE(h) + n обязано помещаться в хэш длиной hlen");

        byte[] hashBase = hashWithLittleEndianValue(base, params.hlen);
        byte[] hashShifted = hashWithLittleEndianValue(shifted, params.hlen);
        assertEquals(
                eOf(hashBase, params), eOf(hashShifted, params), "пара должна давать равные e");

        BigInteger[] sigBase = sign(params, hashBase);
        BigInteger[] sigShifted = sign(params, hashShifted);

        assertEquals(sigBase[0], sigShifted[0], "равные e обязаны давать равный r");
        assertEquals(sigBase[1], sigShifted[1], "равные e обязаны давать равный s");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Подпись по-прежнему детерминирована и проверяется")
    void signatureIsDeterministicAndVerifies(ECParameters params) {
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        byte[] hash = new byte[params.hlen];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) (i * 7 + 3);
        }

        ECDSASigner signer = newSigner(params);
        signer.init(true, keys.getPrivate());
        BigInteger[] first = signer.generateSignature(hash);
        BigInteger[] second = signer.generateSignature(hash);
        assertArrayEquals(first, second, "один хэш и один ключ обязаны давать одну подпись");

        signer.init(false, keys.getPublic());
        assertTrue(signer.verifySignature(hash, first[0], first[1]), "подпись обязана проверяться");
    }

    @Test
    @DisplayName("generateSignature: хэш неверной длины -> IllegalArgumentException")
    void generateSignatureRejectsWrongHashLength() {
        ECParameters params = ECParameters.tc26a256();
        ECDSASigner signer = newSigner(params);
        signer.init(true, fixedKey(params));

        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(new byte[params.hlen - 1]),
                "короткий хэш обязан отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(new byte[params.hlen + 1]),
                "длинный хэш обязан отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(null),
                "null вместо хэша обязан отвергаться");
    }

    @Test
    @DisplayName("verifySignature: хэш неверной длины -> IllegalArgumentException")
    void verifySignatureRejectsWrongHashLength() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        ECDSASigner signer = newSigner(params);
        signer.init(false, keys.getPublic());

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        signer.verifySignature(
                                new byte[params.hlen - 1], BigInteger.ONE, BigInteger.ONE),
                "короткий хэш обязан отвергаться при проверке");
        assertThrows(
                IllegalArgumentException.class,
                () -> signer.verifySignature(null, BigInteger.ONE, BigInteger.ONE),
                "null вместо хэша обязан отвергаться при проверке");
    }

    @Test
    @DisplayName("Подпись: Streebog-256 на 512-битной кривой -> IllegalArgumentException")
    void signingRejectsShortDigestFactoryOnWideCurve() {
        // k из одного блока HMAC длиной 32 байта был бы короче порядка кривой
        ECParameters params = ECParameters.tc26a512();
        ECDSASigner signer = new ECDSASigner(Streebog256::new, NonceMode.DETERMINISTIC, null);
        signer.init(true, fixedKey(params));

        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(new byte[params.hlen]),
                "дайджест короче порядка кривой обязан отвергаться при подписи");
    }

    @Test
    @DisplayName("Подпись: Streebog-512 на 256-битной кривой -> IllegalArgumentException")
    void signingRejectsLongDigestFactoryOnNarrowCurve() {
        ECParameters params = ECParameters.tc26a256();
        ECDSASigner signer = new ECDSASigner(Streebog512::new, NonceMode.DETERMINISTIC, null);
        signer.init(true, fixedKey(params));

        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(new byte[params.hlen]),
                "дайджест длиннее кривой обязан отвергаться при подписи");
    }

    @Test
    @DisplayName(
            "Подпись в гибридном режиме: Streebog-512 на 256-битной кривой отвергается до обращения к датчику")
    void hedgedSigningRejectsLongDigestFactoryBeforeTouchingRandom() {
        // Пара к signingRejectsLongDigestFactoryOnNarrowCurve. Проверка размера дайджеста обязана
        // стоять раньше заполнения Z: иначе при одновременном отказе датчика его исключение скрыло
        // бы настоящую причину
        ECParameters params = ECParameters.tc26a256();
        FixedSecureRandom forbidden = FixedSecureRandom.forbidden();
        ECDSASigner signer = new ECDSASigner(Streebog512::new, NonceMode.HEDGED, forbidden);
        signer.init(true, fixedKey(params));

        assertThrows(
                IllegalArgumentException.class,
                () -> signer.generateSignature(new byte[params.hlen]),
                "дайджест длиннее кривой обязан отвергаться и в гибридном режиме");
        assertEquals(0, forbidden.calls(), "датчик вызван до проверки размера дайджеста");
    }

    @Test
    @DisplayName(
            "DigestSigner: Streebog-256 для сообщения на 512-битной кривой -> IllegalArgumentException")
    void digestSignerRejectsMessageDigestNotMatchingCurve() {
        // Фабрика ECDSASigner подходит кривой, а дайджест сообщения у DigestSigner - нет.
        // Этот случай ловит только проверка длины хэша в generateSignature.
        ECParameters params = ECParameters.tc26a512();
        DigestSigner signer =
                new DigestSigner(
                        new ECDSASigner(Streebog512::new, NonceMode.DETERMINISTIC, null),
                        new Streebog256());
        signer.init(true, fixedKey(params));
        signer.update(new byte[] {1, 2, 3}, 0, 3);

        assertThrows(
                IllegalArgumentException.class,
                signer::sign,
                "хэш сообщения не по кривой обязан отвергаться");
    }

    @Test
    @DisplayName("Проверка подписи не зависит от фабрики дайджеста")
    void verificationIgnoresDigestFactory() {
        ECParameters params = ECParameters.tc26a512();
        KeyPair keys = KeyGenerator.generateKeyPair(params);
        byte[] hash = new byte[params.hlen];
        hash[0] = 0x42;

        ECDSASigner signing = newSigner(params);
        signing.init(true, keys.getPrivate());
        BigInteger[] sig = signing.generateSignature(hash);

        // Фабрика не по кривой при проверке не используется и не должна ломать верификацию
        ECDSASigner verifying = new ECDSASigner(Streebog256::new, NonceMode.DETERMINISTIC, null);
        verifying.init(false, keys.getPublic());
        assertTrue(
                verifying.verifySignature(hash, sig[0], sig[1]),
                "верификация обязана работать с любой фабрикой");
    }
}
