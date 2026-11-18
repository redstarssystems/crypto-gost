package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.SignatureCodec;
import org.rssys.gost.util.FixedSecureRandom;

/**
 * Режим нонса в публичном API: перегрузки {@code Signature.sign}, {@code Signature.signHash},
 * {@code GostSigner.of}. Тесты явно задают режим и от умолчания не зависят.
 */
@DisplayName("Signature и GostSigner: явный режим нонса и источник случайности")
class SignatureNonceModeTest {

    private static final byte[] DATA = "данные для подписи".getBytes(StandardCharsets.UTF_8);

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

    private static PrivateKeyParameters key(ECParameters params) {
        BigInteger d =
                BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567));
        return new PrivateKeyParameters(d, params);
    }

    private static byte[] hash(ECParameters params) {
        byte[] hash = new byte[params.hlen];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = (byte) (i * 7 + 3);
        }
        return hash;
    }

    private static byte[] noise(ECParameters params) {
        int rolen = (params.n.bitLength() + 7) / 8;
        byte[] noise = new byte[rolen];
        for (int i = 0; i < noise.length; i++) {
            noise[i] = (byte) (i * 11 + 9);
        }
        return noise;
    }

    private static byte[] digestOf(ECParameters params, byte[] data) {
        Digest digest = digestFactory(params).get();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "signHash(hash, priv, HEDGED, датчик) даёт те же байты, что ECDSASigner напрямую с тем же датчиком")
    void hedgedSignHashMatchesEcdsaSignerDirectly(ECParameters params) {
        byte[] hash = hash(params);
        BigInteger[] direct;
        ECDSASigner signer =
                new ECDSASigner(
                        digestFactory(params),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(params)));
        signer.init(true, key(params));
        try {
            direct = signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }

        byte[] viaFacade =
                Signature.signHash(
                        hash,
                        key(params),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(params)));

        assertArrayEquals(
                SignatureCodec.encode(direct[0], direct[1], params),
                viaFacade,
                "фасад Signature изменил раскладку нонса относительно ECDSASigner");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "sign(data, priv, HEDGED, датчик) равно signHash(хэш данных, priv, HEDGED, датчик)")
    void hedgedSignOfDataMatchesSignHashOfDigest(ECParameters params) {
        byte[] viaData =
                Signature.sign(
                        DATA,
                        key(params),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(params)));
        byte[] viaHash =
                Signature.signHash(
                        digestOf(params, DATA),
                        key(params),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(params)));

        assertArrayEquals(viaHash, viaData, "sign и signHash дают разные подписи при том же Z");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Детерминированный режим: все пути дают одни байты и не вызывают датчик")
    void deterministicPathsAgreeAndIgnoreRandom(ECParameters params) {
        FixedSecureRandom forbidden = FixedSecureRandom.forbidden();
        byte[] hash = hash(params);

        byte[] viaSignHash = Signature.signHash(hash, key(params), NonceMode.DETERMINISTIC);
        byte[] viaSignHashRandom =
                Signature.signHash(hash, key(params), NonceMode.DETERMINISTIC, forbidden);
        byte[] viaSigner = GostSigner.of(key(params), NonceMode.DETERMINISTIC).signHash(hash);
        byte[] viaData = Signature.sign(DATA, key(params), NonceMode.DETERMINISTIC, forbidden);

        assertArrayEquals(
                viaSignHash, viaSignHashRandom, "датчик изменил детерминированную подпись");
        assertArrayEquals(
                viaSignHash,
                viaSigner,
                "GostSigner.of(priv, DETERMINISTIC) создал третий путь, отличный от Signature.signHash");
        assertArrayEquals(
                Signature.signHash(digestOf(params, DATA), key(params), NonceMode.DETERMINISTIC),
                viaData,
                "sign и signHash расходятся в детерминированном режиме");
        assertEquals(0, forbidden.calls(), "детерминированный режим обратился к датчику");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Гибридные подписи с разными Z различаются и обе верны")
    void hedgedSignaturesWithDifferentNoiseDifferAndVerify(ECParameters params) {
        byte[] hash = hash(params);
        byte[] noiseA = noise(params);
        byte[] noiseB = noise(params);
        noiseB[0] ^= 0x55;

        byte[] first =
                Signature.signHash(
                        hash, key(params), NonceMode.HEDGED, FixedSecureRandom.returning(noiseA));
        byte[] second =
                Signature.signHash(
                        hash, key(params), NonceMode.HEDGED, FixedSecureRandom.returning(noiseB));

        assertNotEquals(
                new BigInteger(1, first), new BigInteger(1, second), "разные Z дали одну подпись");
        var pub = key(params).derivePublicKey();
        assertTrue(Signature.verifyHash(hash, first, pub), "первая гибридная подпись неверна");
        assertTrue(Signature.verifyHash(hash, second, pub), "вторая гибридная подпись неверна");
    }

    @Test
    @DisplayName("Режим по умолчанию - гибридный")
    void defaultModeIsHedged() {
        assertEquals(NonceMode.HEDGED, NonceMode.DEFAULT, "умолчание обязано быть гибридным");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "По умолчанию повторная подпись того же хэша другая, обе верны (Signature, GostSigner)")
    void defaultSignaturesDifferAndVerify(ECParameters params) {
        byte[] hash = hash(params);
        PrivateKeyParameters priv = key(params);
        var pub = priv.derivePublicKey();

        byte[] first = Signature.signHash(hash, priv);
        byte[] second = Signature.signHash(hash, priv);
        byte[] viaSignerFirst = GostSigner.of(priv).signHash(hash);
        byte[] viaSignerSecond = GostSigner.of(priv).signHash(hash);

        assertNotEquals(
                new BigInteger(1, first),
                new BigInteger(1, second),
                "Signature.signHash по умолчанию детерминирован");
        assertNotEquals(
                new BigInteger(1, viaSignerFirst),
                new BigInteger(1, viaSignerSecond),
                "GostSigner.of(priv) по умолчанию детерминирован");
        for (byte[] signature : new byte[][] {first, second, viaSignerFirst, viaSignerSecond}) {
            assertTrue(
                    Signature.verifyHash(hash, signature, pub),
                    "подпись по умолчанию обязана проверяться");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("По умолчанию sign(data) и signHash(hash(data)) различаются, обе верны")
    void defaultSignAndSignHashOfDigestDiffer(ECParameters params) {
        PrivateKeyParameters priv = key(params);
        var pub = priv.derivePublicKey();
        byte[] digest = digestOf(params, DATA);

        byte[] viaData = Signature.sign(DATA, priv);
        byte[] viaHash = Signature.signHash(digest, priv);

        assertNotEquals(
                new BigInteger(1, viaData),
                new BigInteger(1, viaHash),
                "sign и signHash по умолчанию совпали: гибрид не включён");
        assertTrue(Signature.verify(DATA, viaData, pub), "sign по умолчанию неверна");
        assertTrue(Signature.verifyHash(digest, viaHash, pub), "signHash по умолчанию неверна");
        assertTrue(
                Signature.verifyHash(digest, viaData, pub),
                "подпись sign обязана проверяться как подпись хэша данных");
    }

    @Test
    @DisplayName("Режим null отвергается на всех путях")
    void nullModeIsRejected() {
        ECParameters params = ECParameters.tc26a256();
        byte[] hash = hash(params);
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.sign(DATA, key(params), null),
                "sign(data, priv, null)");
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.sign(DATA, key(params), null, null),
                "sign(data, priv, null, rng)");
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.signHash(hash, key(params), null),
                "signHash(hash, priv, null)");
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.signHash(hash, key(params), null, null),
                "signHash(hash, priv, null, rng)");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSigner.of(key(params), null),
                "GostSigner.of(priv, null)");
    }

    @Test
    @DisplayName("Неверная длина хэша отвергается до обращения к датчику")
    void hashLengthIsCheckedBeforeRandomIsTouched() {
        ECParameters params = ECParameters.tc26a256();
        FixedSecureRandom forbidden = FixedSecureRandom.forbidden();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        Signature.signHash(
                                new byte[params.hlen - 1],
                                key(params),
                                NonceMode.HEDGED,
                                forbidden),
                "хэш неверной длины обязан отвергаться");
        assertEquals(0, forbidden.calls(), "датчик вызван до проверки длины хэша");
    }

    @Test
    @DisplayName("Отказ датчика в гибридном режиме: подписи нет, отката на детерминизм нет")
    void randomFailureProducesNoSignature() {
        ECParameters params = ECParameters.tc26a256();
        FixedSecureRandom failing = FixedSecureRandom.failing();

        assertThrows(
                IllegalStateException.class,
                () -> Signature.signHash(hash(params), key(params), NonceMode.HEDGED, failing),
                "при отказе датчика подпись выдаваться не должна");
        assertEquals(1, failing.calls(), "датчик должен быть вызван ровно один раз");
    }

    @Test
    @DisplayName("Гибридный режим запрашивает ровно rolen байт один раз")
    void hedgedRequestsRolenBytesOnce() {
        for (ECParameters params : allCurves().toList()) {
            FixedSecureRandom random = FixedSecureRandom.returning(noise(params));
            Signature.signHash(hash(params), key(params), NonceMode.HEDGED, random);
            assertEquals(1, random.calls(), params.hlen + ": источник вызван не один раз");
            assertEquals(
                    noise(params).length, random.lastRequestedLength(), "запрошено не rolen байт");
        }
    }
}
