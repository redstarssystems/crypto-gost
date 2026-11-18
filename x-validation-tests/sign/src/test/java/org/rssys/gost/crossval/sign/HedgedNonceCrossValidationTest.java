package org.rssys.gost.crossval.sign;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.spec.GostSignatureParameterSpec;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Сверка гибридного нонса ({@link NonceMode#HEDGED}) с независимой реализацией
 * ({@link NonceOracle}) на BouncyCastle.
 *
 * <p>Фиксированная случайная добавка {@code Z} подаётся через публичный конструктор
 * {@code ECDSASigner(factory, mode, SecureRandom)}: подкласс {@link SecureRandom} с
 * заданными байтами. Эталон сам считает {@code k} и {@code (r, s)} по раскладке
 * {@code V || 0x00/0x01 || Z || нули || d || нули || e || curveBinding}, сравнение побайтное.
 * Проверка подписи верификатором BouncyCastle лишь дополняет сравнение: подпись с неверным
 * {@code k} тоже верна, поэтому ошибку раскладки (паддинг, порядок полей) она не заметила бы.
 */
@DisplayName("Гибридный нонс: сверка с независимой реализацией на BouncyCastle")
class HedgedNonceCrossValidationTest {

    /**
     * Датчик, отдающий заранее заданные байты. Подкласс {@link SecureRandom} нужен только затем,
     * чтобы подать в подписант известную добавку {@code Z} через стандартную модель JCA; в
     * производственном коде датчик берётся из {@code CryptoRandom.INSTANCE}.
     */
    private static final class FixedBytesRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;

        private final byte[] bytes;

        FixedBytesRandom(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public void nextBytes(byte[] out) {
            assertEquals(bytes.length, out.length, "запрошена добавка Z неожиданной длины");
            System.arraycopy(bytes, 0, out, 0, out.length);
        }
    }

    private record CurveCase(String name, ECParameters ours, String bcName) {
        @Override
        public String toString() {
            return name;
        }
    }

    private static Stream<CurveCase> curves() {
        return Stream.of(
                new CurveCase(
                        "tc26a256", ECParameters.tc26a256(), "Tc26-Gost-3410-12-256-paramSetA"),
                new CurveCase(
                        "cryptoProA", ECParameters.cryptoProA(), "Tc26-Gost-3410-12-256-paramSetB"),
                new CurveCase(
                        "cryptoProB", ECParameters.cryptoProB(), "Tc26-Gost-3410-12-256-paramSetC"),
                new CurveCase(
                        "cryptoProC", ECParameters.cryptoProC(), "Tc26-Gost-3410-12-256-paramSetD"),
                new CurveCase(
                        "tc26a512", ECParameters.tc26a512(), "Tc26-Gost-3410-12-512-paramSetA"),
                new CurveCase(
                        "tc26b512", ECParameters.tc26b512(), "Tc26-Gost-3410-12-512-paramSetB"),
                new CurveCase(
                        "tc26c512", ECParameters.tc26c512(), "Tc26-Gost-3410-12-512-paramSetC"));
    }

    private static Supplier<Digest> ourDigest(int hlen) {
        return hlen == 32 ? Streebog256::new : Streebog512::new;
    }

    private static byte[] pattern(int length, int multiplier, int addend) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i * multiplier + addend);
        }
        return bytes;
    }

    /** Хэш, у которого {@code LE(хэш) = value}: так ГОСТ читает число {@code e}. */
    private static byte[] hashForE(BigInteger value, int hlen) {
        return NonceOracle.reverse(NonceOracle.int2octets(value, hlen));
    }

    private static byte[] bindingOf(ECDomainParameters domain, int hlen) {
        ECCurve.Fp curve = (ECCurve.Fp) domain.getCurve();
        return NonceOracle.curveBinding(
                curve.getQ(),
                curve.getA().toBigInteger(),
                curve.getB().toBigInteger(),
                domain.getG().getAffineXCoord().toBigInteger(),
                domain.getG().getAffineYCoord().toBigInteger(),
                domain.getN(),
                hlen,
                domain.getH().intValue());
    }

    private static BigInteger[] oracleSignature(
            ECDomainParameters domain, int hlen, BigInteger d, byte[] hash, byte[] z) {
        BigInteger n = domain.getN();
        NonceOracle.Derived derived =
                NonceOracle.derive(n, hlen, d, hash, bindingOf(domain, hlen), z);
        BigInteger r =
                domain.getG()
                        .multiply(derived.k())
                        .normalize()
                        .getAffineXCoord()
                        .toBigInteger()
                        .mod(n);
        BigInteger s = r.multiply(d).add(derived.k().multiply(derived.e())).mod(n);
        return new BigInteger[] {r, s};
    }

    private static BigInteger[] ourHedgedSignature(
            ECParameters ours, int hlen, BigInteger d, byte[] hash, byte[] z) {
        ECDSASigner signer =
                new ECDSASigner(ourDigest(hlen), NonceMode.HEDGED, new FixedBytesRandom(z));
        signer.init(true, new PrivateKeyParameters(d, ours));
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    private static List<BigInteger> keysOf(BigInteger n, int rolen) {
        List<BigInteger> keys = new ArrayList<>();
        keys.add(BigInteger.ONE);
        keys.add(n.subtract(BigInteger.ONE));
        keys.add(BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567)));
        byte[] bytes = pattern(rolen, 29, 7);
        bytes[0] = 0;
        keys.add(new BigInteger(1, bytes));
        return keys;
    }

    private static List<byte[]> hashesOf(BigInteger n, int hlen) {
        List<byte[]> hashes = new ArrayList<>();
        for (BigInteger e :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        n.subtract(BigInteger.ONE),
                        n,
                        n.add(BigInteger.ONE))) {
            hashes.add(hashForE(e, hlen));
        }
        for (int seed = 1; seed <= 4; seed++) {
            hashes.add(pattern(hlen, 31, seed * 17 + 1));
        }
        byte[] allOnes = new byte[hlen];
        java.util.Arrays.fill(allOnes, (byte) 0xFF);
        hashes.add(allOnes);
        return hashes;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Гибридная подпись библиотеки побайтно равна подписи эталона при том же Z")
    void hedgedSignatureMatchesOracle(CurveCase curve) {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curve.bcName());
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger n = x9.getN();
        int hlen = x9.getCurve().getFieldSize() > 256 ? 64 : 32;
        int rolen = (n.bitLength() + 7) / 8;

        int index = 0;
        for (BigInteger d : keysOf(n, rolen)) {
            for (byte[] hash : hashesOf(n, hlen)) {
                // Разный Z на разных парах: ошибка, зависящая от значения Z, не спрячется
                byte[] z = pattern(rolen, 11, 9 + index++);
                String context = curve + ", ключ " + d.toString(16) + ", пара " + index;

                BigInteger[] ours = ourHedgedSignature(curve.ours(), hlen, d, hash, z);
                BigInteger[] reference = oracleSignature(domain, hlen, d, hash, z);
                assertEquals(reference[0], ours[0], context + ": r не совпал с эталоном");
                assertEquals(reference[1], ours[1], context + ": s не совпал с эталоном");

                // Дополнительно: подпись верна по BouncyCastle (e = 0 BouncyCastle не принимает,
                // для такого хэша берётся e = 1: по RFC 7091 §6.1 это та же подпись)
                ECGOST3410_2012Signer verifier = new ECGOST3410_2012Signer();
                verifier.init(
                        false,
                        new ECPublicKeyParameters(domain.getG().multiply(d).normalize(), domain));
                byte[] hashForVerifier =
                        new BigInteger(1, NonceOracle.reverse(hash)).mod(n).signum() == 0
                                ? hashForE(BigInteger.ONE, hlen)
                                : hash;
                assertTrue(
                        verifier.verifySignature(hashForVerifier, ours[0], ours[1]),
                        context + ": BouncyCastle не проверяет гибридную подпись");
            }
        }
    }

    /** Хэш сообщения Стрибогом из BouncyCastle: JCA хэширует сообщение сам, эталон берёт хэш. */
    private static byte[] bcDigest(int hlen, byte[] message) {
        org.bouncycastle.crypto.Digest digest =
                hlen == 32
                        ? new org.bouncycastle.crypto.digests.GOST3411_2012_256Digest()
                        : new org.bouncycastle.crypto.digests.GOST3411_2012_512Digest();
        digest.update(message, 0, message.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName(
            "Подпись через JCA (setParameter + initSign(key, датчик)) побайтно равна подписи эталона при том же Z")
    void hedgedSignatureViaJcaMatchesOracle(CurveCase curve) throws Exception {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curve.bcName());
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger n = x9.getN();
        int hlen = x9.getCurve().getFieldSize() > 256 ? 64 : 32;
        int rolen = (n.bitLength() + 7) / 8;
        BigInteger d = keysOf(n, rolen).get(2);
        byte[] message = "сообщение для подписи через JCA".getBytes(StandardCharsets.UTF_8);
        byte[] z = pattern(rolen, 11, 9);

        if (java.security.Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new RssysGostProvider());
        }
        java.security.Signature jca =
                java.security.Signature.getInstance(
                        hlen == 32 ? "ECGOST3410-2012-256" : "ECGOST3410-2012-512",
                        RssysGostProvider.PROVIDER_NAME);
        jca.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        jca.initSign(
                new GostECPrivateKey(new PrivateKeyParameters(d, curve.ours())),
                new FixedBytesRandom(z));
        jca.update(message);
        byte[] viaJca = jca.sign();

        // Эталон считает k и (r, s) по хэшу сообщения; подпись в формате s || r
        BigInteger[] reference = oracleSignature(domain, hlen, d, bcDigest(hlen, message), z);
        byte[] expected =
                NonceOracle.concatBytes(
                        NonceOracle.int2octets(reference[1], hlen),
                        NonceOracle.int2octets(reference[0], hlen));
        assertArrayEquals(
                expected,
                viaJca,
                curve + ": подпись JCA не совпала с подписью эталона при том же Z");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Гибрид с фиксированным Z отличается от детерминированного режима")
    void hedgedDiffersFromDeterministic(CurveCase curve) {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curve.bcName());
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger n = x9.getN();
        int hlen = x9.getCurve().getFieldSize() > 256 ? 64 : 32;
        int rolen = (n.bitLength() + 7) / 8;
        BigInteger d = keysOf(n, rolen).get(2);
        byte[] hash = pattern(hlen, 7, 3);
        byte[] z = pattern(rolen, 11, 9);

        BigInteger[] hedged = oracleSignature(domain, hlen, d, hash, z);
        BigInteger[] deterministic = oracleSignature(domain, hlen, d, hash, null);
        assertNotEquals(
                deterministic[0],
                hedged[0],
                curve + ": гибрид ничем не отличается от детерминизма");
        assertArrayEquals(
                new BigInteger[] {hedged[0], hedged[1]},
                ourHedgedSignature(curve.ours(), hlen, d, hash, z),
                curve + ": подпись библиотеки не совпала с эталоном");
    }
}
