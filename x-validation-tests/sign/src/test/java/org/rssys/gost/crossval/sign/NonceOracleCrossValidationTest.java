package org.rssys.gost.crossval.sign;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
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
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Сверка выработки нонса {@code k} с независимой реализацией ({@link NonceOracle}) на BouncyCastle.
 *
 * <p>Кросс-валидация подписи (BouncyCastle, OpenSSL, КриптоПро) проверяет только уравнение
 * подписи: любой {@code k} из [1, n-1] даёт верную подпись. Поэтому дефект в выработке нонса, в
 * частности прежний (затравка из байт хэша вместо числа {@code e}), ею не виден. Здесь нонс,
 * восстановленный из подписи библиотеки по формуле {@code k = (s - r·d)·e⁻¹ mod n}, сверяется
 * побайтно с нонсом эталона.
 *
 * <p>Порядок кривой и длина хэша берутся из BouncyCastle ({@link ECGOST3410NamedCurves}), а не из
 * {@code org.rssys.gost}: ошибка в нашем реестре кривых совпала бы в обеих реализациях и осталась
 * бы невидимой, поэтому параметры наших кривых отдельно сравниваются с параметрами BouncyCastle.
 */
@DisplayName("Нонс k: сверка с независимой реализацией на BouncyCastle")
class NonceOracleCrossValidationTest {

    /** Кривые, на которых кандидат нонса отбрасывается часто (комментарий в generateK). */
    private static final Set<String> FREQUENT_REJECTION =
            Set.of("cryptoProB", "tc26a256", "tc26b512", "cryptoProC");

    /** Сколько хэшей перебирать в поиске пары с отбракованными кандидатами. */
    private static final int SEARCH_LIMIT = 20_000;

    /** Наша кривая и имя той же кривой в BouncyCastle (по стандартным именам наборов). */
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

    private static X9ECParameters bcParameters(CurveCase curve) {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9(curve.bcName());
        assertNotNull(x9, "BouncyCastle не знает набор " + curve.bcName());
        return x9;
    }

    /** Длина хэша по размеру поля кривой BouncyCastle, а не по нашим параметрам. */
    private static int hashLength(X9ECParameters x9) {
        return x9.getCurve().getFieldSize() > 256 ? 64 : 32;
    }

    private static Supplier<Digest> ourDigest(int hlen) {
        return hlen == 32 ? Streebog256::new : Streebog512::new;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Параметры наших кривых равны параметрам BouncyCastle")
    void curveParametersMatchBouncyCastle(CurveCase curve) {
        X9ECParameters x9 = bcParameters(curve);
        ECParameters ours = curve.ours();
        ECCurve.Fp bcCurve = (ECCurve.Fp) x9.getCurve();
        BigInteger p = bcCurve.getQ();

        assertEquals(p, ours.p, curve + ": модуль поля p");
        // Без приведения по модулю: идентификатор кривой кодирует a как есть
        assertEquals(bcCurve.getA().toBigInteger(), ours.a, curve + ": коэффициент a");
        assertEquals(bcCurve.getB().toBigInteger(), ours.b, curve + ": коэффициент b");
        assertEquals(
                x9.getG().getAffineXCoord().toBigInteger(), ours.gx, curve + ": x базовой точки");
        assertEquals(
                x9.getG().getAffineYCoord().toBigInteger(), ours.gy, curve + ": y базовой точки");
        assertEquals(x9.getN(), ours.n, curve + ": порядок n");
        assertEquals(x9.getH().intValue(), ours.cofactor, curve + ": кофактор");
        assertEquals(hashLength(x9), ours.hlen, curve + ": длина хэша");
    }

    /** Идентификатор кривой по параметрам BouncyCastle, независимо от {@code org.rssys.gost}. */
    private static byte[] bindingOf(ECDomainParameters domain) {
        ECCurve.Fp curve = (ECCurve.Fp) domain.getCurve();
        int hlen = curve.getFieldSize() > 256 ? 64 : 32;
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

    // ---- Сетка (d, хэш) ----

    /** Хэш, у которого число e = LE(хэш) равно value (до приведения по модулю n). */
    private static byte[] hashForE(BigInteger value, int hlen) {
        return NonceOracle.reverse(NonceOracle.int2octets(value, hlen));
    }

    private static byte[] patternHash(int hlen, int seed) {
        byte[] hash = new byte[hlen];
        for (int i = 0; i < hlen; i++) {
            hash[i] = (byte) (i * 31 + seed * 17 + 1);
        }
        return hash;
    }

    /** Ключ с ведущим нулевым байтом: остаётся меньше n на любой кривой. */
    private static BigInteger patternKey(int rolen, int leadingZeroBytes, int trailingZeroBytes) {
        byte[] bytes = new byte[rolen];
        for (int i = leadingZeroBytes; i < rolen - trailingZeroBytes; i++) {
            bytes[i] = (byte) (i * 29 + 7);
        }
        BigInteger key = new BigInteger(1, bytes);
        assertTrue(key.signum() > 0, "ключ сетки не должен быть нулевым");
        return key;
    }

    private static List<BigInteger> keysOf(BigInteger n) {
        int rolen = (n.bitLength() + 7) / 8;
        List<BigInteger> keys = new ArrayList<>();
        keys.add(BigInteger.ONE);
        keys.add(n.subtract(BigInteger.ONE));
        keys.add(n.subtract(BigInteger.valueOf(12345)));
        keys.add(BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567)));
        keys.add(patternKey(rolen, 1, 0));
        keys.add(patternKey(rolen, 4, 0));
        keys.add(patternKey(rolen, 1, 8));
        return keys;
    }

    private static List<byte[]> hashesOf(BigInteger n, int hlen) {
        List<byte[]> hashes = new ArrayList<>();
        // e = 0, 1, 2, n-2, n-1, n, n+1: границы приведения хэша в число e
        for (BigInteger e :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        BigInteger.TWO,
                        n.subtract(BigInteger.TWO),
                        n.subtract(BigInteger.ONE),
                        n,
                        n.add(BigInteger.ONE))) {
            hashes.add(hashForE(e, hlen));
        }
        for (int seed = 1; seed <= 6; seed++) {
            hashes.add(patternHash(hlen, seed));
        }
        byte[] allOnes = new byte[hlen];
        java.util.Arrays.fill(allOnes, (byte) 0xFF);
        hashes.add(allOnes);
        return hashes;
    }

    private static BigInteger[] ourSignature(
            ECParameters ours, BigInteger d, byte[] hash, int hlen) {
        // Режим закреплён явно: сверка точная, а гибридный режим сверяется отдельным тестом
        ECDSASigner signer = new ECDSASigner(ourDigest(hlen), NonceMode.DETERMINISTIC, null);
        signer.init(true, new PrivateKeyParameters(d, ours));
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    /**
     * Проверяет подпись библиотеки средствами BouncyCastle (ключ и кривая - тоже из
     * BouncyCastle). BouncyCastle считает число e по-своему, поэтому принятая им подпись
     * означает, что e библиотеки равно эталонному, и расхождение e не спрячется за расхождением k.
     */
    private static void assertBouncyCastleVerifies(
            ECDomainParameters domain,
            BigInteger n,
            int hlen,
            BigInteger d,
            byte[] hash,
            BigInteger[] sig,
            String context) {
        ECPublicKeyParameters pub =
                new ECPublicKeyParameters(domain.getG().multiply(d).normalize(), domain);
        ECGOST3410_2012Signer verifier = new ECGOST3410_2012Signer();
        verifier.init(false, pub);
        // BouncyCastle не выполняет правило RFC 7091 §6.2 «если e = 0, взять e = 1»: при
        // e ≡ 0 (mod n) его verifySignature бросает ArithmeticException (BigInteger not
        // invertible). Правило выполняют библиотека и gost-engine OpenSSL. Для таких хэшей
        // BouncyCastle проверяет подпись по хэшу с e = 1: по правилу RFC это та же подпись, а
        // побайтное равенство подписей при e = 0 и e = 1 проверяется отдельным тестом.
        byte[] hashForBouncyCastle =
                new BigInteger(1, NonceOracle.reverse(hash)).mod(n).signum() == 0
                        ? hashForE(BigInteger.ONE, hlen)
                        : hash;
        assertTrue(
                verifier.verifySignature(hashForBouncyCastle, sig[0], sig[1]),
                context
                        + ": BouncyCastle не проверяет подпись библиотеки (расхождение e или"
                        + " кодирования подписи, а не вывода k)");
    }

    /** Сравнивает k, восстановленный из подписи библиотеки, с k эталона. */
    private static void assertNonceMatches(
            CurveCase curve,
            ECDomainParameters domain,
            BigInteger n,
            int hlen,
            BigInteger d,
            byte[] hash,
            String context) {
        BigInteger[] sig = ourSignature(curve.ours(), d, hash, hlen);
        assertBouncyCastleVerifies(domain, n, hlen, d, hash, sig, context);

        NonceOracle.Derived reference = NonceOracle.derive(n, hlen, d, hash, bindingOf(domain));
        BigInteger recovered =
                sig[1].subtract(sig[0].multiply(d))
                        .mod(n)
                        .multiply(reference.e().modInverse(n))
                        .mod(n);
        assertEquals(
                reference.k(),
                recovered,
                context + ": k библиотеки не совпал с k эталона (вывод нонса)");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("k библиотеки совпадает с k независимой реализации на сетке (d, хэш)")
    void nonceMatchesOracleOnGrid(CurveCase curve) {
        X9ECParameters x9 = bcParameters(curve);
        BigInteger n = x9.getN();
        int hlen = hashLength(x9);
        ECDomainParameters domain = new ECDomainParameters(x9);

        int checked = 0;
        int withRejection = 0;
        int withTwoRejections = 0;
        for (BigInteger d : keysOf(n)) {
            for (byte[] hash : hashesOf(n, hlen)) {
                assertNonceMatches(
                        curve, domain, n, hlen, d, hash, curve + ", ключ " + d.toString(16));
                NonceOracle.Derived reference =
                        NonceOracle.derive(n, hlen, d, hash, bindingOf(domain));
                if (reference.rejected() >= 1) {
                    withRejection++;
                }
                if (reference.rejected() >= 2) {
                    withTwoRejections++;
                }
                checked++;
            }
        }
        System.out.printf(
                "[нонс] %s: сверено пар %d, из них с отбракованным кандидатом %d, с двумя подряд %d%n",
                curve, checked, withRejection, withTwoRejections);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Ветка отбраковки кандидата (h.3) и сдвиг bits2int сверяются с эталоном")
    void rejectionBranchAndShiftAreCoveredAndMatch(CurveCase curve) {
        X9ECParameters x9 = bcParameters(curve);
        BigInteger n = x9.getN();
        int hlen = hashLength(x9);
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger d = patternKey((n.bitLength() + 7) / 8, 1, 0);

        // Поиск идёт только эталоном (подпись не нужна), затем найденные пары сверяются целиком
        byte[] oneRejected = null;
        byte[] twoRejected = null;
        for (int counter = 0;
                counter < SEARCH_LIMIT && (oneRejected == null || twoRejected == null);
                counter++) {
            byte[] hash = patternHash(hlen, 1000 + counter);
            int rejected = NonceOracle.derive(n, hlen, d, hash, bindingOf(domain)).rejected();
            if (rejected == 1 && oneRejected == null) {
                oneRejected = hash;
            } else if (rejected >= 2 && twoRejected == null) {
                twoRejected = hash;
            }
        }

        boolean frequent = FREQUENT_REJECTION.contains(curve.name());
        if (frequent) {
            assertNotNull(
                    oneRejected,
                    curve
                            + ": пара с одним отбракованным кандидатом не найдена за "
                            + SEARCH_LIMIT
                            + " хэшей, ветка h.3 не покрыта");
            assertNotNull(
                    twoRejected,
                    curve
                            + ": пара с двумя отбракованными подряд не найдена за "
                            + SEARCH_LIMIT
                            + " хэшей");
        }
        if (oneRejected != null) {
            assertNonceMatches(curve, domain, n, hlen, d, oneRejected, curve + ", один отброшен");
        }
        if (twoRejected != null) {
            assertNonceMatches(curve, domain, n, hlen, d, twoRejected, curve + ", два отброшены");
        }

        // Сдвиг bits2int есть там, где n короче 8·hlen бит; на таких кривых он не нулевой всегда
        int expectedShift = Math.max(0, 8 * hlen - n.bitLength());
        int actualShift =
                NonceOracle.derive(n, hlen, d, patternHash(hlen, 1), bindingOf(domain)).shift();
        assertEquals(expectedShift, actualShift, curve + ": сдвиг bits2int");
        System.out.printf(
                "[нонс] %s: отбраковка 1: %s, отбраковка 2: %s, сдвиг bits2int %d бит%n",
                curve,
                oneRejected != null ? "найдена" : "не найдена за " + SEARCH_LIMIT,
                twoRejected != null ? "найдена" : "не найдена за " + SEARCH_LIMIT,
                actualShift);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Хэши с e = 0, n, n+1 дают e = 1: равные k и побайтно равные подписи")
    void hashesWithSameReducedEGiveSameNonceAndSignature(CurveCase curve) {
        X9ECParameters x9 = bcParameters(curve);
        BigInteger n = x9.getN();
        int hlen = hashLength(x9);
        ECDomainParameters domain = new ECDomainParameters(x9);
        BigInteger d = patternKey((n.bitLength() + 7) / 8, 1, 0);

        byte[] zero = hashForE(BigInteger.ZERO, hlen);
        byte[] one = hashForE(BigInteger.ONE, hlen);
        byte[] modulus = hashForE(n, hlen);
        byte[] modulusPlusOne = hashForE(n.add(BigInteger.ONE), hlen);

        BigInteger[] reference = ourSignature(curve.ours(), d, one, hlen);
        for (byte[] hash : List.of(zero, modulus, modulusPlusOne)) {
            assertNonceMatches(curve, domain, n, hlen, d, hash, curve + ", e сведено к 1");
            BigInteger[] sig = ourSignature(curve.ours(), d, hash, hlen);
            assertEquals(reference[0], sig[0], curve + ": r при e = 1");
            assertEquals(reference[1], sig[1], curve + ": s при e = 1");
        }
        assertEquals(
                NonceOracle.derive(n, hlen, d, one, bindingOf(domain)).k(),
                NonceOracle.derive(n, hlen, d, zero, bindingOf(domain)).k(),
                curve + ": эталон: e = 0 и e = 1 дают один k");
    }
}
