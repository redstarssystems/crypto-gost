package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.Pack;

/**
 * Свойства безопасности подписи ГОСТ Р 34.10-2012. Каждый тест моделирует наблюдателя, который
 * пытается восстановить ключ или добиться принятия чужого ключа или подписи, и утверждает, что
 * ему это не удаётся: ключ не восстанавливается, чужой ключ или подпись отвергаются.
 *
 * <p>Наблюдателю известно всё, кроме {@code d} и {@code k}: открытый ключ, хэши, подписи, параметры
 * кривой. Там, где для проверки свойства нужен сам {@code k}, тест восстанавливает его из
 * подписи по известному {@code d}: {@code k = (s − r·d)·e⁻¹ mod n}.
 */
@DisplayName("Подпись ГОСТ Р 34.10-2012: свойства безопасности")
class SignatureSecurityPropertiesTest {

    /** Случайных пар хэшей на кривую при попытке восстановить ключ. */
    private static final int RANDOM_PAIRS = 20;

    /** Подписей для статистики нонса на 256-битной и 512-битной кривой. */
    private static final int NONCE_SAMPLES_256 = 2000;

    private static final int NONCE_SAMPLES_512 = 600;

    /** Допуск на долю {@code k >= n/2}: при 600 выборках три сигмы равны 0.06. */
    private static final double HALF_FRACTION_TOLERANCE = 0.08;

    /** Сколько фиксированных хэшей проверяем на каждой паре кривых одной длины. */
    private static final int CROSS_CURVE_HASHES = 60;

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

    private static Stream<ECParameters> curvesWithRejectionLoop() {
        // n заметно меньше 2^qlen: кандидат k отбрасывается примерно в половине случаев
        return Stream.of(ECParameters.tc26a256(), ECParameters.tc26c512());
    }

    private static Supplier<Digest> digestFactory(ECParameters params) {
        return params.hlen == Streebog256.DIGEST_SIZE ? Streebog256::new : Streebog512::new;
    }

    private static PrivateKeyParameters fixedKey(ECParameters params) {
        // Воспроизводимый d, заведомо меньше n на любой кривой (n > 2^254)
        BigInteger d =
                BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567));
        return new PrivateKeyParameters(d, params);
    }

    private static PrivateKeyParameters randomKey(ECParameters params) {
        BigInteger d;
        do {
            d = new BigInteger(params.n.bitLength(), CryptoRandom.INSTANCE).mod(params.n);
        } while (d.signum() == 0);
        return new PrivateKeyParameters(d, params);
    }

    private static byte[] randomHash(ECParameters params) {
        byte[] hash = new byte[params.hlen];
        CryptoRandom.INSTANCE.nextBytes(hash);
        return hash;
    }

    /** Хэш, у которого {@code LE(hash) = value}: так ГОСТ читает число {@code e}. */
    private static byte[] hashWithLittleEndianValue(BigInteger value, int hlen) {
        return Pack.reverseBytes(Pack.toFixedLengthBigEndian(value, hlen));
    }

    private static BigInteger eOf(byte[] hash, ECParameters params) {
        BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(params.n);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    /**
     * Подпись в детерминированном режиме, закреплённом явно: проверки опираются на то, что
     * {@code k} - функция {@code (d, e, кривая)}. При случайной добавке {@code Z} такие тесты
     * проходили бы тривиально, например различие {@code k} на двух кривых объяснялось бы разным
     * {@code Z}, а не привязкой к кривой.
     */
    private static BigInteger[] signRaw(PrivateKeyParameters priv, byte[] hash) {
        ECDSASigner signer =
                new ECDSASigner(digestFactory(priv.getParams()), NonceMode.DETERMINISTIC, null);
        signer.init(true, priv);
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    private static boolean verifyRaw(
            PublicKeyParameters pub, byte[] hash, BigInteger r, BigInteger s) {
        ECDSASigner signer =
                new ECDSASigner(digestFactory(pub.getParams()), NonceMode.DETERMINISTIC, null);
        signer.init(false, pub);
        return signer.verifySignature(hash, r, s);
    }

    /** Нонс из подписи по известному ключу: {@code k = (s − r·d)·e⁻¹ mod n}. */
    private static BigInteger recoverK(
            BigInteger d, BigInteger e, BigInteger[] sig, ECParameters params) {
        BigInteger n = params.n;
        return sig[1].subtract(sig[0].multiply(d)).multiply(e.modInverse(n)).mod(n);
    }

    /**
     * Действия наблюдателя при общем нонсе: {@code k = (s1 − s2)/(e1 − e2)},
     * {@code d = (s1 − k·e1)/r1}. Если нонсы на самом деле разные, результат - мусор.
     */
    private static BigInteger recoverKeyFromSharedNonce(
            BigInteger[] sig1,
            BigInteger e1,
            BigInteger[] sig2,
            BigInteger e2,
            ECParameters params) {
        BigInteger n = params.n;
        BigInteger kGuess =
                sig1[1].subtract(sig2[1]).multiply(e1.subtract(e2).modInverse(n)).mod(n);
        return sig1[1].subtract(kGuess.multiply(e1)).multiply(sig1[0].modInverse(n)).mod(n);
    }

    // -------------------------------------------------------------------------
    // 1. Восстановление ключа по двум подписям с общим нонсом
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "Два хэша с равной прежней затравкой и разными e: r различны, формула восстановления даёт не d")
    void sharedNonceRecoveryOnLegacySeedPairsFails(ECParameters params) {
        PrivateKeyParameters priv = fixedKey(params);
        BigInteger d = priv.getD();
        int drop = 8 * params.hlen - params.n.bitLength();
        // Прежняя затравка считалась из BE(hash) старшими qlen битами по модулю n: у обоих хэшей
        // она равна 1, а числа e (из LE) различаются
        byte[] h1 = Pack.toFixedLengthBigEndian(BigInteger.ONE.shiftLeft(drop), params.hlen);
        byte[] h2 =
                Pack.toFixedLengthBigEndian(
                        BigInteger.ONE.add(params.n).shiftLeft(drop), params.hlen);
        assertSharedNonceRecoveryFails(priv, d, h1, h2, params);

        // Развёрнутый хэш: BE(h2) = LE(h1), прежняя затравка одного равна e другого
        for (int i = 0; i < RANDOM_PAIRS; i++) {
            byte[] a = randomHash(params);
            byte[] b = Pack.reverseBytes(a);
            if (eOf(a, params).equals(eOf(b, params))) continue;
            assertSharedNonceRecoveryFails(priv, d, a, b, params);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Случайные пары хэшей: нонсы различны, формула восстановления даёт не d")
    void sharedNonceRecoveryOnRandomPairsFails(ECParameters params) {
        PrivateKeyParameters priv = randomKey(params);
        BigInteger d = priv.getD();
        for (int i = 0; i < RANDOM_PAIRS; i++) {
            byte[] a = randomHash(params);
            byte[] b = randomHash(params);
            assertSharedNonceRecoveryFails(priv, d, a, b, params);
        }
    }

    private static void assertSharedNonceRecoveryFails(
            PrivateKeyParameters priv, BigInteger d, byte[] h1, byte[] h2, ECParameters params) {
        BigInteger e1 = eOf(h1, params);
        BigInteger e2 = eOf(h2, params);
        assertNotEquals(e1, e2, "для восстановления значения e обязаны различаться");

        BigInteger[] sig1 = signRaw(priv, h1);
        BigInteger[] sig2 = signRaw(priv, h2);
        assertNotEquals(sig1[0], sig2[0], "общий r выдал бы общий нонс");
        assertNotEquals(
                recoverK(d, e1, sig1, params),
                recoverK(d, e2, sig2, params),
                "нонс повторился при разных e");

        BigInteger dGuess = recoverKeyFromSharedNonce(sig1, e1, sig2, e2, params);
        assertNotEquals(d, dGuess, "наблюдатель восстановил закрытый ключ");
        // Чужой ключ не даёт верной подписи: формула восстановления не дала и эквивалентного d
        if (dGuess.signum() > 0 && dGuess.compareTo(params.n) < 0) {
            PublicKeyParameters pubGuess =
                    new PrivateKeyParameters(dGuess, params).derivePublicKey();
            assertFalse(
                    verifyRaw(pubGuess, h1, sig1[0], sig1[1]), "подпись верна для постороннего d");
        }
    }

    // -------------------------------------------------------------------------
    // 2. Сбой при вычислении (ADR 07) и самопроверка
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "Сбойная подпись с тем же k раскрывает d (ADR 07); самопроверка verifyHash её отсекает")
    void faultySignatureRevealsKeyButSelfCheckBlocksIt(ECParameters params) {
        PrivateKeyParameters priv = randomKey(params);
        PublicKeyParameters pub = priv.derivePublicKey();
        BigInteger d = priv.getD();
        byte[] hash = randomHash(params);
        BigInteger e = eOf(hash, params);
        BigInteger[] good = signRaw(priv, hash);
        BigInteger k = recoverK(d, e, good, params);

        // Модель сбоя в k·G: r испорчен, s согласован с ним и тем же k (детерминированный нонс)
        BigInteger rFault = good[0].add(BigInteger.ONE).mod(params.n);
        BigInteger sFault = rFault.multiply(d).add(k.multiply(e)).mod(params.n);

        // Наблюдатель: s − s' = (r − r')·d
        BigInteger dRecovered =
                good[1].subtract(sFault)
                        .multiply(good[0].subtract(rFault).modInverse(params.n))
                        .mod(params.n);
        assertEquals(
                d, dRecovered, "модель сбоя обязана восстанавливать d: это принятый риск ADR 07");

        // Рекомендованная защита: сбойная подпись не проходит проверку открытым ключом
        byte[] faultyEncoded = SignatureCodec.encode(rFault, sFault, params);
        assertFalse(
                Signature.verifyHash(hash, faultyEncoded, pub),
                "самопроверка пропустила сбойную подпись");
        assertTrue(
                Signature.verifyHash(hash, SignatureCodec.encode(good[0], good[1], params), pub));
    }

    // -------------------------------------------------------------------------
    // 3. Смещение нонса
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("curvesWithRejectionLoop")
    @DisplayName(
            "Нонс k на кривых с отбраковкой: в [1, n−1], старшие биты без провалов, половина выше n/2")
    void nonceIsUniformOnCurvesWithRejection(ECParameters params) {
        PrivateKeyParameters priv = randomKey(params);
        BigInteger d = priv.getD();
        int samples =
                params.hlen == Streebog256.DIGEST_SIZE ? NONCE_SAMPLES_256 : NONCE_SAMPLES_512;
        // Старшие 4 бита относительно n: k < n, поэтому бакеты выше n >> shift пусты по праву;
        // 16 бакетов дают десятки попаданий в каждый даже при 600 выборках
        int shift = params.n.bitLength() - 4;
        int bucketLimit = params.n.shiftRight(shift).intValue();
        int[] buckets = new int[16];
        BigInteger half = params.n.shiftRight(1);
        int aboveHalf = 0;

        for (int i = 0; i < samples; i++) {
            byte[] hash = randomHash(params);
            BigInteger[] sig = signRaw(priv, hash);
            BigInteger k = recoverK(d, eOf(hash, params), sig, params);
            assertTrue(k.signum() > 0 && k.compareTo(params.n) < 0, "k вне [1, n−1]");
            buckets[k.shiftRight(shift).intValue()]++;
            if (k.compareTo(half) >= 0) aboveHalf++;
        }

        // Смещённый нонс (усечение, неверный сдвиг bits2int) оставил бы пустые бакеты
        for (int b = 0; b < bucketLimit; b++) {
            assertTrue(buckets[b] > 0, "пустой бакет старших бит " + b + " из " + bucketLimit);
        }
        double fraction = (double) aboveHalf / samples;
        assertTrue(
                Math.abs(fraction - 0.5) < HALF_FRACTION_TOLERANCE,
                "доля k >= n/2 равна " + fraction + ": нонс смещён");
    }

    // -------------------------------------------------------------------------
    // 4. Замена кривой и точки малого порядка
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Точка tc26a256 под параметрами cryptoProA (общий p) отвергается")
    void pointFromOtherCurveWithSameFieldIsRejected() {
        ECParameters tc26 = ECParameters.tc26a256();
        ECParameters cpa = ECParameters.cryptoProA();
        assertEquals(tc26.p, cpa.p, "предусловие: у кривых общий модуль поля");
        // Диапазон координат проходит, поэтому отказ обязан дать только тест уравнения кривой
        ECPoint foreign = ECPoint.affine(tc26.gx, tc26.gy, cpa);
        assertThrows(IllegalArgumentException.class, () -> new PublicKeyParameters(foreign, cpa));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Неканонические координаты (x + p) и точка вне кривой отвергаются")
    void nonCanonicalAndOffCurvePointsAreRejected(ECParameters params) {
        PublicKeyParameters pub = randomKey(params).derivePublicKey();
        BigInteger x = pub.getQ().getX();
        BigInteger y = pub.getQ().getY();
        assertThrows(
                IllegalArgumentException.class,
                () -> ECPoint.affine(x.add(params.p), y, params),
                "x + p принят как вторая кодировка ключа");
        BigInteger yOff = y.add(BigInteger.ONE).mod(params.p);
        assertThrows(
                IllegalArgumentException.class,
                () -> new PublicKeyParameters(ECPoint.affine(x, yOff, params), params),
                "точка вне кривой принята");
    }

    @Test
    @DisplayName("Точки порядка 2 и 4 на кривых с кофактором 4 не принимаются как открытый ключ")
    void smallOrderPointsAreRejectedAsPublicKey() {
        for (ECParameters params : List.of(ECParameters.tc26a256(), ECParameters.tc26c512())) {
            for (int order : new int[] {2, 4}) {
                BigInteger[] small = ECPointLadderTest.findSmallOrderPoint(params, order);
                ECPoint point = AffineReference.toEcPoint(small, params);
                assertTrue(point.isOnCurve(), "точка малого порядка обязана лежать на кривой");
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new PublicKeyParameters(point, params),
                        "точка порядка " + order + " принята");
            }
        }
    }

    @Test
    @DisplayName("DER-ключ tc26a512 с OID кривой, заменённым на tc26b512, отвергается")
    void derPublicKeyWithSwappedCurveOidIsRejected() {
        PublicKeyParameters pub = randomKey(ECParameters.tc26a512()).derivePublicKey();
        byte[] der = GostDerCodec.encodePublicKey(pub);
        // 1.2.643.7.1.2.1.2.1 -> ...2.2: последний байт OID набора параметров
        byte[] oidA512 = {0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01};
        int at = indexOf(der, oidA512);
        assertTrue(at >= 0, "OID tc26a512 не найден в SPKI");
        byte[] withReplacedOid = der.clone();
        withReplacedOid[at + oidA512.length - 1] = 0x02;
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.decodePublicKey(withReplacedOid));
        // Контроль: исходный ключ разбирается
        GostDerCodec.decodePublicKey(der);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    // -------------------------------------------------------------------------
    // 5. Малеабельность: вторая подпись без ключа
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "Из верной (r, s) без ключа не получить другую верную: (n−r, s), (r, n−s), (r+n, s), 0 и n")
    void signatureIsNotMalleable(ECParameters params) {
        PrivateKeyParameters priv = randomKey(params);
        PublicKeyParameters pub = priv.derivePublicKey();
        byte[] hash = randomHash(params);
        BigInteger[] sig = signRaw(priv, hash);
        BigInteger r = sig[0], s = sig[1], n = params.n;
        assertTrue(Signature.verifyHash(hash, SignatureCodec.encode(r, s, params), pub));

        BigInteger[][] variants = {
            {n.subtract(r), s},
            {r, n.subtract(s)},
            {n.subtract(r), n.subtract(s)},
            {r.add(n), s},
            {r, s.add(n)},
            {BigInteger.ZERO, s},
            {r, BigInteger.ZERO},
            {n, s},
            {r, n},
        };
        for (BigInteger[] v : variants) {
            String label = "r' = " + v[0].toString(16) + ", s' = " + v[1].toString(16);
            byte[] encoded;
            try {
                encoded = SignatureCodec.encode(v[0], v[1], params);
            } catch (IllegalArgumentException notEncodable) {
                // компонента не помещается в rolen байт: второй кодировки нет
                continue;
            }
            assertFalse(
                    Signature.verifyHash(hash, encoded, pub),
                    "принята посторонняя подпись " + label);
        }

        // Подпись другого ключа под тем же хэшем не подходит к нашему открытому ключу
        BigInteger[] other = signRaw(randomKey(params), hash);
        assertFalse(
                Signature.verifyHash(hash, SignatureCodec.encode(other[0], other[1], params), pub));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName("Подпись неверной длины и с лишним байтом не принимается, а не усекается")
    void signatureOfWrongLengthIsRejected(ECParameters params) {
        PrivateKeyParameters priv = randomKey(params);
        PublicKeyParameters pub = priv.derivePublicKey();
        byte[] hash = randomHash(params);
        byte[] good = Signature.signHash(hash, priv);
        byte[] longer = java.util.Arrays.copyOf(good, good.length + 1);
        byte[] shorter = java.util.Arrays.copyOf(good, good.length - 1);
        assertFalse(Signature.verifyHash(hash, longer, pub), "подпись с лишним байтом принята");
        assertFalse(Signature.verifyHash(hash, shorter, pub), "усечённая подпись принята");
        assertFalse(Signature.verifyHash(hash, new byte[0], pub), "пустая подпись принята");
        assertFalse(Signature.verifyHash(hash, null, pub), "подпись null принята");
    }

    // -------------------------------------------------------------------------
    // 6. Путаница хэшей
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @MethodSource("allCurves")
    @DisplayName(
            "Хэши LE(h) и LE(h) + n дают одну подпись, верную для обоих (свойство e = h mod q)")
    void hashesCongruentModuloNShareSignature(ECParameters params) {
        // LE(h) + n обязано уместиться в hlen байт: у cryptoProA запас над n около 2^128, поэтому
        // base берём 64-битным
        BigInteger base = new BigInteger(64, CryptoRandom.INSTANCE).add(BigInteger.TWO);
        byte[] h1 = hashWithLittleEndianValue(base, params.hlen);
        byte[] h2 = hashWithLittleEndianValue(base.add(params.n), params.hlen);
        assertFalse(java.util.Arrays.equals(h1, h2));

        PrivateKeyParameters priv = randomKey(params);
        PublicKeyParameters pub = priv.derivePublicKey();
        byte[] sig1 = Signature.signHash(h1, priv, NonceMode.DETERMINISTIC);
        byte[] sig2 = Signature.signHash(h2, priv, NonceMode.DETERMINISTIC);
        assertArrayEquals(sig1, sig2, "равное e обязано давать побайтно равную подпись");
        assertTrue(Signature.verifyHash(h1, sig1, pub));
        assertTrue(Signature.verifyHash(h2, sig1, pub));
    }

    @Test
    @DisplayName("Хэш не той длины для кривой отвергается при подписи и проверке")
    void hashOfWrongSizeIsRejected() {
        PrivateKeyParameters k256 = randomKey(ECParameters.cryptoProA());
        PrivateKeyParameters k512 = randomKey(ECParameters.tc26a512());
        byte[] h32 = randomHash(ECParameters.cryptoProA());
        byte[] h64 = randomHash(ECParameters.tc26a512());
        assertThrows(IllegalArgumentException.class, () -> Signature.signHash(h64, k256));
        assertThrows(IllegalArgumentException.class, () -> Signature.signHash(h32, k512));
        byte[] sig256 = Signature.signHash(h32, k256);
        assertThrows(
                IllegalArgumentException.class,
                () -> Signature.verifyHash(h64, sig256, k256.derivePublicKey()));
    }

    // -------------------------------------------------------------------------
    // 7. Состояние подписанта и уничтожение ключа
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("После destroy() подписант отказывает, а не подписывает нулевым ключом")
    void destroyedSignerRefusesToSign() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = randomKey(params);
        byte[] hash = randomHash(params);
        ECDSASigner signer = new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
        signer.init(true, priv);
        signer.destroy();
        assertThrows(IllegalStateException.class, () -> signer.generateSignature(hash));
        assertThrows(IllegalStateException.class, () -> signer.init(true, priv));

        priv.destroy();
        assertThrows(IllegalStateException.class, () -> Signature.signHash(hash, priv));
    }

    @Test
    @DisplayName(
            "Копия ключа в ECDSASigner живёт независимо от priv.destroy(): документированное поведение")
    void signerKeepsOwnKeyCopyAfterPrivateKeyDestroy() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = randomKey(params);
        PublicKeyParameters pub = priv.derivePublicKey();
        byte[] hash = randomHash(params);
        ECDSASigner signer = new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
        signer.init(true, priv);
        priv.destroy();
        try {
            // Подпись верна: подписант работает со своей копией, поэтому владелец обязан вызывать
            // и signer.destroy(), иначе d остаётся в памяти
            BigInteger[] sig = signer.generateSignature(hash);
            assertTrue(verifyRaw(pub, hash, sig[0], sig[1]));
        } finally {
            signer.destroy();
        }
    }

    // -------------------------------------------------------------------------
    // 8. Один d на двух кривых
    // -------------------------------------------------------------------------

    @Test
    @DisplayName(
            "Один d на двух кривых одной длины при равном e даёт разный k: нонс привязан к кривой")
    void sameKeyOnTwoCurvesGivesDifferentNonces() {
        List<ECParameters> curves =
                List.of(
                        ECParameters.tc26a256(),
                        ECParameters.cryptoProA(),
                        ECParameters.cryptoProB(),
                        ECParameters.cryptoProC(),
                        ECParameters.tc26a512(),
                        ECParameters.tc26b512(),
                        ECParameters.tc26c512());
        BigInteger d = fixedKey(curves.get(0)).getD();
        int comparedPairs = 0;
        for (int first = 0; first < curves.size(); first++) {
            for (int second = first + 1; second < curves.size(); second++) {
                ECParameters a = curves.get(first);
                ECParameters b = curves.get(second);
                if (a.hlen != b.hlen) {
                    // Разная длина: другой дайджест и другая длина V и d, общий нонс невозможен
                    continue;
                }
                PrivateKeyParameters privA = new PrivateKeyParameters(d, a);
                PrivateKeyParameters privB = new PrivateKeyParameters(d, b);
                for (int i = 0; i < CROSS_CURVE_HASHES; i++) {
                    // Фиксированный набор: e меньше обоих n, то есть число читается одинаково на
                    // обеих кривых. Без привязки к кривой на таких хэшах k совпадал примерно в
                    // половине случаев, поэтому тест на прежней раскладке красный. Случайные
                    // хэши (разные e на разных кривых) давали бы разный k и без привязки
                    BigInteger e = commonEForCrossCurve(i);
                    byte[] hash = hashWithLittleEndianValue(e, a.hlen);
                    BigInteger[] sigA = signRaw(privA, hash);
                    BigInteger[] sigB = signRaw(privB, hash);
                    assertTrue(
                            verifyRaw(privA.derivePublicKey(), hash, sigA[0], sigA[1]),
                            "подпись на первой кривой обязана проверяться");
                    assertTrue(
                            verifyRaw(privB.derivePublicKey(), hash, sigB[0], sigB[1]),
                            "подпись на второй кривой обязана проверяться");
                    assertNotEquals(
                            recoverK(d, e, sigA, a),
                            recoverK(d, e, sigB, b),
                            "один d и равное e на двух кривых обязаны давать разный k (хэш "
                                    + i
                                    + ")");
                }
                comparedPairs++;
            }
        }
        // 4 кривые по 256 бит и 3 по 512: 6 + 3 пар
        assertEquals(9, comparedPairs, "обязаны сравниваться все пары кривых одной длины");
    }

    /**
     * Число {@code e} для i-го хэша набора: детерминировано, не меньше 2 и заведомо меньше порядка
     * любой кривой (250 бит при n &gt; 2²⁵⁴).
     */
    private static BigInteger commonEForCrossCurve(int index) {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) (i * 31 + index * 17 + 5);
        }
        return new BigInteger(1, seed).shiftRight(6).add(BigInteger.TWO);
    }
}
