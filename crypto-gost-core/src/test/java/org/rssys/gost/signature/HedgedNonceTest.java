package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.util.Pack;

/**
 * Гибридный нонс ({@link NonceMode#HEDGED}): раскладка с добавкой {@code Z}, отличие от
 * детерминированного режима, поведение при отказе источника случайности и затирание {@code Z}.
 *
 * <p>Добавка {@code Z} подаётся через пакетный шов {@code NoiseSource}. Замороженные значения
 * сняты с независимой реализации ({@code NonceOracle} в {@code x-validation-tests/sign}, на
 * BouncyCastle), а не с кода библиотеки: иначе ошибка раскладки (порядок полей, дополнение
 * нулями) попала бы и в «замороженное». Побайтную сверку с эталоном через публичный конструктор
 * делает {@code HedgedNonceCrossValidationTest}.
 */
@DisplayName("ECDSASigner: гибридный нонс (Z, дополнение нулями, затирание, отказ источника)")
class HedgedNonceTest {

    /** Значения для ключей и хэшей из {@code FrozenSignatureVectorsTest}, Z = pattern(rolen, 11, 9). */
    private record Frozen(
            String curve,
            String smallKeyHash1R,
            String smallKeyHash1S,
            String smallKeyHash2R,
            String smallKeyHash2S,
            String fullKeyHash1R,
            String fullKeyHash1S,
            String fullKeyHash2R,
            String fullKeyHash2S) {}

    private static Stream<Frozen> vectors() {
        return Stream.of(
                new Frozen(
                        "tc26a256",
                        "16fd07a9fcbd5715e5dfdff6a1dd5308e15ccdd2ba5c11a1087333a8be340a0b",
                        "3f90c74b4b1c8bb6da93a7dc3c5ea8adfb776a2384def0b0739f66e5f03f34da",
                        "2b09a8b7cce91b2d43dbf7280113a074e4cba5338d3569a8639c376aae5c0878",
                        "4b31f80ae71e94ac31390043d52603662563808c8127d6747833d44fc849186",
                        "1c0205560b01a2be670299ddc5d20fc28332a345b5c9c22ffcc765330bf50ae9",
                        "238eadba80614c786f528ab674c101c402112d2ba3efda6b1b113b8665fdf4aa",
                        "1b8ee4b137d2fcaff86a3781fd08d200df49f1863c61f6f3f6073d58e97bcffd",
                        "3a29d6ee2a1568ae7f9bf49cfb8af8733f2762dffe6439bf33661cac80e5f59d"),
                new Frozen(
                        "tc26a512",
                        "d21fd36dc15e8e55032d853d00f274603e60667cae678d84863c65a86574249bd2f9e7bfb86a207b5425ed672d817d889b0cbc9e22785d68cdcf28d9df3759b3",
                        "480192d821ec1e60e4d255532ff0c5be21584242b068f7baff6211fdb2be41cf5b995752f4dbab32cdc950d85e4319734568f053b0b4ff7d0ab42fe9c707b4a",
                        "5fce59d6e49497a66187c604d76946181049c7031aba962490e7b02cb13ae494be3ff53121630874a405a049bc589435aff113b0790f44f5c045bde8c27da17c",
                        "db79026fa82aa270348eec0752ce5ff55f741b79e0de3d0820217f0c72525090f245b759d4da1e20599f5533425a20d17faf3a7225c8863e8d4e7de40188bd4a",
                        "5ec327b4c404c1164fc5dc0a67ce6ce0f7f6c07596fc0916371f1dab949a5587db0faba01ab30f3ea9c5969e7f2b51c9e1de98a873f76bdd9a901e03ba6422af",
                        "24f67a9b02c345bfe77a0ccbdadb3fadc8c8e3d96dbaa59744a04f29b2c4c059344c5629d3f7c8dadd252e1d7a85ba0d9d6e622c5d2fbe980519433541e0b2d8",
                        "dc4ae21f5ab0ea797cfa07883c737c3da1937f200abb1611b2f453f4103b1cc48b37d7cbadacf5ca30665060724745022f3cf370d12708a5bc083ea82d7a236e",
                        "eabe6943b4469eb6540109a942efe8e6f814742d3f0d044ba4733491c06660272a539a9455cd7f88ab3f1529ad1bc9d3575ae939a9b2a28e9f29c5b1093969bd"),
                new Frozen(
                        "tc26b512",
                        "236add6fe4b74b09f3cd439d0272b2ea851cb931a74978b23deae265bf0ce8a893a7532d1102ec124bdf233879bfbf95292d63d9430ede0f5bab3eac41afa0d2",
                        "14b2578220488b4f75e752cd0bd4829cf50e50a0bc817e0785f1beede3f845c98370c4b9b45aa55b2848ab8bf389ef3c1d0f0591964c4a5ddfd66a5cd05fe594",
                        "2706a9e44375a6734c1c9e845c525c5989b69550ef2d9a34640f9b6f96cf294093f94608cf08d3546113a418cb8d8084f031989af6a81d6d686aee4733213f94",
                        "6c52198598537e3962257aa859baaf8f1a553d34dc6aebb9d68a196bb57a6f33a2061e30b5569d2d6cb967995b17606c6b5601d8a1642d9efe5607cf871d2cac",
                        "6f7a89b10293518ea98f63650a085b38231447a0bfb85ea8710cff3ca49656ac6467dd8d1570939027a6eb77edc19ce62e9412e181d93195ae1a419faf1d2cae",
                        "5648e1952afbfd01234a618a45fdae71ce5cde5566722223247bfa5835e4796ea1b524ef4ec0920c933fbe424b8027d3f5fd4e19d7187182cc4e17b99f449afd",
                        "4a50c1b05236b7ed53330aface0676589b57598df789d477831edf4bce068c34891c84cb6146aec8aee1dffdd2a50a3e497e7b544256f4505eb2e664e8d392da",
                        "14a5e6284a161b93f312c096cbc995a8af2513c99b1e04316152f057b0e85745e7f5d74b38be894628e40207ffceb61485009e3e5f79392bb215d191a071964b"),
                new Frozen(
                        "tc26c512",
                        "1cda917910c870a9310907c1d720fa67975d6c7e3f3ef22858760b947ff080a10bc124106a13cc4eb6c29a604fa42abc5bf52acd14685432903acb7fdd656299",
                        "1e902db63fe380b900f939a34a578621fa6e53c812913f5ef79ff395f803e75196f135a1a15661f90ccf5e8b3848b70cc4ca666856bb0cf9e989f51f9e9bd14",
                        "6615f04cbf8f9c85a71f379b42e2e048871f227a77d341020ed8e56643bb995e5f8a72c5e8afb4c39da808fe213f33d933d78f5f4fe1c7b33c1ecb3203218bd",
                        "3621645b6d94e88854a9774990ab0fd5340e5821426e276b7687a4017fa5fc179abc324eae534c171c8d22256bb4a7974a0299d11f300740f3c12f59126e818b",
                        "89f2876b61c8cca90620cc88cdc90c9015203d089fc45a0db59c74df07e67dca2d3d065b992dc2d3d56523be33c7e3df5771a24b6c32dfa79c464e536d8b932",
                        "153d6481f3d426d5041c7dbbc17f7e46962ffbfbb7bccaadb36258d0456b21620319c83316ab4e015201b1c85140b29f01b1e9a4cf1236613c8d690cab7a41ff",
                        "3e7573bafd53cd6e519024a8630808edbbee0e7901d2484718550e6306c532b80b30a43ec274a59dc5e8aba8380ae1f330288462f6c327bef10a40308193f53",
                        "ccbc1b2af092f96f9f54bce68170e7be916a61041005552e303fbf14a97bffbfdbbcfb6be2a199038041afb53ff63605446e268fbf73c06e4e5d39b606c4d07"),
                new Frozen(
                        "cryptoProA",
                        "28465c0ecc8caf5fba79b241b7c334452365fa9fb4f0b2e36b2b31a05d33724a",
                        "4580e5291f21e572eb8b2cd3bad77570983bea8f1a2b674baaca639804f75128",
                        "3cfe9adc4b106bbd31edada2c548ea4a21faa3b6ef19f8a09199152be94feb19",
                        "2a1ac8900a99f69b3b6bbc68db977901f4caeb754587b68c5a2860db7cfb8a22",
                        "6f1f9f7a30d9b9c8608a8ee287d34c38be839aeeead27a915bc81debf96cd736",
                        "62c3bf20e7ebc6982b987406fc60d972ab27d004624ef7c223ad190dabd8085d",
                        "3db88a50c1f314674ae1be4ff34d7578d1c076498ff7cca0b257722498be437c",
                        "197458dac58b94d90a36a97773499ccac001fcbc1e2330a4c8f3e07f23eaf5d8"),
                new Frozen(
                        "cryptoProB",
                        "314546f343b5472d92175931f90d730b4b9ccbd81b8282aac8ed83e32e3707ac",
                        "5f36ac98248e99385d3758c576132f59a2fa231c932a4df659585e9351667fe9",
                        "26d5b547686c95c174cb9f09e3d7a9986cffdbf98559257724bbdfd304c18950",
                        "30a787f66cd57e8a9d772ca44e4c105a84197dcb1b18a0fe461c41fda2d99f50",
                        "1e199fa064e07b8fbd817c02109435eddd32b91dced088b27d3f0323d177b93e",
                        "50df4ef6cbba994507906ae3cddffb26e980ab70c349c11c673d226f857b5a9f",
                        "70ae653870b196ca1d65be1e3b2eb6dfb632b1f6e46f607d2f89889495543bec",
                        "5a5c18c3407655c7975de58a13ef078601948b03efb314152ea10c60d16b6d20"),
                new Frozen(
                        "cryptoProC",
                        "1b6a719cd4e722e58f007d5ed159c5502db1d647d67b1f7ba8df0f39850a5aa6",
                        "964de91559fd172b646a85535f83ead83781c979d026866baa1167ec6d7aa4c4",
                        "581196f23039ead584a81d9c478bdbdca56eae47e98c5734074f002698008e09",
                        "9bfd4ec9d026b99be08c791b87126af54ba2fb589449dc5d895304ca4c159c4",
                        "490622593589cb137eb43d9c50e9db7dbd0a28d698d20f3409109afeb7d93eaa",
                        "17cd5c99a9de09f77ed31b9dac96a06abee317bc7ce3713829a7945c1c9777c8",
                        "40aa48fdba441b56a894d1f549beb03435dd353c6c4c82f44cfccc8a906054b",
                        "701db3c5d5804b88cd08daea27bcd0c4337ef7cc39def6b00d7b1daabda598c2"));
    }

    private static List<ECParameters> allCurves() {
        return List.of(
                ECParameters.tc26a256(),
                ECParameters.cryptoProA(),
                ECParameters.cryptoProB(),
                ECParameters.cryptoProC(),
                ECParameters.tc26a512(),
                ECParameters.tc26b512(),
                ECParameters.tc26c512());
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

    private static Supplier<Digest> digestFactory(ECParameters params) {
        return params.hlen == Streebog256.DIGEST_SIZE ? Streebog256::new : Streebog512::new;
    }

    private static int rolen(ECParameters params) {
        return (params.n.bitLength() + 7) / 8;
    }

    private static byte[] pattern(int length, int multiplier, int addend) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i * multiplier + addend);
        }
        return bytes;
    }

    private static BigInteger smallKey() {
        return BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567));
    }

    private static BigInteger fullKey(ECParameters params) {
        return new BigInteger(1, pattern(rolen(params), 13, 5))
                .mod(params.n.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);
    }

    /** Источник добавки, отдающий заданные байты и считающий обращения. */
    private static final class FixedNoise implements NoiseSource {
        private final byte[] bytes;
        final AtomicInteger calls = new AtomicInteger();
        byte[] lastRequested;

        FixedNoise(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public void fill(byte[] out) {
            calls.incrementAndGet();
            lastRequested = out;
            assertEquals(bytes.length, out.length, "запрошена добавка Z неожиданной длины");
            System.arraycopy(bytes, 0, out, 0, out.length);
        }
    }

    private static BigInteger[] sign(
            ECDSASigner signer, ECParameters params, BigInteger d, byte[] hash) {
        signer.init(true, new PrivateKeyParameters(d, params));
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    private static BigInteger[] hedgedSign(
            ECParameters params, BigInteger d, byte[] hash, NoiseSource noise) {
        return sign(
                ECDSASigner.withNoiseSource(digestFactory(params), NonceMode.HEDGED, noise),
                params,
                d,
                hash);
    }

    private static BigInteger[] deterministicSign(ECParameters params, BigInteger d, byte[] hash) {
        return sign(
                new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null),
                params,
                d,
                hash);
    }

    private static void assertSignature(
            String message, BigInteger[] actual, String expectedR, String expectedS) {
        assertEquals(new BigInteger(expectedR, 16), actual[0], message + ": r");
        assertEquals(new BigInteger(expectedS, 16), actual[1], message + ": s");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Гибридная подпись с фиксированным Z даёт замороженные (r, s) эталона")
    void hedgedSignatureMatchesFrozenValues(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash1 = pattern(params.hlen, 7, 3);
        byte[] hash2 = new byte[params.hlen];
        Arrays.fill(hash2, (byte) 0xFF);
        byte[] z = pattern(rolen(params), 11, 9);

        assertSignature(
                "малый ключ, хэш 1",
                hedgedSign(params, smallKey(), hash1, new FixedNoise(z)),
                frozen.smallKeyHash1R(),
                frozen.smallKeyHash1S());
        assertSignature(
                "малый ключ, хэш 2",
                hedgedSign(params, smallKey(), hash2, new FixedNoise(z)),
                frozen.smallKeyHash2R(),
                frozen.smallKeyHash2S());
        assertSignature(
                "полный ключ, хэш 1",
                hedgedSign(params, fullKey(params), hash1, new FixedNoise(z)),
                frozen.fullKeyHash1R(),
                frozen.fullKeyHash1S());
        assertSignature(
                "полный ключ, хэш 2",
                hedgedSign(params, fullKey(params), hash2, new FixedNoise(z)),
                frozen.fullKeyHash2R(),
                frozen.fullKeyHash2S());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Гибрид с фиксированным Z не совпадает с детерминированным режимом")
    void hedgedDiffersFromDeterministic(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash = pattern(params.hlen, 7, 3);
        byte[] z = pattern(rolen(params), 11, 9);

        BigInteger[] hedged = hedgedSign(params, smallKey(), hash, new FixedNoise(z));
        BigInteger[] deterministic = deterministicSign(params, smallKey(), hash);

        assertNotEquals(
                deterministic[0],
                hedged[0],
                "гибридная ветка ничем не отличается от детерминированной: Z не используется");
    }

    /** Число e для i-го хэша: меньше порядка любой кривой, поэтому читается одинаково. */
    private static BigInteger commonE(int index) {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) (i * 31 + index * 17 + 5);
        }
        return new BigInteger(1, seed).shiftRight(6).add(BigInteger.TWO);
    }

    private static byte[] hashWithLittleEndianValue(BigInteger value, int hlen) {
        return Pack.reverseBytes(Pack.toFixedLengthBigEndian(value, hlen));
    }

    private static BigInteger recoverK(
            BigInteger d, BigInteger e, BigInteger[] sig, ECParameters params) {
        BigInteger n = params.n;
        return sig[1].subtract(sig[0].multiply(d)).multiply(e.modInverse(n)).mod(n);
    }

    @Test
    @DisplayName(
            "Гибрид с одним Z: один d и равное e на двух кривых одной длины дают разный k (привязка к кривой)")
    void sameKeyAndSameZOnTwoCurvesGiveDifferentNonces() {
        List<ECParameters> curves = allCurves();
        BigInteger d = smallKey();
        int comparedPairs = 0;
        for (int first = 0; first < curves.size(); first++) {
            for (int second = first + 1; second < curves.size(); second++) {
                ECParameters a = curves.get(first);
                ECParameters b = curves.get(second);
                if (a.hlen != b.hlen) {
                    continue;
                }
                // Один и тот же Z на обеих кривых: иначе различие k объяснялось бы разным Z, а не
                // привязкой к кривой
                byte[] z = pattern(rolen(a), 11, 9);
                for (int i = 0; i < 30; i++) {
                    BigInteger e = commonE(i);
                    byte[] hash = hashWithLittleEndianValue(e, a.hlen);
                    BigInteger[] sigA = hedgedSign(a, d, hash, new FixedNoise(z));
                    BigInteger[] sigB = hedgedSign(b, d, hash, new FixedNoise(z));
                    assertNotEquals(
                            recoverK(d, e, sigA, a),
                            recoverK(d, e, sigB, b),
                            "в гибридном режиме привязка к кривой потеряна (хэш " + i + ")");
                }
                comparedPairs++;
            }
        }
        assertEquals(9, comparedPairs, "обязаны сравниваться все пары кривых одной длины");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Гибрид: хэши с e = 0, n, n + 1 дают e = 1 и побайтно равные подписи при равном Z")
    void hashesWithSameReducedEGiveSameHedgedSignature(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] z = pattern(rolen(params), 11, 9);
        BigInteger[] reference =
                hedgedSign(
                        params,
                        smallKey(),
                        hashWithLittleEndianValue(BigInteger.ONE, params.hlen),
                        new FixedNoise(z));
        for (BigInteger e : List.of(BigInteger.ZERO, params.n, params.n.add(BigInteger.ONE))) {
            BigInteger[] sig =
                    hedgedSign(
                            params,
                            smallKey(),
                            hashWithLittleEndianValue(e, params.hlen),
                            new FixedNoise(z));
            assertEquals(reference[0], sig[0], "r при e, сведённом к 1");
            assertEquals(reference[1], sig[1], "s при e, сведённом к 1");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Две гибридные подписи одного хэша со штатным датчиком различаются и обе верны")
    void twoHedgedSignaturesOfSameHashDiffer(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash = pattern(params.hlen, 7, 3);
        BigInteger d = fullKey(params);
        PrivateKeyParameters key = new PrivateKeyParameters(d, params);

        BigInteger[] first =
                sign(
                        new ECDSASigner(digestFactory(params), NonceMode.HEDGED, null),
                        params,
                        d,
                        hash);
        BigInteger[] second =
                sign(
                        new ECDSASigner(digestFactory(params), NonceMode.HEDGED, null),
                        params,
                        d,
                        hash);

        assertNotEquals(first[0], second[0], "две гибридные подписи одного хэша совпали");
        for (BigInteger[] sig : List.of(first, second)) {
            ECDSASigner verifier =
                    new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
            verifier.init(false, key.derivePublicKey());
            assertTrue(
                    verifier.verifySignature(hash, sig[0], sig[1]),
                    "гибридная подпись обязана проверяться");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName(
            "Конструктор без режима гибридный: повторная подпись того же хэша другая, обе верны")
    void defaultConstructorIsHedged(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash = pattern(params.hlen, 7, 3);
        BigInteger d = fullKey(params);
        PrivateKeyParameters key = new PrivateKeyParameters(d, params);

        BigInteger[] first = sign(new ECDSASigner(digestFactory(params)), params, d, hash);
        BigInteger[] second = sign(new ECDSASigner(digestFactory(params)), params, d, hash);

        assertNotEquals(first[0], second[0], "конструктор без режима дал одинаковые подписи");
        for (BigInteger[] sig : List.of(first, second)) {
            ECDSASigner verifier = new ECDSASigner(digestFactory(params));
            verifier.init(false, key.derivePublicKey());
            assertTrue(verifier.verifySignature(hash, sig[0], sig[1]), "подпись неверна");
        }
    }

    @Test
    @DisplayName("Детерминированный режим не обращается к источнику случайности вообще")
    void deterministicModeNeverTouchesNoise() {
        ECParameters params = ECParameters.tc26a256();
        FixedNoise noise = new FixedNoise(pattern(rolen(params), 11, 9));
        ECDSASigner signer =
                ECDSASigner.withNoiseSource(digestFactory(params), NonceMode.DETERMINISTIC, noise);
        BigInteger[] sig = sign(signer, params, smallKey(), pattern(params.hlen, 7, 3));

        assertEquals(0, noise.calls.get(), "детерминированная ветка вызвала источник");
        assertArrayEquals(
                deterministicSign(params, smallKey(), pattern(params.hlen, 7, 3)),
                sig,
                "подпись детерминированного режима изменилась");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName(
            "Публичный конструктор с DETERMINISTIC даёт те же (r, s), что конструктор без режима, и не вызывает датчик")
    void deterministicModeOfPublicConstructorIgnoresRandom(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        AtomicInteger calls = new AtomicInteger();
        // Подкласс SecureRandom нужен только затем, чтобы подсчитать обращения: настоящий датчик
        // в детерминированном режиме трогать нельзя
        SecureRandom counting =
                new SecureRandom() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public void nextBytes(byte[] bytes) {
                        calls.incrementAndGet();
                        throw new AssertionError("датчик вызван в детерминированном режиме");
                    }
                };

        for (byte[] hash : List.of(pattern(params.hlen, 7, 3), new byte[params.hlen])) {
            BigInteger[] explicitMode =
                    sign(
                            new ECDSASigner(
                                    digestFactory(params), NonceMode.DETERMINISTIC, counting),
                            params,
                            fullKey(params),
                            hash);
            BigInteger[] defaultMode = deterministicSign(params, fullKey(params), hash);
            assertArrayEquals(
                    defaultMode,
                    explicitMode,
                    "явный DETERMINISTIC дал подпись, отличную от конструктора без режима");
        }
        assertEquals(0, calls.get(), "переданный датчик вызван в детерминированном режиме");
    }

    @Test
    @DisplayName("Гибридный режим запрашивает ровно rolen байт один раз и затирает Z после подписи")
    void hedgedRequestsRolenBytesOnceAndWipesThem() {
        for (ECParameters params : allCurves()) {
            FixedNoise noise = new FixedNoise(pattern(rolen(params), 11, 9));
            hedgedSign(params, smallKey(), pattern(params.hlen, 7, 3), noise);

            assertEquals(1, noise.calls.get(), params.hlen + ": источник вызван не один раз");
            assertEquals(rolen(params), noise.lastRequested.length, "запрошено не rolen байт");
            assertArrayEquals(
                    new byte[rolen(params)], noise.lastRequested, "Z не затёрт после подписи");
        }
    }

    @Test
    @DisplayName("Отказ источника: подписи нет, Z затёрт, отката на детерминизм нет")
    void noiseFailureProducesNoSignatureAndWipesZ() {
        ECParameters params = ECParameters.tc26a256();
        byte[][] captured = new byte[1][];
        NoiseSource failing =
                out -> {
                    captured[0] = out;
                    // Заполнено лишь частично, затем сбой: уже записанная часть обязана быть
                    // затёрта
                    Arrays.fill(out, 0, out.length / 2, (byte) 0x5A);
                    throw new IllegalStateException("датчик отказал");
                };
        ECDSASigner signer =
                ECDSASigner.withNoiseSource(digestFactory(params), NonceMode.HEDGED, failing);
        signer.init(true, new PrivateKeyParameters(smallKey(), params));
        try {
            assertThrows(
                    IllegalStateException.class,
                    () -> signer.generateSignature(pattern(params.hlen, 7, 3)),
                    "при отказе источника подпись выдаваться не должна");
        } finally {
            signer.destroy();
        }
        assertArrayEquals(
                new byte[rolen(params)], captured[0], "Z остался в памяти после отказа источника");
    }

    @Test
    @DisplayName("Режим не может быть null; null вместо датчика даёт штатный CryptoRandom")
    void constructorArguments() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ECDSASigner(Streebog256::new, null, null),
                "режим null обязан отвергаться");
        ECParameters params = ECParameters.tc26a256();
        BigInteger[] sig =
                sign(
                        new ECDSASigner(Streebog256::new, NonceMode.HEDGED, null),
                        params,
                        smallKey(),
                        pattern(params.hlen, 7, 3));
        assertTrue(sig[0].signum() > 0, "гибридная подпись со штатным датчиком выработана");
    }
}
