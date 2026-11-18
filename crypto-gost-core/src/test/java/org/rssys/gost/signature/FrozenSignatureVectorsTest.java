package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Signature;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;

/**
 * Замороженные эталоны подписи ГОСТ Р 34.10-2012: пара (закрытый ключ, хэш) -> (r, s) на всех
 * семи кривых.
 *
 * <p>Нонс детерминирован, поэтому любое изменение выработки {@code k}, кодирования подписи или
 * порядка байт сразу даёт другие значения. Проверки свойств («подпись верна», «подпись
 * детерминирована») такую правку не замечают: подпись с иным {@code k} остаётся верной.
 * Значения пересчитаны для выработки {@code k} с идентификатором кривой в затравке независимой
 * реализацией ({@code NonceOracle} в {@code x-validation-tests/sign}, на BouncyCastle), а не
 * снимались с кода библиотеки: иначе ошибка привязки к кривой попала бы и в «замороженное».
 * Эталон проверен на прежней раскладке: без идентификатора он воспроизводит все прежние
 * значения (снятые на коммите 88f7929d) побайтно. Новые значения снимались поверх коммита
 * 51e2ed9c с изменением привязки к кривой. Значения, снятые до привязки, недействительны. Они
 * должны оставаться неизменными, пока выработка {@code k} не меняется сознательно.
 *
 * <p>Ключи: малый (≈88 бит, как в {@link DeterministicNonceTest}) и полноразмерный, построенный
 * детерминированно из последовательности байт. Хэши: последовательность {@code i·7 + 3} и все
 * байты 0xFF.
 */
@DisplayName("ECDSASigner: замороженные эталоны подписи на всех кривых")
class FrozenSignatureVectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    /** Эталоны одной кривой; порядок пар: (малый ключ, хэш 1), (малый, хэш 2), (полный, хэш 1), (полный, хэш 2). */
    private record Frozen(
            String curve,
            String smallKeyHash1R,
            String smallKeyHash1S,
            String smallKeyHash2R,
            String smallKeyHash2S,
            String fullKeyHash1R,
            String fullKeyHash1S,
            String fullKeyHash2R,
            String fullKeyHash2S,
            String apiSign,
            String apiSignHash) {}

    private static Stream<Frozen> vectors() {
        return Stream.of(
                // tc26a256
                new Frozen(
                        "tc26a256",
                        "3f8f67dd0d97114f85021fcd1e35a14b5257052eea01ffd930066e5495660f31",
                        "287cc141e111533ed8d7a9539b6ceafc5aff4379cedd51b551fb5fe328a82a58",
                        "2abc47a7eb2e6988627398ef336d4b2d8876db1e085b1cf2b7cab94bcee67ee7",
                        "27a11e8e57c3c090043525eca68537b0edcdba85cd37441540a9a2c7a970b8a6",
                        "38cafdd1432deb1610fa19b251292b4873c935d09b6415ad154d1b28c988faf6",
                        "183b411a4164cf42e03dc76030ee4ae5e0539b8ac3e2194da92e40d15466492e",
                        "280fc4a6b515f186b1775be99cfd21da27e7f6ff6485ce4dff389c250fc8072f",
                        "3b2fd183be5c9651a582d171d50bccc4af863642f581a1d125a7525c80415694",
                        "330020c3d8050c30b18cf1f9fd2e9b06393f64fb2df26dc9ea177c537d96fd7001cddc3f572d4d685c307c8e4be6fd66091d4e702ad77ced0b7e82f02d152633",
                        "183b411a4164cf42e03dc76030ee4ae5e0539b8ac3e2194da92e40d15466492e38cafdd1432deb1610fa19b251292b4873c935d09b6415ad154d1b28c988faf6"),
                // tc26a512
                new Frozen(
                        "tc26a512",
                        "795a83825ec7aa69227f6a3bcfd77c201df950743a8afe99759f120d8de3ddf18d63daafaf92dd0e977f4186707092305facefc20d14d8ee2a12c46b03b3362d",
                        "385cc7f1675a420732cd0db6ff00384b20257a04c0cdfbaf73f04439550afd07306bdde46c16ff41dbcd903e96dbbd508059dd98b18b7ce81e5bd8111cf9b0b9",
                        "9c3c86aea57df315299ab10e6482bdaeb579f6f4a795287a898628311a1146f8603cd6cd79e07e23600ea32453dc70f4efd698a862b88945cca299c494d53912",
                        "9b38e20482f9f4f03336d2976214f9a2b84e7f147c2a275d7145263b44bf8a7314b144ede3021468c7c6af55afdcd76019155e5f154a14bdab3eb34cffe4af50",
                        "d4d6eb37bc883ee84271ee39ea2ce6779af52dfee215bab4345fcf2ae3e2ca81480c6c1d5cb82567b4332519f1fb562eac01df788499994ee73f7c3fb030f034",
                        "e8bab99e576ea1e01dfdcbd9936b337af817f18d8c520a9e3a191bdb2f77af5fe2961c30496b288b8803abd864671be23fce33035f0855f196d882c0f90974d1",
                        "2f932efb5bf1c300daea59275b688c0957efc7888d1bd811fb3794a4a7ead23e240655a5c8a28fa79854d4d179dbfc10fbc3457c221070561dd7590a9e32a6a5",
                        "721dd9985db46a698dfd53f4ab72fcb452ccee751ae2d4eb42cc3b38d3a21d6ee88bb9794e160b396a7f69cba498e93015e04a5bce511bcdf8a0b883828a271c",
                        "651f2ff5e7f37c8a5856021a53c4c89fdfbfd51c744c1446a8e4f4b099d4279fff82499e5aef49bc1489d03b7aa9c67f9b0b2365527f2d4e74817a0bb7cf4aca1d4340c444ee4181e1c2efdd17e120f470937d30d3f19a72106830d657bdc3690059816ed3f04de8819c35cdb2c00234d16dc71a9b90bf1f4bd5bc78942a7308",
                        "e8bab99e576ea1e01dfdcbd9936b337af817f18d8c520a9e3a191bdb2f77af5fe2961c30496b288b8803abd864671be23fce33035f0855f196d882c0f90974d1d4d6eb37bc883ee84271ee39ea2ce6779af52dfee215bab4345fcf2ae3e2ca81480c6c1d5cb82567b4332519f1fb562eac01df788499994ee73f7c3fb030f034"),
                // tc26b512
                new Frozen(
                        "tc26b512",
                        "700b48cbcae862fd1cb0931d111212a2217e9deb6b73a022ee64465421f204122f44115ed1ea7b2422ffe43aaf8a70729f731c47390585574a1a812d8006eaaf",
                        "5c07d659e18344089ece19401faf093328ec8bba4f4616234ebc575efee8d3a6a1d4bf42afa33ea41a424db54c04c5acfd6311ee70fea6fadd7a889a53183e87",
                        "edf0dbb7a338bfb383e3371fa5e0e883347ae924e28694b8cd75b980c055082c0cdea75ee882aa192779b4bd97330f2174f47a1448ed3824c46b925c5422227",
                        "10076542170cf861203d70bffa1d826b64dad53dbb32cee60d71fc6fc872862f91b51838c3a42bcc53ec0453745be29b6ef8f9fb37e8a0af2c072324d16831f3",
                        "1f69040bbcc75d34017edc10d1d016d79fc3dfd00a286a005629b246644b84f89049edd63c76a914030a01326170d8407a7f8a3797ad92f5b62f0a404618dd07",
                        "5a4fb5c2350bf363afda4502a9659fe69a2a658974f4f84693ca20d20b0ea64b2ad005881dcc6ac29e2fd9b1fa2854dfd5160811cd0efc388370ed7911cb4460",
                        "53435af03483f6087cf137750c0f70956e21652c7f09c6d655ba2b2b096288e2c086eb4e9755e7555b229e84e03d384a768d16beac763f898662f0843f5b8210",
                        "1cc97d538fe1290d16d57faa0c38f3c8a37cddccf8641639f8cd419dac79d9ffa81c493f19afdfeeb577750faf39096a185091fbb9ac4ed774f0df6709eedb1c",
                        "59e23f07181011312d8fb65311d70fe5b24d9c11e2297a5686b56c7d3d7396322dc0eee8f3fc52517d0886d03aea0969b04a2f2ee296f6513a8ff826f282284e61e3d787af7da477373d05243408552e581d2ca8afcb952d4dc757614197562dc765fc43e5e3c162deea0a55a0c8e99a6cd964d19580a8a7114c5c79b39daf46",
                        "5a4fb5c2350bf363afda4502a9659fe69a2a658974f4f84693ca20d20b0ea64b2ad005881dcc6ac29e2fd9b1fa2854dfd5160811cd0efc388370ed7911cb44601f69040bbcc75d34017edc10d1d016d79fc3dfd00a286a005629b246644b84f89049edd63c76a914030a01326170d8407a7f8a3797ad92f5b62f0a404618dd07"),
                // tc26c512
                new Frozen(
                        "tc26c512",
                        "283868ae570fa552700ad2152e2efe14ff157f254d04218c16bb14008d5423dc43cf13e2d7492d248efc05c00ce2b6f33de85b356348b2d081ee33e1c1948e60",
                        "d1bca6c5186205c9262b20d7b69d8ec33c21372bb2bad3f4e50aadaf5fb50dd735136d387793c92c7b3067e6d9f4a97b61dcf621b58171c26ab4f56165a5dc5",
                        "382139860e030cab635b60c489c5ffca9d5f2940cc4502f20f79fbd9d8aaffac9c115f781fac8851e416255cf03c1841c1b855a8232a3344f7ffd9441d1c62e",
                        "396b6831ee587acb9d4101df251eefcd6217f04b784d061566d4729282a0f222036f702ee660273d5e31c9934710f48ee413e7c45e59c089113d2c6313af5a20",
                        "13036f97f6476a9ea4f24059c71857e1432b653cde8b8a9797f7dc010e53c2a3878057c9bbb82914bb570c8e6c09068f75e43736be54d95af01f644e6277fcfe",
                        "2852e57d597e7a324cc2c4befde1f2e19e392007b15f33a7f11758b72c15d800fa3251357dc0675a195881046d949e6b212843670783e6c4f35cab6331607fd3",
                        "b3452ebe535b504f2668979278eeb02df73b597dacfe8d15f7d7d6ed8edc0d9faff172c4cdb20ff555c4dfa0985f09cc9168ff645072a061e6a6dc9be2fbafd",
                        "1ebf119b3cbffb85d3240ffeba685b2888c1a00fc5746ba380bd714a0eb74149b2771e4443b1ce2c5b242b258a23518d5498d235cba16ce8356c4ec0e6a0be5c",
                        "2729df7b7728356ea3a07ae34ec5e143e110dbb8741a7b7db4b341bd06e290fd9068fa1dd9780a9ed1494225996a45b9c7f8159c558568c4ec31aaf68f158b9115a16e6891f4d29b098584b65404862ea44e04774a91543873f0e1280df5401a06df5cc38b887f4551c5a0ec4a28340f019bdda88de71a8bed97e3717533f36f",
                        "2852e57d597e7a324cc2c4befde1f2e19e392007b15f33a7f11758b72c15d800fa3251357dc0675a195881046d949e6b212843670783e6c4f35cab6331607fd313036f97f6476a9ea4f24059c71857e1432b653cde8b8a9797f7dc010e53c2a3878057c9bbb82914bb570c8e6c09068f75e43736be54d95af01f644e6277fcfe"),
                // cryptoProA
                new Frozen(
                        "cryptoProA",
                        "ca7dbc2542401c572789a0b4ace1140489935c0deedaa6f1f586bc13e16b54a9",
                        "c311eaefcd97189209b1837ee8ed6a9cc0e719121c3528772d0a30be36ef2c02",
                        "40e7a754b4fc0f005f4e4e064c865b6918042823c2f27cd9b89fd45eb1b6a69a",
                        "53f01e0d7b94fc406d76349f381c83e2e22a383b5f670b21e76cc089641042b8",
                        "25a31d31620db5807dbdbfa36d7dd599cb437d006a0013b0eeecd5b2a46a8b06",
                        "d4612779e535e70feb13202ffe8dd94f0b1672241589a81ddfa34c115d1ed334",
                        "574011497555b3c800721ddddaf0babe8b3cc540491e4b6d083bd3242d5c13ce",
                        "cf64db617c64754308a7ae7a1ae12ea880a5a750834595ca441c88105f394631",
                        "5398f80d06af16c8137a45a0844c918e8fcad3b0ff29dc378ef69fda3a0c7312b7d6d40b6b4e154ca6ac8b2b4d26abbd12b6560084ac8e481dfc50bf6768db43",
                        "d4612779e535e70feb13202ffe8dd94f0b1672241589a81ddfa34c115d1ed33425a31d31620db5807dbdbfa36d7dd599cb437d006a0013b0eeecd5b2a46a8b06"),
                // cryptoProB
                new Frozen(
                        "cryptoProB",
                        "4b56d894f1366ab005fadc0cfb7e572b0d0596f875a548ae0ceec12a253a3ee9",
                        "72814ec48a4a3318d5c87d1eeb23aa361afd1df95d9f06a4f3f4a131d4c49275",
                        "12110cfedc496cd5bb17f81ce7222b65aa7b0de394a3390f063ecc4fc9a6e57f",
                        "62dffdc23687d189249cdca07e47e833635f121223ffeb24a6a46f4e88338651",
                        "15c947c8064c9937c5f784f828eccd31e513864e8f1bfe5cfab54b127b52744c",
                        "3fc0fb69f7da4989cd572b33d31b67fb1c52f132e297a3a5bd3155d491a7e0d8",
                        "748d3341f1d654e75942d28b7d3d300f757b32e57229d36e3fdbd4e5a4e655c",
                        "1de7752e71ece15922c4fbc2a4d290ebc4c0e9492c86260c702a6e97a10c86b7",
                        "7568edfb888fe6364ec469caad9759a4d1e3efbe6e38bdc6693032cc9a082b325d94572c8ed2b49cd1f69170531d9de8a2560b7a29407dfab93dc039ff13bc18",
                        "3fc0fb69f7da4989cd572b33d31b67fb1c52f132e297a3a5bd3155d491a7e0d815c947c8064c9937c5f784f828eccd31e513864e8f1bfe5cfab54b127b52744c"),
                // cryptoProC
                new Frozen(
                        "cryptoProC",
                        "1eeb7824b2855b1ef4a4c5dbd0a6ae436ae411abc6e3e2a0349c38c89c770772",
                        "2e0905f8a239be2502bb796788dcc8f8370976b9672a2bbbfc1444bc37c950c",
                        "60721a9b79b3a57903a0416e3e14a9b1e537099d837660d0d5dc87ceb738ba38",
                        "58ddc64d1436a6dcb30e000856f1f94dbf299c9f143d346269429fe2a036c7d9",
                        "7cbdc75d45cf9eca0ec626519588a9e68e6a30aaa05b15c58cd218a443703de4",
                        "8510e97a979ad51760a0eb0a7a63bbde4047c45d1daf6699ca0402a5131a843e",
                        "716e88b7796d6792bea50c4888de81e6303fc39af2d12bce4051350169e57fcb",
                        "639cfc8a18e3fe9bf81611e4ba4504a6809526c150ccc7a5b9167c562ff74177",
                        "80e430c7e4d2ae26e700378f0610c70fa0c22c5e72e4c00af778d90f3901b5c87bd05f42fafc4a997a41b899209e97743d31b402226ab921300e8d67798041ce",
                        "8510e97a979ad51760a0eb0a7a63bbde4047c45d1daf6699ca0402a5131a843e7cbdc75d45cf9eca0ec626519588a9e68e6a30aaa05b15c58cd218a443703de4"));
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

    private static byte[] pattern(int length, int multiplier, int addend) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i * multiplier + addend);
        }
        return bytes;
    }

    /** Малый ключ: тот же, что в {@link DeterministicNonceTest}. */
    private static BigInteger smallKey() {
        return BigInteger.valueOf(0xC0FFEE).shiftLeft(64).add(BigInteger.valueOf(0x1234567));
    }

    /** Полноразмерный ключ в диапазоне [1, n-1], построенный детерминированно. */
    private static BigInteger fullKey(ECParameters params) {
        int rolen = (params.n.bitLength() + 7) / 8;
        return new BigInteger(1, pattern(rolen, 13, 5))
                .mod(params.n.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);
    }

    private static BigInteger[] sign(ECParameters params, BigInteger d, byte[] hash) {
        ECDSASigner signer = new ECDSASigner(digestFactory(params), NonceMode.DETERMINISTIC, null);
        signer.init(true, new PrivateKeyParameters(d, params));
        try {
            return signer.generateSignature(hash);
        } finally {
            signer.destroy();
        }
    }

    private static void assertSignature(
            String message, BigInteger[] actual, String expectedR, String expectedS) {
        assertEquals(new BigInteger(expectedR, 16), actual[0], message + ": r");
        assertEquals(new BigInteger(expectedS, 16), actual[1], message + ": s");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("ECDSASigner.generateSignature даёт замороженные (r, s)")
    void rawSignatureMatchesFrozenValues(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash1 = pattern(params.hlen, 7, 3);
        byte[] hash2 = new byte[params.hlen];
        Arrays.fill(hash2, (byte) 0xFF);

        assertSignature(
                "малый ключ, хэш 1",
                sign(params, smallKey(), hash1),
                frozen.smallKeyHash1R(),
                frozen.smallKeyHash1S());
        assertSignature(
                "малый ключ, хэш 2",
                sign(params, smallKey(), hash2),
                frozen.smallKeyHash2R(),
                frozen.smallKeyHash2S());
        assertSignature(
                "полный ключ, хэш 1",
                sign(params, fullKey(params), hash1),
                frozen.fullKeyHash1R(),
                frozen.fullKeyHash1S());
        assertSignature(
                "полный ключ, хэш 2",
                sign(params, fullKey(params), hash2),
                frozen.fullKeyHash2R(),
                frozen.fullKeyHash2S());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName(
            "Подписи, выработанные детерминированно до смены умолчания, проверяются штатными путями")
    void frozenSignaturesVerifyUnderDefaultPaths(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        byte[] hash1 = pattern(params.hlen, 7, 3);
        PrivateKeyParameters key = new PrivateKeyParameters(fullKey(params), params);
        PublicKeyParameters pub = key.derivePublicKey();
        BigInteger r = new BigInteger(frozen.fullKeyHash1R(), 16);
        BigInteger s = new BigInteger(frozen.fullKeyHash1S(), 16);

        // Проверка от нонса не зависит: подпись старой раскладки остаётся верной после смены
        // умолчания (ECDSASigner без режима и фасад Signature идут по умолчанию)
        ECDSASigner verifier = new ECDSASigner(digestFactory(params));
        verifier.init(false, pub);
        assertTrue(verifier.verifySignature(hash1, r, s), "ECDSASigner: прежняя подпись неверна");
        assertTrue(
                Signature.verifyHash(hash1, SignatureCodec.encode(r, s, params), pub),
                "Signature.verifyHash: прежняя подпись неверна");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    @DisplayName("Signature.sign и Signature.signHash дают замороженную подпись (s ∥ r)")
    void publicApiSignatureMatchesFrozenValues(Frozen frozen) {
        ECParameters params = curveByName(frozen.curve());
        PrivateKeyParameters key = new PrivateKeyParameters(fullKey(params), params);
        byte[] message = "frozen-vector-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertEquals(
                frozen.apiSign(),
                HEX.formatHex(Signature.sign(message, key, NonceMode.DETERMINISTIC)),
                "Signature.sign: подпись изменилась");
        assertEquals(
                frozen.apiSignHash(),
                HEX.formatHex(
                        Signature.signHash(
                                pattern(params.hlen, 7, 3), key, NonceMode.DETERMINISTIC)),
                "Signature.signHash: подпись изменилась");
    }
}
