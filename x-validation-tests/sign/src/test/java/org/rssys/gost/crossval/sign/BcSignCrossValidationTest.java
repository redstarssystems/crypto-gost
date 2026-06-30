package org.rssys.gost.crossval.sign;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.api.Signature;
import org.rssys.gost.crossval.util.CrossValAssertions;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Кросс-валидация подписи ГОСТ Р 34.10-2012: crypto-gost vs BouncyCastle.
 *
 * Для каждой кривой (7 кривых):
 * — направление 1: crypto-gost подписывает -> BC верифицирует (100 сообщений);
 * — направление 2: BC подписывает -> crypto-gost верифицирует (100 сообщений);
 * — tamper-тест: испорченная подпись отклоняется обеими библиотеками.
 */
class BcSignCrossValidationTest {
    private static byte[][] messages;
    private static final Map<TestData.CurveSpec, CurveCtx> ctx = new HashMap<>();

    private record CurveCtx(ECDomainParameters bcDomain, ECPrivateKeyParameters bcPriv,
                            ECPublicKeyParameters bcPub, PrivateKeyParameters gostPriv,
                            PublicKeyParameters gostPub) {}

    @BeforeAll
    static void setUp() {
        messages = generateMessages();
        for (TestData.CurveSpec spec : TestData.CURVES) {
            ECParameters params = spec.paramsFn().get();
            KeyPair pair = KeyGenerator.generateKeyPair(params);
            ECDomainParameters bcDomain = BcSignHelper.buildBcDomain(params);
            ECPrivateKeyParameters bcPriv = BcSignHelper.toBcPrivKey(pair.getPrivate(), bcDomain);
            ECPublicKeyParameters bcPub = BcSignHelper.toBcPubKey(pair.getPublic(), bcDomain);
            ctx.put(spec, new CurveCtx(bcDomain, bcPriv, bcPub,
                    pair.getPrivate(), pair.getPublic()));
        }
    }

    static Stream<TestData.CurveSpec> curveParams() {
        return Stream.of(TestData.CURVES);
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC dir1: crypto-gost подписывает -> BC верифицирует")
    void crossValidateDir1(TestData.CurveSpec spec) {
        CurveCtx c = ctx.get(spec);
        CrossValAssertions.assertForEachMessage(messages, (msg, i) -> {
            assertTrue(BcSignHelper.bcVerify(msg, Signature.sign(msg, c.gostPriv), c.bcPub, spec.rolen()),
                spec.name() + ": crypto-gost подписал, BC не верифицировал msg[" + i + "]");
        });
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC dir2: BC подписывает -> crypto-gost верифицирует")
    void crossValidateDir2(TestData.CurveSpec spec) {
        CurveCtx c = ctx.get(spec);
        CrossValAssertions.assertForEachMessage(messages, (msg, i) -> {
            assertTrue(Signature.verify(msg, BcSignHelper.bcSign(msg, c.bcPriv, spec.rolen()), c.gostPub),
                spec.name() + ": BC подписал, crypto-gost не верифицировал msg[" + i + "]");
        });
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC tamper: испорченная подпись отклоняется обеими библиотеками")
    void crossValidateTamper(TestData.CurveSpec spec) {
        CurveCtx c = ctx.get(spec);
        CrossValAssertions.assertForEachMessage(messages, (msg, i) -> {
            byte[] gostSig = Signature.sign(msg, c.gostPriv);
            byte[] tampered = gostSig.clone();
            tampered[0] ^= 0x01;
            assertFalse(BcSignHelper.bcVerify(msg, tampered, c.bcPub, spec.rolen()),
                    spec.name() + ": BC принял испорченную подпись crypto-gost msg[" + i + "]");
        });
        CrossValAssertions.assertForEachMessage(messages, (msg, i) -> {
            byte[] bcSig = BcSignHelper.bcSign(msg, c.bcPriv, spec.rolen());
            byte[] tampered = bcSig.clone();
            tampered[0] ^= 0x01;
            assertFalse(Signature.verify(msg, tampered, c.gostPub),
                    spec.name() + ": crypto-gost принял испорченную подпись BC msg[" + i + "]");
        });
    }

    private static byte[][] generateMessages() {
        return TestData.randomMessages(TestData.NUM_MESSAGES, TestData.MSG_SIZE);
    }
}
