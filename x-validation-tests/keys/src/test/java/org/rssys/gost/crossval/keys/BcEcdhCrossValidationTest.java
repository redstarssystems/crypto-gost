package org.rssys.gost.crossval.keys;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyAgreement;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import org.rssys.gost.util.CryptoRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация ECDH между crypto-gost и BouncyCastle.
 * <p>
 * Для каждой кривой — три сценария. BC всегда доступен, precondition не требуется.
 */
class BcEcdhCrossValidationTest {

    static Stream<TestData.CurveSpec> curveParams() {
        return Stream.of(TestData.CURVES);
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("crypto-gost обе стороны: {0}")
    void crossValidateGostBoth(TestData.CurveSpec spec) {
        ECParameters params = spec.paramsFn().get();
        KeyPair pairA = KeyGenerator.generateKeyPair(params);
        KeyPair pairB = KeyGenerator.generateKeyPair(params);
        try {
            byte[] ab = KeyAgreement.computeSharedSecret(pairA.getPrivate(), pairB.getPublic());
            byte[] ba = KeyAgreement.computeSharedSecret(pairB.getPrivate(), pairA.getPublic());

            assertArrayEquals(ab, ba,
                    () -> spec.name() + ": симметричность crypto-gost нарушена\n"
                            + CrossValUtils.diffContext(ab, ba));
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC обе стороны: {0}")
    void crossValidateBcBoth(TestData.CurveSpec spec) {
        ECParameters params = spec.paramsFn().get();
        ECDomainParameters domain = BcKeyHelper.buildBcDomain(params);

        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain, CryptoRandom.INSTANCE));
        AsymmetricCipherKeyPair bcA = gen.generateKeyPair();
        AsymmetricCipherKeyPair bcB = gen.generateKeyPair();

        byte[] ab = bcAgree((ECPrivateKeyParameters) bcA.getPrivate(),
                (ECPublicKeyParameters) bcB.getPublic(), params.hlen);
        byte[] ba = bcAgree((ECPrivateKeyParameters) bcB.getPrivate(),
                (ECPublicKeyParameters) bcA.getPublic(), params.hlen);

        assertArrayEquals(ab, ba,
                () -> spec.name() + ": симметричность BC нарушена\n"
                        + CrossValUtils.diffContext(ab, ba));
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("crypto-gost × BC: {0}")
    void crossValidateMixed(TestData.CurveSpec spec) {
        ECParameters params = spec.paramsFn().get();
        KeyPair gostA = KeyGenerator.generateKeyPair(params);
        ECDomainParameters domain = BcKeyHelper.buildBcDomain(params);

        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain, CryptoRandom.INSTANCE));
        AsymmetricCipherKeyPair bcB = gen.generateKeyPair();
        ECPrivateKeyParameters bcPrivB = (ECPrivateKeyParameters) bcB.getPrivate();
        ECPublicKeyParameters bcPubB = (ECPublicKeyParameters) bcB.getPublic();

        // BC ключи -> crypto-gost
        PrivateKeyParameters gostPrivB = new PrivateKeyParameters(bcPrivB.getD(), params);
        PublicKeyParameters gostPubB = new PublicKeyParameters(
                ECPoint.affine(bcPubB.getQ().getXCoord().toBigInteger(),
                        bcPubB.getQ().getYCoord().toBigInteger(), params),
                params);
        try {
            // crypto-gost priv A × pub B (BC-derived)
            byte[] gostAgreed = KeyAgreement.computeSharedSecret(gostA.getPrivate(), gostPubB);
            // BC priv B × pub A (crypto-gost)
            byte[] bcAgreed = bcAgree(bcPrivB, toBcPub(gostA.getPublic(), domain), params.hlen);

            assertArrayEquals(gostAgreed, bcAgreed,
                    () -> spec.name() + ": crypto-gost × BC не совпадает\n"
                            + CrossValUtils.diffContext(gostAgreed, bcAgreed));
        } finally {
            gostA.getPrivate().destroy();
            gostPrivB.destroy();
        }
    }

    private static byte[] bcAgree(ECPrivateKeyParameters priv, ECPublicKeyParameters pub, int hlen) {
        ECDHCBasicAgreement agree = new ECDHCBasicAgreement();
        agree.init(priv);
        return toLeBytes(agree.calculateAgreement(pub), hlen);
    }

    private static ECPublicKeyParameters toBcPub(PublicKeyParameters gostPub, ECDomainParameters domain) {
        ECPoint q = gostPub.getQ().normalize();
        org.bouncycastle.math.ec.ECPoint bcQ = domain.getCurve().createPoint(q.getX(), q.getY());
        return new ECPublicKeyParameters(bcQ, domain);
    }

    /**
     * Конвертирует BigInteger (X-координата, big-endian) в little-endian
     * фиксированной длины hlen.
     */
    private static byte[] toLeBytes(BigInteger value, int hlen) {
        byte[] be = value.toByteArray();
        byte[] le = new byte[hlen];
        int copyLen = Math.min(be.length, hlen);
        for (int i = 0; i < copyLen; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }
}
