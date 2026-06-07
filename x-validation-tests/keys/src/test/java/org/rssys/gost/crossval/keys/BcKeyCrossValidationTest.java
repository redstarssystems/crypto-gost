package org.rssys.gost.crossval.keys;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jca.spec.GostCurves;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.math.BigInteger;
import org.rssys.gost.util.CryptoRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Кросс-валидация: crypto-gost vs BouncyCastle.
 *
 * <p>Для каждой кривой — отдельный тест на каждую из четырёх проверок.
 * Ключи генерируются внутри каждого теста, состояние между тестами не разделяется.
 */
class BcKeyCrossValidationTest {

    static Stream<TestData.CurveSpec> curveParams() {
        return Stream.of(TestData.CURVES);
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC roundtrip DER: {0}")
    void crossValidateRoundtrip(TestData.CurveSpec spec) {
        // encode→decode не должен терять точность координат и d
        ECParameters params = spec.paramsFn().get();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        PublicKeyParameters pub = pair.getPublic();
        PrivateKeyParameters priv = pair.getPrivate();

        ECPoint q = pub.getQ().normalize();
        BigInteger qx = q.getX();
        BigInteger qy = q.getY();
        BigInteger d = priv.getD();

        byte[] pubDer = GostDerCodec.encodePublicKey(pub);
        byte[] privDer = GostDerCodec.encodePrivateKey(priv);

        PublicKeyParameters pubDecoded = GostDerCodec.decodePublicKey(pubDer);
        PrivateKeyParameters privDecoded = GostDerCodec.decodePrivateKey(privDer);

        ECPoint qRestored = pubDecoded.getQ().normalize();
        assertTrue(qRestored.getX().equals(qx) && qRestored.getY().equals(qy),
                spec.name() + ": координата Q после кодирования/декодирования DER изменилась");
        assertTrue(privDecoded.getD().equals(d),
                spec.name() + ": секретный ключ d после кодирования/декодирования DER изменился");
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC crypto-gost->bc: {0}")
    void crossValidateGostToBc(TestData.CurveSpec spec) {
        ECParameters params = spec.paramsFn().get();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        PublicKeyParameters gostPub = pair.getPublic();
        PrivateKeyParameters gostPriv = pair.getPrivate();

        ECPoint q = gostPub.getQ().normalize();
        BigInteger qx = q.getX();
        BigInteger qy = q.getY();
        BigInteger d = gostPriv.getD();

        ECDomainParameters bcDomain = BcKeyHelper.buildBcDomain(params);
        org.bouncycastle.math.ec.ECPoint bcQ = bcDomain.getCurve().createPoint(qx, qy);

        ECPrivateKeyParameters bcPriv = new ECPrivateKeyParameters(d, bcDomain);
        ECPublicKeyParameters bcPub = new ECPublicKeyParameters(bcQ, bcDomain);

        assertTrue(bcPriv.getD().equals(d),
                spec.name() + ": d crypto-gost→BC не совпадает");
        assertTrue(bcPub.getQ().getXCoord().toBigInteger().equals(qx)
                        && bcPub.getQ().getYCoord().toBigInteger().equals(qy),
                spec.name() + ": Q crypto-gost→BC не совпадает");
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC bc->crypto-gost: {0}")
    void crossValidateBcToGost(TestData.CurveSpec spec) {
        // Q = d·G — сквозная проверка ECPoint.multiply, единственная
        // среди всех тестов, кто тестирует эллиптическую арифметику
        ECParameters params = spec.paramsFn().get();

        ECCurve bcCurve = new ECCurve.Fp(params.p, params.a, params.b);
        org.bouncycastle.math.ec.ECPoint bcG = bcCurve.createPoint(params.gx, params.gy);
        ECDomainParameters bcDomain = new ECDomainParameters(bcCurve, bcG, params.n);

        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(bcDomain, CryptoRandom.INSTANCE));
        AsymmetricCipherKeyPair bcPair = gen.generateKeyPair();

        ECPrivateKeyParameters bcPriv = (ECPrivateKeyParameters) bcPair.getPrivate();
        ECPublicKeyParameters bcPub = (ECPublicKeyParameters) bcPair.getPublic();

        BigInteger d = bcPriv.getD();
        BigInteger qx = bcPub.getQ().getXCoord().toBigInteger();
        BigInteger qy = bcPub.getQ().getYCoord().toBigInteger();

        PrivateKeyParameters gostPriv = new PrivateKeyParameters(d, params);
        ECPoint gostQ = ECPoint.affine(qx, qy, params);
        PublicKeyParameters gostPub = new PublicKeyParameters(gostQ, params);

        ECPoint qNorm = gostPub.getQ().normalize();
        assertTrue(qNorm.getX().equals(qx) && qNorm.getY().equals(qy),
                spec.name() + ": Q BC→crypto-gost не совпадает");
        assertTrue(gostPriv.getD().equals(d),
                spec.name() + ": d BC→crypto-gost не совпадает");

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint expectedQ = g.multiply(d).normalize();
        assertTrue(expectedQ.getX().equals(qx) && expectedQ.getY().equals(qy),
                spec.name() + ": Q = d·G не сошёлся — скалярное умножение дало неверный результат");
    }

    @ParameterizedTest
    @MethodSource("curveParams")
    @DisplayName("BC ASN.1 DER: {0}")
    void crossValidateDerStructure(TestData.CurveSpec spec) {
        ECParameters params = spec.paramsFn().get();
        KeyPair pair = KeyGenerator.generateKeyPair(params);

        byte[] pubDer = GostDerCodec.encodePublicKey(pair.getPublic());
        byte[] privDer = GostDerCodec.encodePrivateKey(pair.getPrivate());

        String expectedSignOid = params.hlen == 32
                ? GostCurves.OID_SIGN_256 : GostCurves.OID_SIGN_512;
        String expectedCurveOid = GostCurves.oidOf(params);

        boolean pubOk = true;
        try {
            var spki = BcKeyHelper.parseSpki(pubDer);
            String algOid = BcKeyHelper.getSignAlgOid(spki);
            String curveOid = BcKeyHelper.getCurveOid(spki);
            pubOk = algOid.equals(expectedSignOid) && curveOid.equals(expectedCurveOid);
        } catch (Exception e) {
            pubOk = false;
        }
        assertTrue(pubOk, spec.name() + ": публичный ключ — OID алгоритма или кривой не совпадает");

        boolean privOk = true;
        try {
            var pki = BcKeyHelper.parsePki(privDer);
            String algOid = BcKeyHelper.getSignAlgOid(pki);
            String curveOid = BcKeyHelper.getCurveOid(pki);
            privOk = algOid.equals(expectedSignOid) && curveOid.equals(expectedCurveOid);
        } catch (Exception e) {
            privOk = false;
        }
        assertTrue(privOk, spec.name() + ": приватный ключ — OID алгоритма или кривой не совпадает");

        assertTrue(pubDer.length > 0 && privDer.length > 0,
                spec.name() + ": пустой DER-блоб");
    }
}
