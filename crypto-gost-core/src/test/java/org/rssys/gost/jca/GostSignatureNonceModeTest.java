package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.spec.GostSignatureParameterSpec;
import org.rssys.gost.jca.spec.GostUkmParameterSpec;
import org.rssys.gost.signature.NonceMode;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.FixedSecureRandom;

/**
 * Выбор режима нонса через JCA: {@code setParameter(GostSignatureParameterSpec)} и источник
 * случайности через {@code initSign(key, random)}. Режим задаётся явно везде, кроме тестов, которые
 * проверяют само умолчание JCA (гибридное).
 */
@DisplayName("GostSignatureSpi: режим нонса и источник случайности через JCA")
@ExtendWith(JcaTestSupport.class)
class GostSignatureNonceModeTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] MSG = "сообщение для подписи".getBytes(StandardCharsets.UTF_8);
    private static final String ALGO_256 = "ECGOST3410-2012-256";
    private static final String CURVE_256 = "cryptopro-A";

    private static KeyPair newKeyPair(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    private static PrivateKeyParameters params(KeyPair pair) {
        return ((GostECPrivateKey) pair.getPrivate()).toPrivateKeyParameters();
    }

    private static byte[] noise(int length) {
        byte[] noise = new byte[length];
        for (int i = 0; i < length; i++) {
            noise[i] = (byte) (i * 11 + 9);
        }
        return noise;
    }

    private static byte[] jcaSign(Signature signature) throws Exception {
        signature.update(MSG);
        return signature.sign();
    }

    @ParameterizedTest
    @CsvSource({"ECGOST3410-2012-256, cryptopro-A, 32", "ECGOST3410-2012-512, tc26-gost-A-512, 64"})
    @DisplayName(
            "JCA в гибридном режиме с фиксированным датчиком равно Signature.sign тем же режимом")
    void hedgedViaJcaMatchesFacade(String algorithm, String curve, int rolen) throws Exception {
        KeyPair pair = newKeyPair(curve);

        Signature signature = Signature.getInstance(algorithm, PROVIDER);
        signature.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        signature.initSign(pair.getPrivate(), FixedSecureRandom.returning(noise(rolen)));
        byte[] viaJca = jcaSign(signature);

        byte[] viaFacade =
                org.rssys.gost.api.Signature.sign(
                        MSG,
                        params(pair),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(rolen)));
        assertArrayEquals(viaFacade, viaJca, "JCA и фасад дали разные гибридные подписи");
    }

    @Test
    @DisplayName("setParameter работает и до, и после initSign")
    void setParameterWorksInBothOrders() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        byte[] expected =
                org.rssys.gost.api.Signature.sign(
                        MSG,
                        params(pair),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(32)));

        Signature before = Signature.getInstance(ALGO_256, PROVIDER);
        before.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        before.initSign(pair.getPrivate(), FixedSecureRandom.returning(noise(32)));
        assertArrayEquals(expected, jcaSign(before), "setParameter до initSign: режим не применён");

        Signature after = Signature.getInstance(ALGO_256, PROVIDER);
        after.initSign(pair.getPrivate(), FixedSecureRandom.returning(noise(32)));
        after.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        assertArrayEquals(
                expected, jcaSign(after), "setParameter после initSign: режим не применён");
    }

    @Test
    @DisplayName("Режим сохраняется между initSign и меняется только новым setParameter")
    void modeSurvivesReinitialization() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        byte[] hedged =
                org.rssys.gost.api.Signature.sign(
                        MSG,
                        params(pair),
                        NonceMode.HEDGED,
                        FixedSecureRandom.returning(noise(32)));
        byte[] deterministic =
                org.rssys.gost.api.Signature.sign(MSG, params(pair), NonceMode.DETERMINISTIC);

        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        signature.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        for (int i = 0; i < 2; i++) {
            signature.initSign(pair.getPrivate(), FixedSecureRandom.returning(noise(32)));
            assertArrayEquals(
                    hedged, jcaSign(signature), "режим не пережил initSign (раунд " + i + ")");
        }

        signature.setParameter(new GostSignatureParameterSpec(NonceMode.DETERMINISTIC));
        signature.initSign(pair.getPrivate());
        assertArrayEquals(deterministic, jcaSign(signature), "новый setParameter не применён");
    }

    @Test
    @DisplayName("Детерминированный режим через JCA не вызывает датчик, переданный в initSign")
    void deterministicModeIgnoresRandom() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        FixedSecureRandom forbidden = FixedSecureRandom.forbidden();

        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        signature.setParameter(new GostSignatureParameterSpec(NonceMode.DETERMINISTIC));
        signature.initSign(pair.getPrivate(), forbidden);
        byte[] viaJca = jcaSign(signature);

        assertEquals(0, forbidden.calls(), "детерминированный режим обратился к датчику");
        assertArrayEquals(
                org.rssys.gost.api.Signature.sign(MSG, params(pair), NonceMode.DETERMINISTIC),
                viaJca,
                "JCA и фасад дали разные детерминированные подписи");
    }

    @Test
    @DisplayName(
            "Отказ датчика из initSign(key, датчик): SignatureException, подписи нет, датчик вызван один раз")
    void randomFailureViaJcaProducesNoSignature() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        FixedSecureRandom failing = FixedSecureRandom.failing();

        // Режим не задаётся: проверяется связка гибридного умолчания JCA с явным датчиком
        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        signature.initSign(pair.getPrivate(), failing);
        signature.update(MSG);

        SignatureException failure = assertThrows(SignatureException.class, signature::sign);
        // Только первый уровень причины: отказ источника, выданный подписантом. Глубже цепочка -
        // деталь реализации
        assertInstanceOf(
                IllegalStateException.class,
                failure.getCause(),
                "причиной отказа JCA должен быть отказ источника случайности");
        assertEquals(
                1,
                failing.calls(),
                "датчик должен быть вызван ровно один раз: подпись без него недопустима");
    }

    @Test
    @DisplayName("initSign(key) после initSign(key, датчик) сбрасывает чужой датчик")
    void plainInitSignDropsPreviousRandom() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        FixedSecureRandom previous = FixedSecureRandom.returning(noise(32));

        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        signature.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        signature.initSign(pair.getPrivate(), previous);
        jcaSign(signature);
        assertEquals(1, previous.calls(), "первая подпись обязана использовать переданный датчик");

        signature.initSign(pair.getPrivate());
        jcaSign(signature);
        assertEquals(1, previous.calls(), "initSign(key) оставил прежний датчик в объекте");
    }

    @Test
    @DisplayName("initVerify после initSign(key, датчик) сбрасывает датчик")
    void initVerifyDropsPreviousRandom() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);
        FixedSecureRandom previous = FixedSecureRandom.returning(noise(32));

        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        signature.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        signature.initSign(pair.getPrivate(), previous);
        signature.initVerify(pair.getPublic());
        signature.initSign(pair.getPrivate());
        jcaSign(signature);

        assertEquals(0, previous.calls(), "initVerify оставил прежний датчик в объекте");
    }

    @Test
    @DisplayName("Гибридная подпись через JCA верна, без датчика берётся штатный источник")
    void hedgedWithDefaultRandomVerifies() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);

        Signature first = Signature.getInstance(ALGO_256, PROVIDER);
        first.setParameter(new GostSignatureParameterSpec(NonceMode.HEDGED));
        first.initSign(pair.getPrivate());
        byte[] sig1 = jcaSign(first);
        byte[] sig2 = jcaSign(first);

        assertNotEquals(
                new BigInteger(1, sig1), new BigInteger(1, sig2), "две гибридные подписи совпали");
        Signature verifier = Signature.getInstance(ALGO_256, PROVIDER);
        verifier.initVerify(pair.getPublic());
        for (byte[] sig : new byte[][] {sig1, sig2}) {
            verifier.update(MSG);
            assertTrue(verifier.verify(sig), "гибридная подпись обязана проверяться");
        }
    }

    @Test
    @DisplayName(
            "JCA по умолчанию (без setParameter) гибридный: две подписи различаются, обе верны")
    void jcaDefaultIsHedged() throws Exception {
        KeyPair pair = newKeyPair(CURVE_256);

        Signature signer = Signature.getInstance(ALGO_256, PROVIDER);
        signer.initSign(pair.getPrivate());
        byte[] first = jcaSign(signer);
        byte[] second = jcaSign(signer);

        assertNotEquals(
                new BigInteger(1, first),
                new BigInteger(1, second),
                "JCA по умолчанию детерминирован: гибрид не включён");
        Signature verifier = Signature.getInstance(ALGO_256, PROVIDER);
        verifier.initVerify(pair.getPublic());
        for (byte[] sig : new byte[][] {first, second}) {
            verifier.update(MSG);
            assertTrue(verifier.verify(sig), "подпись по умолчанию обязана проверяться");
        }
        assertTrue(
                org.rssys.gost.api.Signature.verify(
                        MSG,
                        first,
                        ((org.rssys.gost.jca.key.GostECPublicKey) pair.getPublic())
                                .toPublicKeyParameters()),
                "подпись JCA обязана проверяться штатным API");
    }

    @Test
    @DisplayName("null и чужой spec отвергаются InvalidAlgorithmParameterException")
    void invalidSpecIsRejected() throws Exception {
        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> signature.setParameter((java.security.spec.AlgorithmParameterSpec) null),
                "null вместо spec обязан отвергаться, а не молча давать умолчание");
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> signature.setParameter(new GostUkmParameterSpec(BigInteger.ONE)),
                "чужой spec обязан отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> new GostSignatureParameterSpec(null),
                "режим null в spec обязан отвергаться");
    }

    @Test
    @DisplayName("getParameters возвращает null: режим только задаётся")
    void getParametersReturnsNull() throws Exception {
        Signature signature = Signature.getInstance(ALGO_256, PROVIDER);
        assertNull(
                signature.getParameters(), "режим нонса читать через AlgorithmParameters нельзя");
    }

    @Test
    @DisplayName("GostSignatureParameterSpec: равенство, hashCode и неизменяемость")
    void specEqualsAndHashCode() {
        GostSignatureParameterSpec hedged = new GostSignatureParameterSpec(NonceMode.HEDGED);
        assertEquals(hedged, new GostSignatureParameterSpec(NonceMode.HEDGED));
        assertEquals(
                hedged.hashCode(), new GostSignatureParameterSpec(NonceMode.HEDGED).hashCode());
        assertNotEquals(hedged, new GostSignatureParameterSpec(NonceMode.DETERMINISTIC));
        assertEquals(NonceMode.HEDGED, hedged.getNonceMode());
        assertTrue(Arrays.asList(NonceMode.values()).contains(hedged.getNonceMode()));
    }
}
