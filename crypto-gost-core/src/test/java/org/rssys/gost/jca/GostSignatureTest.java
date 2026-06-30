package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPrivateKeySpec;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostECPublicKeySpec;
import org.rssys.gost.signature.ECPoint;

@DisplayName("GostSignatureSpi — ГОСТ Р 34.10-2012 через JCA Signature")
class GostSignatureTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] MSG =
            "тестовое сообщение ГОСТ ЭП".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // Параметризованные roundtrip-тесты — все кривые
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("roundtripCurves")
    @DisplayName("sign/verify roundtrip с корректной длиной подписи")
    void testRoundtrip(String sigAlgo, String curveName, int expectedSigLen) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        assertNotNull(sig);
        assertEquals(
                expectedSigLen,
                sig.length,
                "Подпись для " + sigAlgo + " = " + expectedSigLen + " байт");

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig), "Подпись должна верифицироваться");
    }

    static Stream<Arguments> roundtripCurves() {
        return Stream.of(
                Arguments.of("ECGOST3410-2012-256", "cryptopro-A", 64),
                Arguments.of("ECGOST3410-2012-256", "tc26-gost-A-256", 64),
                Arguments.of("ECGOST3410-2012-512", "tc26-gost-A-512", 128),
                Arguments.of("ECGOST3410-2012-512", "tc26-gost-B-512", 128));
    }

    @Test
    @DisplayName("ECGOST3410-2012-256: неверная подпись отклоняется")
    void testWrongSignatureRejected256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        // Портим один байт подписи
        sig[0] ^= 0xFF;

        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertFalse(verifier.verify(sig), "Повреждённая подпись должна быть отклонена");
    }

    @Test
    @DisplayName("ECGOST3410-2012-256: чужой ключ не верифицирует подпись")
    void testWrongKeyRejected256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair1 = kpg.generateKeyPair();
        KeyPair pair2 = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair1.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        // Проверяем чужим ключом
        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair2.getPublic()); // чужой ключ
        verifier.update(MSG);
        assertFalse(verifier.verify(sig), "Чужой ключ не должен верифицировать подпись");
    }

    @Test
    @DisplayName("ECGOST3410-2012-256: инкрементальные update работают корректно")
    void testIncrementalUpdate256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        // Подписываем целиком
        Signature signer1 = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer1.initSign(pair.getPrivate());
        signer1.update(MSG);
        byte[] sig = signer1.sign();

        // Верифицируем по частям
        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        int half = MSG.length / 2;
        verifier.update(MSG, 0, half);
        verifier.update(MSG, half, MSG.length - half);
        assertTrue(verifier.verify(sig), "Верификация инкрементальными update должна проходить");
    }

    // -----------------------------------------------------------------------
    // KeyPairGenerator (параметризован)
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @DisplayName("initialize(keySize) даёт кривую с ожидаемым hlen")
    @CsvSource({"256, 32", "512, 64"})
    void testKpgInitBySize(int keySize, int expectedHlen) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(keySize);
        KeyPair pair = kpg.generateKeyPair();

        GostECPublicKey pub = (GostECPublicKey) pair.getPublic();
        assertEquals(
                expectedHlen,
                pub.toPublicKeyParameters().getParams().hlen,
                keySize + "-битная инициализация должна дать кривую с hlen=" + expectedHlen);
    }

    // -----------------------------------------------------------------------
    // Детерминированность подписи (RFC 6979, параметризована)
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @DisplayName("подпись детерминирована — одни данные + ключ -> одна подпись")
    @CsvSource({"ECGOST3410-2012-256, cryptopro-A", "ECGOST3410-2012-512, tc26-gost-A-512"})
    void testSignDeterministic(String sigAlgo, String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer1 = Signature.getInstance(sigAlgo, PROVIDER);
        signer1.initSign(pair.getPrivate());
        signer1.update(MSG);
        byte[] sig1 = signer1.sign();

        Signature signer2 = Signature.getInstance(sigAlgo, PROVIDER);
        signer2.initSign(pair.getPrivate());
        signer2.update(MSG);
        byte[] sig2 = signer2.sign();

        assertArrayEquals(
                sig1, sig2, "RFC 6979: подпись должна быть детерминированной для " + sigAlgo);
    }

    // -----------------------------------------------------------------------
    // KeyFactory roundtrip: открытый ключ
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("KeyFactory: GostECPublicKey -> X509EncodedKeySpec -> GostECPublicKey roundtrip")
    void testPublicKeyX509Roundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        // Экспорт в DER X.509
        byte[] encoded = pair.getPublic().getEncoded();
        assertNotNull(encoded, "Кодирование открытого ключа не должно быть null");

        // Импорт через KeyFactory
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        PublicKey restored = kf.generatePublic(new X509EncodedKeySpec(encoded));

        assertInstanceOf(GostECPublicKey.class, restored);
        GostECPublicKey orig = (GostECPublicKey) pair.getPublic();
        GostECPublicKey restoredKey = (GostECPublicKey) restored;

        ECPoint q1 = orig.toPublicKeyParameters().getQ().normalize();
        ECPoint q2 = restoredKey.toPublicKeyParameters().getQ().normalize();
        assertEquals(q1.getX(), q2.getX(), "Qx должен совпадать после roundtrip");
        assertEquals(q1.getY(), q2.getY(), "Qy должен совпадать после roundtrip");
    }

    @Test
    @DisplayName("KeyFactory: GostECPublicKey -> GostECPublicKeySpec -> GostECPublicKey roundtrip")
    void testPublicKeySpecRoundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);

        // Экспорт в GostECPublicKeySpec
        GostECPublicKeySpec spec = kf.getKeySpec(pair.getPublic(), GostECPublicKeySpec.class);
        assertNotNull(spec);

        // Импорт обратно
        PublicKey restored = kf.generatePublic(spec);
        assertInstanceOf(GostECPublicKey.class, restored);

        GostECPublicKey orig = (GostECPublicKey) pair.getPublic();
        GostECPublicKey restoredKey = (GostECPublicKey) restored;
        ECPoint q1 = orig.toPublicKeyParameters().getQ().normalize();
        ECPoint q2 = restoredKey.toPublicKeyParameters().getQ().normalize();
        assertEquals(q1.getX(), q2.getX(), "Qx должен совпадать после spec roundtrip");
        assertEquals(q1.getY(), q2.getY(), "Qy должен совпадать после spec roundtrip");
    }

    // -----------------------------------------------------------------------
    // KeyFactory roundtrip: закрытый ключ
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "KeyFactory: GostECPrivateKey -> PKCS8EncodedKeySpec -> GostECPrivateKey roundtrip")
    void testPrivateKeyPkcs8Roundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        // Экспорт в DER PKCS#8
        byte[] encoded = pair.getPrivate().getEncoded();
        assertNotNull(encoded, "Кодирование закрытого ключа не должно быть null");

        // Импорт через KeyFactory
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        PrivateKey restored = kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        assertInstanceOf(GostECPrivateKey.class, restored);

        // Восстановленный ключ должен подписывать
        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(restored);
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(
                verifier.verify(sig),
                "Восстановленный закрытый ключ должен создавать верифицируемую подпись");

        ((GostECPrivateKey) restored).destroy();
    }

    @Test
    @DisplayName(
            "KeyFactory: GostECPrivateKey -> GostECPrivateKeySpec -> GostECPrivateKey roundtrip")
    void testPrivateKeySpecRoundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);

        // Экспорт в GostECPrivateKeySpec
        GostECPrivateKeySpec spec = kf.getKeySpec(pair.getPrivate(), GostECPrivateKeySpec.class);
        assertNotNull(spec);

        // Импорт обратно
        PrivateKey restored = kf.generatePrivate(spec);
        assertInstanceOf(GostECPrivateKey.class, restored);

        // Проверяем что d совпадает
        GostECPrivateKey orig = (GostECPrivateKey) pair.getPrivate();
        GostECPrivateKey restoredKey = (GostECPrivateKey) restored;
        assertEquals(
                orig.toPrivateKeyParameters().getD(),
                restoredKey.toPrivateKeyParameters().getD(),
                "d должен совпадать после spec roundtrip");

        restoredKey.destroy();
    }
}
