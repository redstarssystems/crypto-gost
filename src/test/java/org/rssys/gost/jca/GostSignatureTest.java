package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostECPrivateKeySpec;
import org.rssys.gost.jca.key.GostECPublicKeySpec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;

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
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostSignatureSpi — ГОСТ Р 34.10-2012 через JCA Signature")
class GostSignatureTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] MSG = "тестовое сообщение ГОСТ ЭП".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // 256-битные кривые
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ECGOST3410-2012-256 / cryptopro-A: sign/verify roundtrip")
    void testRoundtrip256CryptoProA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        assertNotNull(sig);
        assertEquals(64, sig.length, "Подпись для 256-битной кривой = 64 байта");

        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig), "Подпись должна верифицироваться");
    }

    @Test
    @DisplayName("ECGOST3410-2012-256 / tc26-gost-A-256: roundtrip")
    void testRoundtrip256Tc26A() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("tc26-gost-A-256"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig));
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
        assertTrue(verifier.verify(sig),
            "Верификация инкрементальными update должна проходить");
    }

    // -----------------------------------------------------------------------
    // 512-битные кривые
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ECGOST3410-2012-512 / tc26-gost-A-512: sign/verify roundtrip")
    void testRoundtrip512Tc26A() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("tc26-gost-A-512"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        assertEquals(128, sig.length, "Подпись для 512-битной кривой = 128 байт");

        Signature verifier = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig));
    }

    @Test
    @DisplayName("ECGOST3410-2012-512 / tc26-gost-B-512: roundtrip")
    void testRoundtrip512Tc26B() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("tc26-gost-B-512"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig));
    }

    @Test
    @DisplayName("KeyPairGenerator: initialize(256) → cryptopro-A по умолчанию")
    void testKpgInitBySize256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(256);
        KeyPair pair = kpg.generateKeyPair();

        // Должна быть 256-битная кривая
        GostECPublicKey pub = (GostECPublicKey) pair.getPublic();
        assertEquals(32, pub.toPublicKeyParameters().getParams().hlen,
            "256-битная инициализация должна дать кривую с hlen=32");
    }

    @Test
    @DisplayName("KeyPairGenerator: initialize(512) → tc26a512 по умолчанию")
    void testKpgInitBySize512() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(512);
        KeyPair pair = kpg.generateKeyPair();

        GostECPublicKey pub = (GostECPublicKey) pair.getPublic();
        assertEquals(64, pub.toPublicKeyParameters().getParams().hlen,
            "512-битная инициализация должна дать кривую с hlen=64");
    }

    // -----------------------------------------------------------------------
    // Детерминированность подписи (RFC 6979)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ECGOST3410-2012-256: подпись детерминирована — одни данные + ключ → одна подпись")
    void testSignDeterministic256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer1 = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer1.initSign(pair.getPrivate());
        signer1.update(MSG);
        byte[] sig1 = signer1.sign();

        Signature signer2 = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer2.initSign(pair.getPrivate());
        signer2.update(MSG);
        byte[] sig2 = signer2.sign();

        assertArrayEquals(sig1, sig2, "RFC 6979: подпись должна быть детерминированной");
    }

    @Test
    @DisplayName("ECGOST3410-2012-512: подпись детерминирована")
    void testSignDeterministic512() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("tc26-gost-A-512"));
        KeyPair pair = kpg.generateKeyPair();

        Signature signer1 = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        signer1.initSign(pair.getPrivate());
        signer1.update(MSG);
        byte[] sig1 = signer1.sign();

        Signature signer2 = Signature.getInstance("ECGOST3410-2012-512", PROVIDER);
        signer2.initSign(pair.getPrivate());
        signer2.update(MSG);
        byte[] sig2 = signer2.sign();

        assertArrayEquals(sig1, sig2, "RFC 6979: подпись должна быть детерминированной для 512-бит");
    }

    // -----------------------------------------------------------------------
    // KeyFactory roundtrip: открытый ключ
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("KeyFactory: GostECPublicKey → X509EncodedKeySpec → GostECPublicKey roundtrip")
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
        GostECPublicKey orig    = (GostECPublicKey) pair.getPublic();
        GostECPublicKey restoredKey = (GostECPublicKey) restored;

        ECPoint q1 = orig.toPublicKeyParameters().getQ().normalize();
        ECPoint q2 = restoredKey.toPublicKeyParameters().getQ().normalize();
        assertEquals(q1.getX(), q2.getX(), "Qx должен совпадать после roundtrip");
        assertEquals(q1.getY(), q2.getY(), "Qy должен совпадать после roundtrip");
    }

    @Test
    @DisplayName("KeyFactory: GostECPublicKey → GostECPublicKeySpec → GostECPublicKey roundtrip")
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

        GostECPublicKey orig        = (GostECPublicKey) pair.getPublic();
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
    @DisplayName("KeyFactory: GostECPrivateKey → PKCS8EncodedKeySpec → GostECPrivateKey roundtrip")
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
        assertTrue(verifier.verify(sig), "Восстановленный закрытый ключ должен создавать верифицируемую подпись");

        ((GostECPrivateKey) restored).destroy();
    }

    @Test
    @DisplayName("KeyFactory: GostECPrivateKey → GostECPrivateKeySpec → GostECPrivateKey roundtrip")
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
        GostECPrivateKey orig        = (GostECPrivateKey) pair.getPrivate();
        GostECPrivateKey restoredKey = (GostECPrivateKey) restored;
        assertEquals(
            orig.toPrivateKeyParameters().getD(),
            restoredKey.toPrivateKeyParameters().getD(),
            "d должен совпадать после spec roundtrip");

        restoredKey.destroy();
    }
}
