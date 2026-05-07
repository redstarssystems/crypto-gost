package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPrivateKeySpec;
import org.rssys.gost.jca.key.GostECPublicKey;
import org.rssys.gost.jca.key.GostECPublicKeySpec;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.jca.spec.GostCurves;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostKey — ключевые классы, KeyFactory, SecretKeyFactory, DER-кодирование")
class GostKeyTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // GostSecretKey
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GostSecretKey: getAlgorithm, getFormat, getEncoded")
    void testGostSecretKeyBasics() {
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        GostSecretKey key = new GostSecretKey("Kuznyechik", raw);

        assertEquals("Kuznyechik", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertArrayEquals(raw, key.getEncoded());
    }

    @Test
    @DisplayName("GostSecretKey: destroy обнуляет ключ")
    void testGostSecretKeyDestroy() {
        GostSecretKey key = new GostSecretKey("Kuznyechik", new byte[32]);
        assertFalse(key.isDestroyed());
        key.destroy();
        assertTrue(key.isDestroyed());
        assertThrows(IllegalStateException.class, key::getEncoded);
    }

    // -----------------------------------------------------------------------
    // SecretKeyFactory
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("SecretKeyFactory.Kuznyechik: generateSecret из SecretKeySpec")
    void testSecretKeyFactoryFromSpec() throws Exception {
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        SecretKeySpec spec = new SecretKeySpec(raw, "Kuznyechik");

        SecretKeyFactory skf = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        SecretKey key = skf.generateSecret(spec);

        assertNotNull(key);
        assertInstanceOf(GostSecretKey.class, key);
        assertArrayEquals(raw, key.getEncoded());
    }

    @Test
    @DisplayName("SecretKeyFactory.Kuznyechik: getKeySpec возвращает SecretKeySpec")
    void testSecretKeyFactoryGetKeySpec() throws Exception {
        byte[] raw = new byte[32];
        new java.security.SecureRandom().nextBytes(raw);
        GostSecretKey gostKey = new GostSecretKey("Kuznyechik", raw);

        SecretKeyFactory skf = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        SecretKeySpec spec = (SecretKeySpec) skf.getKeySpec(gostKey, SecretKeySpec.class);

        assertNotNull(spec);
        assertArrayEquals(raw, spec.getEncoded());
    }

    // -----------------------------------------------------------------------
    // GostECPublicKey / GostECPrivateKey — базовые свойства
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GostECPublicKey: getAlgorithm и getFormat")
    void testGostECPublicKeyBasics() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        assertEquals("ECGOST3410-2012", pair.getPublic().getAlgorithm());
        assertEquals("X.509", pair.getPublic().getFormat());
        assertNotNull(pair.getPublic().getEncoded());
    }

    @Test
    @DisplayName("GostECPrivateKey: getAlgorithm и getFormat")
    void testGostECPrivateKeyBasics() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        assertEquals("ECGOST3410-2012", pair.getPrivate().getAlgorithm());
        assertEquals("PKCS#8", pair.getPrivate().getFormat());
        assertNotNull(pair.getPrivate().getEncoded());
    }

    @Test
    @DisplayName("GostECPrivateKey: destroy обнуляет ключ")
    void testGostECPrivateKeyDestroy() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        GostECPrivateKey priv = (GostECPrivateKey) pair.getPrivate();
        assertFalse(priv.isDestroyed());
        priv.destroy();
        assertTrue(priv.isDestroyed());
        assertNull(priv.getEncoded(), "getEncoded должен вернуть null после уничтожения");
    }

    // -----------------------------------------------------------------------
    // KeyFactory — DER roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("KeyFactory: открытый ключ — DER roundtrip X.509 (cryptopro-A)")
    void testPublicKeyDerRoundtripCryptoProA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        // Кодируем в DER
        byte[] encoded = pair.getPublic().getEncoded();
        assertNotNull(encoded);

        // Декодируем обратно
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPublicKey restored = (GostECPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));

        // Сравниваем координаты
        org.rssys.gost.signature.ECPoint qOrig   = ((GostECPublicKey) pair.getPublic()).toPublicKeyParameters().getQ().normalize();
        org.rssys.gost.signature.ECPoint qRestored = restored.toPublicKeyParameters().getQ().normalize();
        assertEquals(qOrig.getX(), qRestored.getX(), "X-координата должна совпадать после DER roundtrip");
        assertEquals(qOrig.getY(), qRestored.getY(), "Y-координата должна совпадать после DER roundtrip");
    }

    @Test
    @DisplayName("KeyFactory: закрытый ключ — DER roundtrip PKCS#8 (cryptopro-A)")
    void testPrivateKeyDerRoundtripCryptoProA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        // Кодируем в DER
        byte[] encoded = pair.getPrivate().getEncoded();
        assertNotNull(encoded);

        // Декодируем обратно
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPrivateKey restored = (GostECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));

        // Сравниваем значения d
        java.math.BigInteger dOrig    = ((GostECPrivateKey) pair.getPrivate()).toPrivateKeyParameters().getD();
        java.math.BigInteger dRestored = restored.toPrivateKeyParameters().getD();
        assertEquals(dOrig, dRestored, "Закрытый ключ d должен совпасть после DER roundtrip");
    }

    @Test
    @DisplayName("KeyFactory: DER roundtrip — 512-битная кривая tc26-gost-A-512")
    void testDerRoundtrip512() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("tc26-gost-A-512"));
        KeyPair pair = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);

        // Открытый ключ
        byte[] pubEncoded = pair.getPublic().getEncoded();
        GostECPublicKey pubRestored = (GostECPublicKey) kf.generatePublic(new X509EncodedKeySpec(pubEncoded));
        assertEquals(
            ((GostECPublicKey) pair.getPublic()).toPublicKeyParameters().getQ().normalize().getX(),
            pubRestored.toPublicKeyParameters().getQ().normalize().getX()
        );

        // Закрытый ключ
        byte[] privEncoded = pair.getPrivate().getEncoded();
        GostECPrivateKey privRestored = (GostECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));
        assertEquals(
            ((GostECPrivateKey) pair.getPrivate()).toPrivateKeyParameters().getD(),
            privRestored.toPrivateKeyParameters().getD()
        );
    }

    @Test
    @DisplayName("KeyFactory: generatePublic из GostECPublicKeySpec")
    void testGeneratePublicFromSpec() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        GostECPublicKey orig = (GostECPublicKey) pair.getPublic();
        org.rssys.gost.signature.ECPoint q = orig.toPublicKeyParameters().getQ().normalize();
        String oid = GostCurves.oidOf(orig.toPublicKeyParameters().getParams());

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPublicKeySpec spec = new GostECPublicKeySpec(q.getX(), q.getY(), oid);
        GostECPublicKey restored = (GostECPublicKey) kf.generatePublic(spec);

        assertEquals(q.getX(), restored.toPublicKeyParameters().getQ().normalize().getX());
        assertEquals(q.getY(), restored.toPublicKeyParameters().getQ().normalize().getY());
    }

    @Test
    @DisplayName("KeyFactory: generatePrivate из GostECPrivateKeySpec")
    void testGeneratePrivateFromSpec() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        GostECPrivateKey orig = (GostECPrivateKey) pair.getPrivate();
        java.math.BigInteger d = orig.toPrivateKeyParameters().getD();
        String oid = GostCurves.oidOf(orig.toPrivateKeyParameters().getParams());

        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPrivateKeySpec spec = new GostECPrivateKeySpec(d, oid);
        GostECPrivateKey restored = (GostECPrivateKey) kf.generatePrivate(spec);

        assertEquals(d, restored.toPrivateKeyParameters().getD());
    }

    // -----------------------------------------------------------------------
    // DER roundtrip — Signature совместима после восстановления ключа
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("DER roundtrip + Signature: ключ восстановленный из DER верифицирует подпись")
    void testSignatureAfterDerRoundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        kpg.initialize(new ECGenParameterSpec("cryptopro-A"));
        KeyPair pair = kpg.generateKeyPair();

        byte[] msg = "данные для подписи после DER roundtrip".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Подписываем оригинальным закрытым ключом
        java.security.Signature signer = java.security.Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // Восстанавливаем открытый ключ из DER
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2012", PROVIDER);
        GostECPublicKey restoredPub = (GostECPublicKey) kf.generatePublic(
            new X509EncodedKeySpec(pair.getPublic().getEncoded()));

        // Верифицируем восстановленным ключом
        java.security.Signature verifier = java.security.Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(restoredPub);
        verifier.update(msg);
        assertTrue(verifier.verify(sig),
            "Восстановленный из DER ключ должен верифици��овать подпись");
    }
}
