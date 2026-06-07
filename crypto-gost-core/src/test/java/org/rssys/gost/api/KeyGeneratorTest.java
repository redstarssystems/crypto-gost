package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;

import org.rssys.gost.util.CryptoRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyGenerator Tests")
class KeyGeneratorTest {

    // -----------------------------------------------------------------------
    // Симметричный ключ
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("generateSymmetricKey: длина 32 байта")
    void testSymmetricKeyLength() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey();
        assertEquals(32, key.getKey().length);
    }

    @Test
    @DisplayName("generateSymmetricKey: два вызова дают разные ключи")
    void testSymmetricKeyUniqueness() {
        SymmetricKey k1 = KeyGenerator.generateSymmetricKey();
        SymmetricKey k2 = KeyGenerator.generateSymmetricKey();
        assertFalse(Arrays.equals(k1.getKey(), k2.getKey()),
            "Два сгенерированных ключа не должны совпадать");
    }

    @Test
    @DisplayName("generateSymmetricKey: с явным CryptoRandom")
    void testSymmetricKeyWithRng() {
        SymmetricKey key = KeyGenerator.generateSymmetricKey(CryptoRandom.INSTANCE);
        assertEquals(32, key.getKey().length);
    }

    // -----------------------------------------------------------------------
    // Ключевая пара ЭП
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("generateKeyPair: базовая точка Q лежит на кривой — cryptoProA")
    void testKeyPairCryptoProA() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        ECPoint q = pair.getPublic().getQ().normalize();
        assertTrue(q.isOnCurve(), "Q должна лежать на кривой CryptoPro-A");
        assertFalse(q.isInfinity(), "Q не должна быть точкой в бесконечности");
    }

    @Test
    @DisplayName("generateKeyPair: n·Q = бесконечность — cryptoProA")
    void testKeyPairOrderCryptoProA() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        ECPoint q = pair.getPublic().getQ();
        assertTrue(q.multiply(params.n).isInfinity(), "n·Q должна быть точкой в бесконечности");
    }

    @Test
    @DisplayName("generateKeyPair: базовая точка Q лежит на кривой — tc26a512")
    void testKeyPairTc26a512() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.tc26a512());
        ECPoint q = pair.getPublic().getQ().normalize();
        assertTrue(q.isOnCurve(), "Q должна лежать на кривой tc26a512");
    }

    @Test
    @DisplayName("generateKeyPair: два вызова дают разные ключи")
    void testKeyPairUniqueness() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair p1 = KeyGenerator.generateKeyPair(params);
        KeyPair p2 = KeyGenerator.generateKeyPair(params);
        assertNotEquals(p1.getPrivate().getD(), p2.getPrivate().getD(),
            "Два сгенерированных закрытых ключа не должны совпадать");
    }

    @Test
    @DisplayName("generateKeyPair: Q = d·G (соответствие закрытого и открытого ключа)")
    void testKeyPairConsistency() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint expectedQ = g.multiply(pair.getPrivate().getD()).normalize();
        ECPoint actualQ   = pair.getPublic().getQ().normalize();

        assertEquals(expectedQ.getX(), actualQ.getX(), "Qx должен совпадать");
        assertEquals(expectedQ.getY(), actualQ.getY(), "Qy должен совпадать");
    }

    @Test
    @DisplayName("generateKeyPair: destroy() закрытого ключа работает")
    void testPrivateKeyDestroy() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        assertFalse(pair.getPrivate().isDestroyed());
        pair.getPrivate().destroy();
        assertTrue(pair.getPrivate().isDestroyed());
        assertThrows(IllegalStateException.class, () -> pair.getPrivate().getD());
    }

    // -----------------------------------------------------------------------
    // Вывод ключа из пароля
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("deriveKey: длина 32 байта")
    void testDeriveKeyLength() throws Exception {
        byte[] password = "test-password".getBytes("UTF-8");
        byte[] salt     = "test-salt-16byt".getBytes("UTF-8");
        SymmetricKey key = KeyGenerator.deriveKey(password, salt, 16, 1, 1);
        assertEquals(32, key.getKey().length);
    }

    @Test
    @DisplayName("deriveKey: детерминированность — одинаковые параметры → одинаковый ключ")
    void testDeriveKeyDeterministic() throws Exception {
        byte[] password = "my-password".getBytes("UTF-8");
        byte[] salt     = "my-salt-16bytes".getBytes("UTF-8");
        SymmetricKey k1 = KeyGenerator.deriveKey(password, salt, 16, 1, 1);
        SymmetricKey k2 = KeyGenerator.deriveKey(password, salt, 16, 1, 1);
        assertArrayEquals(k1.getKey(), k2.getKey(), "Производный ключ должен быть детерминированным");
    }

    @Test
    @DisplayName("deriveKey: разные пароли → разные ключи")
    void testDeriveKeyPasswordSensitivity() throws Exception {
        byte[] salt = "fixed-salt-12345".getBytes("UTF-8");
        SymmetricKey k1 = KeyGenerator.deriveKey("password1".getBytes("UTF-8"), salt, 16, 1, 1);
        SymmetricKey k2 = KeyGenerator.deriveKey("password2".getBytes("UTF-8"), salt, 16, 1, 1);
        assertFalse(Arrays.equals(k1.getKey(), k2.getKey()),
            "Разные пароли должны давать разные ключи");
    }
}
