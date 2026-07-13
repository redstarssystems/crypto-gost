package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Модульные тесты {@link GostSigner}: дефолтная реализация поверх ключа в памяти.
 */
@DisplayName("GostSigner: дефолтная реализация над PrivateKeyParameters")
class GostSignerTest {

    @Test
    @DisplayName("of(null) -> IllegalArgumentException")
    void testOfNull() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSigner.of(null),
                "of(null) должен немедленно падать");
    }

    @Test
    @DisplayName("getPublicKey совпадает с derivePublicKey исходного ключа")
    void testPublicKeyMatchesDerived() {
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        GostSigner signer = GostSigner.of(kp.getPrivate());

        PublicKeyParameters expected = Signature.derivePublicKey(kp.getPrivate());
        // Открытый ключ подписанта должен соответствовать закрытому: Q = d·G.
        // ECPoint не переопределяет equals — сравниваем нормализованные координаты.
        assertEquals(
                expected.getQ().getX(),
                signer.getPublicKey().getQ().getX(),
                "X точки Q должен совпадать");
        assertEquals(
                expected.getQ().getY(),
                signer.getPublicKey().getQ().getY(),
                "Y точки Q должен совпадать");
        assertEquals(
                ECParameters.tc26a256(), signer.getParams(), "параметры кривой должны совпадать");
    }

    @Test
    @DisplayName("signHash даёт подпись, проверяемую getPublicKey")
    void testSignHashSelfConsistent() {
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        GostSigner signer = GostSigner.of(kp.getPrivate());

        byte[] hash = new byte[signer.getParams().hlen];
        for (int i = 0; i < hash.length; i++) hash[i] = (byte) i;

        byte[] sig = signer.signHash(hash);
        assertTrue(
                Signature.verifyHash(hash, sig, signer.getPublicKey()),
                "подпись должна проверяться собственным открытым ключом подписанта");
    }

    @Test
    @DisplayName("после destroy(): signHash падает, getPublicKey возвращает кэш")
    void testDestroyedKeyBehavior() {
        KeyPair kp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        GostSigner signer = GostSigner.of(kp.getPrivate());
        // Открытый ключ выведен eager при of() — фиксируем его до уничтожения.
        PublicKeyParameters pubBefore = signer.getPublicKey();

        kp.getPrivate().destroy();

        byte[] hash = new byte[signer.getParams().hlen];
        assertThrows(
                IllegalStateException.class,
                () -> signer.signHash(hash),
                "signHash на уничтоженном ключе должен падать");
        // Открытый ключ не секретен и кэширован — остаётся доступен после destroy().
        assertSame(
                pubBefore, signer.getPublicKey(), "getPublicKey должен вернуть кэшированный ключ");
    }
}
