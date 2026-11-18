package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.rssys.crypto.util.SCrypt;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.FixedSecureRandom;

@DisplayName("Digest, CmacApi и KeyGenerator: затирание состояния и копий ключа")
class DigestCmacDestroyTest {

    private static final byte[] DATA = "данные".getBytes(StandardCharsets.UTF_8);

    private final SymmetricKey key = KeyGenerator.generateSymmetricKey();

    // -----------------------------------------------------------------------
    // Digest
    // -----------------------------------------------------------------------

    @Test
    @DisplayName(
            "Digest с ключом (HMAC): после destroy() экземпляр непригоден, повторный destroy безопасен")
    void hmacInstanceIsUnusableAfterDestroy() {
        Digest hmac = new Digest(Digest.Algorithm.HMAC_256, key);
        hmac.update(DATA);
        hmac.destroy();
        assertThrows(IllegalStateException.class, () -> hmac.update(DATA), "update после destroy");
        assertThrows(IllegalStateException.class, hmac::digest, "digest после destroy");
        assertDoesNotThrow(hmac::destroy, "повторный destroy");
    }

    @Test
    @DisplayName("Digest в try-with-resources даёт тот же HMAC, что статический метод")
    void hmacInTryWithResourcesMatchesStatic() {
        byte[] viaInstance;
        try (Digest hmac = new Digest(Digest.Algorithm.HMAC_512, key)) {
            hmac.update(DATA);
            viaInstance = hmac.digest();
        }
        assertArrayEquals(Digest.hmac512(DATA, key), viaInstance, "HMAC-Стрибог-512");
    }

    @Test
    @DisplayName("Digest без ключа: в try-with-resources даёт тот же хэш, что статический метод")
    void plainDigestInTryWithResourcesMatchesStatic() {
        byte[] viaInstance;
        try (Digest hash = new Digest(Digest.Algorithm.STREEBOG_256)) {
            hash.update(DATA);
            viaInstance = hash.digest();
        }
        assertArrayEquals(Digest.digest256(DATA), viaInstance, "хэш Стрибог-256");
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Digest.Algorithm.class)
    @DisplayName(
            "После destroy() update, digest и reset бросают IllegalStateException для всех алгоритмов")
    void everyAlgorithmIsUnusableAfterDestroy(Digest.Algorithm algorithm) {
        boolean keyed =
                algorithm == Digest.Algorithm.HMAC_256 || algorithm == Digest.Algorithm.HMAC_512;
        Digest digest = keyed ? new Digest(algorithm, key) : new Digest(algorithm);
        digest.update(DATA);
        digest.destroy();

        assertThrows(IllegalStateException.class, () -> digest.update(DATA), "update");
        assertThrows(IllegalStateException.class, digest::digest, "digest");
        assertThrows(IllegalStateException.class, digest::reset, "reset");
        assertDoesNotThrow(digest::destroy, "повторный destroy");
        assertDoesNotThrow(digest::close, "close после destroy");
    }

    // -----------------------------------------------------------------------
    // CmacApi
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CmacApi: после destroy() экземпляр непригоден, повторный destroy безопасен")
    void cmacInstanceIsUnusableAfterDestroy() {
        CmacApi cmac = new CmacApi(key);
        cmac.update(DATA);
        cmac.destroy();
        assertThrows(IllegalStateException.class, () -> cmac.update(DATA), "update после destroy");
        assertThrows(IllegalStateException.class, cmac::digest, "digest после destroy");
        assertThrows(IllegalStateException.class, cmac::reset, "reset после destroy");
        assertDoesNotThrow(cmac::destroy, "повторный destroy");
        assertDoesNotThrow(cmac::close, "close после destroy");
    }

    @Test
    @DisplayName("CmacApi в try-with-resources даёт тот же тег, что статический метод")
    void cmacInTryWithResourcesMatchesStatic() {
        byte[] viaInstance;
        try (CmacApi cmac = new CmacApi(key)) {
            viaInstance = cmac.update(DATA).digest();
        }
        assertArrayEquals(CmacApi.cmac(DATA, key), viaInstance, "CMAC-Кузнечик");
    }

    // -----------------------------------------------------------------------
    // KeyGenerator: затирание исходного массива не должно задеть выданный ключ
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("generateSymmetricKey сохраняет ключ после затирания исходного массива")
    void generatedKeySurvivesSourceWipe() {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i + 1);
        }
        SymmetricKey generated =
                KeyGenerator.generateSymmetricKey(FixedSecureRandom.returning(bytes));
        assertArrayEquals(bytes, generated.getKey(), "ключ должен совпасть с байтами датчика");
    }

    @Test
    @DisplayName("deriveKey сохраняет ключ после затирания исходного массива")
    void derivedKeySurvivesSourceWipe() throws Exception {
        byte[] password = "пароль".getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[16];
        SymmetricKey derived = KeyGenerator.deriveKey(password, salt, 16, 1, 1);
        assertArrayEquals(
                SCrypt.generate(password, salt, 16, 1, 1, 32),
                derived.getKey(),
                "ключ должен совпасть с результатом scrypt");
    }
}
