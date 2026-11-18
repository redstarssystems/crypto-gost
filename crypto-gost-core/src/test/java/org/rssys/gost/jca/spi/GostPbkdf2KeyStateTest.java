package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Фабрика PBKDF2: уничтоженные ключи дают проверяемые исключения")
@ExtendWith(JcaTestSupport.class)
class GostPbkdf2KeyStateTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final String ALGORITHM = "PBKDF2WithHmacStreebog512";

    private static GostSecretKey derivedKey(SecretKeyFactory factory) throws Exception {
        byte[] salt = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(salt);
        return (GostSecretKey)
                factory.generateSecret(new PBEKeySpec("пароль".toCharArray(), salt, 10, 256));
    }

    @Test
    @DisplayName("getKeySpec уничтоженного ключа даёт InvalidKeySpecException")
    void getKeySpecOfDestroyedKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        GostSecretKey key = derivedKey(factory);
        key.destroy();
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.getKeySpec(key, SecretKeySpec.class),
                "ключ уничтожен");
    }

    @Test
    @DisplayName("translateKey уничтоженного ключа даёт InvalidKeyException")
    void translateDestroyedKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        GostSecretKey key = derivedKey(factory);
        key.destroy();
        assertThrows(InvalidKeyException.class, () -> factory.translateKey(key), "ключ уничтожен");
    }

    @Test
    @DisplayName("getKeySpec и translateKey действующего ключа возвращают те же байты")
    void liveKeyRoundTrips() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        GostSecretKey key = derivedKey(factory);
        SecretKeySpec spec = (SecretKeySpec) factory.getKeySpec(key, SecretKeySpec.class);
        assertArrayEquals(key.getEncoded(), spec.getEncoded(), "байты в спецификации");
        assertArrayEquals(
                key.getEncoded(),
                factory.translateKey(new SecretKeySpec(spec.getEncoded(), "RAW")).getEncoded(),
                "байты после translateKey");
    }
}
