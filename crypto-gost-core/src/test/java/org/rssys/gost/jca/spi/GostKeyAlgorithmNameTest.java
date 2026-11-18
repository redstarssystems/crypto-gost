package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Имя алгоритма ключа: шифры и фабрика ключей Кузнечика проверяют его, MAC нет")
@ExtendWith(JcaTestSupport.class)
class GostKeyAlgorithmNameTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    private static byte[] bytes(int length) {
        byte[] value = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(value);
        return value;
    }

    // -----------------------------------------------------------------------
    // Шифры
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cipher.init отвергает ключ с чужим именем алгоритма (например, AES)")
    void cipherRejectsForeignAlgorithmName() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        IvParameterSpec iv = new IvParameterSpec(bytes(8));
        assertThrows(
                InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(bytes(32), "AES"), iv),
                "ключ AES не должен молча становиться ключом Кузнечика");
        assertThrows(
                InvalidKeyException.class,
                () ->
                        cipher.init(
                                Cipher.ENCRYPT_MODE,
                                new GostSecretKey("HmacGOST3411-2012-256", bytes(32)),
                                iv),
                "ключ HMAC не должен использоваться как ключ шифра");
    }

    @Test
    @DisplayName("Cipher.init принимает имена Kuznyechik и GOST3412-2015 без учёта регистра")
    void cipherAcceptsKuznyechikNames() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        for (String name : new String[] {"Kuznyechik", "kuznyechik", "GOST3412-2015"}) {
            IvParameterSpec iv = new IvParameterSpec(bytes(8));
            assertDoesNotThrow(
                    () -> cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(bytes(32), name), iv),
                    "имя " + name);
        }
    }

    @Test
    @DisplayName(
            "Cipher.init с уничтоженным ключом даёт InvalidKeyException, а не IllegalStateException")
    void cipherRejectsDestroyedKeyWithCheckedException() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        GostSecretKey key = new GostSecretKey("Kuznyechik", bytes(32));
        key.destroy();
        assertThrows(
                InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(bytes(8))),
                "уничтоженный ключ");
    }

    @Test
    @DisplayName("Cipher.init с ключом неверной длины даёт InvalidKeyException")
    void cipherRejectsWrongKeyLength() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        GostSecretKey key = new GostSecretKey("Kuznyechik", bytes(16));
        assertThrows(
                InvalidKeyException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(bytes(8))),
                "ключ из 16 байт для Кузнечика");
    }

    // -----------------------------------------------------------------------
    // Фабрика ключей
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("SecretKeyFactory: спецификация и ключ с именем AES отвергаются")
    void factoryRejectsForeignAlgorithmName() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        SecretKeySpec aes = new SecretKeySpec(bytes(32), "AES");
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.generateSecret(aes),
                "generateSecret с именем AES");
        assertThrows(
                InvalidKeyException.class, () -> factory.translateKey(aes), "translateKey с AES");
    }

    @Test
    @DisplayName("SecretKeyFactory: имя Kuznyechik принимается и даёт GostSecretKey")
    void factoryAcceptsKuznyechikName() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        byte[] raw = bytes(32);
        SecretKey generated = factory.generateSecret(new SecretKeySpec(raw, "Kuznyechik"));
        assertInstanceOf(GostSecretKey.class, generated, "тип ключа");
        assertEquals("Kuznyechik", generated.getAlgorithm(), "имя алгоритма");
        assertArrayEquals(raw, generated.getEncoded(), "байты ключа");
        assertSame(generated, factory.translateKey(generated), "свой ключ возвращается как есть");
    }

    @Test
    @DisplayName(
            "SecretKeyFactory: ключ с неверной длиной и уничтоженный отвергаются проверяемым исключением")
    void factoryRejectsBadKeysWithCheckedExceptions() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.generateSecret(new SecretKeySpec(bytes(16), "Kuznyechik")),
                "generateSecret с ключом в 16 байт");

        GostSecretKey destroyed = new GostSecretKey("Kuznyechik", bytes(32));
        destroyed.destroy();
        assertThrows(
                InvalidKeyException.class,
                () -> factory.translateKey(destroyed),
                "translateKey уничтоженного ключа");
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.getKeySpec(destroyed, SecretKeySpec.class),
                "getKeySpec уничтоженного ключа");
    }

    @Test
    @DisplayName("SecretKeyFactory.getKeySpec не заменяет имя алгоритма чужого ключа на Kuznyechik")
    void factoryGetKeySpecRejectsForeignKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("Kuznyechik", PROVIDER);
        GostSecretKey hmacKey = new GostSecretKey("HmacGOST3411-2012-256", bytes(32));
        assertThrows(
                InvalidKeySpecException.class,
                () -> factory.getKeySpec(hmacKey, SecretKeySpec.class),
                "ключ другого алгоритма не должен получать ярлык Kuznyechik");
    }

    // -----------------------------------------------------------------------
    // MAC
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("HMAC принимает RAW-ключ с любым именем и любой непустой длины")
    void hmacAcceptsAnyRawKey() throws Exception {
        for (int length : new int[] {1, 16, 32, 100}) {
            Mac mac = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);
            assertDoesNotThrow(
                    () -> mac.init(new SecretKeySpec(bytes(length), "RAW")),
                    "ключ HMAC длиной " + length);
        }
    }

    @Test
    @DisplayName("CMAC принимает ключ Кузнечика под любым именем, но только длиной 32 байта")
    void cmacRequiresThirtyTwoByteKey() throws Exception {
        Mac mac = Mac.getInstance("CMAC-Kuznyechik", PROVIDER);
        assertDoesNotThrow(
                () -> mac.init(new GostSecretKey("Kuznyechik", bytes(32))), "ключ из 32 байт");
        assertDoesNotThrow(
                () -> mac.init(new SecretKeySpec(bytes(32), "RAW")), "RAW-ключ из 32 байт");
        assertThrows(
                InvalidKeyException.class,
                () -> mac.init(new SecretKeySpec(bytes(16), "RAW")),
                "ключ из 16 байт: проверяемое исключение, а не из шифра");
    }

    @Test
    @DisplayName("Mac.init с уничтоженным ключом даёт InvalidKeyException")
    void macRejectsDestroyedKey() throws Exception {
        Mac mac = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);
        GostSecretKey key = new GostSecretKey("HmacGOST3411-2012-256", bytes(32));
        key.destroy();
        assertThrows(InvalidKeyException.class, () -> mac.init(key), "уничтоженный ключ MAC");
    }
}
