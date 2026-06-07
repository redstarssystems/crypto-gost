package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.util.CryptoRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostCipherSpi — Кузнечик через JCA Cipher")
class GostCipherTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] DATA_16  = "0123456789ABCDEF".getBytes();
    private static final byte[] DATA_48  = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".getBytes();
    private static final byte[] DATA_ODD = "нечётное число байт".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // CTR
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR/NoPadding: roundtrip совпадает с Cipher API")
    void testCtrRoundtrip() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);

        byte[] iv = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // JCA шифрование
        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = enc.doFinal(DATA_48);

        // JCA расшифрование
        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = dec.doFinal(ciphertext);

        assertArrayEquals(DATA_48, decrypted, "CTR roundtrip должен восстановить исходные данные");
    }

    @Test
    @DisplayName("CTR/NoPadding: результат совпадает с org.rssys.gost.api.Cipher CTR")
    void testCtrMatchesReferenceApi() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);

        byte[] iv = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // JCA
        javax.crypto.Cipher jca = javax.crypto.Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        jca.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] jcaResult = jca.doFinal(DATA_48);

        // Эталонный API
        byte[] refResult = Cipher.encrypt(DATA_48, keyParam, iv, Cipher.Mode.CTR);

        assertArrayEquals(refResult, jcaResult,
            "JCA Cipher CTR должен давать тот же результат что и org.rssys.gost.api.Cipher");
    }

    @Test
    @DisplayName("CTR/NoPadding: нечётная длина данных")
    void testCtrOddLength() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(DATA_ODD);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(DATA_ODD, pt);
    }

    // -----------------------------------------------------------------------
    // CBC
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CBC/PKCS5Padding: roundtrip с кратными блоку данными")
    void testCbcPkcs5Roundtrip() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);

        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/PKCS5Padding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(DATA_48);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/PKCS5Padding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(DATA_48, pt, "CBC/PKCS5Padding roundtrip должен восстановить данные");
    }

    @Test
    @DisplayName("CBC/PKCS5Padding: некратные блоку данные шифруются корректно")
    void testCbcPkcs5OddLength() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Данные некратные 16 байт
        byte[] data = Arrays.copyOf(DATA_48, 37);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/PKCS5Padding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(data);
        // Шифртекст кратен блоку (PKCS7 добавит padding)
        assertEquals(0, ct.length % 16);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/PKCS5Padding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("CBC/PKCS5Padding: совпадает с org.rssys.gost.api.Cipher CBC")
    void testCbcMatchesReferenceApi() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // JCA
        javax.crypto.Cipher jca = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/PKCS5Padding", PROVIDER);
        jca.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] jcaResult = jca.doFinal(DATA_48);

        // Эталонный API
        byte[] refResult = Cipher.encrypt(DATA_48, keyParam, iv, Cipher.Mode.CBC, Cipher.Padding.PKCS7);

        assertArrayEquals(refResult, jcaResult,
            "JCA Cipher CBC должен давать тот же результат что и org.rssys.gost.api.Cipher");
    }

    @Test
    @DisplayName("CBC/NoPadding: данные кратные 16 байт шифруются без ошибок")
    void testCbcNoPadding() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(DATA_48);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CBC/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(DATA_48, pt);
    }

    // -----------------------------------------------------------------------
    // OFB
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("OFB/NoPadding: roundtrip")
    void testOfbRoundtrip() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/OFB/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(DATA_48);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/OFB/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(DATA_48, pt);
    }

    // -----------------------------------------------------------------------
    // CFB
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CFB/NoPadding: roundtrip")
    void testCfbRoundtrip() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("Kuznyechik/CFB/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(DATA_48);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("Kuznyechik/CFB/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] pt = dec.doFinal(ct);

        assertArrayEquals(DATA_48, pt);
    }

    // -----------------------------------------------------------------------
    // CTR-ACPKM-OMAC
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR-ACPKM-OMAC/NoPadding: roundtrip через JCA SPI")
    void testOmacDecryptViaJca() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key = new GostSecretKey("Kuznyechik", keyParam);

        byte[] ukm = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(ukm);
        IvParameterSpec ivSpec = new IvParameterSpec(ukm);

        byte[] plaintext = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(plaintext);

        javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance(
            "Kuznyechik/CTR-ACPKM-OMAC/NoPadding", PROVIDER);
        enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ct = enc.doFinal(plaintext);

        javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance(
            "Kuznyechik/CTR-ACPKM-OMAC/NoPadding", PROVIDER);
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] recovered = dec.doFinal(ct);

        assertArrayEquals(plaintext, recovered,
            "CTR-ACPKM-OMAC roundtrip: расшифрованный текст должен совпадать с исходным");

        // Повреждённый тег должен отклоняться
        ct[ct.length - 1] ^= 0xFF;
        dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivSpec);
        assertThrows(AEADBadTagException.class, () -> dec.doFinal(ct),
            "CTR-ACPKM-OMAC: повреждённый тег должен вызывать AEADBadTagException");
    }

    // -----------------------------------------------------------------------
    // KeyGenerator через JCA
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("KeyGenerator.Kuznyechik: генерирует ключ 32 байта")
    void testKeyGeneratorLength() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("Kuznyechik", PROVIDER);
        javax.crypto.SecretKey key = kg.generateKey();
        assertNotNull(key);
        assertEquals(32, key.getEncoded().length);
        assertEquals("Kuznyechik", key.getAlgorithm());
    }

    @Test
    @DisplayName("KeyGenerator.Kuznyechik: два вызова дают разные ключи")
    void testKeyGeneratorUniqueness() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("Kuznyechik", PROVIDER);
        javax.crypto.SecretKey k1 = kg.generateKey();
        javax.crypto.SecretKey k2 = kg.generateKey();
        assertFalse(Arrays.equals(k1.getEncoded(), k2.getEncoded()),
            "Два сгенерированных ключа не должны совпадать");
    }
}
