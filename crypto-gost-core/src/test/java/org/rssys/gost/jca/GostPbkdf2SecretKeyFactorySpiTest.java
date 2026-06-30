package org.rssys.gost.jca;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.key.GostSecretKey;

@DisplayName("GostPbkdf2SecretKeyFactorySpi — PBKDF2WithHmacStreebog512")
class GostPbkdf2SecretKeyFactorySpiTest {

    private static final String ALGORITHM = "PBKDF2WithHmacStreebog512";
    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private static byte[] hex(String s) {
        s = s.replaceAll("\\s+", "");
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(s.charAt(i), 16) << 4)
                                    | Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    @Test
    @DisplayName("SecretKeyFactory.getInstance() — алгоритм доступен через провайдер")
    void testFactoryAvailable() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        assertNotNull(skf);
        PBEKeySpec spec = new PBEKeySpec("p".toCharArray(), "s".getBytes(), 1, 32 * 8);
        assertNotNull(skf.generateSecret(spec));
    }

    @Test
    @DisplayName("engineGenerateSecret(PBEKeySpec) — RFC 9337 вектор 1: c=1, dkLen=64")
    void testVector1() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1, 64 * 8);
        SecretKey key = skf.generateSecret(spec);
        byte[] expected =
                hex(
                        "64 77 0a f7 f7 48 c3 b1 c9 ac 83 1d bc fd 85 c2 "
                                + "61 11 b3 0a 8a 65 7d dc 30 56 b8 0c a7 3e 04 0d "
                                + "28 54 fd 36 81 1f 6d 82 5c c4 ab 66 ec 0a 68 a4 "
                                + "90 a9 e5 cf 51 56 b3 a2 b7 ee cd db f9 a1 6b 47");
        assertArrayEquals(expected, key.getEncoded());
        assertEquals("PBKDF2WithHmacStreebog512", key.getAlgorithm());
    }

    @Test
    @DisplayName("engineGenerateSecret(PBEKeySpec) — RFC 9337 вектор 2: c=2, dkLen=64")
    void testVector2() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 2, 64 * 8);
        SecretKey key = skf.generateSecret(spec);
        byte[] expected =
                hex(
                        "5a 58 5b af df bb 6e 88 30 d6 d6 8a a3 b4 3a c0 "
                                + "0d 2e 4a eb ce 01 c9 b3 1c 2c ae d5 6f 02 36 d4 "
                                + "d3 4b 2b 8f bd 2c 4e 89 d5 4d 46 f5 0e 47 d4 5b "
                                + "ba c3 01 57 17 43 11 9e 8d 3c 42 ba 66 d3 48 de");
        assertArrayEquals(expected, key.getEncoded());
    }

    @Test
    @DisplayName("engineGenerateSecret(PBEKeySpec) — RFC 9337 вектор 3: c=4096, dkLen=64")
    void testVector3() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 4096, 64 * 8);
        SecretKey key = skf.generateSecret(spec);
        byte[] expected =
                hex(
                        "e5 2d eb 9a 2d 2a af f4 e2 ac 9d 47 a4 1f 34 c2 "
                                + "03 76 59 1c 67 80 7f 04 77 e3 25 49 dc 34 1b c7 "
                                + "86 7c 09 84 1b 6d 58 e2 9d 03 47 c9 96 30 1d 55 "
                                + "df 0d 34 e4 7c f6 8f 4e 3c 2c da f1 d9 ab 86 c3");
        assertArrayEquals(expected, key.getEncoded());
    }

    @Test
    @DisplayName("engineGenerateSecret(PBEKeySpec) — пароль/соль с null-байтами")
    void testPasswordWithNullBytes() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        byte[] saltWithZero = new byte[] {'s', 'a', 0, 'l', 't'};
        PBEKeySpec spec =
                new PBEKeySpec(
                        new char[] {'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd'},
                        saltWithZero,
                        4096,
                        64 * 8);
        SecretKey key = skf.generateSecret(spec);
        byte[] expected =
                hex(
                        "50 df 06 28 85 b6 98 01 a3 c1 02 48 eb 0a 27 ab "
                                + "6e 52 2f fe b2 0c 99 1c 66 0f 00 14 75 d7 3a 4e "
                                + "16 7f 78 2c 18 e9 7e 92 97 6d 9c 1d 97 08 31 ea "
                                + "78 cc b8 79 f6 70 68 cd ac 19 10 74 08 44 e8 30");
        assertArrayEquals(expected, key.getEncoded());
    }

    @Test
    @DisplayName("engineGenerateSecret(PBEKeySpec) — выдаёт GostSecretKey")
    void testReturnsGostSecretKey() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1, 32 * 8);
        SecretKey key = skf.generateSecret(spec);
        assertInstanceOf(GostSecretKey.class, key);
    }

    @Test
    @DisplayName("engineGetKeySpec(SecretKey, SecretKeySpec.class) — round-trip")
    void testGetKeySpec() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1, 32 * 8);
        SecretKey key = skf.generateSecret(spec);

        SecretKeySpec keySpec = (SecretKeySpec) skf.getKeySpec(key, SecretKeySpec.class);
        assertNotNull(keySpec);
        assertArrayEquals(key.getEncoded(), keySpec.getEncoded());
        assertEquals("PBKDF2WithHmacStreebog512", keySpec.getAlgorithm());
    }

    @Test
    @DisplayName("engineGetKeySpec(SecretKey, PBEKeySpec.class) — бросает InvalidKeySpecException")
    void testGetKeySpecPbeRejected() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("p".toCharArray(), "s".getBytes(), 1, 32 * 8);
        SecretKey key = skf.generateSecret(spec);

        assertThrows(InvalidKeySpecException.class, () -> skf.getKeySpec(key, PBEKeySpec.class));
    }

    @Test
    @DisplayName("engineTranslateKey — GostSecretKey возвращается как есть")
    void testTranslateGostSecretKey() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("p".toCharArray(), "s".getBytes(), 1, 32 * 8);
        GostSecretKey key = (GostSecretKey) skf.generateSecret(spec);

        SecretKey translated = skf.translateKey(key);
        assertSame(key, translated);
    }

    @Test
    @DisplayName(
            "engineTranslateKey — GostSecretKey с чужим алгоритмом бросает InvalidKeyException")
    void testTranslateWrongAlgorithm() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        GostSecretKey wrongKey = new GostSecretKey("Kuznyechik", new byte[32]);
        assertThrows(InvalidKeyException.class, () -> skf.translateKey(wrongKey));
    }

    @Test
    @DisplayName("engineTranslateKey — SecretKeySpec -> GostSecretKey")
    void testTranslateSecretKeySpec() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        byte[] raw = new byte[32];
        raw[0] = 0x01;
        SecretKeySpec spec = new SecretKeySpec(raw, "PBKDF2WithHmacStreebog512");

        SecretKey key = skf.translateKey(spec);
        assertInstanceOf(GostSecretKey.class, key);
        assertArrayEquals(raw, key.getEncoded());
    }

    @Test
    @DisplayName("engineGenerateSecret(SecretKeySpec) — создаёт GostSecretKey")
    void testGenerateSecretFromSpec() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        byte[] raw = new byte[32];
        raw[0] = 0x02;
        SecretKeySpec spec = new SecretKeySpec(raw, "PBKDF2WithHmacStreebog512");

        SecretKey key = skf.generateSecret(spec);
        assertInstanceOf(GostSecretKey.class, key);
        assertArrayEquals(raw, key.getEncoded());
    }

    @Test
    @DisplayName("PBEKeySpec с keyLength < 8 бит — InvalidKeySpecException")
    void testKeyLengthTooSmall() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), "salt".getBytes(), 1, 4);
        assertThrows(InvalidKeySpecException.class, () -> skf.generateSecret(spec));
    }

    @Test
    @DisplayName("PBEKeySpec с salt=null — InvalidKeySpecException")
    void testSaltNull() throws Exception {
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray());
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        assertThrows(InvalidKeySpecException.class, () -> skf.generateSecret(spec));
    }

    @Test
    @DisplayName("Неизвестный KeySpec — InvalidKeySpecException")
    void testUnknownKeySpec() throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM, PROVIDER);
        assertThrows(
                InvalidKeySpecException.class,
                () -> skf.generateSecret(new javax.crypto.spec.DESKeySpec(new byte[8])));
    }
}
