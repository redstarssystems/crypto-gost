package org.rssys.gost.jca;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.CmacApi;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GostMacSpi — HMAC и CMAC через JCA Mac")
class GostMacTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] DATA = "тест MAC ГОСТ".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    // -----------------------------------------------------------------------
    // HMAC-Стрибог-256
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("HmacGOST3411-2012-256: getInstance не бросает исключений")
    void testGetInstanceHmac256() throws Exception {
        Mac mac = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);
        assertNotNull(mac);
        assertEquals(32, mac.getMacLength());
    }

    @Test
    @DisplayName("HmacGOST3411-2012-256: результат совпадает с Digest.hmac256")
    void testHmac256MatchesReferenceApi() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("HmacGOST3411-2012-256", keyParam);

        Mac mac    = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);
        mac.init(key);
        byte[] jcaResult = mac.doFinal(DATA);

        byte[] refResult = Digest.hmac256(DATA, keyParam);
        assertArrayEquals(refResult, jcaResult,
            "JCA Mac должен давать тот же результат что и Digest.hmac256");
    }

    @Test
    @DisplayName("HmacGOST3411-2012-256: SecretKeySpec с форматом RAW принимается")
    void testHmac256WithSecretKeySpec() throws Exception {
        byte[] rawKey = KeyGenerator.generateSymmetricKey().getKey();
        SecretKeySpec key = new SecretKeySpec(rawKey, "HmacGOST3411-2012-256");

        Mac mac = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);
        mac.init(key);
        byte[] result = mac.doFinal(DATA);
        assertEquals(32, result.length);
    }

    @Test
    @DisplayName("HmacGOST3411-2012-256: инкрементальный update = однократный doFinal")
    void testHmac256Incremental() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("HmacGOST3411-2012-256", keyParam);

        Mac mac = Mac.getInstance("HmacGOST3411-2012-256", PROVIDER);

        // Полный вызов
        mac.init(key);
        byte[] full = mac.doFinal(DATA);

        // Инкрементальный
        mac.init(key);
        for (byte b : DATA) {
            mac.update(b);
        }
        byte[] incremental = mac.doFinal();

        assertArrayEquals(full, incremental);
    }

    // -----------------------------------------------------------------------
    // HMAC-Стрибог-512
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("HmacGOST3411-2012-512: результат совпадает с Digest.hmac512, длина 64")
    void testHmac512MatchesReferenceApi() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("HmacGOST3411-2012-512", keyParam);

        Mac mac    = Mac.getInstance("HmacGOST3411-2012-512", PROVIDER);
        mac.init(key);
        byte[] jcaResult = mac.doFinal(DATA);

        byte[] refResult = Digest.hmac512(DATA, keyParam);
        assertArrayEquals(refResult, jcaResult);
        assertEquals(64, jcaResult.length);
    }

    @Test
    @DisplayName("HmacGOST3411-2012-512: эталонный вектор RFC 7836 Appendix B")
    void testHmac512_RFC7836_AppendixB() throws Exception {
        // RFC 7836, Appendix B — HMAC_GOSTR3411_2012_512
        // Ключ K = 00 01 02 ... 1f (32 байта)
        byte[] rawKey = new byte[32];
        for (int i = 0; i < 32; i++) rawKey[i] = (byte) i;

        byte[] msg = fromHex("0126bdb87800af214341456563780100");

        String expected = "a59bab22ecae19c65fbde6e5f4e9f5d8" +
                          "549d31f037f9df9b905500e171923a77" +
                          "3d5f1530f2ed7e964cb2eedc29e9ad2f" +
                          "3afe93b2814f79f5000ffc0366c251e6";

        SecretKeySpec key = new SecretKeySpec(rawKey, "HmacGOST3411-2012-512");
        Mac mac = Mac.getInstance("HmacGOST3411-2012-512", PROVIDER);
        mac.init(key);
        byte[] result = mac.doFinal(msg);

        assertEquals(expected, toHex(result),
            "JCA HMAC-512 должен совпадать с эталоном RFC 7836 Appendix B");
    }

    // -----------------------------------------------------------------------
    // CMAC-Кузнечик
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CMAC-Kuznyechik: getInstance не бросает исключений")
    void testGetInstanceCmac() throws Exception {
        Mac mac = Mac.getInstance("CMAC-Kuznyechik", PROVIDER);
        assertNotNull(mac);
        assertEquals(16, mac.getMacLength());
    }

    @Test
    @DisplayName("CMAC-Kuznyechik: результат совпадает с CmacApi.cmac")
    void testCmacMatchesReferenceApi() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);

        Mac mac = Mac.getInstance("CMAC-Kuznyechik", PROVIDER);
        mac.init(key);
        byte[] jcaResult = mac.doFinal(DATA);

        byte[] refResult = CmacApi.cmac(DATA, keyParam);
        assertArrayEquals(refResult, jcaResult,
            "JCA Mac должен давать тот же результат что и CmacApi.cmac");
        assertEquals(16, jcaResult.length);
    }

    @Test
    @DisplayName("CMAC-Kuznyechik: инкрементальный update = однократный doFinal")
    void testCmacIncremental() throws Exception {
        SymmetricKey keyParam = KeyGenerator.generateSymmetricKey();
        GostSecretKey key     = new GostSecretKey("Kuznyechik", keyParam);

        Mac mac = Mac.getInstance("CMAC-Kuznyechik", PROVIDER);

        mac.init(key);
        byte[] full = mac.doFinal(DATA);

        mac.init(key);
        mac.update(DATA, 0, DATA.length / 2);
        mac.update(DATA, DATA.length / 2, DATA.length - DATA.length / 2);
        byte[] chunked = mac.doFinal();

        assertArrayEquals(full, chunked);
    }

    @Test
    @DisplayName("CMAC-Kuznyechik: разные ключи дают разные теги")
    void testCmacDifferentKeys() throws Exception {
        SymmetricKey key1 = KeyGenerator.generateSymmetricKey();
        SymmetricKey key2 = KeyGenerator.generateSymmetricKey();

        Mac mac = Mac.getInstance("CMAC-Kuznyechik", PROVIDER);

        mac.init(new GostSecretKey("Kuznyechik", key1));
        byte[] tag1 = mac.doFinal(DATA);

        mac.init(new GostSecretKey("Kuznyechik", key2));
        byte[] tag2 = mac.doFinal(DATA);

        assertFalse(java.util.Arrays.equals(tag1, tag2),
            "Разные ключи должны давать разные теги");
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                             + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return data;
    }
}
