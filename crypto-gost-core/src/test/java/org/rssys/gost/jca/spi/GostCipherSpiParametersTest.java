package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("Параметры шифр-SPI: длина IV и тег MGM")
@ExtendWith(JcaTestSupport.class)
class GostCipherSpiParametersTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final HexFormat HEX = HexFormat.of();

    private static final SecretKeySpec STANDARD_KEY =
            new SecretKeySpec(
                    HEX.parseHex(
                            "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
                    "Kuznyechik");

    private static final byte[] IV32 =
            HEX.parseHex("1234567890abcef0a1b2c3d4e5f001122334455667788990" + "1213141516171819");

    private static final byte[] PLAIN =
            HEX.parseHex(
                    "1122334455667700ffeeddccbbaa9988"
                            + "00112233445566778899aabbcceeff0a"
                            + "112233445566778899aabbcceeff0a00"
                            + "2233445566778899aabbcceeff0a0011");

    /** Контрольный пример CBC, ГОСТ Р 34.13-2015, А.1.4 (m = 2n). */
    private static final byte[] CBC_CIPHER_IV32 =
            HEX.parseHex(
                    "689972d4a085fa4d90e52e3d6d7dcc27"
                            + "2826e661b478eca6af1e8e448d5ea5ac"
                            + "fe7babf1e91999e85640e8b0f49d90d0"
                            + "167688065a895c631a2d9a1560b63970");

    private static byte[] icn() {
        byte[] value = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(value);
        value[0] &= 0x7F;
        return value;
    }

    // -----------------------------------------------------------------------
    // Длина IV
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CBC через JCA с IV из 32 байт даёт контрольный пример А.1.4 стандарта")
    void cbcWithTwoBlockIvMatchesStandard() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CBC/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, STANDARD_KEY, new IvParameterSpec(IV32));
        assertArrayEquals(CBC_CIPHER_IV32, cipher.doFinal(PLAIN), "шифртекст при m = 2n");
        assertArrayEquals(IV32, cipher.getIV(), "getIV возвращает IV целиком");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(
            strings = {
                "Kuznyechik/CBC/NoPadding",
                "Kuznyechik/CFB/NoPadding",
                "Kuznyechik/OFB/NoPadding"
            })
    @DisplayName("IV, не кратный блоку, отвергается; кратный принимается")
    void ivLengthMustBeMultipleOfBlock(String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, PROVIDER);
        for (int length : new int[] {0, 1, 15, 17, 31}) {
            assertThrows(
                    InvalidAlgorithmParameterException.class,
                    () ->
                            cipher.init(
                                    Cipher.ENCRYPT_MODE,
                                    STANDARD_KEY,
                                    new IvParameterSpec(new byte[length == 0 ? 1 : length])),
                    "IV длиной " + length + " должен отвергаться");
        }
        for (int length : new int[] {16, 32, 48}) {
            byte[] iv = new byte[length];
            CryptoRandom.INSTANCE.nextBytes(iv);
            assertDoesNotThrow(
                    () -> cipher.init(Cipher.ENCRYPT_MODE, STANDARD_KEY, new IvParameterSpec(iv)),
                    "IV длиной " + length + " должен приниматься");
        }
    }

    @Test
    @DisplayName("CTR принимает IV только в 8 байт")
    void ctrRequiresEightByteIv() throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/CTR/NoPadding", PROVIDER);
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () ->
                        cipher.init(
                                Cipher.ENCRYPT_MODE,
                                STANDARD_KEY,
                                new IvParameterSpec(new byte[16])),
                "CTR с IV в 16 байт");
        assertDoesNotThrow(
                () ->
                        cipher.init(
                                Cipher.ENCRYPT_MODE,
                                STANDARD_KEY,
                                new IvParameterSpec(new byte[8])),
                "CTR с IV в 8 байт");
    }

    // -----------------------------------------------------------------------
    // MGM и GCMParameterSpec
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "tLen={0}")
    @ValueSource(ints = {32, 64, 96, 120})
    @DisplayName("GCMParameterSpec с тегом не 128 бит отвергается: усечение тега не поддерживается")
    void gcmSpecWithTruncatedTagIsRejected(int tagBits) throws Exception {
        Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", PROVIDER);
        InvalidAlgorithmParameterException failure =
                assertThrows(
                        InvalidAlgorithmParameterException.class,
                        () ->
                                cipher.init(
                                        Cipher.ENCRYPT_MODE,
                                        STANDARD_KEY,
                                        new GCMParameterSpec(tagBits, icn())),
                        "тег в " + tagBits + " бит не поддерживается");
        assertTrue(
                failure.getMessage().contains("128"),
                "сообщение должно называть допустимую длину: " + failure.getMessage());
    }

    @Test
    @DisplayName("GCMParameterSpec с тегом в 128 бит работает и совместим с IvParameterSpec")
    void gcmSpecWithFullTagIsAccepted() throws Exception {
        byte[] icn = icn();
        byte[] plain = Arrays.copyOf(PLAIN, 20);

        Cipher encrypt = Cipher.getInstance("Kuznyechik/MGM/NoPadding", PROVIDER);
        encrypt.init(Cipher.ENCRYPT_MODE, STANDARD_KEY, new GCMParameterSpec(128, icn));
        byte[] sealed = encrypt.doFinal(plain);
        assertEquals(plain.length + 16, sealed.length, "шифртекст и тег в 16 байт");

        Cipher decrypt = Cipher.getInstance("Kuznyechik/MGM/NoPadding", PROVIDER);
        decrypt.init(Cipher.DECRYPT_MODE, STANDARD_KEY, new IvParameterSpec(icn));
        assertArrayEquals(plain, decrypt.doFinal(sealed), "расшифрование через IvParameterSpec");
    }
}
