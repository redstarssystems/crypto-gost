package org.rssys.gost.crossval.kuznyechik;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.util.CryptoRandom;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация Кузнечик: crypto-gost vs BouncyCastle.
 *
 * Для каждого режима (CTR, CBC, CFB, OFB) и каждого размера:
 * — шифрование обеими библиотеками → сравнение шифртекстов;
 * — расшифрование шифртекста собеседника → сравнение с исходным plaintext.
 * CBC дополнительно проверяется без паддинга (PKCS7 убирается).
 */
class BcCrossValidationTest {

    private static String keyIv(byte[] key, byte[] iv) {
        return "key=" + CrossValUtils.toHex(key) + " iv=" + CrossValUtils.toHex(iv);
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.kuznyechik.TestData#cipherModeParams")
    @DisplayName("BC-кросс-валидация CTR/CBC/CFB/OFB")
    void crossValidate(Cipher.Mode mode, int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] iv = mode == Cipher.Mode.CTR ? new byte[8] : new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);

        SymmetricKey symmetricKey = new SymmetricKey(key);
        Cipher.Padding padding = TestData.paddingFor(mode);

        String kv = keyIv(key, iv);
        byte[] ciphertextGost = Cipher.encrypt(plaintext, symmetricKey, iv, mode, padding);
        byte[] ciphertextBc = TestData.bcEncrypt(mode, plaintext, key, iv);
        byte[] decryptedGost = TestData.bcDecrypt(mode, ciphertextGost, key, iv);
        byte[] decryptedBc = Cipher.decrypt(ciphertextBc, symmetricKey, iv, mode, padding);

        assertArrayEquals(ciphertextGost, ciphertextBc,
                () -> "Несовпадение шифртекста ГОСТ/BC: mode=" + mode + " size=" + size + " "
                        + CrossValUtils.diffContext(ciphertextGost, ciphertextBc) + " " + kv);
        assertArrayEquals(plaintext, decryptedGost,
                () -> "Ошибка расшифрования шифртекста BC: mode=" + mode + " size=" + size + " "
                        + CrossValUtils.diffContext(plaintext, decryptedGost) + " " + kv);
        assertArrayEquals(plaintext, decryptedBc,
                () -> "Ошибка расшифрования шифртекста ГОСТ: mode=" + mode + " size=" + size + " "
                        + CrossValUtils.diffContext(plaintext, decryptedBc) + " " + kv);
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.kuznyechik.TestData#cbcNoPadSizes")
    @DisplayName("BC-кросс-валидация CBC/NoPad")
    void crossValidateCbcNoPad(int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);

        SymmetricKey symmetricKey = new SymmetricKey(key);

        String kv = keyIv(key, iv);
        byte[] ciphertextGost = Cipher.encrypt(plaintext, symmetricKey, iv, Cipher.Mode.CBC, Cipher.Padding.NONE);
        byte[] ciphertextBc = BcHelper.bcCbc(plaintext, key, iv, true);
        byte[] decryptedGost = BcHelper.bcCbc(ciphertextGost, key, iv, false);
        byte[] decryptedBc = Cipher.decrypt(ciphertextBc, symmetricKey, iv, Cipher.Mode.CBC, Cipher.Padding.NONE);

        assertArrayEquals(ciphertextGost, ciphertextBc,
                () -> "Несовпадение шифртекста ГОСТ/BC: CBC/NoPad size=" + size + " "
                        + CrossValUtils.diffContext(ciphertextGost, ciphertextBc) + " " + kv);
        assertArrayEquals(plaintext, decryptedGost,
                () -> "Ошибка расшифрования шифртекста BC: CBC/NoPad size=" + size + " "
                        + CrossValUtils.diffContext(plaintext, decryptedGost) + " " + kv);
        assertArrayEquals(plaintext, decryptedBc,
                () -> "Ошибка расшифрования шифртекста ГОСТ: CBC/NoPad size=" + size + " "
                        + CrossValUtils.diffContext(plaintext, decryptedBc) + " " + kv);
    }

}
