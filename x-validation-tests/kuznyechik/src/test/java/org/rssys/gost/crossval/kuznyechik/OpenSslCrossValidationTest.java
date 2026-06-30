package org.rssys.gost.crossval.kuznyechik;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.Cipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.util.CryptoRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Кросс-валидация Кузнечик: crypto-gost vs OpenSSL.
 *
 * Для каждого режима (CTR, CBC, CFB, OFB) и размера:
 * — шифрование обеими -> сравнение;
 * — расшифрование шифртекста собеседника -> сверка с plaintext.
 * Тест пропускается, если OpenSSL недоступен или собран без Кузнечика.
 */
class OpenSslCrossValidationTest {

    @BeforeAll
    static void checkOpenSsl() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeKuznyechikCipher();
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.kuznyechik.TestData#cbcNoPadSizes")
    @DisplayName("Кросс-валидация с OpenSSL CBC/NoPad")
    void crossValidateCbcNoPad(int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);

        SymmetricKey symmetricKey = new SymmetricKey(key);

        String kv = "key=" + CrossValUtils.toHex(key) + " iv=" + CrossValUtils.toHex(iv);
        byte[] ciphertextGost = Cipher.encrypt(plaintext, symmetricKey, iv, Cipher.Mode.CBC, Cipher.Padding.NONE);
        byte[] ciphertextOpenSsl = CompatHelper.opensslOp(Cipher.Mode.CBC, "-e", key, iv, plaintext, true);

        assertArrayEquals(ciphertextGost, ciphertextOpenSsl,
                () -> "Несовпадение шифртекста: CBC/NoPad size=" + size
                        + " " + CrossValUtils.diffContext(ciphertextGost, ciphertextOpenSsl) + " " + kv);

        byte[] decryptedFromOpenSsl = Cipher.decrypt(ciphertextOpenSsl, symmetricKey, iv, Cipher.Mode.CBC, Cipher.Padding.NONE);
        assertArrayEquals(plaintext, decryptedFromOpenSsl,
                () -> "OpenSSL->ГОСТ ошибка: CBC/NoPad size=" + size
                        + " " + CrossValUtils.diffContext(plaintext, decryptedFromOpenSsl) + " " + kv);

        byte[] decryptedFromGost = CompatHelper.opensslOp(Cipher.Mode.CBC, "-d", key, iv, ciphertextGost, true);
        assertArrayEquals(plaintext, decryptedFromGost,
                () -> "ГОСТ->OpenSSL ошибка: CBC/NoPad size=" + size
                        + " " + CrossValUtils.diffContext(plaintext, decryptedFromGost) + " " + kv);
    }

    @ParameterizedTest
    @MethodSource("org.rssys.gost.crossval.kuznyechik.TestData#cipherModeParams")
    @DisplayName("Кросс-валидация с OpenSSL")
    void crossValidate(Cipher.Mode mode, int size) throws Exception {
        byte[] key = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(iv);
        byte[] plaintext = TestData.randomBytes(size, CryptoRandom.INSTANCE);

        SymmetricKey symmetricKey = new SymmetricKey(key);
        Cipher.Padding padding = TestData.paddingFor(mode);

        byte[] ivForGost = mode == Cipher.Mode.CTR
                ? java.util.Arrays.copyOf(iv, 8)
                : iv;
        String kv = "key=" + CrossValUtils.toHex(key) + " iv=" + CrossValUtils.toHex(iv);
        byte[] ciphertextGost = Cipher.encrypt(plaintext, symmetricKey, ivForGost, mode, padding);

        byte[] ciphertextOpenSsl = CompatHelper.opensslOp(mode, "-e", key, iv, plaintext);
        assertArrayEquals(ciphertextGost, ciphertextOpenSsl,
                () -> "Несовпадение шифртекста: mode=" + mode + " size=" + size
                        + " " + CrossValUtils.diffContext(ciphertextGost, ciphertextOpenSsl) + " " + kv);

        byte[] decryptedFromOpenSsl = Cipher.decrypt(ciphertextOpenSsl, symmetricKey, ivForGost, mode, padding);
        assertArrayEquals(plaintext, decryptedFromOpenSsl,
                () -> "OpenSSL->ГОСТ ошибка дешифровки: mode=" + mode + " size=" + size
                        + " " + CrossValUtils.diffContext(plaintext, decryptedFromOpenSsl) + " " + kv);

        byte[] decryptedFromGost = CompatHelper.opensslOp(mode, "-d", key, iv, ciphertextGost);
        assertArrayEquals(plaintext, decryptedFromGost,
                () -> "ГОСТ->OpenSSL ошибка дешифровки: mode=" + mode + " size=" + size
                        + " " + CrossValUtils.diffContext(plaintext, decryptedFromGost) + " " + kv);
    }
}
