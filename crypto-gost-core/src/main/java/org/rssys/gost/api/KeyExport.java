package org.rssys.gost.api;

import java.security.MessageDigest;
import java.util.Arrays;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

/**
 * Экспорт и импорт ключей по алгоритмам KExp15/KImp15 (RFC 9189 §8.2.1).
 *
 * <p>Алгоритмы основаны на блочном шифре Кузнечик (ГОСТ Р 34.12-2015):
 * аутентифицированное шифрование секрета {@code S} с помощью двух независимых
 * ключей {@code K_ENC} (шифрование) и {@code K_MAC} (имитовставка) в схеме
 * MAC-then-Encrypt: сначала OMAC(IV || S), затем CTR-Encrypt(S || CEK_MAC).
 *
 * <p>Параметры Кузнечика:
 * <ul>
 *   <li>размер блока {@code n = 16} байт (длина CEK_MAC)</li>
 *   <li>размер ключа {@code k = 32} байта</li>
 *   <li>длина IV = {@code n/2 = 8} байт</li>
 * </ul>
 *
 * <p><b>Пример использования (типовой сценарий с KDF_TREE):</b>
 * <pre>{@code
 * // Отправитель вырабатывает K_ENC и K_MAC из ключа переноса KEK.
 * // Порядок следования K_MAC/K_ENC в keys определяется протоколом,
 * // здесь — условный пример (keys[0..31] -> K_MAC, keys[32..63] -> K_ENC).
 * byte[] ukm = new byte[8];
 * CryptoRandom.INSTANCE.nextBytes(ukm);
 * byte[] keys = KdfTreeGostR3411_2012_256.generate(
 *     kek, "kexp15".getBytes(), ukm, 2, 32);
 * SymmetricKey kMac = new SymmetricKey(Arrays.copyOfRange(keys, 0, 32));
 * SymmetricKey kEnc = new SymmetricKey(Arrays.copyOfRange(keys, 32, 64));
 * Arrays.fill(keys, (byte) 0);
 *
 * // Экспорт
 * byte[] wrapped = KeyExport.kExp15(secret, kMac, kEnc, ukm);
 *
 * // Получатель: те же шаги для kEnc/kMac из KEK + UKM
 * byte[] restored = KeyExport.kImp15(wrapped, kMac, kEnc, ukm);
 * }</pre>
 *
 * <p>Все методы статические и потокобезопасны.
 *
 * @see CmacApi
 * @see Cipher
 * @see org.rssys.gost.kdf.KdfTreeGostR3411_2012_256
 */
public final class KeyExport {

    /** Размер блока Кузнечика (и тега CMAC) в байтах. */
    static final int BLOCK_SIZE = 16;

    /** Длина IV в байтах (n/2). */
    static final int IV_LENGTH = 8;

    /** Размер ключа Кузнечика в байтах. */
    static final int KEY_LENGTH = 32;

    private KeyExport() {}

    /**
     * KExp15: экспорт ключа (RFC 9189 §8.2.1).
     *
     * <p>Вычисляет OMAC-128(K_MAC, IV || secret) и упаковывает
     * {@code secret || CEK_MAC} в CTR-шифртекст.
     *
     * <p>Порядок параметров соответствует RFC 9189 §8.2.1: K_MAC перед K_ENC.
     *
     * @param secret экспортируемый секрет (должен быть непустым)
     * @param kMac   ключ имитовставки (32 байта)
     * @param kEnc   ключ шифрования (32 байта)
     * @param iv     вектор инициализации (8 байт)
     * @return зашифрованный секрет длиной {@code secret.length + 16} байт
     * @throws IllegalArgumentException при невалидных аргументах
     */
    public static byte[] kExp15(byte[] secret, SymmetricKey kMac, SymmetricKey kEnc, byte[] iv) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret must not be null or empty");
        }
        if (kEnc == null || kMac == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }
        if (iv == null || iv.length != IV_LENGTH) {
            throw new IllegalArgumentException(
                    "IV must be " + IV_LENGTH + " bytes, got " + (iv == null ? "null" : iv.length));
        }

        byte[] cekMac = null;
        try {
            // CMAC: OMAC(K_MAC, IV || secret)
            cekMac = new CmacApi(kMac).update(iv).update(secret).digest();

            // CTR-Encrypt(K_ENC, IV, secret || CEK_MAC)
            byte[] plaintext = concat(secret, cekMac);
            try {
                return Cipher.encrypt(plaintext, kEnc, iv, Cipher.Mode.CTR);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } finally {
            if (cekMac != null) {
                Arrays.fill(cekMac, (byte) 0);
            }
        }
    }

    /**
     * KImp15: импорт ключа (RFC 9189 §8.2.1).
     *
     * <p>Дешифрует CTR-шифртекст, разделяет на секрет и CEK_MAC,
     * верифицирует имитовставку. При несовпадении MAC — fail-closed.
     * Затирает промежуточные массивы даже при неожиданном исключении.
     *
     * @param sExp зашифрованный секрет (длиной не менее 17 байт)
     * @param kMac ключ имитовставки (32 байта)
     * @param kEnc ключ шифрования (32 байта)
     * @param iv   вектор инициализации (8 байт)
     * @return расшифрованный секрет
     * @throws AuthenticationException если MAC не совпадает
     * @throws IllegalArgumentException при невалидных аргументах
     */
    public static byte[] kImp15(byte[] sExp, SymmetricKey kMac, SymmetricKey kEnc, byte[] iv)
            throws AuthenticationException {
        if (sExp == null || sExp.length < BLOCK_SIZE + 1) {
            throw new IllegalArgumentException(
                    "Wrapped key must be at least " + (BLOCK_SIZE + 1) + " bytes");
        }
        if (kEnc == null || kMac == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }
        if (iv == null || iv.length != IV_LENGTH) {
            throw new IllegalArgumentException(
                    "IV must be " + IV_LENGTH + " bytes, got " + (iv == null ? "null" : iv.length));
        }

        int secretLen = sExp.length - BLOCK_SIZE;

        byte[] plain = null;
        byte[] secret = null;
        byte[] cekMac = null;
        byte[] expected = null;
        boolean success = false;
        try {
            plain = Cipher.decrypt(sExp, kEnc, iv, Cipher.Mode.CTR);

            // RFC 9189 §8.2.1: SExp = CTR-Encrypt(K_ENC, IV, S || CEK_MAC),
            // поэтому после decrypt: plain = S || CEK_MAC
            secret = Arrays.copyOfRange(plain, 0, secretLen);
            cekMac = Arrays.copyOfRange(plain, secretLen, sExp.length);

            // OMAC(K_MAC, IV || S)
            expected = new CmacApi(kMac).update(iv).update(secret).digest();

            if (!MessageDigest.isEqual(expected, cekMac)) {
                Arrays.fill(secret, (byte) 0);
                secret = null;
                throw new AuthenticationException("KImp15 MAC mismatch");
            }

            success = true;
            return secret;
        } finally {
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
            if (cekMac != null) {
                Arrays.fill(cekMac, (byte) 0);
            }
            if (expected != null) {
                Arrays.fill(expected, (byte) 0);
            }
            if (!success && secret != null) {
                Arrays.fill(secret, (byte) 0);
            }
        }
    }

    /**
     * Склеивает два массива в новый.
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
