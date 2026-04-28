package org.rssys.gost.api;

import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.AuthenticationException;

import java.security.MessageDigest;
import java.util.Arrays;

import org.rssys.gost.util.CryptoRandom;

/**
 * API для аутентифицированного шифрования по ГОСТ Р 34.13-2015
 *
 * <p>Реализует схему: шифрование Кузнечиком в режиме CTR (гамма) с контролем
 * целостности через имитовставку CMAC.
 *
 * <h3>Формат пакета:</h3>
 * <pre>
 *   [IV (8 байт)] [CMAC(plaintext) (8 байт)] [ciphertext (N байт)]
 * </pre>
 * Overhead: 16 байт на сообщение.
 *
 *
 * <p>Все методы потокобезопасны.
 */
public final class AuthenticatedCipher {

    /**
     * Длина IV для режима CTR по ГОСТ Р 34.13-2015 §4.4 (n/2 = 8 байт).
     */
    static final int IV_LEN = 8;

    /**
     * Длина усечённого CMAC-тега в пакете (64 бит).
     */
    static final int TAG_LEN = 8;

    /**
     * Минимальная длина пакета: IV + TAG.
     */
    static final int MIN_PACKET_LEN = IV_LEN + TAG_LEN;

    private AuthenticatedCipher() {
    }

    /**
     * Шифрует данные с аутентификацией.
     *
     * <p>CMAC вычисляется от открытого текста согласно ГОСТ Р 34.13-2015 §4.6.
     * IV генерируется случайно при каждом вызове.
     *
     * @param plaintext открытые данные
     * @param key       ключ Кузнечика (32 байта)
     * @return буфер зашифрованных данных вида {@code [IV(8)] [CMAC(8)] [ciphertext(N)]}
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key) {
        byte[] iv = new byte[IV_LEN];
        CryptoRandom.INSTANCE.nextBytes(iv);

        // CMAC от открытого текста (ГОСТ Р 34.13-2015 §4.6)
        byte[] fullTag = computeCmac(plaintext, key);
        byte[] tag = Arrays.copyOf(fullTag, TAG_LEN);

        byte[] ciphertext = ctrEncrypt(plaintext, key, iv);

        // Сборка пакета: [IV(8)] [TAG(8)] [ciphertext(N)]
        byte[] encryptedData = new byte[IV_LEN + TAG_LEN + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, IV_LEN);
        System.arraycopy(tag, 0, encryptedData, IV_LEN, TAG_LEN);
        System.arraycopy(ciphertext, 0, encryptedData, IV_LEN + TAG_LEN, ciphertext.length);

        Arrays.fill(tag, (byte) 0);
        return encryptedData;
    }

    /**
     * Расшифровывает блок данных и проверяет целостность.
     *
     * @param encryptedData пакет вида {@code [IV(8)] [CMAC(8)] [ciphertext(N)]}
     * @param key           ключ Кузнечика (32 байта) — тот же что при {@link #seal}
     * @return открытые данные
     * @throws AuthenticationException если CMAC не совпал (данные повреждены или подменены)
     */
    public static byte[] open(byte[] encryptedData, SymmetricKey key)
            throws AuthenticationException {
        if (encryptedData == null || encryptedData.length < MIN_PACKET_LEN) {
            throw new AuthenticationException(
                    "Packet too short: expected at least " + MIN_PACKET_LEN +
                            " bytes, got " + (encryptedData == null ? 0 : encryptedData.length));
        }

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LEN);
        byte[] tag = Arrays.copyOfRange(encryptedData, IV_LEN, IV_LEN + TAG_LEN);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LEN + TAG_LEN, encryptedData.length);

        byte[] plaintext = ctrEncrypt(ciphertext, key, iv); // CTR симметричен

        // CMAC от расшифрованного открытого текста
        byte[] expected = Arrays.copyOf(computeCmac(plaintext, key), TAG_LEN);

        // Constant-time сравнение (защита от timing-атак)
        boolean valid = MessageDigest.isEqual(expected, tag);

        Arrays.fill(expected, (byte) 0);
        Arrays.fill(iv, (byte) 0);

        if (!valid) {
            Arrays.fill(plaintext, (byte) 0);
            throw new AuthenticationException(
                    "Integrity violation: CMAC mismatch. " +
                            "Data corrupted, tampered, or wrong key used.");
        }

        return plaintext;
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы (package-private — используются в AuthenticatedStream)
    // -----------------------------------------------------------------------

    /**
     * Шифрует/расшифровывает данные в режиме CTR (симметричная операция).
     */
    static byte[] ctrEncrypt(byte[] data, SymmetricKey key, byte[] iv) {
        if (data.length == 0) return new byte[0];
        Ctr ctr = new Ctr(new Kuznyechik());
        ctr.init(true, new ParametersWithIV(key, iv));
        byte[] out = new byte[data.length];
        ctr.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    /**
     * Вычисляет полный CMAC-16 от данных
     */
    static byte[] computeCmac(byte[] data, SymmetricKey key) {
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(key);
        cmac.update(data, 0, data.length);
        byte[] tag = new byte[cmac.getMacSize()];
        cmac.doFinal(tag, 0);
        return tag;
    }
}
