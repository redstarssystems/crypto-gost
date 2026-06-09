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
 * <p>Реализует схему Encrypt-then-MAC (EtM): сначала шифрование Кузнечиком
 * в режиме CTR, затем имитовставка CMAC от шифртекста. Верификация
 * выполняется до расшифрования — неверный тег не даёт oracle на plaintext.
 *
 * <h3>Формат пакета:</h3>
 * <pre>
 *   [IV (8 байт)] [CMAC(ciphertext) (16 байт)] [ciphertext (N байт)]
 * </pre>
 * Overhead: 24 байта на сообщение.
 *
 * <p>Все методы потокобезопасны.
 */
public final class AuthenticatedCipher {

    /**
     * Длина IV для режима CTR по ГОСТ Р 34.13-2015 §4.4 (n/2 = 8 байт).
     */
    static final int IV_LEN = 8;

    /**
     * Длина полного CMAC-тега в пакете (128 бит = размер блока Кузнечика).
     */
    static final int TAG_LEN = 16;

    /**
     * Минимальная длина пакета: IV + TAG.
     */
    static final int MIN_PACKET_LEN = IV_LEN + TAG_LEN;

    private AuthenticatedCipher() {
    }

    /**
     * Шифрует данные с аутентификацией (Encrypt-then-MAC).
     *
     * <p>Порядок: CTR-шифрование, затем CMAC от шифртекста.
     * IV генерируется случайно при каждом вызове.
     *
     * @param plaintext открытые данные
     * @param key       ключ Кузнечика (32 байта)
     * @return буфер зашифрованных данных вида {@code [IV(8)] [CMAC(16)] [ciphertext(N)]}
     */
    public static byte[] seal(byte[] plaintext, SymmetricKey key) {
        byte[] iv = new byte[IV_LEN];
        CryptoRandom.INSTANCE.nextBytes(iv);

        byte[] ciphertext = ctrEncrypt(plaintext, key, iv);

        // CMAC(IV || ciphertext) — IV тоже аутентифицируется
        byte[] fullTag = computeCmac(iv, ciphertext, key);

        // Сборка пакета: [IV(8)] [TAG(16)] [ciphertext(N)]
        byte[] encryptedData = new byte[IV_LEN + TAG_LEN + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, IV_LEN);
        System.arraycopy(fullTag, 0, encryptedData, IV_LEN, TAG_LEN);
        System.arraycopy(ciphertext, 0, encryptedData, IV_LEN + TAG_LEN, ciphertext.length);

        Arrays.fill(fullTag, (byte) 0);
        return encryptedData;
    }

    /**
     * Расшифровывает блок данных и проверяет целостность.
     *
     * <p>Верификация CMAC от шифртекста выполняется до расшифрования —
     * неверный тег не даёт oracle на plaintext.
     *
     * @param encryptedData пакет вида {@code [IV(8)] [CMAC(16)] [ciphertext(N)]}
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

        // CMAC(IV || ciphertext) — верификация ДО расшифрования
        byte[] expected = computeCmac(iv, ciphertext, key);

        boolean valid = MessageDigest.isEqual(expected, tag);

        Arrays.fill(expected, (byte) 0);

        if (!valid) {
            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(tag, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            throw new AuthenticationException(
                    "Integrity violation: CMAC mismatch. " +
                            "Data corrupted, tampered, or wrong key used.");
        }

        // Только после успешной верификации — расшифрование
        byte[] plaintext = ctrEncrypt(ciphertext, key, iv);

        Arrays.fill(ciphertext, (byte) 0);
        Arrays.fill(tag, (byte) 0);
        Arrays.fill(iv, (byte) 0);

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
        return computeCmac(null, data, key);
    }

    /**
     * Вычисляет CMAC от AAD || data.
     *
     * @param aad  дополнительные аутентифицированные данные (может быть null)
     * @param data основные данные
     * @param key  ключ Кузнечика (32 байта)
     * @return полный CMAC (16 байт)
     */
    static byte[] computeCmac(byte[] aad, byte[] data, SymmetricKey key) {
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(key);
        if (aad != null) {
            cmac.update(aad, 0, aad.length);
        }
        cmac.update(data, 0, data.length);
        byte[] tag = new byte[cmac.getMacSize()];
        cmac.doFinal(tag, 0);
        return tag;
    }
}
