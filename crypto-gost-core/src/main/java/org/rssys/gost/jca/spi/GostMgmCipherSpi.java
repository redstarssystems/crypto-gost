package org.rssys.gost.jca.spi;

import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.AuthenticationException;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.rssys.gost.util.CryptoRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Реализация {@link CipherSpi} для аутентифицированного шифрования
 * Кузнечик-MGM (Multilinear Galois Mode, RFC 9058).
 *
 * <p>Регистрируется в провайдере как {@code "Kuznyechik/MGM/NoPadding"}.
 *
 * <p>Пример использования:
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("Kuznyechik/MGM/NoPadding", provider);
 *
 * // Шифрование
 * cipher.init(Cipher.ENCRYPT_MODE, key);        // ICN генерируется автоматически
 * cipher.updateAAD(aad);
 * byte[] ciphertext = cipher.doFinal(plaintext); // без ICN — только C || T
 * byte[] icn = cipher.getIV();                  // ICN для передачи получателю
 *
 * // Расшифрование
 * cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(icn));
 * cipher.updateAAD(aad);
 * byte[] plaintext = cipher.doFinal(ciphertext); // бросает AEADBadTagException при ошибке
 * }</pre>
 */
public final class GostMgmCipherSpi extends CipherSpi {

    /**
     * Длина ICN для Кузнечика-MGM: 16 байт (127-битное значение, MSB=0, RFC 9058 §3).
     */
    private static final int ICN_LEN = 16;
    /** Размер тега в байтах. */
    private static final int TAG_LEN = 16;

    private Mgm     mgm;
    private boolean forEncryption;
    private byte[]  icn;
    private boolean initialized;
    private boolean aadUpdated;

    /** Буфер накопленного ввода (для расшифрования нужно знать где тег). */
    private byte[] inputBuffer = new byte[0];

    /**
     * Режим задаётся только как часть трансформации «Kuznyechik/MGM/NoPadding».
     * Отдельной установки не требует; любое значение кроме «MGM» отклоняется.
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"MGM".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException(
                "Only MGM mode is supported by this SPI, got: " + mode);
        }
    }

    /** Единственный поддерживаемый padding — NoPadding (MGM — потоковый AEAD). */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException(
                "Only NoPadding is supported for MGM, got: " + padding);
        }
    }

    /** @return 16 . */
    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    /**
     * Возвращает ICN, использованный при последней инициализации.
     *
     * @return копию ICN или {@code null} если не инициализирован
     */
    @Override
    protected byte[] engineGetIV() {
        return (icn != null) ? Arrays.copyOf(icn, icn.length) : null;
    }

    /**
     * Возвращает ожидаемый размер выходного буфера.
     * <p>
     * При шифровании:  входные данные + TAG_LEN (тег добавляется в {@code doFinal}).
     * При расшифровании: max(0, ввод - TAG_LEN).
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        int total = inputBuffer.length + inputLen;
        if (forEncryption) {
            return total + TAG_LEN;
        } else {
            return Math.max(0, total - TAG_LEN);
        }
    }

    /** @return {@code null} — отдельные AlgorithmParameters не используются. */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        SymmetricKey keyParam = extractSymmetricKey(key);
        forEncryption = (opmode == javax.crypto.Cipher.ENCRYPT_MODE
                      || opmode == javax.crypto.Cipher.WRAP_MODE);

        if (params instanceof IvParameterSpec) {
            byte[] iv = ((IvParameterSpec) params).getIV();
            validateIcn(iv);
            icn = Arrays.copyOf(iv, iv.length);
        } else if (params instanceof GCMParameterSpec) {
            byte[] iv = ((GCMParameterSpec) params).getIV();
            validateIcn(iv);
            icn = Arrays.copyOf(iv, iv.length);
        } else if (params == null) {
            if (forEncryption) {
                // Генерируем случайный ICN при шифровании; MSB должен быть 0 (RFC 9058 §3)
                icn = new byte[ICN_LEN];
                (random != null ? random : CryptoRandom.INSTANCE).nextBytes(icn);
                icn[0] &= 0x7F; // обеспечиваем MSB=0
            } else {
                throw new InvalidAlgorithmParameterException(
                    "MGM decryption requires an ICN (IvParameterSpec with 16 bytes, MSB=0)");
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                "Unsupported parameter type: " + params.getClass().getName()
                + ". Use IvParameterSpec(16 bytes, MSB=0) or GCMParameterSpec");
        }

        if (mgm != null) mgm.destroy();
        mgm = new Mgm(new Kuznyechik());
        mgm.init(forEncryption, new ParametersWithIV(keyParam, icn));

        inputBuffer = new byte[0];
        aadUpdated  = false;
        initialized = true;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException(
                    "Cannot extract IvParameterSpec from AlgorithmParameters", e);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Init failed: " + e.getMessage(), e);
        }
    }

    /**
     * Добавляет ассоциированные данные.
     * Должен вызываться до первого {@code update}/{@code doFinal}.
     */
    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        checkInitialized();
        mgm.updateAAD(src, offset, len);
        aadUpdated = true;
    }

    /**
     * Накапливает входные данные.
     * <p>
     * MGM обрабатывает данные только в {@code doFinal}, чтобы при расшифровании
     * корректно отделить тег (последние TAG_LEN байт) от шифртекста.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();
        appendToBuffer(input, inputOffset, inputLen);
        return new byte[0]; // накопление — вывод пуст до doFinal
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    /**
     * Финализирует шифрование или расшифрование.
     * <p>
     * При шифровании: обрабатывает все накопленные данные, добавляет тег.
     * Выход: {@code [шифртекст] [тег (16 байт)]}.
     * <p>
     * При расшифровании: отделяет тег (последние 16 байт буфера),
     * расшифровывает шифртекст, верифицирует тег.
     * Бросает {@link AEADBadTagException} при несовпадении — данные не возвращаются.
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        if (input != null && inputLen > 0) {
            appendToBuffer(input, inputOffset, inputLen);
        }

        try {
            if (forEncryption) {
                return doFinalEncrypt();
            } else {
                return doFinalDecrypt();
            }
        } finally {
            // Сбрасываем буфер после завершения
            inputBuffer = new byte[0];
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (result.length > output.length - outputOffset) {
            throw new ShortBufferException(
                "Output buffer too small: need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }


    /** Шифрует все накопленные данные и добавляет тег. */
    private byte[] doFinalEncrypt() {
        int   ptLen = inputBuffer.length;
        byte[] out  = new byte[ptLen + TAG_LEN];

        mgm.processBytes(inputBuffer, 0, ptLen, out, 0);
        mgm.finishEncryption(out, ptLen);

        return out;
    }

    /**
     * Расшифровывает накопленные данные и верифицирует тег.
     * Тег — последние TAG_LEN байт буфера.
     */
    private byte[] doFinalDecrypt() throws BadPaddingException {
        if (inputBuffer.length < TAG_LEN) {
            throw new AEADBadTagException(
                "Input too short to contain MGM tag: need at least "
                + TAG_LEN + " bytes, got " + inputBuffer.length);
        }

        int    ctLen      = inputBuffer.length - TAG_LEN;
        byte[] ciphertext = Arrays.copyOf(inputBuffer, ctLen);

        byte[] plaintext = new byte[ctLen];
        if (ctLen > 0) {
            mgm.processBytes(ciphertext, 0, ctLen, plaintext, 0);
        }

        try {
            // Тег — последние TAG_LEN байт
            mgm.finishDecryption(inputBuffer, ctLen);
        } catch (AuthenticationException e) {
            // Обнуляем открытый текст перед выбросом исключения
            Arrays.fill(plaintext, (byte) 0);
            throw new AEADBadTagException("MGM authentication tag mismatch");
        }

        return plaintext;
    }

    /** Добавляет байты в конец внутреннего буфера. */
    private void appendToBuffer(byte[] input, int offset, int len) {
        if (len <= 0) return;
        byte[] newBuf = new byte[inputBuffer.length + len];
        System.arraycopy(inputBuffer, 0, newBuf, 0, inputBuffer.length);
        System.arraycopy(input, offset, newBuf, inputBuffer.length, len);
        inputBuffer = newBuf;
    }

    /**
     * Проверяет ICN: 16 байт, старший бит = 0 (RFC 9058 §3).
     */
    private static void validateIcn(byte[] iv) throws InvalidAlgorithmParameterException {
        if (iv == null || iv.length != ICN_LEN) {
            throw new InvalidAlgorithmParameterException(
                "MGM ICN (IV) must be exactly " + ICN_LEN + " bytes (MSB=0), got "
                + (iv == null ? "null" : iv.length));
        }
        if ((iv[0] & 0x80) != 0) {
            throw new InvalidAlgorithmParameterException(
                "MGM ICN MSB (bit 127) must be 0 per RFC 9058 §3");
        }
    }

    /**
     * Извлекает {@link SymmetricKey} из JCA-ключа.
     */
    private static SymmetricKey extractSymmetricKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (key instanceof GostSecretKey) {
            return ((GostSecretKey) key).toSymmetricKey();
        }
        if (key instanceof SecretKey && "RAW".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            if (encoded == null || encoded.length != 32) {
                throw new InvalidKeyException(
                    "Kuznyechik requires 32-byte key, got "
                    + (encoded == null ? "null" : encoded.length));
            }
            return new SymmetricKey(encoded);
        }
        throw new InvalidKeyException(
            "Unsupported key type: " + key.getClass().getName()
            + ". Expected GostSecretKey or SecretKey with RAW format");
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException(
                "Cipher not initialized — call init() first");
        }
    }
}
