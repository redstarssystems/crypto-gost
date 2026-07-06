package org.rssys.gost.jca.spi;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.cipher.mode.Ofb;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.ISO7816d4Padding;
import org.rssys.gost.util.Pkcs7Padding;

/**
 * Реализация {@link CipherSpi} для алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015)
 * <b>Важно:</b> JCE управляет буферизацией. Для потоковых режимов (CTR/CFB/OFB)
 * {@code engineUpdate} возвращает байты по мере поступления. Для CBC — блоками.
 *
 * <p><b>Безопасность (режим CTR):</b> при инициализации без параметров nonce
 * генерируется случайно и составляет всего 64 бита (блок счётчика по
 * ГОСТ Р 34.13-2015 §4.4 = IV(8 байт) ‖ counter(8 байт), младшая половина —
 * счётчик, поэтому расширить nonce нельзя). Безопасный предел — не более
 * ~2^16 сообщений на одном ключе. При его превышении растёт вероятность
 * коллизии nonce по «парадоксу дней рождения» (≈50% к ~2^32 сообщений):
 * совпадение nonce даёт одинаковый keystream (счётчик у обоих стартует с 0),
 * и XOR двух шифртекстов раскрывает открытый текст — потеря
 * конфиденциальности. Для больших объёмов передавайте явный уникальный nonce
 * через {@link IvParameterSpec} (например, монотонный счётчик) либо
 * используйте {@code Kuznyechik/CTR-ACPKM} (детерминированный UKM + секционная
 * смена ключа). Подробности — ADR-06 (crypto-gost-core/doc/adr/adr-06.adoc).
 */
public final class GostCipherSpi extends CipherSpi {

    private static final int BLOCK_SIZE = 16;

    private static final String MODE_CTR = "CTR";
    private static final String MODE_CBC = "CBC";
    private static final String MODE_CFB = "CFB";
    private static final String MODE_OFB = "OFB";

    private static final String PAD_NONE = "NoPadding";
    private static final String PAD_PKCS5 = "PKCS5Padding";
    private static final String PAD_PKCS7 = "PKCS7Padding";
    private static final String PAD_ISO = "ISO7816-4";

    /** Текущий режим шифрования. По умолчанию CTR. */
    private String mode = MODE_CTR;

    /** Текущий padding. По умолчанию NoPadding. */
    private String padding = PAD_NONE;

    /** Активный блочный шифр с режимом (Ctr/Cbc/Cfb/Ofb). */
    private BlockCipher cipher;

    /** Признак шифрования (true) или расшифрования (false). */
    private boolean forEncryption;

    /** IV, использованный при инициализации (для engineGetIV). */
    private byte[] currentIv;

    /** Буфер накопленных входных данных (для CBC и потоковых режимов). */
    private byte[] inputBuffer = new byte[0];

    /** Признак того, что шифр инициализирован. */
    private boolean initialized = false;

    /**
     * Устанавливает режим шифрования.
     *
     * @param modeStr CTR, CBC, CFB, OFB
     * @throws NoSuchAlgorithmException если режим не поддерживается
     */
    @Override
    protected void engineSetMode(String modeStr) throws java.security.NoSuchAlgorithmException {
        if (modeStr == null) {
            throw new java.security.NoSuchAlgorithmException("Mode must not be null");
        }
        String upper = modeStr.toUpperCase();
        if (!upper.equals(MODE_CTR)
                && !upper.equals(MODE_CBC)
                && !upper.equals(MODE_CFB)
                && !upper.equals(MODE_OFB)) {
            throw new java.security.NoSuchAlgorithmException(
                    "Unsupported mode: " + modeStr + ". Supported: CTR, CBC, CFB, OFB");
        }
        this.mode = upper;
    }

    /**
     * Устанавливает схему дополнения.
     *
     * @param paddingStr NoPadding, PKCS5Padding, PKCS7Padding, ISO7816-4
     * @throws NoSuchPaddingException если padding не поддерживается
     */
    @Override
    protected void engineSetPadding(String paddingStr) throws NoSuchPaddingException {
        if (paddingStr == null) {
            throw new NoSuchPaddingException("Padding must not be null");
        }
        String norm = paddingStr.trim();
        if (norm.equalsIgnoreCase(PAD_NONE)
                || norm.equalsIgnoreCase(PAD_PKCS5)
                || norm.equalsIgnoreCase(PAD_PKCS7)
                || norm.equalsIgnoreCase(PAD_ISO)) {
            this.padding = norm;
        } else {
            throw new NoSuchPaddingException(
                    "Unsupported padding: "
                            + paddingStr
                            + ". Supported: NoPadding, PKCS5Padding, PKCS7Padding, ISO7816-4");
        }
    }

    /** @return 16 Для потоковых режимов JCE ожидает 1 или BLOCK_SIZE. */
    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    /**
     * Возвращает IV.
     *
     * @return копию IV или {@code null} если шифр не инициализирован
     */
    @Override
    protected byte[] engineGetIV() {
        return (currentIv != null) ? Arrays.copyOf(currentIv, currentIv.length) : null;
    }

    /**
     * Возвращает ожидаемый размер выходного буфера для {@code inputLen} байт входа.
     * <p>
     * Для потоковых режимов (CTR/CFB/OFB) вывод = ввод.
     * Для CBC с padding — выровнен до кратного блоку.
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        int buffered = inputBuffer.length;
        int total = buffered + inputLen;
        if (!mode.equals(MODE_CBC)) {
            // Потоковые режимы: вывод совпадает с вводом
            return total;
        }
        if (forEncryption) {
            // При шифровании с padding: до следующего полного блока
            if (!isPaddingNone()) {
                return ((total / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return (total / BLOCK_SIZE) * BLOCK_SIZE;
        } else {
            // При расшифровании: не меньше total (padding будет снят в doFinal)
            return total;
        }
    }

    /** @return {@code null} — отдельные AlgorithmParameters не поддерживаются */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Инициализирует шифр с ключом и параметрами алгоритма.
     * <p>
     * Принимает {@link IvParameterSpec} для IV. Если параметры {@code null} —
     * IV генерируется случайным образом через {@code random}.
     * <p>
     * Для CTR авто-nonce ограничен 64 битами и безопасен лишь до ~2^16
     * сообщений на ключ (см. Javadoc класса / ADR-06); для контроля над
     * уникальностью передавайте {@link IvParameterSpec} с явным значением.
     */
    @Override
    protected void engineInit(
            int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        SymmetricKey keyParam = extractSymmetricKey(key);

        byte[] iv;
        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
            validateIv(iv);
        } else if (params == null) {
            // Генерируем случайный IV
            iv = generateIv(random != null ? random : CryptoRandom.INSTANCE);
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported parameter type: "
                            + params.getClass().getName()
                            + ". Expected IvParameterSpec");
        }

        forEncryption =
                (opmode == javax.crypto.Cipher.ENCRYPT_MODE
                        || opmode == javax.crypto.Cipher.WRAP_MODE);

        initCipher(keyParam, iv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
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
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // Не произойдёт — null параметры допустимы
            throw new InvalidKeyException("Unexpected parameter error", e);
        }
    }

    /**
     * Обрабатывает часть входных данных.
     * <p>
     * Для потоковых режимов (CTR/CFB/OFB) данные шифруются немедленно.
     * Для CBC данные накапливаются и шифруются полными блоками.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkInitialized();
        appendToBuffer(input, inputOffset, inputLen);

        if (!mode.equals(MODE_CBC)) {
            // Потоковые режимы: шифруем весь накопленный буфер немедленно
            byte[] result = processStreamBytes(inputBuffer, 0, inputBuffer.length);
            // Затираем прежний буфер (мог содержать plaintext/ciphertext) перед сбросом.
            Arrays.fill(inputBuffer, (byte) 0);
            inputBuffer = new byte[0];
            return result;
        }

        // CBC: обрабатываем только полные блоки, оставляем остаток в буфере
        int fullBlocks = inputBuffer.length / BLOCK_SIZE;
        if (fullBlocks == 0) {
            return new byte[0];
        }
        int processLen = fullBlocks * BLOCK_SIZE;
        byte[] result = processCbcBlocks(inputBuffer, 0, processLen);
        // Оставляем хвост в буфере
        byte[] tail = Arrays.copyOfRange(inputBuffer, processLen, inputBuffer.length);
        inputBuffer = tail;
        return result;
    }

    @Override
    protected int engineUpdate(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (result.length > output.length - outputOffset) {
            throw new ShortBufferException(
                    "Output buffer too small: need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    /**
     * Завершает шифрование/расшифрование.
     * <p>
     * При шифровании CBC добавляет padding (если не NoPadding).
     * При расшифровании CBC снимает padding.
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkInitialized();
        if (input != null && inputLen > 0) {
            appendToBuffer(input, inputOffset, inputLen);
        }

        byte[] result;
        if (!mode.equals(MODE_CBC)) {
            // Потоковые режимы: шифруем оставшиеся байты
            result = processStreamBytes(inputBuffer, 0, inputBuffer.length);
        } else {
            result = doFinalCbc();
        }

        // Сбрасываем буфер после завершения; затираем прежнее содержимое.
        Arrays.fill(inputBuffer, (byte) 0);
        inputBuffer = new byte[0];
        return result;
    }

    @Override
    protected int engineDoFinal(
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (result.length > output.length - outputOffset) {
            throw new ShortBufferException(
                    "Output buffer too small: need " + result.length + " bytes");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    /**
     * Создаёт и инициализирует блочный шифр с нужным режимом.
     */
    private void initCipher(SymmetricKey keyParam, byte[] iv) {
        this.currentIv = Arrays.copyOf(iv, iv.length);

        if (cipher != null) {
            cipher.destroy();
        }
        // Затираем прежний буфер (мог содержать plaintext/ciphertext) перед сбросом.
        Arrays.fill(this.inputBuffer, (byte) 0);
        this.inputBuffer = new byte[0];

        ParametersWithIV params = new ParametersWithIV(keyParam, iv);

        switch (mode) {
            case MODE_CTR:
                cipher = new Ctr(new Kuznyechik());
                break;
            case MODE_CBC:
                cipher = new Cbc(new Kuznyechik());
                break;
            case MODE_CFB:
                cipher = new Cfb(new Kuznyechik());
                break;
            case MODE_OFB:
                cipher = new Ofb(new Kuznyechik());
                break;
            default:
                throw new IllegalStateException("Unknown mode: " + mode);
        }

        cipher.init(forEncryption, params);
        initialized = true;
    }

    /**
     * Шифрует/расшифровывает байты для потоковых режимов (CTR/CFB/OFB).
     * <p>
     * CTR: использует {@link Ctr#processBytes} для обработки произвольного числа байт.
     * CFB/OFB: накапливает данные до полного блока (BLOCK_SIZE), затем обрабатывает
     * через {@link BlockCipher#processBlock}; хвост менее BLOCK_SIZE байт
     * обрабатывается как последний неполный блок через буфер с дополнением.
     * <p>
     * Согласно ГОСТ Р 34.13-2015: CFB и OFB работают с полноблочным сегментом (s = n = 16 байт).
     * Неполный последний блок обрабатывается отдельно с сохранением только нужных байт.
     */
    private byte[] processStreamBytes(byte[] data, int offset, int len) {
        if (len == 0) return new byte[0];
        byte[] out = new byte[len];
        if (cipher instanceof Ctr) {
            // CTR поддерживает произвольную длину напрямую
            ((Ctr) cipher).processBytes(data, offset, len, out, 0);
            return out;
        }
        // CFB/OFB: блочная обработка
        int outPos = 0;
        int fullBlocks = len / BLOCK_SIZE;
        // Обрабатываем полные блоки
        for (int i = 0; i < fullBlocks; i++) {
            cipher.processBlock(data, offset + i * BLOCK_SIZE, out, outPos);
            outPos += BLOCK_SIZE;
        }
        // Обрабатываем хвост (< BLOCK_SIZE байт) через буфер с нулевым дополнением
        int remaining = len - fullBlocks * BLOCK_SIZE;
        if (remaining > 0) {
            byte[] tail = new byte[BLOCK_SIZE];
            byte[] tailOut = new byte[BLOCK_SIZE];
            System.arraycopy(data, offset + fullBlocks * BLOCK_SIZE, tail, 0, remaining);
            cipher.processBlock(tail, 0, tailOut, 0);
            System.arraycopy(tailOut, 0, out, outPos, remaining);
        }
        return out;
    }

    /**
     * Обрабатывает полные блоки CBC (только кратные BLOCK_SIZE).
     */
    private byte[] processCbcBlocks(byte[] data, int offset, int len) {
        byte[] out = new byte[len];
        for (int pos = 0; pos < len; pos += BLOCK_SIZE) {
            cipher.processBlock(data, offset + pos, out, pos);
        }
        return out;
    }

    /**
     * Завершает CBC с обработкой padding.
     */
    private byte[] doFinalCbc() throws IllegalBlockSizeException, BadPaddingException {
        if (forEncryption) {
            return doFinalCbcEncrypt();
        } else {
            return doFinalCbcDecrypt();
        }
    }

    private byte[] doFinalCbcEncrypt() throws IllegalBlockSizeException {
        byte[] paddedData;
        if (isPaddingNone()) {
            if (inputBuffer.length % BLOCK_SIZE != 0) {
                throw new IllegalBlockSizeException(
                        "CBC/NoPadding requires data length to be a multiple of "
                                + BLOCK_SIZE
                                + ", got "
                                + inputBuffer.length);
            }
            paddedData = inputBuffer;
        } else if (isPkcs5OrPkcs7()) {
            paddedData = Pkcs7Padding.addPadding(inputBuffer, BLOCK_SIZE);
        } else {
            // ISO7816-4
            int padLen = BLOCK_SIZE - (inputBuffer.length % BLOCK_SIZE);
            paddedData = new byte[inputBuffer.length + padLen];
            System.arraycopy(inputBuffer, 0, paddedData, 0, inputBuffer.length);
            ISO7816d4Padding.addPadding(paddedData, inputBuffer.length);
        }
        return processCbcBlocks(paddedData, 0, paddedData.length);
    }

    private byte[] doFinalCbcDecrypt() throws IllegalBlockSizeException, BadPaddingException {
        if (inputBuffer.length % BLOCK_SIZE != 0) {
            throw new IllegalBlockSizeException(
                    "CBC ciphertext length must be a multiple of "
                            + BLOCK_SIZE
                            + ", got "
                            + inputBuffer.length);
        }
        if (inputBuffer.length == 0) {
            return new byte[0];
        }
        byte[] decrypted = processCbcBlocks(inputBuffer, 0, inputBuffer.length);
        if (isPaddingNone()) {
            return decrypted;
        }
        try {
            if (isPkcs5OrPkcs7()) {
                return Pkcs7Padding.removePadding(decrypted, BLOCK_SIZE);
            } else {
                // ISO7816-4
                int padCount = ISO7816d4Padding.padCount(decrypted);
                return Arrays.copyOf(decrypted, decrypted.length - padCount);
            }
        } catch (Exception e) {
            throw new BadPaddingException("Invalid padding");
        }
    }

    /** Добавляет данные в конец внутреннего буфера. */
    private void appendToBuffer(byte[] input, int offset, int len) {
        if (len <= 0) return;
        byte[] newBuf = new byte[inputBuffer.length + len];
        System.arraycopy(inputBuffer, 0, newBuf, 0, inputBuffer.length);
        System.arraycopy(input, offset, newBuf, inputBuffer.length, len);
        inputBuffer = newBuf;
    }

    /** Генерирует случайный IV нужной длины для текущего режима.
     * <p>
     * Для CTR это 64-битный nonce (BLOCK_SIZE/2 = 8 байт): при > ~2^16
     * сообщений на одном ключе возникает birthday-риск коллизии nonce
     * (повтор keystream -> раскрытие plaintext); см. Javadoc класса и ADR-06. */
    private byte[] generateIv(SecureRandom random) {
        int ivLen = mode.equals(MODE_CTR) ? BLOCK_SIZE / 2 : BLOCK_SIZE;
        byte[] iv = new byte[ivLen];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Проверяет корректность IV для текущего режима.
     *
     * @throws InvalidAlgorithmParameterException если длина IV неверна
     */
    private void validateIv(byte[] iv) throws InvalidAlgorithmParameterException {
        if (iv == null) {
            throw new InvalidAlgorithmParameterException("IV must not be null");
        }
        int expectedLen = mode.equals(MODE_CTR) ? BLOCK_SIZE / 2 : BLOCK_SIZE;
        if (iv.length != expectedLen) {
            throw new InvalidAlgorithmParameterException(
                    "Invalid IV length for "
                            + mode
                            + ": expected "
                            + expectedLen
                            + " bytes, got "
                            + iv.length);
        }
    }

    /**
     * Извлекает {@link SymmetricKey} из JCA-ключа через общий {@link SymmetricKeyExtractor}.
     */
    private static SymmetricKey extractSymmetricKey(Key key) throws InvalidKeyException {
        return SymmetricKeyExtractor.fromKey(key);
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized — call init() first");
        }
    }

    private boolean isPaddingNone() {
        return padding.equalsIgnoreCase(PAD_NONE);
    }

    private boolean isPkcs5OrPkcs7() {
        return padding.equalsIgnoreCase(PAD_PKCS5) || padding.equalsIgnoreCase(PAD_PKCS7);
    }
}
