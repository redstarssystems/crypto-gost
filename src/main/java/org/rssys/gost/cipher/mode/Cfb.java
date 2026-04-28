package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

/**
 * Режим CFB (Cipher FeedBack) по ГОСТ Р 34.13-2015.
 *
 * <p>Поддерживает настраиваемый размер сегмента s (по умолчанию s = blockSize).
 */
public class Cfb extends AbstractStreamMode implements StreamCipher {

    /** Размер сегмента в байтах (bitBlockSize / 8). */
    private final int s;

    /** Текущий гамма-блок (ключевой поток). */
    private byte[] gamma;

    /** Буфер для s байт входных данных (шифртекст при шифровании, открытый — при расшифровании). */
    private final byte[] inBuf;

    /** Позиция внутри текущего гамма-блока. */
    private int byteCount;

    private boolean forEncryption;

    /** Полноблочный CFB (s == blockSize). */
    public Cfb(BlockCipher cipher) {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /** CFB с размером сегмента bitBlockSize бит. */
    public Cfb(BlockCipher cipher, int bitBlockSize) {
        super(cipher);
        this.s     = bitBlockSize / 8;
        this.inBuf = new byte[this.s];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        reset();
        ParametersWithIV ivParams = requireIV(params, "CFB");
        byte[] iv = ivParams.getIV();
        if (iv.length < blockSize) {
            throw new IllegalArgumentException("IV length must be >= block size");
        }
        this.forEncryption = forEncryption;
        initRegister(iv);
        // CFB всегда использует базовый шифр в режиме шифрования
        cipher.init(true, ivParams.getParameters());
        this.initialized = true;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
    }

    /** Возвращает размер сегмента s (байт, обрабатываемых за один гамма-шаг). */
    @Override
    public int getBlockSize() {
        return s;
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        checkInitialized();
        checkInputBounds(in, inOff, s);
        checkOutputBounds(out, outOff, s);
        processBytes(in, inOff, s, out, outOff);
        return s;
    }

    public byte returnByte(byte in) {
        return calculateByte(in);
    }

    /**
     * Основной метод обработки байта.
     * Каждые s байт генерируется новый гамма-блок.
     */
    @Override
    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            gamma = createGamma();
        }
        byte out = (byte) (gamma[byteCount] ^ in);
        inBuf[byteCount++] = forEncryption ? out : in;
        if (byteCount == s) {
            byteCount = 0;
            // R = LSB(R, m - s) || inBuf — сдвиг с s байтами шифртекста
            shiftRegister(inBuf, 0, s);
        }
        return out;
    }

    /**
     * Генерация гаммы: зашифровать MSB(R, blockSize), взять MSB(..., s).
     */
    private byte[] createGamma() {
        byte[] msb = new byte[blockSize];
        System.arraycopy(R, 0, msb, 0, blockSize);
        byte[] enc = new byte[blockSize];
        cipher.processBlock(msb, 0, enc, 0);
        byte[] result = new byte[s];
        System.arraycopy(enc, 0, result, 0, s);
        return result;
    }

    @Override
    public void reset() {
        resetRegister();
        if (gamma != null) {
            java.util.Arrays.fill(gamma, (byte) 0);
        }
        java.util.Arrays.fill(inBuf, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }
}
