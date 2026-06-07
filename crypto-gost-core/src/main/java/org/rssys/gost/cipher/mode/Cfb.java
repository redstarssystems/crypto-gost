package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;

/**
 * Режим CFB (Cipher FeedBack) по ГОСТ Р 34.13-2015.
 *
 * <p>Поддерживает настраиваемый размер сегмента s (по умолчанию s = blockSize).
 */
public class Cfb extends AbstractStreamMode implements StreamCipher {

    /** Размер сегмента в байтах (bitBlockSize / 8). */
    private final int s;

    /** Scratch-буфер гаммы (blockSize байт, zero-alloc). */
    private final byte[] gammaBuf;

    /** Буфер для s байт входных данных (шифртекст при шифровании, открытый — при расшифровании). */
    private final byte[] inBuf;

    /** Позиция внутри текущего гамма-блока. */
    private int byteCount;

    private boolean forEncryption;

    /** Прямая ссылка на Kuznyechik для zero-alloc encryptToFields. */
    private final Kuznyechik kuz;

    /** Полноблочный CFB (s == blockSize). */
    public Cfb(Kuznyechik cipher) {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /** CFB с размером сегмента bitBlockSize бит. */
    public Cfb(Kuznyechik cipher, int bitBlockSize) {
        super(cipher);
        this.kuz     = cipher;
        this.s       = bitBlockSize / 8;
        this.gammaBuf = new byte[blockSize];
        this.inBuf   = new byte[this.s];
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

    @Override
    protected int processBlocks(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (byteCount != 0 || s != blockSize || m != blockSize) {
            return 0;
        }
        int limit = len - (len % blockSize);
        if (limit == 0) {
            return 0;
        }
        for (int i = 0; i < limit; i += blockSize) {
            long rHi = (long) LONG_BE.get(R, 0);
            long rLo = (long) LONG_BE.get(R, 8);
            kuz.encryptToFields(rHi, rLo);
            long gHi = kuz.getEncBufHi();
            long gLo = kuz.getEncBufLo();
            long inHi = (long) LONG_BE.get(in, inOff + i);
            long inLo = (long) LONG_BE.get(in, inOff + i + 8);
            if (forEncryption) {
                long oHi = inHi ^ gHi;
                long oLo = inLo ^ gLo;
                LONG_BE.set(R, 0, oHi);
                LONG_BE.set(R, 8, oLo);
                LONG_BE.set(out, outOff + i,     oHi);
                LONG_BE.set(out, outOff + i + 8, oLo);
            } else {
                // Расшифрование: R = входной шифртекст (до XOR)
                LONG_BE.set(R, 0, inHi);
                LONG_BE.set(R, 8, inLo);
                LONG_BE.set(out, outOff + i,     inHi ^ gHi);
                LONG_BE.set(out, outOff + i + 8, inLo ^ gLo);
            }
        }
        return limit;
    }

    public byte returnByte(byte in) {
        return calculateByte(in);
    }

    /**
     * Основной метод обработки байта.
     * Каждые s байт генерируется новый гамма-блок через encryptToFields (zero-alloc).
     */
    @Override
    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            long rHi = (long) LONG_BE.get(R, 0);
            long rLo = (long) LONG_BE.get(R, 8);
            kuz.encryptToFields(rHi, rLo);
            LONG_BE.set(gammaBuf, 0, kuz.getEncBufHi());
            LONG_BE.set(gammaBuf, 8, kuz.getEncBufLo());
        }
        byte out = (byte) (gammaBuf[byteCount] ^ in);
        inBuf[byteCount++] = forEncryption ? out : in;
        if (byteCount == s) {
            byteCount = 0;
            shiftRegister(inBuf, 0, s);
        }
        return out;
    }

    @Override
    public void reset() {
        resetRegister();
        java.util.Arrays.fill(gammaBuf, (byte) 0);
        java.util.Arrays.fill(inBuf, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }
}
