package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;

/**
 * Режим OFB (Output FeedBack).
 */
public class Ofb extends AbstractStreamMode implements StreamCipher {

    /** Scratch-буфер гаммы (blockSize байт, zero-alloc). */
    private final byte[] Y;

    /** Позиция внутри текущего блока гаммы. */
    private int byteCount;

    /** Прямая ссылка на Kuznyechik для zero-alloc encryptToFields. */
    private final Kuznyechik kuz;

    public Ofb(Kuznyechik cipher) {
        super(cipher);
        this.kuz = cipher;
        this.Y   = new byte[blockSize];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        reset();
        ParametersWithIV ivParams = requireIV(params, "OFB");
        byte[] iv = ivParams.getIV();
        if (iv.length < blockSize) {
            throw new IllegalArgumentException("IV length must be >= block size");
        }
        initRegister(iv);
        // OFB симметричен — направление не влияет на генерацию гаммы,
        // но ключ передаётся в базовый шифр всегда в режиме шифрования
        cipher.init(true, ivParams.getParameters());
        this.initialized = true;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/OFB";
    }

    @Override
    public int getBlockSize() {
        return blockSize;
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        checkInitialized();
        checkInputBounds(in, inOff, blockSize);
        checkOutputBounds(out, outOff, blockSize);
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    @Override
    protected int processBlocks(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (byteCount != 0 || m != blockSize) {
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
            // R = зашифрованное значение (обратная связь)
            LONG_BE.set(R, 0, gHi);
            LONG_BE.set(R, 8, gLo);
            long inHi = (long) LONG_BE.get(in, inOff + i);
            long inLo = (long) LONG_BE.get(in, inOff + i + 8);
            LONG_BE.set(out, outOff + i,     inHi ^ gHi);
            LONG_BE.set(out, outOff + i + 8, inLo ^ gLo);
        }
        return limit;
    }

    public byte returnByte(byte in) {
        return calculateByte(in);
    }

    /**
     * Основной метод: XOR байта с гаммой.
     * Каждые blockSize байт генерируется новый Y через encryptToFields (zero-alloc).
     */
    @Override
    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            long rHi = (long) LONG_BE.get(R, 0);
            long rLo = (long) LONG_BE.get(R, 8);
            kuz.encryptToFields(rHi, rLo);
            LONG_BE.set(Y, 0, kuz.getEncBufHi());
            LONG_BE.set(Y, 8, kuz.getEncBufLo());
        }
        byte rv = (byte) (Y[byteCount] ^ in);
        if (++byteCount == blockSize) {
            byteCount = 0;
            shiftRegister(Y, 0, blockSize);
        }
        return rv;
    }

    @Override
    public void reset() {
        resetRegister();
        java.util.Arrays.fill(Y, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }
}
