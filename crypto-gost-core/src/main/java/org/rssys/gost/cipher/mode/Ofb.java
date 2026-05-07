package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

/**
 * Режим OFB (Output FeedBack).
 */
public class Ofb extends AbstractStreamMode implements StreamCipher {

    /** Текущий блок гаммы. */
    private final byte[] Y;

    /** Позиция внутри текущего блока гаммы. */
    private int byteCount;

    public Ofb(BlockCipher cipher) {
        super(cipher);
        this.Y = new byte[blockSize];
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

    public byte returnByte(byte in) {
        return calculateByte(in);
    }

    /**
     * Основной метод: XOR байта с гаммой Y.
     * Каждые blockSize байт генерируется новый Y и обновляется R.
     */
    @Override
    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            generateY();
        }
        byte rv = (byte) (Y[byteCount] ^ in);
        if (++byteCount == blockSize) {
            byteCount = 0;
            // R = LSB(R, m - blockSize) || Y — сдвиг с гаммой (не шифртекстом)
            shiftRegister(Y, 0, blockSize);
        }
        return rv;
    }

    /**
     * Генерация гаммы Y: зашифровать MSB(R, blockSize).
     */
    private void generateY() {
        cipher.processBlock(R, 0, Y, 0);
    }

    @Override
    public void reset() {
        resetRegister();
        java.util.Arrays.fill(Y, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }
}
