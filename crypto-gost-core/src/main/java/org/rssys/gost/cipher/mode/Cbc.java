package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

/**
 * Режим CBC (Cipher Block Chaining, простая замена с зацеплением) по ГОСТ Р 34.13-2015 §4.2.
 */
public class Cbc extends AbstractStreamMode {

    private boolean forEncryption;

    public Cbc(BlockCipher cipher) {
        super(cipher);
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        reset();
        ParametersWithIV ivParams = requireIV(params, "CBC");
        byte[] iv = ivParams.getIV();
        if (iv.length < blockSize) {
            throw new IllegalArgumentException("IV length must be >= block size");
        }
        this.forEncryption = forEncryption;
        initRegister(iv);
        cipher.init(forEncryption, ivParams.getParameters());
        this.initialized = true;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/CBC";
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
        return forEncryption ? encryptBlock(in, inOff, out, outOff)
                             : decryptBlock(in, inOff, out, outOff);
    }

    // CBC не является потоковым режимом — calculateByte не используется
    @Override
    protected byte calculateByte(byte in) {
        throw new UnsupportedOperationException("CBC does not support byte-by-byte processing");
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // C[i] = E(K, P[i] XOR C[i-1]): XOR с MSB(R, blockSize)
        byte[] block = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            block[i] = (byte) (in[inOff + i] ^ R[i]);
        }
        cipher.processBlock(block, 0, out, outOff);
        // Обновляем R шифртекстом C[i]
        shiftRegister(out, outOff, blockSize);
        return blockSize;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // P[i] = D(K, C[i]) XOR C[i-1]: запоминаем C[i] до расшифрования
        byte[] block = new byte[blockSize];
        cipher.processBlock(in, inOff, block, 0);
        for (int i = 0; i < blockSize; i++) {
            out[outOff + i] = (byte) (block[i] ^ R[i]);
        }
        // Обновляем R шифртекстом C[i]
        shiftRegister(in, inOff, blockSize);
        return blockSize;
    }

    @Override
    public void reset() {
        resetRegister();
        cipher.reset();
    }
}
