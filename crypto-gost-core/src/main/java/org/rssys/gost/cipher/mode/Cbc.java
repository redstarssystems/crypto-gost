package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.DataLengthException;

/**
 * Режим CBC (Cipher Block Chaining, простая замена с зацеплением) по ГОСТ Р 34.13-2015 §4.2.
 */
public class Cbc extends AbstractStreamMode {

    private boolean forEncryption;

    /** Прямая ссылка на Kuznyechik для zero-alloc encryptToFields. */
    private final Kuznyechik kuz;

    /** Scratch-буфер для decryptBlock (чтобы не использовать R как scratch). */
    private final byte[] scratchBuf;

    public Cbc(Kuznyechik cipher) {
        super(cipher);
        this.kuz = cipher;
        this.scratchBuf = new byte[blockSize];
    }

    /** Legacy: для CMAC, где BlockCipher передаётся через интерфейс. */
    public Cbc(BlockCipher cipher) {
        super(cipher);
        this.kuz = cipher instanceof Kuznyechik ? (Kuznyechik) cipher : null;
        this.scratchBuf = new byte[blockSize];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException {
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
        return forEncryption
                ? encryptBlock(in, inOff, out, outOff)
                : decryptBlock(in, inOff, out, outOff);
    }

    // CBC не является потоковым режимом — calculateByte не используется
    @Override
    protected byte calculateByte(byte in) {
        throw new UnsupportedOperationException("CBC does not support byte-by-byte processing");
    }

    private int encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // C[i] = E(K, P[i] XOR C[i-1])
        if (kuz != null) {
            // fast path: zero-alloc через encryptToFields
            long inHi = (long) LONG_BE.get(in, inOff);
            long inLo = (long) LONG_BE.get(in, inOff + 8);
            long rHi = (long) LONG_BE.get(R, 0);
            long rLo = (long) LONG_BE.get(R, 8);
            kuz.encryptToFields(inHi ^ rHi, inLo ^ rLo);
            LONG_BE.set(out, outOff, kuz.getEncBufHi());
            LONG_BE.set(out, outOff + 8, kuz.getEncBufLo());
        } else {
            // fallback для не-Kuznyechik шифров (CMAC): scratchBuf уже предзадан
            for (int i = 0; i < blockSize; i++) {
                scratchBuf[i] = (byte) (in[inOff + i] ^ R[i]);
            }
            cipher.processBlock(scratchBuf, 0, out, outOff);
        }
        shiftRegister(out, outOff, blockSize);
        return blockSize;
    }

    private int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // P[i] = D(K, C[i]) XOR C[i-1]
        long rHi = (long) LONG_BE.get(R, 0);
        long rLo = (long) LONG_BE.get(R, 8);
        cipher.processBlock(in, inOff, scratchBuf, 0);
        long dHi = (long) LONG_BE.get(scratchBuf, 0);
        long dLo = (long) LONG_BE.get(scratchBuf, 8);
        LONG_BE.set(out, outOff, dHi ^ rHi);
        LONG_BE.set(out, outOff + 8, dLo ^ rLo);
        shiftRegister(in, inOff, blockSize);
        return blockSize;
    }

    @Override
    public void reset() {
        resetRegister();
        java.util.Arrays.fill(scratchBuf, (byte) 0);
        cipher.reset();
    }
}
