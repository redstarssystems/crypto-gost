package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;

/**
 * Режим гаммирования (CTR/GCTR — Gamma, Counter Mode) по ГОСТ Р 34.13-2015
 * Режим симметричен: encrypt = decrypt.
 */
public class Ctr extends AbstractStreamMode implements StreamCipher {

    /** Текущее значение счётчика (blockSize байт). */
    private final byte[] CTR;

    /** Начальное значение (blockSize/2 байт) — для reset(). */
    private byte[] IV;

    /** Текущий буфер гаммы (blockSize байт). */
    private byte[] buf;

    /** Позиция внутри текущего буфера гаммы. */
    private int byteCount;

    /** Прямая ссылка на Kuznyechik для zero-alloc encryptToFields. */
    private final Kuznyechik kuz;

    public Ctr(Kuznyechik cipher) {
        super(cipher);
        this.kuz  = cipher;
        this.CTR  = new byte[blockSize];
        this.buf  = new byte[blockSize];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        reset();
        ParametersWithIV ivParams = requireIV(params, "CTR");
        byte[] iv = ivParams.getIV();
        int expectedIvLen = blockSize / 2;
        if (iv.length != expectedIvLen) {
            throw new IllegalArgumentException(
                "CTR mode requires IV of length " + expectedIvLen + " bytes");
        }
        this.IV = new byte[expectedIvLen];
        System.arraycopy(iv, 0, IV, 0, expectedIvLen);
        // Счётчик: первые blockSize/2 байт = IV, остальные = 0
        System.arraycopy(IV, 0, CTR, 0, expectedIvLen);
        java.util.Arrays.fill(CTR, expectedIvLen, blockSize, (byte) 0);
        // CTR симметричен — направление не имеет значения для генерации гаммы
        cipher.init(true, ivParams.getParameters());
        this.initialized = true;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/GCTR";
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

    /**
     * Пакетная обработка полных блоков.
     *
     * <p>В отличие от MGM, batch-разделение (4×encryptToFields → 4×XOR) не нужно:
     * в CTR нет второго независимого потока вычислений (MAC/Galois-field), который
     * batch разделял бы. Единственный конвейер — encryptToFields → XOR → counter++ —
     * JIT разворачивает самостоятельно.
     */
    @Override
    protected int processBlocks(byte[] in, int inOff, int len, byte[] out, int outOff) {
        if (byteCount != 0) {
            return 0;
        }
        int limit = len - (len % blockSize);
        if (limit == 0) {
            return 0;
        }
        long ctrHi = (long) LONG_BE.get(CTR, 0);
        long ctrLo = (long) LONG_BE.get(CTR, 8);
        for (int i = 0; i < limit; i += blockSize) {
            kuz.encryptToFields(ctrHi, ctrLo);
            long inHi = (long) LONG_BE.get(in, inOff + i);
            long inLo = (long) LONG_BE.get(in, inOff + i + 8);
            LONG_BE.set(out, outOff + i,     inHi ^ kuz.getEncBufHi());
            LONG_BE.set(out, outOff + i + 8, inLo ^ kuz.getEncBufLo());
            ctrLo++;
        }
        LONG_BE.set(CTR, 8, ctrLo);
        return limit;
    }

    public byte returnByte(byte in) {
        return calculateByte(in);
    }

    /**
     * Основной метод: XOR байта с гаммой.
     * Каждые blockSize байт генерируется новый блок гаммы, счётчик инкрементируется.
     */
    @Override
    protected byte calculateByte(byte in) {
        if (byteCount == 0) {
            generateBuf();
        }
        byte rv = (byte) (buf[byteCount] ^ in);
        if (++byteCount == blockSize) {
            byteCount = 0;
            incrementCTR();
        }
        return rv;
    }

    /**
     * Зашифровать счётчик CTR блочным шифром, результат записать в buf.
     */
    private void generateBuf() {
        cipher.processBlock(CTR, 0, buf, 0);
    }

    /**
     * Инкремент счётчика по ГОСТ Р 34.13-2015 §4.4 (CTR_add):
     * инкрементируется только младшая половина CTR[blockSize/2 .. blockSize-1].
     * Старшая половина CTR[0 .. blockSize/2-1] (= IV) остаётся неизменной.
     */
    private void incrementCTR() {
        for (int i = blockSize - 1; i >= blockSize / 2; i--) {
            if (++CTR[i] != 0) break;
        }
    }

    @Override
    public void reset() {
        if (IV != null) {
            System.arraycopy(IV, 0, CTR, 0, IV.length);
            java.util.Arrays.fill(CTR, IV.length, blockSize, (byte) 0);
        }
        java.util.Arrays.fill(buf, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }
}
