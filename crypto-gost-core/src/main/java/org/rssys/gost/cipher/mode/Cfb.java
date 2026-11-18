package org.rssys.gost.cipher.mode;

import java.util.Arrays;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;

/**
 * Режим CFB (Cipher FeedBack) по ГОСТ Р 34.13-2015.
 *
 * <p>Поддерживает настраиваемый размер сегмента s (по умолчанию s = blockSize).
 */
public final class Cfb extends AbstractStreamCipherMode {

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

    /**
     * CFB с размером сегмента bitBlockSize бит.
     *
     * <p>Сегмент должен быть кратен байту и не длиннее блока шифра: гамма берётся как старшие
     * {@code s} байт зашифрованного регистра, а на длинном сегменте это чтение выходит за блок.
     * Некратное значение молча округлялось бы вниз и давало бы режим с другим размером сегмента,
     * чем запросил вызывающий. ГОСТ Р 34.13-2015 допускает любые {@code 1 <= s <= n} бит; здесь
     * поддерживаются только кратные байту, потому что весь поток обрабатывается по байтам.
     *
     * @param cipher       блочный шифр
     * @param bitBlockSize размер сегмента в битах: кратен 8, от 8 до размера блока в битах
     * @throws IllegalArgumentException если размер сегмента некратен 8 или вне допустимого диапазона
     */
    public Cfb(Kuznyechik cipher, int bitBlockSize) {
        super(cipher);
        int maxSegmentBits = blockSize * Byte.SIZE;
        if (bitBlockSize % Byte.SIZE != 0
                || bitBlockSize < Byte.SIZE
                || bitBlockSize > maxSegmentBits) {
            throw new IllegalArgumentException(
                    "CFB segment size must be a multiple of 8 bits in range [8, "
                            + maxSegmentBits
                            + "]");
        }
        this.kuz = cipher;
        this.s = bitBlockSize / Byte.SIZE;
        this.gammaBuf = new byte[blockSize];
        this.inBuf = new byte[this.s];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException {
        reset();
        ParametersWithIV ivParams = requireIV(params, "CFB");
        byte[] iv = ivParams.getIV();
        this.forEncryption = forEncryption;
        initRegister(iv);
        // CFB всегда использует базовый шифр в режиме шифрования
        cipher.init(true, ivParams.getParameters());
        this.initialized = true;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/CFB" + (s * Byte.SIZE);
    }

    /** Возвращает размер сегмента s (байт, обрабатываемых за один гамма-шаг). */
    @Override
    public int getBlockSize() {
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
                LONG_BE.set(out, outOff + i, oHi);
                LONG_BE.set(out, outOff + i + 8, oLo);
            } else {
                // Расшифрование: R = входной шифртекст (до XOR)
                LONG_BE.set(R, 0, inHi);
                LONG_BE.set(R, 8, inLo);
                LONG_BE.set(out, outOff + i, inHi ^ gHi);
                LONG_BE.set(out, outOff + i + 8, inLo ^ gLo);
            }
        }
        return limit;
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
        Arrays.fill(gammaBuf, (byte) 0);
        Arrays.fill(inBuf, (byte) 0);
        byteCount = 0;
        cipher.reset();
    }

    @Override
    public void destroy() {
        Arrays.fill(gammaBuf, (byte) 0);
        Arrays.fill(inBuf, (byte) 0);
        byteCount = 0;
        super.destroy();
    }
}
