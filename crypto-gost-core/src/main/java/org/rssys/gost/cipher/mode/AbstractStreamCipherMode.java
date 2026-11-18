package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.util.DataLengthException;

/**
 * Потоковые режимы (CFB, CTR, OFB по ГОСТ Р 34.13-2015): обработка произвольной длины, где полные
 * блоки идут пакетно, а неполный хвост побайтово.
 *
 * <p>Подклассы реализуют {@link #calculateByte} и при необходимости переопределяют
 * {@link #processBlocks} для блочной арифметики на длинных словах.
 */
abstract class AbstractStreamCipherMode extends AbstractRegisterMode implements StreamCipher {

    protected AbstractStreamCipherMode(BlockCipher cipher) {
        super(cipher);
    }

    /**
     * Обрабатывает {@code len} байт: делегирует полные блоки в {@link #processBlocks},
     * неполный хвост — побайтово через {@link #calculateByte}.
     */
    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        checkInitialized();
        checkInputBounds(in, inOff, len);
        checkOutputBounds(out, outOff, len);
        int processed = processBlocks(in, inOff, len, out, outOff);
        for (int i = processed; i < len; i++) {
            out[outOff + i] = calculateByte(in[inOff + i]);
        }
        return len;
    }

    /**
     * Обрабатывает один блок: для CFB блок равен сегменту s, для остальных режимов размеру блока
     * шифра.
     */
    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        int size = getBlockSize();
        processBytes(in, inOff, size, out, outOff);
        return size;
    }

    /**
     * Обрабатывает полные блоки входных данных, по умолчанию побайтово через
     * {@link #calculateByte}. Подклассы переопределяют для блочной long-арифметики.
     *
     * @return количество обработанных байт (всегда кратно blockSize)
     */
    protected int processBlocks(byte[] in, int inOff, int len, byte[] out, int outOff) {
        int limit = len - (len % blockSize);
        for (int i = 0; i < limit; i++) {
            out[outOff + i] = calculateByte(in[inOff + i]);
        }
        return limit;
    }

    /** Обрабатывает один байт. */
    protected abstract byte calculateByte(byte in);

    @Override
    public byte returnByte(byte in) {
        return calculateByte(in);
    }
}
