package org.rssys.gost.cipher;

import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

/**
 * Расширение {@link BlockCipher} для режимов с побайтовой обработкой данных.
 * <p>Реализуют режимы гаммирования по ГОСТ Р 34.13-2015:

 */
public interface StreamCipher extends BlockCipher {

    /**
     * Обрабатывает {@code len} байт входного буфера, результат записывает в выходной.
     *
     * @param in     входной буфер
     * @param inOff  смещение во входном буфере
     * @param len    количество байт
     * @param out    выходной буфер
     * @param outOff смещение в выходном буфере
     * @return количество записанных байт (всегда равно {@code len})
     * @throws DataLengthException   если входной буфер слишком короткий
     * @throws OutputLengthException если выходной буфер слишком короткий
     */
    int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
            throws DataLengthException, OutputLengthException;

    /**
     * Обрабатывает один байт.
     *
     * @param in входной байт
     * @return выходной байт
     */
    byte returnByte(byte in);
}
