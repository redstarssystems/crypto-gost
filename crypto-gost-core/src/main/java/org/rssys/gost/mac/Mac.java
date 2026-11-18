package org.rssys.gost.mac;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.util.DataLengthException;

public interface Mac {
    void init(CipherParameters params) throws IllegalArgumentException;

    String getAlgorithmName();

    int getMacSize();

    void update(byte in) throws IllegalStateException;

    void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException;

    int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException;

    void reset();

    /**
     * Обнуляет ключевой материал и внутреннее состояние.
     * После вызова экземпляр неинициализирован: прежним ключом считать нельзя,
     * его можно повторно инициализировать через {@link #init}. Это единое правило
     * {@code destroy()} в библиотеке: затереть секреты и вернуть объект в состояние до
     * инициализации (для хэша без ключа см. {@code Digest.destroy()}).
     */
    default void destroy() {}
}
