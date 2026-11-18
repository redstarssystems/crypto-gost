package org.rssys.gost.digest;

public interface Digest {
    String getAlgorithmName();

    int getDigestSize();

    int getByteLength();

    void update(byte in);

    void update(byte[] in, int inOff, int len);

    int doFinal(byte[] out, int outOff);

    void reset();

    /**
     * Затирает внутреннее состояние и возвращает дайджест в начальное состояние.
     *
     * <p>Правило {@code destroy()} в библиотеке одно: затереть секреты и вернуть объект в
     * состояние до инициализации. У {@code Mac} это неинициализированное состояние, и нужен новый
     * {@code init}. У хэша нет ключа и шага {@code init}, поэтому состояние до инициализации и есть
     * рабочее начальное: объект после вызова пригоден, вызывать {@link #reset()} перед повторным
     * использованием не нужно. По умолчанию действует как {@link #reset()}; реализации с
     * дополнительными рабочими буферами затирают и их. Публичный {@code api.Digest}, у которого
     * ключ задаётся в конструкторе, после {@code destroy()} непригоден.
     */
    default void destroy() {
        reset();
    }
}
