package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;

/**
 * Интерфейс электронной подписи по ГОСТ Р 34.10-2012.
 * <p>
 * Предоставляет методы инициализации, накопления данных, выработки и проверки подписи.
 */
public interface Signer {
    void init(boolean forSigning, CipherParameters params);

    void update(byte b);

    void update(byte[] in, int inOff, int len);

    byte[] sign();

    boolean verify(byte[] signature);

    void reset();

    /**
     * Затирает ключевой материал и внутреннее состояние подписанта. Идемпотентен. После вызова
     * подписант непригоден. Нужен тому, кто создал подписанта напрямую: временная копия закрытого
     * ключа и хвост подписываемого сообщения иначе остаются в куче до сборки мусора.
     */
    void destroy();
}
