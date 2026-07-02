package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;

/**
 * Параметры открытого ключа для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Содержит точку открытого ключа {@code Q} и параметры кривой {@link ECParameters}.
 * Валидность точки (принадлежность кривой и подгруппе порядка n) проверяется
 * в конструкторе через {@link ECPoint#isValidPublicKey()}.
 * Для кривых с кофактором &gt; 1 (TC26_C_512, h = 4) выполняется полная проверка
 * подгруппы — создание объекта может быть незначительно медленнее.
 */
public final class PublicKeyParameters implements CipherParameters {
    private final ECPoint q;
    private final ECParameters params;

    /**
     * @param q      точка открытого ключа Q на эллиптической кривой
     * @param params параметры кривой
     * @throws IllegalArgumentException если {@code q} или {@code params} равны {@code null},
     *                                  или точка не является валидным открытым ключом
     */
    public PublicKeyParameters(ECPoint q, ECParameters params) {
        if (q == null) throw new IllegalArgumentException("Q must not be null");
        if (params == null) throw new IllegalArgumentException("params must not be null");
        if (!q.isValidPublicKey()) {
            throw new IllegalArgumentException("public key point is not on the curve");
        }
        this.q = q;
        this.params = params;
    }

    /** @return точка открытого ключа Q */
    public ECPoint getQ() {
        return q;
    }

    /** @return параметры кривой */
    public ECParameters getParams() {
        return params;
    }
}
