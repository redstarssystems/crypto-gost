package org.rssys.gost.signature;

import java.util.Objects;
import org.rssys.gost.cipher.CipherParameters;

/**
 * Параметры открытого ключа для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Содержит точку открытого ключа {@code Q} и параметры кривой {@link ECParameters}.
 * Кривая, на которой построена точка, должна совпадать с объявленными параметрами
 * ({@link ECParameters#equals(Object)}, структурное равенство).
 * <p>
 * Параметры, равные зарегистрированной кривой по значению, но не являющиеся её
 * экземпляром, годятся для вычислений (подпись, ECDH), но такой ключ нельзя закодировать
 * в DER: канонический OID ({@code GostCurves.oidOf}) назначается только зарегистрированным
 * экземплярам. Для кодирования используйте параметры из {@code ECParameters.tc26a256()} и аналогов.
 * Валидность точки (принадлежность кривой и подгруппе порядка n) проверяется
 * в конструкторе через {@link ECPoint#isValidPublicKey()}.
 * Точка хранится в аффинной форме (нормализуется при создании).
 * Для кривых с кофактором &gt; 1 (TC26-A-256 и TC26-C-512, h = 4) выполняется полная проверка
 * подгруппы — создание объекта может быть незначительно медленнее.
 */
public final class PublicKeyParameters implements CipherParameters {
    private final ECPoint q;
    private final ECParameters params;

    /**
     * @param q      точка открытого ключа Q на эллиптической кривой
     * @param params параметры кривой
     * @throws IllegalArgumentException если {@code q} или {@code params} равны {@code null},
     *                                  точка построена на другой кривой, чем {@code params},
     *                                  или не является валидным открытым ключом
     */
    public PublicKeyParameters(ECPoint q, ECParameters params) {
        this(q, params, false);
    }

    /**
     * Выводит открытый ключ {@code Q = d·G} из закрытого.
     * <p>
     * Принимает именно закрытый ключ, а не готовую точку: точку считает сам метод, поэтому
     * передать сюда внешнюю точку нельзя ни по ошибке, ни умышленно. На этом держится
     * инвариант «любой {@code PublicKeyParameters} проверен», на который опираются ECDH,
     * разбор DER и TLS.
     * <p>
     * Для зарегистрированной кривой порядок G равен n, поэтому {@code d·G} лежит в подгруппе
     * по построению, и полная проверка подгруппы (на кривых с кофактором 4 это ещё одно
     * скалярное умножение) пропускается. Принадлежность кривой проверяется всегда. Для
     * самодельной кривой и равной по значению копии порядок G никто не гарантировал,
     * поэтому подгруппа проверяется так же, как у внешнего ключа, по объявленному кофактору.
     *
     * @throws IllegalStateException если закрытый ключ уничтожен
     */
    static PublicKeyParameters derivedFrom(PrivateKeyParameters priv) {
        ECParameters params = priv.getParams();
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint q = g.multiply(priv.getD());
        return new PublicKeyParameters(q, params, params.isRegistered());
    }

    private PublicKeyParameters(ECPoint q, ECParameters params, boolean subgroupGuaranteed) {
        if (q == null) throw new IllegalArgumentException("Q must not be null");
        if (params == null) throw new IllegalArgumentException("params must not be null");
        // isValidPublicKey() проверяет точку по её собственной кривой; без сверки с params
        // точка одной кривой попала бы в ключ, объявленный на другой, и потребители
        // (ECDH, проверка подписи) смешали бы параметры двух кривых.
        if (!params.equals(q.getParams())) {
            throw new IllegalArgumentException("point curve does not match key parameters");
        }
        // Точка хранится в аффинной форме: так equals и hashCode сводятся к сравнению координат без
        // обращения поля.
        // Нормализуем до проверки: isOnCurve и isValidPublicKey сами нормализуют точку, и для
        // аффинной она возвращается сразу, поэтому инверсия поля ровно одна на любой вход.
        ECPoint affine = q.normalize();
        boolean valid = subgroupGuaranteed ? affine.isOnCurve() : affine.isValidPublicKey();
        if (!valid) {
            throw new IllegalArgumentException(
                    "public key point is not on the curve or not in the prime-order subgroup");
        }
        this.q = affine;
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

    /**
     * Равенство по кривой и точке. Точка хранится в аффинной форме, поэтому одна точка, заданная в
     * проективной или в аффинной форме, даёт равные ключи. Данные открытые, сравнение за
     * постоянное время не нужно.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof PublicKeyParameters that)) return false;
        return params.equals(that.params)
                && q.getX().equals(that.q.getX())
                && q.getY().equals(that.q.getY());
    }

    /** Хэш по кривой и аффинным координатам, согласован с {@link #equals(Object)}. */
    @Override
    public int hashCode() {
        return Objects.hash(params, q.getX(), q.getY());
    }
}
