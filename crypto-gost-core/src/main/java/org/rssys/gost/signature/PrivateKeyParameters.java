package org.rssys.gost.signature;

import java.math.BigInteger;
import java.util.Arrays;
import javax.security.auth.Destroyable;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.util.Pack;

/**
 * Параметры секретного ключа для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Содержит закрытый ключ {@code d} и параметры кривой {@link ECParameters}.
 * <p>
 * Ключ хранится как {@code byte[]} для возможности явного обнуления через {@link #destroy()}.
 * BigInteger immutable и не обнуляется — поэтому конвертация в BigInteger выполняется
 * только в момент использования ({@link #getD()}), а не при хранении.
 * <p>
 * Ограничение JVM: BigInteger, возвращаемый {@link #getD()}, останется в heap до GC.
 * Для минимизации времени жизни ключевого материала вызывайте {@link #destroy()} как
 * можно раньше после завершения криптографических операций.
 * <p>
 * <b>Потокобезопасность.</b> Объект не синхронизирован: {@link #destroy()} не должен пересекаться
 * ни с одной операцией над ключом, в том числе с {@code Signature.sign}, который сам потокобезопасен
 * только для неизменяемых и не уничтожаемых параллельно ключей. Параллельное уничтожение дало бы
 * подпись под частично обнулённым ключом.
 */
public final class PrivateKeyParameters implements CipherParameters, Destroyable {
    private byte[] dBytes;
    private final ECParameters params;
    private boolean destroyed = false;

    /**
     * @param d      закрытый ключ; должен удовлетворять 0 &lt; d &lt; q
     * @param params параметры кривой
     */
    public PrivateKeyParameters(BigInteger d, ECParameters params) {
        if (d == null) throw new IllegalArgumentException("d must not be null");
        if (params == null) throw new IllegalArgumentException("params must not be null");
        // Диапазон проверяется по исходному значению, до сериализации: иначе усечение до rolen байт
        // превращает 2^(8·rolen)+5 в 5, а потеря знака превращает -1 в 255, и неверный скаляр
        // проходит проверку как валидный ключ.
        if (d.signum() <= 0 || d.compareTo(params.n) >= 0) {
            throw new IllegalArgumentException("d must satisfy 0 < d < n");
        }
        // Сохраняем как byte[] для возможности обнуления
        int rolen = (params.n.bitLength() + 7) / 8;
        // строгое преобразование: 0 < d < n уже проверено, усечение старших байт невозможно
        this.dBytes = Pack.toFixedLengthBigEndian(d, rolen);
        this.params = params;
    }

    /**
     * Возвращает закрытый ключ как BigInteger.
     * <p>
     * Каждый вызов создаёт новый объект BigInteger из внутреннего byte[].
     *
     * @throws IllegalStateException если объект уже уничтожен
     */
    public BigInteger getD() {
        if (destroyed) throw new IllegalStateException("PrivateKeyParameters has been destroyed");
        return new BigInteger(1, dBytes);
    }

    /**
     * Возвращает внутренний byte[] закрытого ключа (defensive copy).
     *
     * @throws IllegalStateException если объект уже уничтожен
     */
    public byte[] getDBytes() {
        if (destroyed) throw new IllegalStateException("PrivateKeyParameters has been destroyed");
        return Arrays.copyOf(dBytes, dBytes.length);
    }

    /**
     * Вычисляет открытый ключ {@code Q = d·G}.
     * <p>
     * Внешних точек метод не принимает: {@code Q} считается из собственного {@code d}.
     * Поэтому для зарегистрированных кривых принадлежность подгруппе гарантирована построением,
     * и дорогая проверка {@code multiply(n)} на кривых с кофактором 4 не повторяется;
     * принадлежность кривой проверяется всегда. Самодельная кривая или равная по значению
     * копия проходит ту же проверку, что и внешний ключ: подгруппа проверяется по
     * объявленному кофактору (при {@code h = 1} достаточно принадлежности кривой, при
     * {@code h > 1} выполняется {@code multiply(n)}). Верность объявленного кофактора
     * остаётся на совести создателя самодельных параметров.
     *
     * @return открытый ключ, соответствующий этому закрытому
     * @throws IllegalStateException если закрытый ключ уничтожен
     */
    public PublicKeyParameters derivePublicKey() {
        return PublicKeyParameters.derivedFrom(this);
    }

    public ECParameters getParams() {
        return params;
    }

    /**
     * Обнуляет ключевой материал в памяти.
     * После вызова объект непригоден для использования.
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(dBytes, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
