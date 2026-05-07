package org.rssys.gost.jca.spi;

import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;

import java.security.MessageDigestSpi;

/**
 * Реализация {@link MessageDigestSpi} для хэш-функции Стрибог (ГОСТ Р 34.11-2012).
 * <p>
 * Предоставляет два конкретных подкласса, регистрируемых в провайдере:
 * <ul>
 *   <li>{@link Streebog256Spi} — Стрибог-256</li>
 *   <li>{@link Streebog512Spi} — Стрибог-512</li>
 * </ul>
 * <p>
 * Все операции делегируются низкоуровневым реализациям
 * {@link org.rssys.gost.digest.Streebog256} и {@link org.rssys.gost.digest.Streebog512}.
 */
public abstract class GostMessageDigestSpi extends MessageDigestSpi {

    /** Делегат — низкоуровневая реализация хэш-функции. */
    private final Digest delegate;

    /**
     * @param delegate конкретная реализация Стрибог (256 или 512)
     */
    protected GostMessageDigestSpi(Digest delegate) {
        this.delegate = delegate;
    }

    /** Сбрасывает внутреннее состояние хэш-функции. */
    @Override
    protected void engineReset() {
        delegate.reset();
    }

    /** Добавляет один байт к вычислению хэша. */
    @Override
    protected void engineUpdate(byte input) {
        delegate.update(input);
    }

    /** Добавляет часть массива к вычислению хэша. */
    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        delegate.update(input, offset, len);
    }

    /**
     * Завершает вычисление и возвращает значение хэша.
     * Внутренне состояние сбрасывается после вызова (делегируется {@code doFinal}).
     */
    @Override
    protected byte[] engineDigest() {
        byte[] out = new byte[delegate.getDigestSize()];
        delegate.doFinal(out, 0); // doFinal вызывает reset() внутри
        return out;
    }

    /** @return длина дайджеста в байтах */
    @Override
    protected int engineGetDigestLength() {
        return delegate.getDigestSize();
    }

    /**
     * Клонирование запрещено — делегат содержит изменяемое состояние алгоритма
     * (массивы {@code h}, {@code N}, {@code Sigma}, {@code block}).
     * Shallow copy через {@code super.clone()} привело бы к разделению этого состояния
     * между копиями и нарушению корректности вычислений.
     *
     * @throws CloneNotSupportedException всегда
     */
    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException(
            "GostMessageDigestSpi cannot be cloned — delegate state is mutable");
    }

    /**
     * Стрибог-256
     * <p>
     * Регистрируется в провайдере как {@code "GOST3411-2012-256"}.
     */
    public static final class Streebog256Spi extends GostMessageDigestSpi {
        public Streebog256Spi() {
            super(new Streebog256());
        }
    }

    /**
     * Стрибог-512
     * <p>
     * Регистрируется в провайдере как {@code "GOST3411-2012-512"}.
     */
    public static final class Streebog512Spi extends GostMessageDigestSpi {
        public Streebog512Spi() {
            super(new Streebog512());
        }
    }
}
