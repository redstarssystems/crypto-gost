package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;

import javax.security.auth.Destroyable;
import java.math.BigInteger;
import java.util.Arrays;

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
    // Сохраняем как byte[] для возможности обнуления
    byte[] raw = d.toByteArray();
    // toByteArray() может содержать ведущий 0x00 для знакового представления — убираем
    int rolen = (params.n.bitLength() + 7) / 8;
    this.dBytes = new byte[rolen];
    if (raw.length <= rolen) {
      System.arraycopy(raw, 0, this.dBytes, rolen - raw.length, raw.length);
    } else {
      // обрезаем ведущий 0x00
      System.arraycopy(raw, raw.length - rolen, this.dBytes, 0, rolen);
    }
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
