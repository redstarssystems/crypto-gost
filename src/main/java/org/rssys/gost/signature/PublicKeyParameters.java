package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;

/**
 * Параметры открытого ключа для алгоритма электронной подписи ГОСТ Р 34.10-2012.
 * <p>
 * Содержит точку открытого ключа {@code Q} и параметры кривой {@link ECParameters}.
 * Корректность точки (нахождение на кривой) проверяется в {@link org.rssys.gost.signature.ECDSASigner#init}.
 */
public final class PublicKeyParameters implements CipherParameters {
  private final ECPoint q;
  private final ECParameters params;

  /**
   * @param q      точка открытого ключа Q на эллиптической кривой
   * @param params параметры кривой
   * @throws IllegalArgumentException если {@code q} или {@code params} равны {@code null}
   */
  public PublicKeyParameters(ECPoint q, ECParameters params) {
    if (q == null) throw new IllegalArgumentException("Q must not be null");
    if (params == null) throw new IllegalArgumentException("params must not be null");
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
