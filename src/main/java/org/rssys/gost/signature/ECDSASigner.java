package org.rssys.gost.signature;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.util.Pack;

import javax.security.auth.Destroyable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * Реализация алгоритма электронной подписи ГОСТ Р 34.10-2012 (RFC 7091).
 * <p>
 * Хэш-значение H интерпретируется как целое число e по правилу RFC 7091 §5.3:
 * байты хэша переводятся в число с младшим байтом сначала (little-endian LSB first).
 * Это означает, что перед вызовом {@code new BigInteger(1, hash)} байты должны быть
 * реверсированы относительно того, как их возвращает Streebog.

 * Ссылки:
 * <ul>
 *   <li>ГОСТ Р 34.10-2012 / RFC 7091: https://www.rfc-editor.org/rfc/rfc7091</li>
 *   <li>RFC 6979: https://www.rfc-editor.org/rfc/rfc6979</li>
 * </ul>
 */
public final class ECDSASigner implements Destroyable {
  private byte[] dBytes;      // закрытый ключ хранится как byte[] для возможности обнуления
  private ECPoint q;
  private ECParameters params;
  private boolean forSigning;
  private final Supplier<Digest> digestFactory;
  private boolean destroyed = false;

  /**
   * Кешированная базовая точка G, инициализируется в {@link #init}.
   * Используется как исходная точка для построения wNAF-таблицы.
   */
  private ECPoint cachedG;

  /**
   * Предвычисленная wNAF-таблица для базовой точки G: {@code cachedGTable[i] = (2i+1)·G}.
   * Строится один раз в {@link #init} через {@link ECPoint#buildWNafTable(int)}.
   * Используется только в {@link #verifySignature} для ускорения умножения {@code z1·G}.
   * — заменяет лестницу Монтгомери на wNAF.
   */
  private ECPoint[] cachedGTable;

  /**
   * Предвычисленная wNAF-таблица для публичного ключа Q: {@code cachedQTable[i] = (2i+1)·Q}.
   * Строится один раз в {@link #init} при инициализации для верификации.
   * Переиспользуется во всех вызовах {@link #verifySignature}, устраняя повторное
   * построение таблицы (1 twice() + 3 add() при w=4) на каждый вызов.
   * {@code null} в signing-режиме — Q недоступен.
   */
  private ECPoint[] cachedQTable;

  private int wnafW;

  /** Размер окна wNAF для G и Q. Значение 4 оптимально для 256-бит; для 512-бит рассмотреть 5. */
  private static final int WNAF_W_256 = 4;
  private static final int WNAF_W_512 = 5;

  /**
   * Создаёт signer с фабрикой дайджестов.
   * <p>
   * Фабрика вызывается один раз при каждом вызове {@link #generateSignature(byte[])}
   * для получения свежего экземпляра {@link Digest} внутри алгоритма RFC 6979.
   * Это исключает конфликт состояний между хэшированием сообщения во внешнем коде
   * и внутренним использованием дайджеста для выработки k.
   *
   * @param digestFactory фабрика, создающая новый экземпляр дайджеста (Streebog256 или Streebog512)
   */
  public ECDSASigner(Supplier<Digest> digestFactory) {
    if (digestFactory == null) throw new IllegalArgumentException("digestFactory must not be null");
    this.digestFactory = digestFactory;
  }


  public void init(boolean forSigning, CipherParameters params) {
    if (destroyed) throw new IllegalStateException("ECDSASigner has been destroyed");
    this.forSigning = forSigning;
    if (forSigning) {
      if (!(params instanceof PrivateKeyParameters)) {
        throw new IllegalArgumentException("for signing, expected PrivateKeyParameters");
      }
      PrivateKeyParameters priv = (PrivateKeyParameters) params;
      this.params = priv.getParams();
      this.q = null;
      this.dBytes = priv.getDBytes();
      BigInteger dVal = new BigInteger(1, this.dBytes);
      if (dVal.signum() <= 0 || dVal.compareTo(this.params.n) >= 0) {
        throw new IllegalArgumentException("private key d must satisfy 0 < d < q");
      }
    } else {
      if (!(params instanceof PublicKeyParameters)) {
        throw new IllegalArgumentException("for verification, expected PublicKeyParameters");
      }
      PublicKeyParameters pub = (PublicKeyParameters) params;
      this.q = pub.getQ();
      this.params = pub.getParams();
      this.dBytes = null;

      ECPoint norm = q.normalize();
      if (norm.isInfinity() || !norm.isOnCurve() || !norm.multiply(this.params.n).isInfinity()) {
        throw new IllegalArgumentException("public key point is not valid");
      }
    }
    // Кешируем G и строим wNAF-таблицу один раз после инициализации параметров
    this.wnafW = (this.params.n.bitLength() > 256) ? WNAF_W_512 : WNAF_W_256;
    this.cachedG = ECPoint.affine(this.params.gx, this.params.gy, this.params);
    this.cachedGTable = this.cachedG.buildWNafTable(this.wnafW);
    this.cachedQTable = forSigning ? null : q.buildWNafTable(this.wnafW);
  }

  public BigInteger[] generateSignature(byte[] hash) {
    if (destroyed) throw new IllegalStateException("ECDSASigner has been destroyed");

    // RFC 7091 §5.3: хэш интерпретируется как целое число с LSB first (little-endian)
    BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(params.n);
    if (e.signum() == 0) {
      e = BigInteger.ONE;
    }

    // k генерируется детерминированно (RFC 6979) и является секретным эфемерным ключом.
    // Его компрометация раскрывает долговременный d, поэтому умножение k·G должно
    // выполняться с постоянным временем — через Montgomery ladder, а не wNAF.
    BigInteger k = generateK(hash);

    // Используем constant-time multiply (лестница Монтгомери) без предвычисленных таблиц
    ECPoint rPoint = cachedG.multiply(k).normalize();
    BigInteger r = rPoint.getX().mod(params.n);

    BigInteger dVal = new BigInteger(1, dBytes);
    BigInteger s = r.multiply(dVal).add(k.multiply(e)).mod(params.n);

    if (r.signum() == 0 || s.signum() == 0) {
      throw new IllegalStateException("signature produced zero r or s");
    }

    return new BigInteger[]{r, s};
  }

  public boolean verifySignature(byte[] hash, BigInteger r, BigInteger s) {
    BigInteger n = params.n;
    // RFC 7091 §6.2, Step 1: проверить 0 < r < q, 0 < s < q
    if (r.signum() < 1 || r.compareTo(n) >= 0) return false;
    if (s.signum() < 1 || s.compareTo(n) >= 0) return false;

    // RFC 7091 §5.3: хэш интерпретируется как целое число с LSB first (little-endian)
    BigInteger e = new BigInteger(1, Pack.reverseBytes(hash)).mod(n);
    if (e.signum() == 0) {
      e = BigInteger.ONE;
    }

    BigInteger v  = e.modInverse(n);
    BigInteger z1 = s.multiply(v).mod(n);
    BigInteger z2 = n.subtract(r).multiply(v).mod(n);

    ECPoint rPoint = ECPoint.shamirMultiply(
            z1, cachedGTable,
            z2, cachedQTable,
            wnafW, params);

    if (rPoint.isInfinity()) return false;

    BigInteger R = rPoint.getX().mod(n);
    return R.equals(r);
  }

  /**
   * Детерминированная генерация нонса k по RFC 6979 §3.2.
   */
  private BigInteger generateK(byte[] hash) {
    BigInteger n = params.n;
    Digest freshDigest = digestFactory.get();
    int hlen  = freshDigest.getDigestSize();
    int rolen = (n.bitLength() + 7) / 8;

    byte[] bx = int2octets(new BigInteger(1, dBytes), rolen);
    byte[] b1 = bits2octets(hash, n, rolen);

    byte[] v = new byte[hlen];
    Arrays.fill(v, (byte) 0x01);

    byte[] k = new byte[hlen];
    Arrays.fill(k, (byte) 0x00);

    Hmac hmac = new Hmac(freshDigest);

    try {
      // K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h1))
      hmac.init(k);
      hmac.update(v,  0, v.length);
      hmac.update(new byte[]{0x00}, 0, 1);
      hmac.update(bx, 0, bx.length);
      hmac.update(b1, 0, b1.length);
      Arrays.fill(k, (byte) 0);
      k = new byte[hlen];
      hmac.doFinal(k, 0);

      hmac.init(k);
      hmac.update(v, 0, v.length);
      Arrays.fill(v, (byte) 0);
      v = new byte[hlen];
      hmac.doFinal(v, 0);

      // K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h1))
      hmac.init(k);
      hmac.update(v,  0, v.length);
      hmac.update(new byte[]{0x01}, 0, 1);
      hmac.update(bx, 0, bx.length);
      hmac.update(b1, 0, b1.length);
      Arrays.fill(k, (byte) 0);
      k = new byte[hlen];
      hmac.doFinal(k, 0);

      hmac.init(k);
      hmac.update(v, 0, v.length);
      Arrays.fill(v, (byte) 0);
      v = new byte[hlen];
      hmac.doFinal(v, 0);

      while (true) {
        hmac.init(k);
        hmac.update(v, 0, v.length);
        Arrays.fill(v, (byte) 0);
        v = new byte[hlen];
        hmac.doFinal(v, 0);

        BigInteger ki = bits2int(v, n.bitLength());
        if (ki.signum() > 0 && ki.compareTo(n) < 0) {
          return ki;
        }

        // Повторная итерация: K = HMAC(K, V || 0x00)
        hmac.init(k);
        hmac.update(v, 0, v.length);
        hmac.update(new byte[]{0x00}, 0, 1);
        Arrays.fill(k, (byte) 0);
        k = new byte[hlen];
        hmac.doFinal(k, 0);

        hmac.init(k);
        hmac.update(v, 0, v.length);
        Arrays.fill(v, (byte) 0);
        v = new byte[hlen];
        hmac.doFinal(v, 0);
      }
    } finally {
      Arrays.fill(k,  (byte) 0);
      Arrays.fill(v,  (byte) 0);
      Arrays.fill(bx, (byte) 0);
      Arrays.fill(b1, (byte) 0);
      hmac.clear();
    }
  }

  private static byte[] int2octets(BigInteger x, int rolen) {
    byte[] xBytes = x.toByteArray();
    byte[] result = new byte[rolen];
    if (xBytes.length <= rolen) {
      System.arraycopy(xBytes, 0, result, rolen - xBytes.length, xBytes.length);
    } else {
      System.arraycopy(xBytes, xBytes.length - rolen, result, 0, rolen);
    }
    return result;
  }

  private static byte[] bits2octets(byte[] hash, BigInteger n, int rolen) {
    BigInteger h = bits2int(hash, n.bitLength()).mod(n);
    return int2octets(h, rolen);
  }

  private static BigInteger bits2int(byte[] hash, int qBitLength) {
    BigInteger result = new BigInteger(1, hash);
    int hlen = hash.length * 8;
    if (hlen > qBitLength) {
      result = result.shiftRight(hlen - qBitLength);
    }
    return result;
  }

  /**
   * Обнуляет ключевой материал (dBytes) в памяти.
   * После вызова объект непригоден для использования.
   */
  @Override
  public void destroy() {
    if (!destroyed) {
      if (dBytes != null) {
        Arrays.fill(dBytes, (byte) 0);
      }
      destroyed = true;
    }
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }
}