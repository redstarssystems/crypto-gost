package org.rssys.gost.signature;

import java.math.BigInteger;

/**
 * Точка на эллиптической кривой в проективных координатах Якоби.
 * Координаты хранятся как {@link FieldElement} в форме Монтгомери.
 * BigInteger используется только на входе (affine/infinity) и на выходе (getX/getY).
 */
public final class ECPoint {
  private final FieldElement x;
  private final FieldElement y;
  private final FieldElement z;
  private final ECParameters params;

  private ECPoint(FieldElement x, FieldElement y, FieldElement z, ECParameters params) {
    this.x = x; this.y = y; this.z = z; this.params = params;
  }

  public static ECPoint infinity(ECParameters params) {
    FieldElement zero = FieldElement.zero(params.montParams);
    return new ECPoint(zero, zero, zero, params);
  }

  public static ECPoint affine(BigInteger bx, BigInteger by, ECParameters params) {
    FieldElement.MontgomeryParams mp = params.montParams;
    return new ECPoint(FieldElement.of(bx, mp), FieldElement.of(by, mp), FieldElement.one(mp), params);
  }

  public boolean isInfinity() { return z.isZero(); }

  public ECPoint normalize() {
    if (isInfinity()) return this;
    FieldElement one = FieldElement.one(params.montParams);
    if (z.equals(one)) return this;
    FieldElement zInv   = z.invert();               // ← constant-time через Ферма
    FieldElement zInvSq = zInv.square();
    FieldElement zInvCu = zInvSq.multiply(zInv);
    return new ECPoint(x.multiply(zInvSq), y.multiply(zInvCu), one, params);
  }

  public BigInteger getX() { return x.toBigInteger(); }
  public BigInteger getY() { return y.toBigInteger(); }

  public ECPoint twice() {
    FieldElement y2 = y.square();
    FieldElement s  = x.multiply(y2).shiftLeft(2);
    FieldElement m;
    if (params.aIsZero) {
      FieldElement x2 = x.square();
      m = x2.shiftLeft(1).add(x2);
    } else {
      FieldElement z2 = z.square();
      if (params.aIsMinusThree) {
        FieldElement prod = x.subtract(z2).multiply(x.add(z2));
        m = prod.shiftLeft(1).add(prod);
      } else {
        FieldElement x2  = x.square();
        FieldElement x2t3 = x2.shiftLeft(1).add(x2);
        m = x2t3.add(params.fa.multiply(z2.square()));
      }
    }
    FieldElement nx = m.square().subtract(s.shiftLeft(1));
    FieldElement ny = m.multiply(s.subtract(nx)).subtract(y2.square().shiftLeft(3));
    FieldElement nz = y.multiply(z).shiftLeft(1);

    // CT-select: если isInfinity → this, иначе → новый результат
    long[] zLimbs = z.limbs();
    long zAcc = 0;
    for (long limb : zLimbs) zAcc |= limb;
    long isInf = (~(zAcc | -zAcc)) >>> 63;

    FieldElement rx = selectFE(nx, x, isInf);
    FieldElement ry = selectFE(ny, y, isInf);
    FieldElement rz = selectFE(nz, z, isInf);
    return new ECPoint(rx, ry, rz, params);
  }

  public ECPoint add(ECPoint other) {
    if (params.aIsMinusThree) return addComplete(other);
    return addCompleteGeneral(other);
  }


  private static ECPoint negatePoint(ECPoint pt) {
    return new ECPoint(pt.x, pt.y.negate(), pt.z, pt.params);
  }

  /**
   * Интерливинговый wNAF для одновременного вычисления k1·P1 + k2·P2
   * (Shamir's trick, interleaved wNAF).
   * Применяется только при верификации — скаляры k1, k2 публичны.
   *
   * @param k1     первый скаляр
   * @param table1 предвычисленная wNAF-таблица для P1: (2i+1)·P1
   * @param k2     второй скаляр
   * @param table2 предвычисленная wNAF-таблица для P2: (2i+1)·P2
   * @param w      ширина окна (одинаковая для обеих точек)
   * @return k1·P1 + k2·P2 в нормализованных координатах
   */
  public static ECPoint shamirMultiply(
          BigInteger k1, ECPoint[] table1,
          BigInteger k2, ECPoint[] table2,
          int w, ECParameters params) {
    int[] naf1 = computeWNaf(k1, w);
    int[] naf2 = computeWNaf(k2, w);
    int len = Math.max(naf1.length, naf2.length);
    ECPoint result = infinity(params);
    for (int i = len - 1; i >= 0; i--) {
      result = result.twice();
      int d1 = (i < naf1.length) ? naf1[i] : 0;
      int d2 = (i < naf2.length) ? naf2[i] : 0;
      if (d1 != 0) {
        int idx = (Math.abs(d1) - 1) >> 1;
        ECPoint pt = table1[idx];
        result = result.add(d1 > 0 ? pt : negatePoint(pt));
      }
      if (d2 != 0) {
        int idx = (Math.abs(d2) - 1) >> 1;
        ECPoint pt = table2[idx];
        result = result.add(d2 > 0 ? pt : negatePoint(pt));
      }
    }
    return result.normalize();
  }

  /**
   * Complete addition для произвольного a (Renes, Costello, Renes 2016, Algorithm 1).
   * Корректен для всех пар точек: различных, равных, противоположных, ∞.
   * Применяется для кривых где a ≠ −3 (TC26-A-256, TC26-C-512).
   * Стоимость: 12M + 2S.
   *
   * <p>Все ветвления по значениям точек отсутствуют — результат выбирается
   * через CT-select аналогично {@link #addComplete}.
   *
   * <p>Ссылка: https://eprint.iacr.org/2015/1060, Algorithm 1.
   */
  /**
   * Complete addition в координатах Якоби для произвольного a.
   * <p>
   * Базовая формула — стандартная Якоби add (EFD add-2007-bl, 11M + 5S),
   * корректная для P≠Q и P≠O.
   * Для corner cases (P=Q, P=-Q, P=O, Q=O) результат выбирается через CT-select
   * без ветвлений, аналогично {@link #addComplete} для a=−3.
   * <p>
   * Стоимость: ~11M + 5S + overhead CT-select.
   */
  private ECPoint addCompleteGeneral(ECPoint other) {
    // CT-маски для граничных случаев (без ветвлений по значению)
    long zAcc1 = 0, zAcc2 = 0;
    for (long limb : z.limbs())       zAcc1 |= limb;
    for (long limb : other.z.limbs()) zAcc2 |= limb;
    // m1 = 1 если this == infinity, m2 = 1 если other == infinity
    long m1 = (~(zAcc1 | -zAcc1)) >>> 63;
    long m2 = (~(zAcc2 | -zAcc2)) >>> 63;

    // Стандартная Якоби add (EFD add-2007-bl)
    // (X1:Y1:Z1) + (X2:Y2:Z2) → (X3:Y3:Z3)
    // x_aff = X/Z², y_aff = Y/Z³
    FieldElement z1z1 = z.square();           // Z1Z1 = Z1²
    FieldElement z2z2 = other.z.square();     // Z2Z2 = Z2²
    FieldElement u1   = x.multiply(z2z2);     // U1 = X1·Z2Z2
    FieldElement u2   = other.x.multiply(z1z1); // U2 = X2·Z1Z1
    FieldElement s1   = y.multiply(z2z2).multiply(other.z);  // S1 = Y1·Z2Z2·Z2
    FieldElement s2   = other.y.multiply(z1z1).multiply(z);  // S2 = Y2·Z1Z1·Z1
    FieldElement h    = u2.subtract(u1);      // H = U2-U1
    FieldElement r    = s2.subtract(s1);      // R = S2-S1

    // CT-определение corner cases (вычисляем маски без ветвлений)
    long hAcc = 0, rAcc = 0;
    for (long limb : h.limbs()) hAcc |= limb;
    for (long limb : r.limbs()) rAcc |= limb;
    long hIsZero = ((hAcc | -hAcc) >>> 63) ^ 1L; // 1 если H==0
    long rIsZero = ((rAcc | -rAcc) >>> 63) ^ 1L; // 1 если R==0
    long mEq     = hIsZero & rIsZero;             // 1 если P==Q (удвоение)

    // Предвычисляем удвоение (нужно если P==Q)
    ECPoint dbl = this.twice();

    // Основная формула Якоби add
    FieldElement hh   = h.square();               // HH = H²
    FieldElement hhh  = hh.multiply(h);           // HHH = H³
    FieldElement u1hh = u1.multiply(hh);          // U1HH = U1·HH
    FieldElement nx   = r.square().subtract(hhh).subtract(u1hh.shiftLeft(1));
    FieldElement ny   = r.multiply(u1hh.subtract(nx)).subtract(s1.multiply(hhh));
    FieldElement nz   = z.multiply(other.z).multiply(h); // Z3 = Z1·Z2·H

    // CT-select: P==Q → удвоение; P==-Q (H==0, R≠0) → infinity
    FieldElement rx = selectFE(nx, dbl.x, mEq);
    FieldElement ry = selectFE(ny, dbl.y, mEq);
    FieldElement rz = selectFE(nz, dbl.z, mEq);
    // H==0, R≠0 → P==-Q → результат infinity (Z=0)
    long mNeg = hIsZero & (rIsZero ^ 1L);
    FieldElement zero = FieldElement.zero(params.montParams);
    rx = selectFE(rx, zero, mNeg);
    ry = selectFE(ry, zero, mNeg);
    rz = selectFE(rz, zero, mNeg);
    // other == infinity → результат this
    rx = selectFE(rx, x,       m2);
    ry = selectFE(ry, y,       m2);
    rz = selectFE(rz, z,       m2);
    // this == infinity → результат other
    rx = selectFE(rx, other.x, m1);
    ry = selectFE(ry, other.y, m1);
    rz = selectFE(rz, other.z, m1);

    return new ECPoint(rx, ry, rz, params);
  }

  /**
   * Complete addition (Costello & Longa 2016, Alg. 4) для a = −3.
   * Корректен для всех пар точек: различных, равных, противоположных, ∞.
   * Стоимость: 12M + 4S.
   */
  private ECPoint addComplete(ECPoint other) {
    // вычисляем маску без тернарного оператора через OR лимбов
    // isZero() уже constnt-time, но тернарный ?: → условный переход в JIT.
    // Используем арифметическое приведение: (acc | -acc) >>> 63 даёт 1 если acc != 0.
    long zAcc1 = 0, zAcc2 = 0;
    for (long limb : z.limbs())       zAcc1 |= limb;
    for (long limb : other.z.limbs()) zAcc2 |= limb;
    // m = 1 если точка — бесконечность (z == 0), 0 иначе.
    // Если zAcc == 0: (0 | -0) >>> 63 = 0 → NOT → 1. Если zAcc != 0: старший бит >>> 63 = 1 → NOT → 0.
    long m1 = (~(zAcc1 | -zAcc1)) >>> 63;
    long m2 = (~(zAcc2 | -zAcc2)) >>> 63;

    FieldElement z1z1 = z.square();
    FieldElement z2z2 = other.z.square();
    FieldElement u1   = x.multiply(z2z2);
    FieldElement u2   = other.x.multiply(z1z1);
    FieldElement s1   = y.multiply(z2z2).multiply(other.z);
    FieldElement s2   = other.y.multiply(z1z1).multiply(z);
    FieldElement h    = u2.subtract(u1);
    FieldElement r    = s2.subtract(s1);

    // оба isZero() вызываются всегда, результат комбинируется без ветвлений
    // isZero() возвращает boolean через OR лимбов — сам CT, но boolean → long требует CT-конверсии.
    // Формула: если acc == 0, то (acc | -acc) имеет старший бит 0, >>> 63 = 0, XOR 1 = 1 (zero).
    //          если acc != 0, то (acc | -acc) имеет старший бит 1, >>> 63 = 1, XOR 1 = 0 (not zero).
    long hAcc = 0, rAcc = 0;
    for (long limb : h.limbs()) hAcc |= limb;
    for (long limb : r.limbs()) rAcc |= limb;
    long hIsZero = ((hAcc | -hAcc) >>> 63) ^ 1L; // 1 если h == 0, иначе 0
    long rIsZero = ((rAcc | -rAcc) >>> 63) ^ 1L; // 1 если r == 0, иначе 0
    long mEq = hIsZero & rIsZero;                 // 1 только если оба == 0, без &&

    ECPoint dbl = this.twice();

    FieldElement hh   = h.square();
    FieldElement hhh  = hh.multiply(h);
    FieldElement u1hh = u1.multiply(hh);
    FieldElement nx   = r.square().subtract(hhh).subtract(u1hh.shiftLeft(1));
    FieldElement ny   = r.multiply(u1hh.subtract(nx)).subtract(s1.multiply(hhh));
    FieldElement nz   = h.multiply(z).multiply(other.z);

    FieldElement rx = selectFE(nx, dbl.x, mEq);
    FieldElement ry = selectFE(ny, dbl.y, mEq);
    FieldElement rz = selectFE(nz, dbl.z, mEq);
    rx = selectFE(rx, x,       m2);
    ry = selectFE(ry, y,       m2);
    rz = selectFE(rz, z,       m2);
    rx = selectFE(rx, other.x, m1);
    ry = selectFE(ry, other.y, m1);
    rz = selectFE(rz, other.z, m1);

    return new ECPoint(rx, ry, rz, params);
  }

  private static FieldElement selectFE(FieldElement a, FieldElement b, long cond) {
    long mask = -cond;
    long[] al = a.limbs(), bl = b.limbs();
    long[] rl = new long[al.length];
    for (int i = 0; i < al.length; i++) rl[i] = al[i] ^ ((al[i] ^ bl[i]) & mask);
    return a.withLimbs(rl);
  }

  public ECPoint multiply(BigInteger k) {
    int bitLen = params.n.bitLength();
    int[] bits = new int[bitLen];
    for (int i = 0; i < bitLen; i++) bits[i] = k.testBit(i) ? 1 : 0;
    ECPoint r0 = infinity(params), r1 = this;
    for (int i = bitLen - 1; i >= 0; i--) {
      int bit = bits[i];
      ECPoint[] sw = cswap(r0, r1, bit);
      r0 = sw[0]; r1 = sw[1];
      r1 = r0.add(r1);
      r0 = r0.twice();
      sw = cswap(r0, r1, bit);
      r0 = sw[0]; r1 = sw[1];
    }
    return r0.normalize();
  }

  private static ECPoint[] cswap(ECPoint a, ECPoint b, int swap) {
    long c = swap & 1L;
    return new ECPoint[]{
            new ECPoint(selectFE(a.x,b.x,c), selectFE(a.y,b.y,c), selectFE(a.z,b.z,c), a.params),
            new ECPoint(selectFE(b.x,a.x,c), selectFE(b.y,a.y,c), selectFE(b.z,a.z,c), b.params)
    };
  }

  public ECPoint[] buildWNafTable(int w) {
    int tableSize = 1 << (w - 2);
    ECPoint[] table = new ECPoint[tableSize];
    table[0] = this;
    ECPoint p2 = this.twice();
    for (int i = 1; i < tableSize; i++) table[i] = table[i-1].add(p2);
    return table;
  }


  static int[] computeWNaf(BigInteger k, int w) {
    int pow2w = 1 << w, pow2w1 = 1 << (w - 1);
    int[] naf = new int[k.bitLength() + 1];
    int idx = 0;
    while (k.signum() > 0) {
      if (k.testBit(0)) {
        int rem = k.intValue() & (pow2w - 1);
        int digit = (rem >= pow2w1) ? rem - pow2w : rem;
        naf[idx] = digit;
        k = k.subtract(BigInteger.valueOf(digit));
      } else { naf[idx] = 0; }
      k = k.shiftRight(1); idx++;
    }
    return naf;
  }

  public boolean isOnCurve() {
    if (isInfinity()) return false;
    ECPoint norm = normalize();
    BigInteger p = params.p;
    BigInteger bx = norm.x.toBigInteger(), by = norm.y.toBigInteger();
    BigInteger y2  = by.multiply(by).mod(p);
    BigInteger x3  = bx.multiply(bx).mod(p).multiply(bx).mod(p);
    BigInteger rhs = x3.add(params.a.multiply(bx)).add(params.b).mod(p);
    return y2.equals(rhs);
  }
}