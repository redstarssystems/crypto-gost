package org.rssys.gost.signature;

import java.math.BigInteger;

/**
 * Точка на эллиптической кривой в проективных координатах Якоби.
 * Координаты хранятся как {@code FieldElement} в форме Монтгомери.
 * BigInteger используется только на входе (affine/infinity) и на выходе (getX/getY).
 */
public final class ECPoint {
    private final FieldElement x;
    private final FieldElement y;
    private final FieldElement z;
    private final ECParameters params;

    private ECPoint(FieldElement x, FieldElement y, FieldElement z, ECParameters params) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.params = params;
    }

    /** Кривая, на которой построена точка; нужна для сверки с объявленными параметрами ключа. */
    ECParameters getParams() {
        return params;
    }

    public static ECPoint infinity(ECParameters params) {
        FieldElement zero = FieldElement.zero(params.montParams);
        return new ECPoint(zero, zero, zero, params);
    }

    /**
     * Создаёт точку по аффинным координатам.
     *
     * <p>Координаты обязаны быть каноническими: {@code 0 <= x, y < p}. Приведение по модулю
     * {@code p} молча принимало бы {@code (x + p, y)} и отрицательные значения как ту же точку,
     * то есть один ключ имел бы несколько кодировок. Принадлежность кривой и подгруппе здесь не
     * проверяется, для этого есть {@link #isValidPublicKey()}.
     *
     * @throws IllegalArgumentException если {@code x} или {@code y} вне диапазона {@code [0, p)}
     */
    public static ECPoint affine(BigInteger bx, BigInteger by, ECParameters params) {
        if (bx.signum() < 0
                || by.signum() < 0
                || bx.compareTo(params.p) >= 0
                || by.compareTo(params.p) >= 0) {
            throw new IllegalArgumentException(
                    "Point coordinate is outside the canonical range [0, p)");
        }
        FieldElement.MontgomeryParams mp = params.montParams;
        return new ECPoint(
                FieldElement.of(bx, mp), FieldElement.of(by, mp), FieldElement.one(mp), params);
    }

    public boolean isInfinity() {
        return z.isZero();
    }

    public ECPoint normalize() {
        if (isInfinity()) return this;
        FieldElement one = FieldElement.one(params.montParams);
        if (z.isEqualTo(one)) return this;
        FieldElement zInv = z.invert(); // <- constant-time через Ферма
        FieldElement zInvSq = zInv.square();
        FieldElement zInvCu = zInvSq.multiply(zInv);
        return new ECPoint(x.multiply(zInvSq), y.multiply(zInvCu), one, params);
    }

    public BigInteger getX() {
        return x.toBigInteger();
    }

    public BigInteger getY() {
        return y.toBigInteger();
    }

    public ECPoint twice() {
        FieldElement y2 = y.square();
        FieldElement s = x.multiply(y2).shiftLeft(2);
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
                FieldElement x2 = x.square();
                FieldElement x2t3 = x2.shiftLeft(1).add(x2);
                m = x2t3.add(params.fa.multiply(z2.square()));
            }
        }
        FieldElement nx = m.square().subtract(s.shiftLeft(1));
        FieldElement ny = m.multiply(s.subtract(nx)).subtract(y2.square().shiftLeft(3));
        FieldElement nz = y.multiply(z).shiftLeft(1);

        // CT-select: если isInfinity -> this, иначе -> новый результат
        long[] zLimbs = z.limbs();
        long zAcc = 0;
        for (long limb : zLimbs) zAcc |= limb;
        long isInf = (~(zAcc | -zAcc)) >>> 63;

        FieldElement rx = selectFE(nx, x, isInf);
        FieldElement ry = selectFE(ny, y, isInf);
        FieldElement rz = selectFE(nz, z, isInf);
        return new ECPoint(rx, ry, rz, params);
    }

    /**
     * Полное сложение: корректно для любых пар точек, в том числе равных, противоположных и
     * бесконечности.
     *
     * <p>Полевая формула - EFD add-1998-cmo-2 (12M + 4S), коэффициент {@code a} в ней не
     * участвует, поэтому метод один для всех кривых. Случай {@code P == Q} формула не
     * покрывает, его закрывает удвоение: {@link #twice()} всегда вычисляется заранее, а
     * результат выбирается масками без ветвлений по значениям точек (9 вызовов
     * {@code selectFE}, каждый с аллокацией). Там, где {@code P != Q} гарантировано структурой
     * алгоритма, дешевле {@link #addDistinct}.
     *
     * <p>Если результат - бесконечность, об этом говорит только {@link #isInfinity()}:
     * значения {@code X} и {@code Y} при {@code Z = 0} произвольны.
     */
    public ECPoint add(ECPoint other) {
        return addJacobian(other, twice());
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
            BigInteger k1,
            ECPoint[] table1,
            BigInteger k2,
            ECPoint[] table2,
            int w,
            ECParameters params) {
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

    private static FieldElement selectFE(FieldElement a, FieldElement b, long cond) {
        long mask = -cond;
        long[] al = a.limbs(), bl = b.limbs();
        long[] rl = new long[al.length];
        for (int i = 0; i < al.length; i++) rl[i] = al[i] ^ ((al[i] ^ bl[i]) & mask);
        return a.withLimbs(rl);
    }

    /**
     * Сложение двух разных точек без вложенного удвоения. Годится только там, где
     * {@code this != other} гарантировано структурой алгоритма, например в лестнице
     * {@link #multiply}: разность её регистров всегда равна {@code ±P}, а не нулю. В отличие от
     * {@link #add} не вычисляет {@link #twice()} и не выбирает между суммой и удвоением, что
     * экономит около трети стоимости сложения.
     *
     * <p>Предусловие: точки равны только если обе - бесконечность. При {@code this == other}
     * (и не бесконечность) формула вырождается и возвращает бесконечность, а не {@code 2P};
     * вызывающий обязан сам исключить этот случай.
     *
     * <p>Остальные граничные случаи корректны: {@code P + (−P)} даёт бесконечность
     * (координата {@code Z3 = H·Z1·Z2} обнуляется сама), {@code O + Q = Q}, {@code P + O = P},
     * {@code O + O = O}. Бесконечность в результате распознаётся только по {@code Z = 0},
     * значения {@code X} и {@code Y} при этом произвольны.
     */
    ECPoint addDistinct(ECPoint other) {
        return addJacobian(other, null);
    }

    /**
     * Общая реализация сложения в координатах Якоби (EFD add-1998-cmo-2, 12M + 4S).
     *
     * <p>Без ветвлений по значениям точек: бесконечность определяется масками по {@code Z},
     * итог выбирается масками. Маски {@code H == 0} и {@code R == 0} нужны только для случая
     * {@code P == Q}, поэтому при {@code doubled == null} они не вычисляются. Само наличие
     * {@code doubled} определяется вызывающим методом, а не данными, так что на постоянство
     * времени это не влияет.
     *
     * @param doubled результат {@code this.twice()} для полного сложения или {@code null}, если
     *     {@code this != other} гарантировано вызывающим
     */
    private ECPoint addJacobian(ECPoint other, ECPoint doubled) {
        long zAcc1 = 0, zAcc2 = 0;
        for (long limb : z.limbs()) zAcc1 |= limb;
        for (long limb : other.z.limbs()) zAcc2 |= limb;
        // m = 1 если точка - бесконечность (Z == 0): (acc | -acc) >>> 63 даёт 1 при acc != 0
        long m1 = (~(zAcc1 | -zAcc1)) >>> 63;
        long m2 = (~(zAcc2 | -zAcc2)) >>> 63;

        FieldElement z1z1 = z.square();
        FieldElement z2z2 = other.z.square();
        FieldElement u1 = x.multiply(z2z2);
        FieldElement u2 = other.x.multiply(z1z1);
        FieldElement s1 = y.multiply(z2z2).multiply(other.z);
        FieldElement s2 = other.y.multiply(z1z1).multiply(z);
        FieldElement h = u2.subtract(u1);
        FieldElement r = s2.subtract(s1);

        FieldElement hh = h.square();
        FieldElement hhh = hh.multiply(h);
        FieldElement u1hh = u1.multiply(hh);
        FieldElement nx = r.square().subtract(hhh).subtract(u1hh.shiftLeft(1));
        FieldElement ny = r.multiply(u1hh.subtract(nx)).subtract(s1.multiply(hhh));
        FieldElement nz = h.multiply(z).multiply(other.z);

        FieldElement rx = nx, ry = ny, rz = nz;
        if (doubled != null) {
            // P == Q <=> H == 0 и R == 0; при H == 0, R != 0 (P == −Q) Z3 = 0 сам даёт
            // бесконечность
            long hAcc = 0, rAcc = 0;
            for (long limb : h.limbs()) hAcc |= limb;
            for (long limb : r.limbs()) rAcc |= limb;
            long hIsZero = ((hAcc | -hAcc) >>> 63) ^ 1L;
            long rIsZero = ((rAcc | -rAcc) >>> 63) ^ 1L;
            long mEq = hIsZero & rIsZero;
            rx = selectFE(rx, doubled.x, mEq);
            ry = selectFE(ry, doubled.y, mEq);
            rz = selectFE(rz, doubled.z, mEq);
        }
        // other == O -> this; затем this == O -> other (при обеих O результат тоже O)
        rx = selectFE(rx, x, m2);
        ry = selectFE(ry, y, m2);
        rz = selectFE(rz, z, m2);
        rx = selectFE(rx, other.x, m1);
        ry = selectFE(ry, other.y, m1);
        rz = selectFE(rz, other.z, m1);
        return new ECPoint(rx, ry, rz, params);
    }

    /**
     * Скалярное умножение {@code k·P} лестницей Монтгомери с обменом регистров через маску.
     *
     * <p>Допустимый скаляр: {@code 0 <= k} и {@code k.bitLength() <= n.bitLength()}, где
     * {@code n} - порядок базовой точки кривой. Приведение по модулю {@code n} не выполняется:
     * {@code k = n} и {@code k = n + 1} допустимы (для точки подгруппы дают бесконечность и
     * {@code P}, для точки вне подгруппы {@code nP} и {@code nP + P}), {@code k = 0} даёт
     * бесконечность. Лестница читает только {@code n.bitLength()} младших бит, поэтому более
     * длинный скаляр молча усекался бы и давал неверный результат; такой скаляр отвергается.
     *
     * <p>Результат определяется только групповым законом: для точки вне кривой он не
     * определён. Если результат - бесконечность, использовать нужно только
     * {@link #isInfinity()}, значения {@link #getX()} и {@link #getY()} при этом не имеют смысла.
     * Чтение бит через {@link BigInteger#testBit(int)} не гарантирует постоянное время: путь
     * зависит от длины числа.
     *
     * @param k скаляр
     * @return {@code k·P}
     * @throws IllegalArgumentException если {@code k} равен {@code null}, отрицателен или
     *     длиннее порядка кривой
     */
    public ECPoint multiply(BigInteger k) {
        if (k == null) {
            throw new IllegalArgumentException("k must not be null");
        }
        int bitLen = params.n.bitLength();
        if (k.signum() < 0 || k.bitLength() > bitLen) {
            throw new IllegalArgumentException("Scalar k is outside the range [0, 2^bitLength(n))");
        }
        ECPoint r0 = infinity(params), r1 = this;
        int previousBit = 0;
        for (int i = bitLen - 1; i >= 0; i--) {
            int bit = k.testBit(i) ? 1 : 0;
            // Второй обмен предыдущей итерации и первый обмен текущей идут подряд, поэтому
            // сливаются в один по условию bit ^ previousBit: один обмен на итерацию вместо двух
            ECPoint[] sw = cswap(r0, r1, bit ^ previousBit);
            r0 = sw[0];
            r1 = sw[1];
            previousBit = bit;
            // инвариант: r1 - r0 = ±P, поэтому при P != O точки различны и полное сложение
            // с вычислением twice() ради случая P == Q здесь не нужно
            r1 = r0.addDistinct(r1);
            r0 = r0.twice();
        }
        // последний обмен возвращает регистры в положение, в котором результат лежит в r0
        return cswap(r0, r1, previousBit)[0].normalize();
    }

    private static ECPoint[] cswap(ECPoint a, ECPoint b, int swap) {
        long c = swap & 1L;
        return new ECPoint[] {
            new ECPoint(
                    selectFE(a.x, b.x, c), selectFE(a.y, b.y, c), selectFE(a.z, b.z, c), a.params),
            new ECPoint(
                    selectFE(b.x, a.x, c), selectFE(b.y, a.y, c), selectFE(b.z, a.z, c), b.params)
        };
    }

    public ECPoint[] buildWNafTable(int w) {
        int tableSize = 1 << (w - 2);
        ECPoint[] table = new ECPoint[tableSize];
        table[0] = this;
        ECPoint p2 = this.twice();
        for (int i = 1; i < tableSize; i++) table[i] = table[i - 1].add(p2);
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
            } else {
                naf[idx] = 0;
            }
            k = k.shiftRight(1);
            idx++;
        }
        return naf;
    }

    public boolean isOnCurve() {
        if (isInfinity()) return false;
        ECPoint norm = normalize();
        BigInteger p = params.p;
        BigInteger bx = norm.x.toBigInteger(), by = norm.y.toBigInteger();
        BigInteger y2 = by.multiply(by).mod(p);
        BigInteger x3 = bx.multiply(bx).mod(p).multiply(bx).mod(p);
        BigInteger rhs = x3.add(params.a.multiply(bx)).add(params.b).mod(p);
        return y2.equals(rhs);
    }

    /**
     * Проверяет, что точка является корректным открытым ключом:
     * лежит на кривой и принадлежит подгруппе простого порядка n.
     * <p>
     * Для кривых с кофактором 1 (все стандартные ГОСТ-кривые, кроме TC26-A-256 и TC26-C-512)
     * проверка ограничивается {@link #isOnCurve()}, поскольку все точки на кривой
     * автоматически принадлежат подгруппе. Для кривых с кофактором &gt; 1
     * (TC26-A-256 и TC26-C-512, h = 4) дополнительно проверяется {@code multiply(n).isInfinity()}.
     *
     * @return {@code true} если точка является валидным открытым ключом
     */
    public boolean isValidPublicKey() {
        if (!isOnCurve()) {
            return false;
        }
        if (params.cofactor == 1) {
            return true;
        }
        return multiply(params.n).isInfinity();
    }
}
