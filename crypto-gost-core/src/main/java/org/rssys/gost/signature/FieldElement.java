package org.rssys.gost.signature;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Элемент поля GF(p) для кривых ГОСТ Р 34.10-2012, представленный в форме Монтгомери.
 * <p>
 * Внутреннее представление: {@code long[]} в формате Монтгомери, лимбы little-endian,
 * каждый лимб 64 бита без знака (интерпретируется как {@code long} со знаком, но
 * арифметика использует {@code Long.toUnsignedLong} и {@code Math.unsignedMultiplyHigh}).
 * <ul>
 *   <li>256-бит (paramSetA, B): 4 лимба × 64 бит</li>
 *   <li>512-бит (paramSetC, D): 8 лимбов × 64 бит</li>
 * </ul>
 *
 * <p><b>Форма Монтгомери:</b> элемент {@code a} хранится как {@code a·R mod p},
 * где {@code R = 2^(64·numLimbs)}. Умножение двух элементов выполняется через
 * {@link #montMul}, который возвращает {@code (a·R)·(b·R)·R⁻¹ mod p = a·b·R mod p}.
 *
 * <p><b>Жизненный цикл:</b>
 * <ol>
 *   <li>Создать из {@link BigInteger} через {@link #of(BigInteger, MontgomeryParams)}
 *       — конвертирует в форму Монтгомери: {@code a·R mod p}</li>
 *   <li>Выполнять операции {@link #add}, {@link #subtract}, {@link #multiply},
 *       {@link #square}, {@link #negate}</li>
 *   <li>Преобразовать обратно в {@link BigInteger} через {@link #toBigInteger}
 *       — вызывается только при {@link ECPoint#normalize()}</li>
 * </ol>
 *
 * <p><b>Параметры Монтгомери</b> (класс {@link MontgomeryParams}) вычисляются один раз
 * на набор параметров кривой в {@link ECParameters} и переиспользуются.
 *
 * <p><b>Безопасность:</b> на уровне алгоритма нет явных ветвлений по значениям лимбов, число
 * шагов цикла от значений не зависит, а условное вычитание и выбор результата выполняются
 * масками. Переносы вычисляются условными выражениями вида {@code cond ? 1L : 0L}, поэтому
 * постоянное время на уровне машинного кода JIT не гарантируется и здесь не заявляется.
 */
final class FieldElement {

    // -------------------------------------------------------------------------
    // Параметры Монтгомери
    // -------------------------------------------------------------------------

    /**
     * Предвычисленные параметры для арифметики Монтгомери по данному модулю p.
     * Вычисляются один раз в {@link ECParameters} и передаются в каждый {@link FieldElement}.
     */
    static final class MontgomeryParams {
        /**
         * Модуль p в виде массива лимбов (little-endian, 64-бит).
         */
        final long[] p;

        /**
         * Число лимбов: 4 для 256-бит, 8 для 512-бит.
         */
        final int n;

        /**
         * Константа Монтгомери: {@code m0 = −p⁻¹ mod 2^64}.
         * Используется в inner loop алгоритма CIOS.
         */
        final long m0;

        /**
         * {@code R mod p = 2^(64n) mod p} — используется для конвертации в форму Монтгомери.
         * Хранится в виде лимбов.
         */
        final long[] rModP;

        /**
         * p − 2 — константа для инверсии через малую теорему Ферма a^(p−2) mod p.
         */
        final BigInteger expPMinus2;

        /**
         * {@code R² mod p} — используется для конвертации {@code a -> a·R mod p}
         * через одно {@code montMul(a, R²) = a·R² · R⁻¹ = a·R mod p}.
         */
        final long[] r2ModP;

        /**
         * Вычисляет параметры Монтгомери для модуля {@code modulus}.
         * Вызывается один раз при создании {@link ECParameters}.
         *
         * @param modulus простое число p (модуль поля)
         */
        MontgomeryParams(BigInteger modulus) {
            this.n = (modulus.bitLength() + 63) / 64;
            this.p = toLimbs(modulus, n);

            // m0 = −p⁻¹ mod 2^64
            // p·p⁻¹ ≡ 1 (mod 2^64) -> m0 = −p⁻¹ mod 2^64
            BigInteger mod64 = BigInteger.ONE.shiftLeft(64);
            BigInteger pMod64 = modulus.mod(mod64);
            BigInteger pInv = pMod64.modInverse(mod64);
            BigInteger m0Big = mod64.subtract(pInv).mod(mod64);
            this.m0 = m0Big.longValue();

            // R mod p = 2^(64n) mod p
            BigInteger R = BigInteger.ONE.shiftLeft(64 * n);
            this.rModP = toLimbs(R.mod(modulus), n);
            // BigInteger.TWO добавлен в Android API 33 (Java 9); ZERO/ONE/TEN — с API 1.
            // Проверено: javap -cp android.jar java.math.BigInteger | grep "TWO" пуст на API 31/32.
            BigInteger two = BigInteger.valueOf(2);
            this.expPMinus2 = modulus.subtract(two);
            // R² mod p = R·R mod p
            this.r2ModP = toLimbs(R.multiply(R).mod(modulus), n);
        }
    }

    // -------------------------------------------------------------------------
    // Поля экземпляра
    // -------------------------------------------------------------------------

    /**
     * Лимбы в форме Монтгомери: {@code value = a·R mod p}, little-endian.
     */
    private final long[] limbs;

    /**
     * Параметры Монтгомери для данного поля.
     */
    private final MontgomeryParams mp;

    private FieldElement(long[] limbs, MontgomeryParams mp) {
        this.limbs = limbs;
        this.mp = mp;
    }

    // -------------------------------------------------------------------------
    // Фабричные методы
    // -------------------------------------------------------------------------

    /**
     * Создаёт элемент поля из {@link BigInteger}, конвертируя в форму Монтгомери.
     * {@code result = a·R mod p}.
     */
    public static FieldElement of(BigInteger a, MontgomeryParams mp) {
        long[] aLimbs = toLimbs(a.mod(toBigInteger(mp.p, mp.n)), mp.n);
        // a·R mod p = montMul(a, R² mod p) · R⁻¹ · R = montMul(a, R²)
        return new FieldElement(montMul(aLimbs, mp.r2ModP, mp), mp);
    }

    /**
     * Нулевой элемент поля (аддитивная нейтраль).
     */
    public static FieldElement zero(MontgomeryParams mp) {
        return new FieldElement(new long[mp.n], mp);
    }

    /**
     * Единичный элемент поля в форме Монтгомери: {@code R mod p}.
     */
    public static FieldElement one(MontgomeryParams mp) {
        return new FieldElement(mp.rModP.clone(), mp);
    }

    // В hot-path invert() каждый вызов selectFE создаёт новый long[] — ~4 alloc на итерацию.
    // cswap обменивает содержимое массивов напрямую через маскированный XOR, без аллокаций.
    // Для CT достаточно, что обе ветки (swap и no-swap) выполняют одинаковое количество
    // операций с одинаковым шаблоном доступа к памяти.
    private static void cswap(long[] a, long[] b, long cond) {
        long mask = -cond;
        for (int i = 0; i < a.length; i++) {
            long t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    /**
     * Инверсия элемента поля: a^(p−2) mod p (малая теорема Ферма).
     * Constant-time: фиксированное число итераций по битам p−2,
     * без ветвлений по значению. Работает только для простого p.
     */
    public FieldElement invert() {
        int n = mp.n;
        BigInteger exp = mp.expPMinus2;
        int bitLen = exp.bitLength();

        // Пять предвыделенных буферов: 0 аллокаций на итерацию
        // вместо ~6 в оригинале (2×selectFE + 2×montMul + 2×condSub).
        // a, b — начальные r0=1, r1=this
        // c, d — рабочие s0, s1 для результатов montMul
        // t — временный буфер для CIOS
        long[] a = new long[n];
        long[] b = new long[n];
        long[] c = new long[n];
        long[] d = new long[n];
        long[] t = new long[n + 2];

        System.arraycopy(mp.rModP, 0, a, 0, n);
        System.arraycopy(limbs, 0, b, 0, n);

        long[] r0 = a, r1 = b, s0 = c, s1 = d;

        // Лестница Монтгомери (square-and-multiply, слева направо).
        // На каждой итерации:
        //   1) cswap(r0, r1, bit) — если бит=1, обмен: квадрат пойдёт
        //      в r0, а произведение в r1 (Montgomery ladder invariant)
        //   2) s0 = r0*r1, s1 = r0²
        //   3) cswap(s0, s1, bit) — обратный обмен, восстанавливающий
        //      правильное положение: r0' = r0², r1' = r0*r1
        //   4) ref-swap: r0 ссылается на s1, r1 на s0; старые буферы
        //      переиспользуются как s0, s1 на следующей итерации
        for (int i = bitLen - 1; i >= 0; i--) {
            long bit = exp.testBit(i) ? 1L : 0L;
            cswap(r0, r1, bit);
            montMulBuf(r0, r1, t, s0, mp);
            montMulBuf(r0, r0, t, s1, mp);
            cswap(s0, s1, bit);

            long[] tmp0 = r0, tmp1 = r1;
            r0 = s1;
            r1 = s0;
            s0 = tmp0;
            s1 = tmp1;
        }

        return new FieldElement(r0, mp);
    }

    /**
     * Конвертирует из формы Монтгомери обратно в обычное представление.
     * Вызывается только в {@link ECPoint#normalize()} — один раз на операцию.
     */
    public BigInteger toBigInteger() {
        // montMul(a·R, 1) = a·R · 1 · R⁻¹ = a mod p
        long[] one = new long[mp.n];
        one[0] = 1L;
        long[] normal = montMul(limbs, one, mp);
        try {
            return toBigInteger(normal, mp.n);
        } finally {
            // координата общей точки ECDH - секрет: промежуточное значение не оставляем в куче
            Arrays.fill(normal, 0L);
        }
    }

    // -------------------------------------------------------------------------
    // Арифметические операции
    // -------------------------------------------------------------------------

    /**
     * Сложение: {@code (a + b) mod p}.
     * Константное время: условная редукция через битовую маску.
     */
    public FieldElement add(FieldElement other) {
        long[] sum = new long[mp.n];
        addInternal(limbs, other.limbs, mp, sum);
        return new FieldElement(sum, mp);
    }

    /**
     * Вычитание: {@code (a − b) mod p}.
     * Реализовано как {@code a + (p − b)}.
     */
    public FieldElement subtract(FieldElement other) {
        long[] neg = subInternal(other.limbs, mp); // p - b
        // neg - временный буфер, в него же пишем сумму: одна аллокация вместо двух
        addInternal(limbs, neg, mp, neg);
        return new FieldElement(neg, mp);
    }

    /**
     * Отрицание: {@code (−a) mod p = p − a}.
     * <p>
     * Constant-time: без ветвления по значению. Всегда вычисляется {@code p − a},
     * затем результат обнуляется через маску если {@code a == 0}.
     * Наивный {@code if (isZero()) return this} создаёт timing-ветвление по
     * секретным данным, а {@code subInternal([0..0])} возвращает {@code p} вместо 0.
     */
    public FieldElement negate() {
        long[] neg = subInternal(limbs, mp);
        // nonZero = 1 если хотя бы один лимб != 0, иначе 0 — без ветвления
        long acc = 0;
        for (long l : limbs) acc |= l;
        long nonZero = (acc | -acc) >>> 63; // 1 если ненулевой, 0 если нулевой
        long keepMask = -nonZero; // 0xFFFF...F если ненулевой, 0 если нулевой
        long[] result = new long[mp.n];
        for (int i = 0; i < mp.n; i++) result[i] = neg[i] & keepMask;
        return new FieldElement(result, mp);
    }

    /**
     * Умножение: {@code (a·b) mod p} через алгоритм CIOS Монтгомери.
     */
    public FieldElement multiply(FieldElement other) {
        return new FieldElement(montMul(limbs, other.limbs, mp), mp);
    }

    /**
     * Возведение в квадрат: {@code a² mod p}.
     * Использует то же montMul — JIT обычно оптимизирует одинаковые операнды.
     */
    public FieldElement square() {
        return new FieldElement(montMul(limbs, limbs, mp), mp);
    }

    /**
     * Сдвиг влево на {@code bits} позиций с редукцией по p, то есть умножение на 2<sup>bits</sup>.
     * <p>
     * Реализован как {@code bits} удвоений на одном буфере: сложение с редукцией в разы дешевле
     * умножения Монтгомери на константу, а буфер выделяется один раз. Для {@code bits <= 0}
     * возвращает сам элемент.
     */
    public FieldElement shiftLeft(int bits) {
        if (bits <= 0) {
            return this;
        }
        long[] doubled = new long[mp.n];
        addInternal(limbs, limbs, mp, doubled);
        for (int i = 1; i < bits; i++) {
            addInternal(doubled, doubled, mp, doubled);
        }
        return new FieldElement(doubled, mp);
    }

    /**
     * Проверка на равенство нулю (в форме Монтгомери 0 -> все лимбы = 0).
     */
    public boolean isZero() {
        long acc = 0;
        for (long limb : limbs) acc |= limb;
        return acc == 0;
    }

    /**
     * Проверка на равенство за постоянное время (сравниваются все лимбы без раннего выхода).
     * Названа не {@code equals}: класс внутренний, элементы поля не кладут в коллекции, и метод с
     * именем {@code equals} без переопределения {@code equals(Object)} легко принять за него.
     * Элементы разных полей с одинаковым числом лимбов не равны: модуль открытый, его сравнение не
     * раскрывает секретов.
     */
    boolean isEqualTo(FieldElement that) {
        if (that.mp != mp && !Arrays.equals(that.mp.p, mp.p)) {
            return false;
        }
        long diff = 0;
        for (int i = 0; i < mp.n; i++) diff |= limbs[i] ^ that.limbs[i];
        return diff == 0;
    }

    /**
     * Доступ к лимбам.
     */
    long[] limbs() {
        return limbs;
    }

    /**
     * Клонирование для cswap.
     */
    FieldElement withLimbs(long[] newLimbs) {
        return new FieldElement(newLimbs, mp);
    }

    // -------------------------------------------------------------------------
    // Внутренние алгоритмы
    // -------------------------------------------------------------------------

    /**
     * Алгоритм CIOS (Coarsely Integrated Operand Scanning) Монтгомери.
     * <p>
     * Вычисляет {@code a·b·R⁻¹ mod p} для a, b в форме Монтгомери.
     * Стоимость: n² умножений 64×64->128 бит.
     * <p>
     * Реализация следует алгоритму из:
     * Koç, Acar, Kaliski — «Analyzing and Comparing Montgomery Multiplication Algorithms»
     * IEEE Micro 1996, Algorithm CIOS.
     */
    // Hot-path multiply/square: свежие массивы, JIT знает t.length=n+2, out.length=n.
    // bounds check elimination от new long[] — +12-15% vs буферной версии.
    // CIOS-цикл (for i 0..n, for j 0..n) ДУБЛИРУЕТ montMulBuf(). Отличия:
    //   — t и out выделяются здесь (montMulBuf получает готовые);
    //   — t обнуляется через new long[] (montMulBuf — явным циклом).
    // РЕГРЕССИЯ: тест montMulEqualsMontMulBuf улавливает расхождение.
    static long[] montMul(long[] a, long[] b, MontgomeryParams mp) {
        int n = mp.n;
        long[] t = new long[n + 2];
        long[] out = new long[n];

        for (int i = 0; i < n; i++) {
            long carry = 0;
            for (int j = 0; j < n; j++) {
                long lo = mulLo(a[i], b[j]);
                long hi = mulHi(a[i], b[j]);
                long sum = t[j] + lo;
                long c1 = Long.compareUnsigned(sum, t[j]) < 0 ? 1L : 0L;
                sum += carry;
                long c2 = Long.compareUnsigned(sum, carry) < 0 ? 1L : 0L;
                t[j] = sum;
                carry = hi + c1 + c2;
            }
            t[n] += carry;
            t[n + 1] += Long.compareUnsigned(t[n], carry) < 0 ? 1L : 0L;

            long m = t[0] * mp.m0;

            carry = 0;
            for (int j = 0; j < n; j++) {
                long lo = mulLo(m, mp.p[j]);
                long hi = mulHi(m, mp.p[j]);
                long sum = t[j] + lo;
                long c1 = Long.compareUnsigned(sum, t[j]) < 0 ? 1L : 0L;
                sum += carry;
                long c2 = Long.compareUnsigned(sum, carry) < 0 ? 1L : 0L;
                t[j] = sum;
                carry = hi + c1 + c2;
            }
            long sum = t[n] + carry;
            long c1 = Long.compareUnsigned(sum, t[n]) < 0 ? 1L : 0L;
            t[n] = sum;
            t[n + 1] += c1;

            System.arraycopy(t, 1, t, 0, n + 1);
            t[n + 1] = 0;
        }

        System.arraycopy(t, 0, out, 0, n);
        conditionalSubtract(out, mp.p, t[n], out);
        return out;
    }

    // Буферная версия montMul для hot-path в invert().
    // Параметры:
    //   t   — рабочий буфер размера n+2 (переиспользуется между вызовами)
    //   out — результат размера n (предвыделен, перезаписывается)
    // Вызов conditionalSubtract(out, ..., out) безопасен: каждая итерация
    // читает out[i] до записи, коллизии индексов нет.
    // CIOS-цикл (for i 0..n, for j 0..n) ДУБЛИРУЕТ montMul(). Отличия:
    //   — t и out получены извне (montMul выделяет сам);
    //   — t обнуляется явным циклом (montMul — через new long[]).
    // РЕГРЕССИЯ: тест montMulEqualsMontMulBuf улавливает расхождение.
    static void montMulBuf(long[] a, long[] b, long[] t, long[] out, MontgomeryParams mp) {
        int n = mp.n;
        for (int j = 0; j < n + 2; j++) t[j] = 0L;

        for (int i = 0; i < n; i++) {
            long carry = 0;
            for (int j = 0; j < n; j++) {
                long lo = mulLo(a[i], b[j]);
                long hi = mulHi(a[i], b[j]);
                long sum = t[j] + lo;
                long c1 = Long.compareUnsigned(sum, t[j]) < 0 ? 1L : 0L;
                sum += carry;
                long c2 = Long.compareUnsigned(sum, carry) < 0 ? 1L : 0L;
                t[j] = sum;
                carry = hi + c1 + c2;
            }
            t[n] += carry;
            t[n + 1] += Long.compareUnsigned(t[n], carry) < 0 ? 1L : 0L;

            long m = t[0] * mp.m0;

            carry = 0;
            for (int j = 0; j < n; j++) {
                long lo = mulLo(m, mp.p[j]);
                long hi = mulHi(m, mp.p[j]);
                long sum = t[j] + lo;
                long c1 = Long.compareUnsigned(sum, t[j]) < 0 ? 1L : 0L;
                sum += carry;
                long c2 = Long.compareUnsigned(sum, carry) < 0 ? 1L : 0L;
                t[j] = sum;
                carry = hi + c1 + c2;
            }
            long sum = t[n] + carry;
            long c1 = Long.compareUnsigned(sum, t[n]) < 0 ? 1L : 0L;
            t[n] = sum;
            t[n + 1] += c1;

            System.arraycopy(t, 1, t, 0, n + 1);
            t[n + 1] = 0;
        }

        System.arraycopy(t, 0, out, 0, n);
        conditionalSubtract(out, mp.p, t[n], out);
    }

    /**
     * Сложение с финальной условной редукцией (без ветвления): записывает в {@code out}
     * {@code a + b − p}, если {@code a + b >= p}, иначе {@code a + b}.
     * <p>
     * {@code out} не должен быть массивом лимбов живого {@link FieldElement}: элементы
     * неизменяемы и массив может использоваться ещё кем-то. Совпадение {@code out == a} и
     * {@code out == b} допустимо только для временных массивов, которыми вызывающий больше не
     * пользуется; после вызова такие операнды считаются испорченными. Само совпадение безопасно:
     * лимб {@code i} читается из операндов до записи в {@code out[i]}, а лимбы с другими
     * индексами на него не влияют.
     */
    static void addInternal(long[] a, long[] b, MontgomeryParams mp, long[] out) {
        int n = mp.n;
        long carry = 0;
        for (int i = 0; i < n; i++) {
            // Двухшаговая формула (Knuth, Hacker's Delight): избегает overflow при a+b+carry.
            // Шаг 1: partial = a + b (может wrap); carry_ab = перенос из a+b.
            long partial = a[i] + b[i];
            long carryAb = Long.compareUnsigned(partial, a[i]) < 0 ? 1L : 0L;
            // Шаг 2: sum = partial + carry_in (carry_in = 0 или 1, overflow невозможен если partial
            // != MAX).
            long s = partial + carry;
            long carryCin = Long.compareUnsigned(s, partial) < 0 ? 1L : 0L;
            carry = carryAb | carryCin;
            out[i] = s;
        }
        conditionalSubtract(out, mp.p, carry, out);
    }

    /**
     * Вычитание: {@code p − a mod p}.
     * Если a = 0, возвращает {@code p}, а не 0: результат не приведён по модулю. Это допустимо,
     * потому что вызывающие ({@link #subtract}, {@link #negate}) либо складывают его через
     * {@link #addInternal} с условной редукцией, либо обнуляют маской.
     */
    static long[] subInternal(long[] a, MontgomeryParams mp) {
        int n = mp.n;
        long[] result = new long[n];
        long borrow = 0;
        for (int i = 0; i < n; i++) {
            // Двухшаговая формула: избегает overflow при a[i]+borrow.
            // Шаг 1: diff = p[i] - a[i]; borrow_pa = перенос из p-a.
            long diff = mp.p[i] - a[i];
            long borrowPa = Long.compareUnsigned(mp.p[i], a[i]) < 0 ? 1L : 0L;
            // Шаг 2: вычтем borrow_in.
            long d = diff - borrow;
            long borrowCin = Long.compareUnsigned(diff, borrow) < 0 ? 1L : 0L;
            borrow = borrowPa | borrowCin;
            result[i] = d;
        }
        return result;
    }

    /**
     * Условное вычитание без ветвления: если {@code overflowBit != 0} или {@code a >= p},
     * записывает в {@code out} значение {@code a − p}, иначе {@code a}.
     * <p>
     * Используется как финальный шаг в {@link #montMul}, {@link #montMulBuf} и
     * {@link #addInternal}. {@code out} может совпадать с {@code a}: чтение {@code a[i]}
     * предшествует записи {@code out[i]}, а лимбы с другими индексами на него не влияют.
     * Маска вычитания: 0 - не вычитать, все биты 1 - вычитать.
     */
    static void conditionalSubtract(long[] a, long[] p, long overflowBit, long[] out) {
        int n = a.length;
        long gt = 0, lt = 0;
        for (int i = n - 1; i >= 0; i--) {
            long aGtP = Long.compareUnsigned(a[i], p[i]) > 0 ? 1L : 0L;
            long aLtP = Long.compareUnsigned(a[i], p[i]) < 0 ? 1L : 0L;
            gt |= aGtP & ~lt & ~gt;
            lt |= aLtP & ~gt & ~lt;
        }
        long ge = overflowBit | gt | (1L ^ (lt | gt));
        long mask = -ge;
        long borrow = 0;
        for (int i = 0; i < n; i++) {
            long sub = p[i] & mask;
            long diff = a[i] - sub;
            long borrowSub = Long.compareUnsigned(a[i], sub) < 0 ? 1L : 0L;
            long d = diff - borrow;
            long borrowCin = Long.compareUnsigned(diff, borrow) < 0 ? 1L : 0L;
            borrow = borrowSub | borrowCin;
            out[i] = d;
        }
    }

    // -------------------------------------------------------------------------
    // Вспомогательные методы
    // -------------------------------------------------------------------------

    /**
     * MethodHandle для {@code Math.unsignedMultiplyHigh(long, long)}, доступного с JDK 18 и
     * отсутствующего в Android 14 (API 34). {@code null}, если метода нет, - тогда используется
     * {@link #mulHighFallback}. Замена на {@code Math.multiplyHigh} с поправкой на знак (она есть
     * везде) на 512-битных кривых замедляла умножение на 14 %, поэтому быстрый путь оставлен.
     */
    private static final MethodHandle MUL_HIGH = resolveMulHigh();

    private static MethodHandle resolveMulHigh() {
        try {
            return MethodHandles.lookup()
                    .findStatic(
                            Math.class,
                            "unsignedMultiplyHigh",
                            MethodType.methodType(long.class, long.class, long.class));
        } catch (NoSuchMethodException | IllegalAccessException e) {
            return null; // Android 14 и JDK до 18: метода нет, используется mulHighFallback
        }
    }

    /**
     * Младшие 64 бита произведения a·b (беззнаковое 64×64).
     */
    private static long mulLo(long a, long b) {
        return a * b; // Java long умножение — автоматически даёт lo-часть
    }

    /**
     * Старшие 64 бита произведения a·b (беззнаковое 64×64).
     * Стратегия выбрана один раз при загрузке класса: {@code Math.unsignedMultiplyHigh} (одна
     * инструкция MULQ) там, где он есть, иначе {@link #mulHighFallback}.
     */
    private static long mulHi(long a, long b) {
        if (MUL_HIGH != null) {
            try {
                return (long) MUL_HIGH.invokeExact(a, b);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable t) {
                // invokeExact объявляет Throwable, но чистая арифметика проверяемых исключений не
                // бросает: молчаливый переход на запасной путь скрыл бы сбой JVM
                throw new AssertionError("Math.unsignedMultiplyHigh failed", t);
            }
        }
        return mulHighFallback(a, b);
    }

    /**
     * Переносимая реализация старшего слова 64×64->128 через разбивку на 32-битные половины
     * (четыре умножения). Работает на любой JVM, в том числе на Android 14, где нет
     * {@code Math.unsignedMultiplyHigh}.
     */
    private static long mulHighFallback(long a, long b) {
        long aLo = a & 0xFFFFFFFFL, aHi = a >>> 32;
        long bLo = b & 0xFFFFFFFFL, bHi = b >>> 32;
        long p0 = aLo * bLo;
        long p1 = aLo * bHi;
        long p2 = aHi * bLo;
        long p3 = aHi * bHi;
        long mid = (p0 >>> 32) + (p1 & 0xFFFFFFFFL) + (p2 & 0xFFFFFFFFL);
        return p3 + (p1 >>> 32) + (p2 >>> 32) + (mid >>> 32);
    }

    /**
     * Конвертирует {@link BigInteger} в массив лимбов little-endian.
     * Число должно быть неотрицательным и умещаться в {@code n} лимбов.
     */
    static long[] toLimbs(BigInteger val, int n) {
        long[] limbs = new long[n];
        byte[] bytes = val.toByteArray();
        // BigInteger.toByteArray() — big-endian, возможен ведущий 0x00
        int start = (bytes[0] == 0) ? 1 : 0;
        int len = bytes.length - start;
        for (int i = 0; i < len; i++) {
            int byteIdx = len - 1 - i; // байт с конца (little-endian)
            int limbIdx = i / 8;
            int bitShift = (i % 8) * 8;
            if (limbIdx < n) {
                limbs[limbIdx] |= ((long) (bytes[start + byteIdx] & 0xFF)) << bitShift;
            }
        }
        return limbs;
    }

    /**
     * Конвертирует массив лимбов little-endian в {@link BigInteger}.
     */
    static BigInteger toBigInteger(long[] limbs, int n) {
        byte[] bytes = new byte[n * 8 + 1]; // +1 для знакового бита
        try {
            for (int i = 0; i < n; i++) {
                long limb = limbs[i];
                for (int j = 0; j < 8; j++) {
                    // big-endian порядок байт в массиве, лимбы little-endian
                    bytes[bytes.length - 1 - (i * 8 + j)] = (byte) (limb >> (j * 8));
                }
            }
            return new BigInteger(1, bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
