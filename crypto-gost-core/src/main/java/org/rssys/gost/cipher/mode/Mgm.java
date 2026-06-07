package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.AuthenticationException;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Режим MGM (Multilinear Galois Mode) — аутентифицированное шифрование с
 * ассоциированными данными (AEAD) по RFC 9058 и Р 1323565.1.026-2019.
 *
 * <p>Алгоритм основан на принципе Encrypt-then-MAC (EtM):
 * <ol>
 *   <li>Шифрование открытого текста в режиме счётчика (CTR-подобный)</li>
 *   <li>Вычисление тега аутентификации над AAD и шифртекстом с помощью
 *       мультилинейной функции Галуа</li>
 * </ol>
 *
 * <p>Ссылки:
 * <ul>
 *   <li>RFC 9058 — Multilinear Galois Mode (MGM)</li>
 *   <li>Р 1323565.1.026-2019 — Режимы аутентифицированного шифрования блочного шифра</li>
 * </ul>
 *
 * <h2>Ключевые оптимизации относительно исходной реализации</h2>
 *
 * <h3>Long-арифметика вместо byte[] на горячем пути</h3>
 * Исходная реализация хранила счётчики Y, Z и аккумулятор sum как {@code byte[16]},
 * создавая на каждый блок несколько временных массивов (H, gamma, ctBlock, product).
 * Теперь все блоки хранятся как пары {@code (hi, lo) : long} — поля экземпляра.
 * Никаких {@code new byte[]} в {@code processBytes} или {@code updateAAD}.
 *
 * <h3>Zero-allocation шифрование через {@link Kuznyechik#encryptToFields}</h3>
 * Исходная реализация вызывала {@code cipher.processBlock(src, 0, dst, 0)} — два
 * byte[]-прохода с копированием. Теперь {@link Kuznyechik#encryptToFields} пишет
 * результат напрямую в поля {@code encBufHi}/{@code encBufLo}, читаемые через
 * геттеры. Ни одной аллокации на вызов шифра.
 *
 * <h3>GF(2^128) на long-арифметике</h3>
 * Исходный алгоритм итерировал 128 бит побитово, на каждом шаге сдвигая {@code byte[16]}
 * через {@code multiplyByW} (16 байтовых операций). Теперь: два {@code long}-сдвига +
 * одна XOR с константой {@code 0x87L} на итерацию — примерно в 4 раза меньше операций.
 *
 * <h3>Batch CTR — 4 блока гаммы за раз</h3>
 * Для типичного TLS-record ≈ 88 блоков: 22 batch-итерации вместо 88 вызовов шифра.
 * Улучшает branch prediction и I-cache locality горячего цикла.
 *
 * <h3>incr_r / incr_l как long++</h3>
 * Исходная реализация инкрементировала счётчики побайтовым циклом с переносом.
 * Теперь: {@code yLo++} (incr_r) и {@code zHi++} (incr_l). Корректно при числе
 * блоков < 2^64, что всегда выполняется в реальных сценариях.
 */
public final class Mgm {

    // Полином редукции GF(2^128): f(w) - w^128 = w^7 + w^2 + w + 1
    // RFC 9058 §3, Р 1323565.1.026-2019 §5.1
    private static final long GF128_POLY = 0x87L;

    private static final VarHandle LONG_BE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    private static final int BLOCK = 16;

    // Число блоков гаммы, генерируемых за один batch.
    // Значение 4 подобрано эмпирически: баланс между I-cache нагрузкой и branch overhead.
    private static final int BATCH = 4;

    private final Kuznyechik cipher;

    /** Размер тега в байтах (S/8 по RFC 9058). */
    private final int tagSize;

    // Счётчики и аккумулятор — long-пары вместо byte[].
    // Семантика big-endian: hi = байты 0..7, lo = байты 8..15.
    private long yHi, yLo;      // счётчик шифрования Y  (инкремент правой половины: yLo++)
    private long zHi, zLo;      // счётчик аутентификации Z (инкремент левой половины: zHi++)
    private long sumHi, sumLo;  // аккумулятор мультилинейной функции

    // Длины обработанных данных в битах (для финального шага MAC, RFC 9058 §4.1)
    private long aadBitLen;
    private long ctBitLen;

    // Сохранённый ICN для reinitICN()
    private byte[] icn;
    private boolean forEncryption;
    private boolean initialized;
    /** Признак того, что обработка данных начата (AAD больше нельзя добавлять). */
    private boolean aadFinished;
    private boolean finished;

    // Scratch-буфер для неполных блоков AAD/CT — выделяется один раз в конструкторе
    private final byte[] partial = new byte[BLOCK];
    // Буфер неполного AAD-блока для поддержки множественных updateAAD()
    private final byte[] aadBuf = new byte[BLOCK];
    private int aadBufLen;
    // Batch-буфер для CTR-гаммы — BATCH блоков, выделяется один раз
    private final byte[] gammaBuf = new byte[BATCH * BLOCK];

    // Scratch-буферы таблицы GF(2^128) — без аллокаций на горячем пути
    private final long[] mulTabHi = new long[16];
    private final long[] mulTabLo = new long[16];

    /**
     * Результат последнего вызова {@link #gf128MulTo}.
     * Перезаписывается при каждом вызове — прочитать немедленно.
     * Содержит X⊗Y в GF(2^128).
     */
    private long mulResHi, mulResLo;

    /**
     * Создаёт MGM с тегом размером с блок шифра (16 байт для Кузнечика).
     *
     * @param cipher блочный шифр (Кузнечик: blockSize = 16 байт)
     */
    public Mgm(Kuznyechik cipher) {
        this(cipher, BLOCK);
    }

    /**
     * Создаёт MGM с тегом заданного размера.
     *
     * @param cipher  блочный шифр
     * @param tagSize размер тега в байтах (8..16 для Кузнечика)
     * @throws IllegalArgumentException если tagSize вне допустимого диапазона
     */
    public Mgm(Kuznyechik cipher, int tagSize) {
        if (tagSize < 8 || tagSize > BLOCK) {
            throw new IllegalArgumentException(
                    "MGM tag size must be 8.." + BLOCK + " bytes, got " + tagSize);
        }
        this.cipher  = cipher;
        this.tagSize = tagSize;
    }

    /**
     * Инициализирует MGM.
     *
     * @param forEncryption {@code true} — шифрование, {@code false} — расшифрование
     * @param params        {@link ParametersWithIV}: ключ + ICN длиной {@code blockSize} байт
     * @throws IllegalArgumentException если параметры некорректны
     */
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof ParametersWithIV ivp)) {
            throw new IllegalArgumentException("MGM requires ParametersWithIV (key + ICN)");
        }
        byte[] iv = ivp.getIV();

        // ICN ∈ V_{n-1}: n-1 = 127 бит. В байтах: 16 байт, где старший бит = 0.
        // RFC 9058 §3: ICN хранится как 128-битный вектор с нулём в бите 127.
        if (iv.length != BLOCK) {
            throw new IllegalArgumentException(
                    "MGM ICN must be " + BLOCK + " bytes (with MSB=0), got " + iv.length);
        }
        if ((iv[0] & 0x80) != 0) {
            throw new IllegalArgumentException(
                    "MGM ICN must have MSB (bit 127) = 0, per RFC 9058 §3");
        }

        this.forEncryption = forEncryption;
        this.icn           = Arrays.copyOf(iv, iv.length);

        // Инициализируем шифр ключом (E_K используется всегда в режиме шифрования блока)
        cipher.init(true, ivp.getParameters());

        initCounters();
        this.initialized = true;
        this.aadFinished = false;
        this.finished    = false;
    }

    /**
     * Переинициализирует MGM с новым ICN, пропуская дорогостоящий
     * {@code cipher.init()} (ключевое расписание).
     *
     * <p>Симметричный ключ и вычисленные subKeys от предыдущего вызова
     * {@link #init} переиспользуются. Это безопасно, так как subKeys
     * read-only в {@code processBlock}.
     *
     * <p>Все per-message состояние (счётчики Y/Z, аккумулятор MAC, флаги)
     * сбрасывается — идентично поведению {@link #init}.
     *
     * <p>Используется на hot path TLS 1.3 с TLSTREE: 8191/8192 записей
     * используют тот же ключ, меняется только ICN (sequence number).
     *
     * @param newIcn новый ICN ({@code blockSize} байт, MSB=0)
     * @throws IllegalStateException    если MGM не был инициализирован через {@link #init}
     * @throws IllegalArgumentException если ICN некорректной длины или MSB != 0
     */
    public void reinitICN(byte[] newIcn) {
        if (!initialized) {
            throw new IllegalStateException("MGM not initialized with key — call init() first");
        }
        if (newIcn.length != BLOCK) {
            throw new IllegalArgumentException(
                    "MGM ICN must be " + BLOCK + " bytes (with MSB=0), got " + newIcn.length);
        }
        if ((newIcn[0] & 0x80) != 0) {
            throw new IllegalArgumentException(
                    "MGM ICN must have MSB (bit 127) = 0, per RFC 9058 §3");
        }
        this.icn = Arrays.copyOf(newIcn, newIcn.length);
        this.aadFinished = false;
        this.finished    = false;
        initCounters();
    }

    /**
     * Добавляет ассоциированные данные для аутентификации.
     *
     * <p>AAD не шифруется. Должен вызываться до первого вызова {@link #processBytes}.
     * Неполный последний блок дополняется нулями (RFC 9058 §4.1, шаг 2).
     *
     * @param aad    данные AAD
     * @param offset смещение
     * @param len    длина
     * @throws IllegalStateException если обработка данных уже началась
     */
    public void updateAAD(byte[] aad, int offset, int len) {
        checkInitialized();
        if (aadFinished) {
            throw new IllegalStateException("AAD must be provided before ciphertext processing");
        }
        if (len == 0) return;

        int pos = 0;

        // Если есть неполный блок от предыдущего вызова — дополняем до полного
        if (aadBufLen > 0) {
            int fill = Math.min(BLOCK - aadBufLen, len);
            System.arraycopy(aad, offset, aadBuf, aadBufLen, fill);
            aadBufLen += fill;
            pos += fill;
            aadBitLen = Math.addExact(aadBitLen, (long) fill * 8);
            if (aadBufLen == BLOCK) {
                long bhi = (long) LONG_BE.get(aadBuf, 0);
                long blo = (long) LONG_BE.get(aadBuf, 8);
                macStep(bhi, blo);
                aadBufLen = 0;
            }
        }

        // Полные блоки — хэшируем сразу
        while (pos + BLOCK <= len) {
            long bhi = (long) LONG_BE.get(aad, offset + pos);
            long blo = (long) LONG_BE.get(aad, offset + pos + 8);
            macStep(bhi, blo);
            aadBitLen = Math.addExact(aadBitLen, (long) BLOCK * 8);
            pos += BLOCK;
        }

        // Неполный хвост — в буфер
        int remaining = len - pos;
        if (remaining > 0) {
            System.arraycopy(aad, offset + pos, aadBuf, 0, remaining);
            Arrays.fill(aadBuf, remaining, BLOCK, (byte) 0);
            aadBufLen = remaining;
            aadBitLen = Math.addExact(aadBitLen, (long) remaining * 8);
        }
    }

    /**
     * Шифрует или расшифровывает данные.
     *
     * <p>При первом вызове AAD автоматически финализируется.
     * Неполный последний блок поддерживается.
     * MAC вычисляется по принципу EtM: всегда над шифртекстом.
     *
     * @param input  входные данные
     * @param inOff  смещение
     * @param len    длина
     * @param output выходной буфер (длина >= len)
     * @param outOff смещение в выходном буфере
     * @return количество записанных байт (равно len)
     */
    public int processBytes(byte[] input, int inOff, int len,
                            byte[] output, int outOff) {
        checkInitialized();
        ensureAadFinished();
        if (len == 0) return 0;

        int pos = 0;

        // Пакетная обработка BATCH полных блоков за раз:
        // генерируем гамму пачкой, затем XOR и MAC каждого блока
        while (pos + BATCH * BLOCK <= len) {
            for (int b = 0; b < BATCH; b++) {
                // Гамма = E(K, Y_i)
                cipher.encryptToFields(yHi, yLo);
                LONG_BE.set(gammaBuf, b * BLOCK,     cipher.getEncBufHi());
                LONG_BE.set(gammaBuf, b * BLOCK + 8, cipher.getEncBufLo());
                yLo++; // incr_r: wraparound недостижим — ctBitLen (Math.addExact) сработает
                       // при 2^60 байт, что на 8 порядков меньше 2^68 байт до переполнения
            }
            for (int b = 0; b < BATCH; b++) {
                int off = pos + b * BLOCK;
                long dhi = (long) LONG_BE.get(input, inOff + off);
                long dlo = (long) LONG_BE.get(input, inOff + off + 8);
                long ghi = (long) LONG_BE.get(gammaBuf, b * BLOCK);
                long glo = (long) LONG_BE.get(gammaBuf, b * BLOCK + 8);
                long ohi = dhi ^ ghi;
                long olo = dlo ^ glo;
                LONG_BE.set(output, outOff + off,     ohi);
                LONG_BE.set(output, outOff + off + 8, olo);
                // MAC над шифртекстом (EtM: при шифровании над output, при расшифровании над input)
                macStep(forEncryption ? ohi : dhi, forEncryption ? olo : dlo);
            }
            ctBitLen = Math.addExact(ctBitLen, (long) BATCH * BLOCK * 8);
            pos += BATCH * BLOCK;
        }

        // Остаток — по одному блоку
        while (pos < len) {
            int blen = Math.min(BLOCK, len - pos);

            // Гамма = E(K, Y_i)
            cipher.encryptToFields(yHi, yLo);
            long ghi = cipher.getEncBufHi();
            long glo = cipher.getEncBufLo();
            yLo++; // incr_r: wraparound недостижим — ctBitLen (Math.addExact) сработает
                   // при 2^60 байт, что на 8 порядков меньше 2^68 байт до переполнения

            long dhi, dlo;
            if (blen == BLOCK) {
                dhi = (long) LONG_BE.get(input, inOff + pos);
                dlo = (long) LONG_BE.get(input, inOff + pos + 8);
            } else {
                // Неполный блок: дополняем нулями перед XOR и MAC
                Arrays.fill(partial, (byte) 0);
                System.arraycopy(input, inOff + pos, partial, 0, blen);
                dhi = (long) LONG_BE.get(partial, 0);
                dlo = (long) LONG_BE.get(partial, 8);
            }

            long ohi = dhi ^ ghi;
            long olo = dlo ^ glo;

            if (blen == BLOCK) {
                LONG_BE.set(output, outOff + pos,     ohi);
                LONG_BE.set(output, outOff + pos + 8, olo);
            } else {
                // Записываем только blen байт выходных данных
                LONG_BE.set(partial, 0, ohi);
                LONG_BE.set(partial, 8, olo);
                System.arraycopy(partial, 0, output, outOff + pos, blen);
                // Обнуляем хвост результата для MAC: гамма XOR нули = гамма, нам нужны нули
                if (blen <= 8) {
                    ohi &= (-1L << ((8 - blen) * 8));
                    olo = 0L;
                } else {
                    olo &= (-1L << ((BLOCK - blen) * 8));
                }
            }

            // MAC над шифртекстом (EtM)
            macStep(forEncryption ? ohi : dhi, forEncryption ? olo : dlo);
            ctBitLen = Math.addExact(ctBitLen, (long) blen * 8);
            pos += blen;
        }
        return len;
    }

    /**
     * Завершает шифрование и записывает тег аутентификации.
     *
     * @param output выходной буфер
     * @param outOff смещение (должно быть достаточно места для {@link #getTagSize()} байт)
     * @return размер тега в байтах
     * @throws IllegalStateException если MGM не инициализирован или уже завершён
     */
    public int finishEncryption(byte[] output, int outOff) {
        if (finished) throw new IllegalStateException("Already finished; call init() for new message");
        finished = true;
        checkInitialized();
        ensureAadFinished();
        writeTag(output, outOff);
        return tagSize;
    }

    /**
     * Завершает расшифрование и проверяет тег аутентификации.
     *
     * <p>Сравнение выполняется за constant-time через {@link MessageDigest#isEqual}.
     *
     * @param tag    буфер с принятым тегом
     * @param offset смещение тега
     * @throws AuthenticationException если тег не совпадает
     * @throws IllegalStateException   если MGM не инициализирован или уже завершён
     */
    public void finishDecryption(byte[] tag, int offset) throws AuthenticationException {
        if (finished) throw new IllegalStateException("Already finished; call init() for new message");
        finished = true;
        checkInitialized();
        ensureAadFinished();
        byte[] computed = new byte[BLOCK];
        writeTag(computed, 0);
        byte[] received = Arrays.copyOfRange(tag, offset, offset + tagSize);
        if (!MessageDigest.isEqual(Arrays.copyOf(computed, tagSize), received)) {
            throw new AuthenticationException("MGM authentication tag mismatch");
        }
    }

    /** @return размер тега в байтах */
    public int getTagSize() {
        return tagSize;
    }

    /** @return имя алгоритма {@code "GOST3412-2015/MGM"} */
    public String getAlgorithmName() {
        return "GOST3412-2015/MGM";
    }

    /** @return размер блока шифра в байтах */
    public int getBlockSize() {
        return BLOCK;
    }

    // -----------------------------------------------------------------------
    // Внутренние методы
    // -----------------------------------------------------------------------

    /**
     * Инициализирует счётчики Y и Z из ICN.
     * По RFC 9058 §4.1:
     * <pre>
     *   Y_1 = E(K, 0^1 || ICN)  — старший бит = 0 (ICN уже содержит 0 в бите 127)
     *   Z_1 = E(K, 1^1 || ICN)  — выставляем старший бит в 1
     * </pre>
     * ICN = 16 байт, старший бит (бит 127) = 0.
     * {@code 0^1 || ICN} = ICN как есть (старший бит уже 0).
     * {@code 1^1 || ICN} = ICN с выставленным старшим битом (OR с {@code Long.MIN_VALUE} в hi).
     */
    private void initCounters() {
        long icnHi = (long) LONG_BE.get(icn, 0);
        long icnLo = (long) LONG_BE.get(icn, 8);

        // Y_1 = E(K, 0^1 || ICN): ICN уже имеет MSB=0, используем как есть
        cipher.encryptToFields(icnHi, icnLo);
        yHi = cipher.getEncBufHi();
        yLo = cipher.getEncBufLo();

        // Z_1 = E(K, 1^1 || ICN): выставляем MSB (бит 127) в 1
        cipher.encryptToFields(icnHi | Long.MIN_VALUE, icnLo);
        zHi = cipher.getEncBufHi();
        zLo = cipher.getEncBufLo();

        sumHi = 0L; sumLo = 0L;
        aadBitLen = 0L;
        ctBitLen  = 0L;
        aadBufLen = 0;
    }

    /**
     * Финализирует AAD: сбрасывает буфер неполного блока (с дополнением нулями)
     * в macStep. Безопасно вызывать многократно — повторный вызов idempotent.
     * Должен быть вызван до writeTag().
     */
    private void ensureAadFinished() {
        if (aadFinished) return;
        aadFinished = true;
        if (aadBufLen > 0) {
            // Дополняем нулями в aadBuf (последние BLOCK - aadBufLen байт уже 0 от предыдущего раза)
            long bhi = (long) LONG_BE.get(aadBuf, 0);
            long blo = (long) LONG_BE.get(aadBuf, 8);
            macStep(bhi, blo);
            Arrays.fill(aadBuf, (byte) 0);
            aadBufLen = 0;
        }
    }

    /**
     * Обновляет накопитель MAC одним полным (или дополненным нулями) блоком.
     *
     * <p>По RFC 9058 §4.1:
     * <pre>
     *   H_i = E(K, Z_i)
     *   sum = sum XOR (H_i (*) block)   — (*) умножение в GF(2^128)
     *   Z_{i+1} = incr_l(Z_i)
     * </pre>
     *
     * Без аллокаций в куче (scratch-поля): {@link Kuznyechik#encryptToFields} пишет H_i
     * прямо в поля шифра, {@link #gf128MulAccum} использует scratch-буферы {@code mulTabHi}/
     * {@code mulTabLo} и накапливает результат в {@code sumHi}/{@code sumLo}.
     */
    private void macStep(long bhi, long blo) {
        // H_i = E(K, Z_i)
        cipher.encryptToFields(zHi, zLo);
        zHi++; // incr_l: аналогично yLo — защищён aadBitLen/ctBitLen рубежом
        gf128MulAccum(cipher.getEncBufHi(), cipher.getEncBufLo(), bhi, blo);
    }

    /**
     * Вычисляет финальный тег и записывает {@link #tagSize} байт в {@code out[off]}.
     *
     * <p>По RFC 9058 §4.1 (финальный шаг):
     * <pre>
     *   H = E(K, Z)
     *   finSum = sum XOR (H (*) (len(A) || len(C)))
     *   T = MSB_S(E(K, finSum))
     * </pre>
     * len(A) и len(C) — длины в битах, каждая как {@code n/2 = 8} байт в big-endian.
     */
    private void writeTag(byte[] out, int off) {
        // H = E(K, Z_{h+q+1})
        cipher.encryptToFields(zHi, zLo);
        long hhi = cipher.getEncBufHi();
        long hlo = cipher.getEncBufLo();

        // finSum = sum ^ (H (*) lenBlock), где lenBlock = (aadBitLen || ctBitLen)
        // Длины в битах помещаются в 64 бита → hi-части lenBlock = 0, используем только lo
        gf128MulTo(hhi, hlo, aadBitLen, ctBitLen);
        long fsHi = sumHi ^ mulResHi;
        long fsLo = sumLo ^ mulResLo;

        // T = MSB_S(E(K, finSum))
        cipher.encryptToFields(fsHi, fsLo);
        // Записываем tagSize байт: сначала hi (байты 0..7), затем lo (байты 8..15)
        if (tagSize >= 8) {
            LONG_BE.set(out, off, cipher.getEncBufHi());
            if (tagSize == BLOCK) {
                LONG_BE.set(out, off + 8, cipher.getEncBufLo());
            } else {
                byte[] tmp8 = new byte[8];
                LONG_BE.set(tmp8, 0, cipher.getEncBufLo());
                System.arraycopy(tmp8, 0, out, off + 8, tagSize - 8);
            }
        } else {
            byte[] tmp8 = new byte[8];
            LONG_BE.set(tmp8, 0, cipher.getEncBufHi());
            System.arraycopy(tmp8, 0, out, off, tagSize);
        }
    }

    // -----------------------------------------------------------------------
    // GF(2^128) умножение — long-арифметика, алгоритм «right-to-left comb»
    //
    // Поле GF(2^128) задаётся неприводимым многочленом
    // f(w) = w^128 + w^7 + w^2 + w + 1 (RFC 9058 §3).
    // Представление: big-endian, бит 127 — MSB первого байта, бит 0 — LSB последнего.
    // В long-парах: бит 127 = MSB xHi, бит 0 = LSB xLo.
    //
    // Алгоритм: итерируем по 64 битам xLo (w^0..w^63), затем по 64 битам xHi (w^64..w^127).
    // На каждом шаге: если бит == 1, XOR result с V; затем V = V · w.
    //
    // multiply-by-w в GF(2^128):
    //   128-битный сдвиг влево: (vHi, vLo) → ((vHi<<1)|(vLo>>>63), vLo<<1)
    //   Если выдвинулся MSB vHi: XOR с редукционным полиномом 0x87 в LSB vLo.
    //
    // Это в ~4 раза эффективнее побайтового multiplyByW из исходной реализации:
    // 2 long-сдвига + 1 условный XOR вместо 16 байтовых операций.
    // -----------------------------------------------------------------------

    /**
     * Вычисляет {@code result = X ⊗ Y} в GF(2^128) и сохраняет в {@link #mulResHi}/{@link #mulResLo}.
     * Таблица строится в scratch-полях {@link #mulTabHi}/{@link #mulTabLo} — без аллокаций в куче.
     *
     * <h3>Алгоритм: 4-битный Horner</h3>
     * Вместо 128 итераций по 1 биту — 32 итерации по 4 бита (nibble) с
     * предвычисленной таблицей tab[16].
     *
     * <p>Шаг 1 — таблица: {@code tab[k] = k · Y} для k ∈ [0..15].
     * Строится за 15 шагов: чётные k через multiply-by-w от tab[k/2],
     * нечётные k через XOR: tab[k] = tab[k-1] ^ Y.
     *
     * <p>Шаг 2 — Horner слева направо, от старшего nibble X к младшему:
     * <pre>
     *   result = 0
     *   for n in nibbles(X):  // 32 nibbles, старший → младший
     *       result = mulW4(result) ^ tab[n]
     * </pre>
     * {@code mulW4(r)} = r · w^4: 4 последовательных multiply-by-w,
     * каждый = 2 сдвига + 1 условный XOR с 0x87.
     */
    private void gf128MulTo(long xHi, long xLo, long yHi, long yLo) {
        // ---- Шаг 1: tab[k] = k · Y в scratch-полях mulTabHi/mulTabLo ----
        mulTabHi[1] = yHi;  mulTabLo[1] = yLo;
        for (int k = 2; k < 16; k++) {
            if ((k & 1) == 0) {
                long ph = mulTabHi[k >> 1], pl = mulTabLo[k >> 1];
                long msb = ph >>> 63;
                mulTabHi[k] = (ph << 1) | (pl >>> 63);
                mulTabLo[k] = (pl << 1) ^ (GF128_POLY & -msb);
            } else {
                mulTabHi[k] = mulTabHi[k - 1] ^ yHi;
                mulTabLo[k] = mulTabLo[k - 1] ^ yLo;
            }
        }

        // ---- Шаг 2: Horner, 32 nibble от MSB к LSB ----
        long rHi = 0L, rLo = 0L;

        for (int shift = 60; shift >= 0; shift -= 4) {
            long m, h, l;
            m = rHi >>> 63;  h = (rHi << 1) | (rLo >>> 63);  l = (rLo << 1) ^ (GF128_POLY & -m);
            m = h   >>> 63;  rHi = (h << 1) | (l  >>> 63);   rLo = (l  << 1) ^ (GF128_POLY & -m);
            m = rHi >>> 63;  h = (rHi << 1) | (rLo >>> 63);  l = (rLo << 1) ^ (GF128_POLY & -m);
            m = h   >>> 63;  rHi = (h << 1) | (l  >>> 63);   rLo = (l  << 1) ^ (GF128_POLY & -m);
            int n = (int)(xHi >>> shift) & 0xF;
            rHi ^= mulTabHi[n];
            rLo ^= mulTabLo[n];
        }

        for (int shift = 60; shift >= 0; shift -= 4) {
            long m, h, l;
            m = rHi >>> 63;  h = (rHi << 1) | (rLo >>> 63);  l = (rLo << 1) ^ (GF128_POLY & -m);
            m = h   >>> 63;  rHi = (h << 1) | (l  >>> 63);   rLo = (l  << 1) ^ (GF128_POLY & -m);
            m = rHi >>> 63;  h = (rHi << 1) | (rLo >>> 63);  l = (rLo << 1) ^ (GF128_POLY & -m);
            m = h   >>> 63;  rHi = (h << 1) | (l  >>> 63);   rLo = (l  << 1) ^ (GF128_POLY & -m);
            int n = (int)(xLo >>> shift) & 0xF;
            rHi ^= mulTabHi[n];
            rLo ^= mulTabLo[n];
        }

        mulResHi = rHi;
        mulResLo = rLo;
    }

    /**
     * Накапливает {@code sum ^= X ⊗ Y} в GF(2^128). Без аллокаций в куче (scratch-поля).
     * Используется в {@link #macStep} на горячем пути.
     */
    private void gf128MulAccum(long xHi, long xLo, long yHi, long yLo) {
        gf128MulTo(xHi, xLo, yHi, yLo);
        sumHi ^= mulResHi;
        sumLo ^= mulResLo;
    }

    // -----------------------------------------------------------------------
    // Публичный byte[]-адаптер для тестов
    // -----------------------------------------------------------------------

    /**
     * Умножение двух элементов GF(2^128) с полиномом f(w) = w^128+w^7+w^2+w+1
     * (RFC 9058 §3).
     *
     * <p>Алгоритм «right-to-left comb»: итерируем по битам X от w^0 к w^127.
     * На каждом шаге: если бит X_i = 1, XOR результата с текущим Y·w^i;
     * затем сдвигаем Y влево на w с редукцией.
     * Этот порядок гарантирует коммутативность.
     *
     * <p>Метод предназначен для тестов корректности GF-арифметики.
     * На горячем пути MGM используется {@link #gf128MulAccum}.
     *
     * @param X левый множитель (16 байт, big-endian)
     * @param Y правый множитель (16 байт, big-endian)
     * @return X ⊗ Y в GF(2^128), 16 байт, big-endian
     */
    public static byte[] gf128Mul(byte[] X, byte[] Y) {
        if (X.length != 16 || Y.length != 16) {
            throw new IllegalArgumentException("gf128Mul: оба аргумента должны быть 16 байт");
        }
        long xHi = (long) LONG_BE.get(X, 0);
        long xLo = (long) LONG_BE.get(X, 8);
        long yHi = (long) LONG_BE.get(Y, 0);
        long yLo = (long) LONG_BE.get(Y, 8);

        long rHi = 0L, rLo = 0L;
        long vHi = yHi, vLo = yLo;
        long x = xLo;
        for (int i = 0; i < 64; i++) {
            // ct сравнение: if ((x & 1L) != 0) { rHi ^= vHi; rLo ^= vLo; }
            long bit = -(x & 1L);
            rHi ^= vHi & bit;
            rLo ^= vLo & bit;

            long mask = -(vHi >>> 63);   // 0xFFFF...FF если MSB=1, иначе 0
            vHi = (vHi << 1) | (vLo >>> 63);
            vLo = (vLo << 1) ^ (GF128_POLY & mask);
            x >>>= 1;
        }
        x = xHi;
        for (int i = 0; i < 64; i++) {
            // ct сравнение: if ((x & 1L) != 0) { rHi ^= vHi; rLo ^= vLo; }
            long bit = -(x & 1L);
            rHi ^= vHi & bit;
            rLo ^= vLo & bit;
            
            long mask = -(vHi >>> 63);   // 0xFFFF...FF если MSB=1, иначе 0
            vHi = (vHi << 1) | (vLo >>> 63);
            vLo = (vLo << 1) ^ (GF128_POLY & mask);
            x >>>= 1;
        }

        byte[] result = new byte[16];
        LONG_BE.set(result, 0, rHi);
        LONG_BE.set(result, 8, rLo);
        return result;
    }

    /**
     * Обнуляет всё состояние: делегирует {@link Kuznyechik#destroy()},
     * затирает счётчики, аккумулятор MAC, ICN и scratch-буферы.
     * После вызова экземпляр непригоден для использования.
     */
    public void destroy() {
        cipher.destroy();
        yHi = 0L; yLo = 0L;
        zHi = 0L; zLo = 0L;
        sumHi = 0L; sumLo = 0L;
        aadBitLen = 0L;
        ctBitLen = 0L;
        if (icn != null) {
            Arrays.fill(icn, (byte) 0);
            icn = null;
        }
        Arrays.fill(partial, (byte) 0);
        Arrays.fill(aadBuf, (byte) 0);
        aadBufLen = 0;
        Arrays.fill(gammaBuf, (byte) 0);
        Arrays.fill(mulTabHi, 0L);
        Arrays.fill(mulTabLo, 0L);
        mulResHi = 0L; mulResLo = 0L;
        initialized = false;
        forEncryption = false;
        aadFinished = false;
        finished = false;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("MGM not initialized — call init() first");
        }
    }
}
