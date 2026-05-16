package org.rssys.gost.cipher;

import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Реализация блочного шифра «Кузнечик» (Grasshopper) по ГОСТ Р 34.12-2015.
 *
 * <ul>
 *   <li>Размер блока: 128 бит (16 байт)</li>
 *   <li>Длина ключа: 256 бит (32 байта)</li>
 *   <li>Количество раундов: 10 (9 полных раундов LSX + финальный XOR с K9)</li>
 * </ul>
 *
 * <h2>Ключевые оптимизации относительно исходной реализации</h2>
 *
 * <h3>T-таблицы переупакованы из {@code byte[16][256][16]} в {@code long[16][256]} × 2</h3>
 * Исходная реализация хранила T-таблицы как {@code byte[][][]}: каждый lookup возвращал
 * {@code byte[16]}, после чего следовали 16 байтовых XOR. Итого на раунд: 16 × 16 = 256
 * байтовых операций.
 * <p>
 * Теперь: {@code T_HI_S[i][x]} и {@code T_LO_S[i][x]} хранят 8 байт результата как {@code long}.
 * На каждый раунд: 16 lookups → 32 long-XOR (вместо 256 байтовых). Таблицы ≈ 64 КБ —
 * укладываются в L2.
 *
 * <h3>PI встроен в T_HI_S / T_LO_S (только шифрование)</h3>
 * Исходная реализация: горячий путь шифрования обращался к {@code T[i][PI[byte]]}.
 * Два уровня индексирования — лишний indirect lookup через массив PI.
 * <p>
 * Теперь: {@code T_HI_S[i][x] = L(e_i · PI[x])} предвычислен при загрузке класса —
 * один lookup вместо двух, 16 PI-обращений на блок устранены.
 * <p>
 * Для расшифрования S⁻¹ применяется <em>после</em> L⁻¹, поэтому PI_INV нельзя встроить
 * в T_INV по входу. Вместо этого добавлены таблицы {@code SI_HI[p][b] / SI_LO[p][b]}
 * ({@code = (long)PI_INV[b] << (56-8·p)}) — применение S⁻¹ к 128-битному значению за
 * 16 lookups + 16 OR, без побайтовых shift-chains.
 *
 * <h3>Блок как пара (hi, lo) : long — нет byte[] на горячем пути</h3>
 * Исходная реализация копировала входной блок в {@code scratchBlock[16]} и работала
 * побайтово. Теперь блок читается двумя {@code VarHandle.getLong} и хранится как два
 * {@code long} в регистрах JIT. Никаких {@code new byte[]} в {@code processBlock}.
 *
 * <h3>Раундовые ключи как long[] вместо byte[][]</h3>
 * {@code skHi[10]} и {@code skLo[10]} вместо {@code byte[10][16]}. Исключает двойное
 * разыменование указателей в цикле раундов.
 *
 * <h3>VarHandle для I/O блоков</h3>
 * {@code LONG_BE.get(arr, off)} генерирует одну инструкцию {@code MOV r64, [mem]} вместо
 * 8 {@code MOVZX}. Два вызова = весь 16-байтовый блок. Не требует {@code --add-opens}.
 *
 * <h3>Инлайн LSX — устранены long[] returns</h3>
 * Промежуточные методы объявлены {@code private static} — JIT инлайнит их без virtual
 * dispatch и без escape analysis, регаля {@code hi}/{@code lo} в регистры. Нет аллокаций
 * ни в каком сценарии прогрева.
 *
 * <h2>Совместимость</h2>
 * Drop-in замена исходного {@code Kuznyechik} — реализует тот же интерфейс {@link BlockCipher}.
 * Требует JDK 9+ (VarHandle); оптимально работает на JDK 25+ с прогретым JIT.
 */
public final class Kuznyechik implements BlockCipher {

    /** Размер блока шифра в байтах (ГОСТ Р 34.12-2015): 128 бит = 16 байт. */
    public static final int BLOCK_SIZE = 16;

    /** Размер ключа в байтах (ГОСТ Р 34.12-2015): 256 бит = 32 байта. */
    public static final int KEY_SIZE = 32;

    // VarHandle для чтения/записи long из byte[] в big-endian порядке.
    // Стандартный API JDK 9+, не требует --add-opens.
    private static final VarHandle LONG_BE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    // -----------------------------------------------------------------------
    // Таблица замен S (Pi) и её инверсия — ГОСТ Р 34.12-2015, приложение А
    // -----------------------------------------------------------------------

    // PI[x]     = S(x)    — прямая S-замена
    // PI_INV[x] = S⁻¹(x)  — обратная S-замена
    // Хранятся как int[] для удобства индексирования без знакового расширения.
    private static final int[] PI     = new int[256];
    private static final int[] PI_INV = new int[256];

    static {
        byte[] piBytes = {
                (byte)0xFC,(byte)0xEE,(byte)0xDD,(byte)0x11,(byte)0xCF,(byte)0x6E,(byte)0x31,(byte)0x16,
                (byte)0xFB,(byte)0xC4,(byte)0xFA,(byte)0xDA,(byte)0x23,(byte)0xC5,(byte)0x04,(byte)0x4D,
                (byte)0xE9,(byte)0x77,(byte)0xF0,(byte)0xDB,(byte)0x93,(byte)0x2E,(byte)0x99,(byte)0xBA,
                (byte)0x17,(byte)0x36,(byte)0xF1,(byte)0xBB,(byte)0x14,(byte)0xCD,(byte)0x5F,(byte)0xC1,
                (byte)0xF9,(byte)0x18,(byte)0x65,(byte)0x5A,(byte)0xE2,(byte)0x5C,(byte)0xEF,(byte)0x21,
                (byte)0x81,(byte)0x1C,(byte)0x3C,(byte)0x42,(byte)0x8B,(byte)0x01,(byte)0x8E,(byte)0x4F,
                (byte)0x05,(byte)0x84,(byte)0x02,(byte)0xAE,(byte)0xE3,(byte)0x6A,(byte)0x8F,(byte)0xA0,
                (byte)0x06,(byte)0x0B,(byte)0xED,(byte)0x98,(byte)0x7F,(byte)0xD4,(byte)0xD3,(byte)0x1F,
                (byte)0xEB,(byte)0x34,(byte)0x2C,(byte)0x51,(byte)0xEA,(byte)0xC8,(byte)0x48,(byte)0xAB,
                (byte)0xF2,(byte)0x2A,(byte)0x68,(byte)0xA2,(byte)0xFD,(byte)0x3A,(byte)0xCE,(byte)0xCC,
                (byte)0xB5,(byte)0x70,(byte)0x0E,(byte)0x56,(byte)0x08,(byte)0x0C,(byte)0x76,(byte)0x12,
                (byte)0xBF,(byte)0x72,(byte)0x13,(byte)0x47,(byte)0x9C,(byte)0xB7,(byte)0x5D,(byte)0x87,
                (byte)0x15,(byte)0xA1,(byte)0x96,(byte)0x29,(byte)0x10,(byte)0x7B,(byte)0x9A,(byte)0xC7,
                (byte)0xF3,(byte)0x91,(byte)0x78,(byte)0x6F,(byte)0x9D,(byte)0x9E,(byte)0xB2,(byte)0xB1,
                (byte)0x32,(byte)0x75,(byte)0x19,(byte)0x3D,(byte)0xFF,(byte)0x35,(byte)0x8A,(byte)0x7E,
                (byte)0x6D,(byte)0x54,(byte)0xC6,(byte)0x80,(byte)0xC3,(byte)0xBD,(byte)0x0D,(byte)0x57,
                (byte)0xDF,(byte)0xF5,(byte)0x24,(byte)0xA9,(byte)0x3E,(byte)0xA8,(byte)0x43,(byte)0xC9,
                (byte)0xD7,(byte)0x79,(byte)0xD6,(byte)0xF6,(byte)0x7C,(byte)0x22,(byte)0xB9,(byte)0x03,
                (byte)0xE0,(byte)0x0F,(byte)0xEC,(byte)0xDE,(byte)0x7A,(byte)0x94,(byte)0xB0,(byte)0xBC,
                (byte)0xDC,(byte)0xE8,(byte)0x28,(byte)0x50,(byte)0x4E,(byte)0x33,(byte)0x0A,(byte)0x4A,
                (byte)0xA7,(byte)0x97,(byte)0x60,(byte)0x73,(byte)0x1E,(byte)0x00,(byte)0x62,(byte)0x44,
                (byte)0x1A,(byte)0xB8,(byte)0x38,(byte)0x82,(byte)0x64,(byte)0x9F,(byte)0x26,(byte)0x41,
                (byte)0xAD,(byte)0x45,(byte)0x46,(byte)0x92,(byte)0x27,(byte)0x5E,(byte)0x55,(byte)0x2F,
                (byte)0x8C,(byte)0xA3,(byte)0xA5,(byte)0x7D,(byte)0x69,(byte)0xD5,(byte)0x95,(byte)0x3B,
                (byte)0x07,(byte)0x58,(byte)0xB3,(byte)0x40,(byte)0x86,(byte)0xAC,(byte)0x1D,(byte)0xF7,
                (byte)0x30,(byte)0x37,(byte)0x6B,(byte)0xE4,(byte)0x88,(byte)0xD9,(byte)0xE7,(byte)0x89,
                (byte)0xE1,(byte)0x1B,(byte)0x83,(byte)0x49,(byte)0x4C,(byte)0x3F,(byte)0xF8,(byte)0xFE,
                (byte)0x8D,(byte)0x53,(byte)0xAA,(byte)0x90,(byte)0xCA,(byte)0xD8,(byte)0x85,(byte)0x61,
                (byte)0x20,(byte)0x71,(byte)0x67,(byte)0xA4,(byte)0x2D,(byte)0x2B,(byte)0x09,(byte)0x5B,
                (byte)0xCB,(byte)0x9B,(byte)0x25,(byte)0xD0,(byte)0xBE,(byte)0xE5,(byte)0x6C,(byte)0x52,
                (byte)0x59,(byte)0xA6,(byte)0x74,(byte)0xD2,(byte)0xE6,(byte)0xF4,(byte)0xB4,(byte)0xC0,
                (byte)0xD1,(byte)0x66,(byte)0xAF,(byte)0xC2,(byte)0x39,(byte)0x4B,(byte)0x63,(byte)0xB6
        };
        for (int i = 0; i < 256; i++) {
            PI[i]         = piBytes[i] & 0xFF;
            PI_INV[PI[i]] = i;
        }
    }

    // -----------------------------------------------------------------------
    // Линейное преобразование L — ГОСТ Р 34.12-2015, таблица А.2
    // -----------------------------------------------------------------------

    // Коэффициенты линейного преобразования L (вектор λ).
    // L реализуется как 16 применений регистра сдвига с обратной связью (R-шаг).
    private static final int[] L_FACTORS = {
            0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
            0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
    };

    // Неприводимый полином GF(2^8): x^8 + x^7 + x^6 + x + 1 = 0xC3
    // ГОСТ Р 34.12-2015, таблица А.2
    private static final int GF_POLY = 0xC3;

    // -----------------------------------------------------------------------
    // Lookup-таблицы для шифрования и расшифрования
    //
    // Шифрование (LSX = XOR + S + L):
    //   T_HI_S[i][x] = верхние 8 байт L(e_i · PI[x])  — PI встроен
    //   T_LO_S[i][x] = нижние  8 байт L(e_i · PI[x])  — PI встроен
    //   Горячий путь: T_HI_S[i][byte] — один lookup вместо T[i][PI[byte]].
    //
    // Расшифрование (XSL⁻¹ = XOR + L⁻¹ + S⁻¹):
    //   T_INV_HI[i][x] = верхние 8 байт L⁻¹(e_i · x)  — без PI_INV
    //   T_INV_LO[i][x] = нижние  8 байт L⁻¹(e_i · x)  — без PI_INV
    //   S⁻¹ применяется отдельно после сборки L⁻¹-результата через SI_HI/SI_LO.
    //
    // S⁻¹ как long-таблица (расшифрование):
    //   SI_HI[p][b] = (long)PI_INV[b] << (56 - 8·p)  для позиции байта p в hi-части
    //   SI_LO[p][b] = (long)PI_INV[b] << (56 - 8·p)  для позиции байта p в lo-части
    //   Применение S⁻¹ к паре (rhi, rlo): 16 lookups + 16 OR — без shift-chains.
    //
    // Суммарный размер: ≈ 164 КБ — L2-resident на современных CPU.
    // -----------------------------------------------------------------------
    private static final long[][] T_HI_S   = new long[16][256];
    private static final long[][] T_LO_S   = new long[16][256];
    private static final long[][] T_INV_HI = new long[16][256];
    private static final long[][] T_INV_LO = new long[16][256];
    private static final long[][] SI_HI    = new long[8][256];
    private static final long[][] SI_LO    = new long[8][256];

    static {
        buildAllTables();
    }

    // -----------------------------------------------------------------------
    // Построение таблиц (выполняется один раз при загрузке класса)
    // -----------------------------------------------------------------------

    /** Умножение a · b в GF(2^8) с полиномом GF_POLY. */
    private static byte gfMul(int a, int b) {
        int r = 0, x = a;
        for (int n = 0; n < 8; n++, b >>= 1) {
            if ((b & 1) != 0) r ^= x;
            boolean msb = (x & 0x80) != 0;
            x = (x << 1) & 0xFF;
            if (msb) x ^= GF_POLY;
        }
        return (byte) r;
    }

    /**
     * R-шаг (регистр сдвига с обратной связью) — один шаг преобразования L.
     * Применяется 16 раз для получения полного L-преобразования.
     */
    private static void applyR(byte[] a) {
        byte fb = a[15];
        for (int i = 14; i >= 0; i--) fb ^= gfMul(a[i] & 0xFF, L_FACTORS[i]);
        System.arraycopy(a, 0, a, 1, 15);
        a[0] = fb;
    }

    /** Обратный R-шаг для L⁻¹-преобразования. */
    private static void applyRInv(byte[] a) {
        byte[] t = new byte[16];
        System.arraycopy(a, 1, t, 0, 15);
        t[15] = a[0];
        byte fb = t[15];
        for (int i = 14; i >= 0; i--) fb ^= gfMul(t[i] & 0xFF, L_FACTORS[i]);
        System.arraycopy(a, 1, a, 0, 15);
        a[15] = fb;
    }

    /** Полное L или L⁻¹ преобразование: 16 применений R или R⁻¹. */
    private static void applyL(byte[] a, boolean inv) {
        for (int s = 0; s < 16; s++) { if (inv) applyRInv(a); else applyR(a); }
    }

    private static void buildAllTables() {
        byte[] tmp = new byte[16];
        for (int i = 0; i < 16; i++) {
            for (int x = 0; x < 256; x++) {
                // Шифрование: T_HI_S[i][x] = L(e_i · PI[x]), PI встроен
                Arrays.fill(tmp, (byte) 0);
                tmp[i] = (byte) PI[x];
                applyL(tmp, false);
                T_HI_S[i][x] = (long) LONG_BE.get(tmp, 0);
                T_LO_S[i][x] = (long) LONG_BE.get(tmp, 8);

                // Расшифрование: T_INV_HI[i][x] = L⁻¹(e_i · x), без PI_INV
                Arrays.fill(tmp, (byte) 0);
                tmp[i] = (byte) x;
                applyL(tmp, true);
                T_INV_HI[i][x] = (long) LONG_BE.get(tmp, 0);
                T_INV_LO[i][x] = (long) LONG_BE.get(tmp, 8);
            }
        }
        // S⁻¹ как long-таблица: байт b в позиции p вносит вклад PI_INV[b] на свою позицию
        for (int p = 0; p < 8; p++) {
            int shift = 56 - 8 * p;
            for (int b = 0; b < 256; b++) {
                long v = (long) PI_INV[b] << shift;
                SI_HI[p][b] = v;
                SI_LO[p][b] = v;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Состояние экземпляра
    // -----------------------------------------------------------------------

    // Раундовые ключи как long-пары вместо byte[][].
    // skHi[i]/skLo[i] — верхние/нижние 8 байт i-го раундового ключа (big-endian).
    // Исключает двойное разыменование в цикле раундов.
    private final long[] skHi = new long[10];
    private final long[] skLo = new long[10];
    private boolean forEncryption;
    private boolean keyInitialized;

    /**
     * Scratch-поля для zero-allocation вызова из {@link org.rssys.gost.cipher.mode.Mgm}.
     * Читать только через {@link #getEncBufHi()} / {@link #getEncBufLo()} сразу
     * после {@link #encryptToFields} — значения действительны только до следующего вызова.
     * Не потокобезопасно: один экземпляр = один поток.
     */
    private long encBufHi, encBufLo;

    /** Результат последнего {@link #encryptToFields}: старшие 8 байт зашифрованного блока. */
    public long getEncBufHi() { return encBufHi; }

    /** Результат последнего {@link #encryptToFields}: младшие 8 байт зашифрованного блока. */
    public long getEncBufLo() { return encBufLo; }

    @Override
    public String getAlgorithmName() {
        return "GOST3412-2015";
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
        if (!(params instanceof SymmetricKey sk)) {
            throw new IllegalArgumentException(
                    "invalid parameter passed to Kuznyechik.init - " + params.getClass().getName());
        }
        byte[] key = sk.getKey();
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException(
                    "invalid key size: " + key.length + " bytes, required " + KEY_SIZE + " bytes");
        }
        this.forEncryption  = forEncryption;
        this.keyInitialized = true;
        generateSubKeys(key);
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        if (!keyInitialized)           throw new IllegalStateException("Kuznyechik not initialized");
        if (inOff  + BLOCK_SIZE > in.length)  throw new DataLengthException("input buffer too short");
        if (outOff + BLOCK_SIZE > out.length) throw new OutputLengthException("output buffer too short");
        if (forEncryption) encryptBlockInlined(in, inOff, out, outOff);
        else               decryptBlockInlined(in, inOff, out, outOff);
        return BLOCK_SIZE;
    }

    @Override
    public void reset() {
        // subKeys не изменяются при обработке блоков — сброс не требуется
    }

    // -----------------------------------------------------------------------
    // Шифрование: 9 раундов LSX + финальный XOR с K9
    //
    // LSX = XOR с ключом → S-замена (PI, встроена в T_HI_S/T_LO_S) → L-преобразование.
    // Весь граф раундов виден JIT в одном методе: hi/lo держатся в регистрах без spill,
    // 32 независимых XOR на раунд переупорядочиваются планировщиком.
    // -----------------------------------------------------------------------
    private void encryptBlockInlined(byte[] in, int inOff, byte[] out, int outOff) {
        long hi = (long) LONG_BE.get(in, inOff);
        long lo = (long) LONG_BE.get(in, inOff + 8);

        for (int r = 0; r < 9; r++) {
            long xhi = hi ^ skHi[r];
            long xlo = lo ^ skLo[r];
            hi = lsxHi(xhi, xlo);
            lo = lsxLo(xhi, xlo);
        }

        // Финальный XOR с последним ключом (без S и L — ГОСТ Р 34.12-2015, §4.2)
        LONG_BE.set(out, outOff,     hi ^ skHi[9]);
        LONG_BE.set(out, outOff + 8, lo ^ skLo[9]);
    }

    // -----------------------------------------------------------------------
    // Расшифрование: 9 раундов XSL⁻¹ + финальный XOR с K0
    //
    // XSL⁻¹ = XOR с ключом → L⁻¹ (через T_INV) → S⁻¹ (через SI_HI/SI_LO).
    // Порядок S⁻¹ после L⁻¹ делает невозможным встраивание PI_INV в T_INV по входу
    // (в отличие от шифрования). SI_HI[p][b] / SI_LO[p][b] хранят (long)PI_INV[b]
    // сдвинутый на позицию p — побайтовый OR собирает результат без shift-chains.
    // -----------------------------------------------------------------------
    private void decryptBlockInlined(byte[] in, int inOff, byte[] out, int outOff) {
        long hi = (long) LONG_BE.get(in, inOff);
        long lo = (long) LONG_BE.get(in, inOff + 8);

        for (int r = 9; r > 0; r--) {
            long xhi = hi ^ skHi[r];
            long xlo = lo ^ skLo[r];

            // L⁻¹ через T_INV (без S⁻¹)
            long rhi = invLHi(xhi, xlo);
            long rlo = invLLo(xhi, xlo);

            // S⁻¹ через SI_HI/SI_LO: каждый байт вносит вклад на свою позицию в long
            hi = SI_HI[0][(int)(rhi >>> 56) & 0xFF] | SI_HI[1][(int)(rhi >>> 48) & 0xFF]
                    | SI_HI[2][(int)(rhi >>> 40) & 0xFF] | SI_HI[3][(int)(rhi >>> 32) & 0xFF]
                    | SI_HI[4][(int)(rhi >>> 24) & 0xFF] | SI_HI[5][(int)(rhi >>> 16) & 0xFF]
                    | SI_HI[6][(int)(rhi >>>  8) & 0xFF] | SI_HI[7][(int) rhi          & 0xFF];

            lo = SI_LO[0][(int)(rlo >>> 56) & 0xFF] | SI_LO[1][(int)(rlo >>> 48) & 0xFF]
                    | SI_LO[2][(int)(rlo >>> 40) & 0xFF] | SI_LO[3][(int)(rlo >>> 32) & 0xFF]
                    | SI_LO[4][(int)(rlo >>> 24) & 0xFF] | SI_LO[5][(int)(rlo >>> 16) & 0xFF]
                    | SI_LO[6][(int)(rlo >>>  8) & 0xFF] | SI_LO[7][(int) rlo          & 0xFF];
        }

        // Финальный XOR с K0
        LONG_BE.set(out, outOff,     hi ^ skHi[0]);
        LONG_BE.set(out, outOff + 8, lo ^ skLo[0]);
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы LSX и L⁻¹
    //
    // private static — JIT инлайнит без virtual dispatch, escape analysis не нужен.
    // Используются как в encryptBlockInlined/decryptBlockInlined, так и в generateSubKeys.
    // -----------------------------------------------------------------------

    /** Верхние 8 байт результата LSX(xhi, xlo): S-замена через T_HI_S + L. */
    private static long lsxHi(long xhi, long xlo) {
        return T_HI_S[ 0][(int)(xhi >>> 56) & 0xFF] ^ T_HI_S[ 1][(int)(xhi >>> 48) & 0xFF]
                ^ T_HI_S[ 2][(int)(xhi >>> 40) & 0xFF] ^ T_HI_S[ 3][(int)(xhi >>> 32) & 0xFF]
                ^ T_HI_S[ 4][(int)(xhi >>> 24) & 0xFF] ^ T_HI_S[ 5][(int)(xhi >>> 16) & 0xFF]
                ^ T_HI_S[ 6][(int)(xhi >>>  8) & 0xFF] ^ T_HI_S[ 7][(int) xhi          & 0xFF]
                ^ T_HI_S[ 8][(int)(xlo >>> 56) & 0xFF] ^ T_HI_S[ 9][(int)(xlo >>> 48) & 0xFF]
                ^ T_HI_S[10][(int)(xlo >>> 40) & 0xFF] ^ T_HI_S[11][(int)(xlo >>> 32) & 0xFF]
                ^ T_HI_S[12][(int)(xlo >>> 24) & 0xFF] ^ T_HI_S[13][(int)(xlo >>> 16) & 0xFF]
                ^ T_HI_S[14][(int)(xlo >>>  8) & 0xFF] ^ T_HI_S[15][(int) xlo          & 0xFF];
    }

    /** Нижние 8 байт результата LSX(xhi, xlo): S-замена через T_LO_S + L. */
    private static long lsxLo(long xhi, long xlo) {
        return T_LO_S[ 0][(int)(xhi >>> 56) & 0xFF] ^ T_LO_S[ 1][(int)(xhi >>> 48) & 0xFF]
                ^ T_LO_S[ 2][(int)(xhi >>> 40) & 0xFF] ^ T_LO_S[ 3][(int)(xhi >>> 32) & 0xFF]
                ^ T_LO_S[ 4][(int)(xhi >>> 24) & 0xFF] ^ T_LO_S[ 5][(int)(xhi >>> 16) & 0xFF]
                ^ T_LO_S[ 6][(int)(xhi >>>  8) & 0xFF] ^ T_LO_S[ 7][(int) xhi          & 0xFF]
                ^ T_LO_S[ 8][(int)(xlo >>> 56) & 0xFF] ^ T_LO_S[ 9][(int)(xlo >>> 48) & 0xFF]
                ^ T_LO_S[10][(int)(xlo >>> 40) & 0xFF] ^ T_LO_S[11][(int)(xlo >>> 32) & 0xFF]
                ^ T_LO_S[12][(int)(xlo >>> 24) & 0xFF] ^ T_LO_S[13][(int)(xlo >>> 16) & 0xFF]
                ^ T_LO_S[14][(int)(xlo >>>  8) & 0xFF] ^ T_LO_S[15][(int) xlo          & 0xFF];
    }

    /** Верхние 8 байт результата L⁻¹(xhi, xlo) через T_INV_HI (без S⁻¹). */
    private static long invLHi(long xhi, long xlo) {
        return T_INV_HI[ 0][(int)(xhi >>> 56) & 0xFF] ^ T_INV_HI[ 1][(int)(xhi >>> 48) & 0xFF]
                ^ T_INV_HI[ 2][(int)(xhi >>> 40) & 0xFF] ^ T_INV_HI[ 3][(int)(xhi >>> 32) & 0xFF]
                ^ T_INV_HI[ 4][(int)(xhi >>> 24) & 0xFF] ^ T_INV_HI[ 5][(int)(xhi >>> 16) & 0xFF]
                ^ T_INV_HI[ 6][(int)(xhi >>>  8) & 0xFF] ^ T_INV_HI[ 7][(int) xhi          & 0xFF]
                ^ T_INV_HI[ 8][(int)(xlo >>> 56) & 0xFF] ^ T_INV_HI[ 9][(int)(xlo >>> 48) & 0xFF]
                ^ T_INV_HI[10][(int)(xlo >>> 40) & 0xFF] ^ T_INV_HI[11][(int)(xlo >>> 32) & 0xFF]
                ^ T_INV_HI[12][(int)(xlo >>> 24) & 0xFF] ^ T_INV_HI[13][(int)(xlo >>> 16) & 0xFF]
                ^ T_INV_HI[14][(int)(xlo >>>  8) & 0xFF] ^ T_INV_HI[15][(int) xlo          & 0xFF];
    }

    /** Нижние 8 байт результата L⁻¹(xhi, xlo) через T_INV_LO (без S⁻¹). */
    private static long invLLo(long xhi, long xlo) {
        return T_INV_LO[ 0][(int)(xhi >>> 56) & 0xFF] ^ T_INV_LO[ 1][(int)(xhi >>> 48) & 0xFF]
                ^ T_INV_LO[ 2][(int)(xhi >>> 40) & 0xFF] ^ T_INV_LO[ 3][(int)(xhi >>> 32) & 0xFF]
                ^ T_INV_LO[ 4][(int)(xhi >>> 24) & 0xFF] ^ T_INV_LO[ 5][(int)(xhi >>> 16) & 0xFF]
                ^ T_INV_LO[ 6][(int)(xhi >>>  8) & 0xFF] ^ T_INV_LO[ 7][(int) xhi          & 0xFF]
                ^ T_INV_LO[ 8][(int)(xlo >>> 56) & 0xFF] ^ T_INV_LO[ 9][(int)(xlo >>> 48) & 0xFF]
                ^ T_INV_LO[10][(int)(xlo >>> 40) & 0xFF] ^ T_INV_LO[11][(int)(xlo >>> 32) & 0xFF]
                ^ T_INV_LO[12][(int)(xlo >>> 24) & 0xFF] ^ T_INV_LO[13][(int)(xlo >>> 16) & 0xFF]
                ^ T_INV_LO[14][(int)(xlo >>>  8) & 0xFF] ^ T_INV_LO[15][(int) xlo          & 0xFF];
    }

    // -----------------------------------------------------------------------
    // Zero-allocation API для Mgm
    //
    // Mgm.macStep и Mgm.processBytes вызывают encryptToFields вместо processBlock,
    // избегая byte[]-round-trip. Результат доступен через getEncBufHi/getEncBufLo
    // сразу после вызова. Не потокобезопасно.
    // -----------------------------------------------------------------------

    /**
     * Шифрует (inHi, inLo) и записывает результат в {@link #encBufHi}/{@link #encBufLo}.
     * Предназначен для вызова из {@link org.rssys.gost.cipher.mode.Mgm} без создания
     * промежуточных массивов. Не потокобезопасен.
     *
     * @param inHi верхние 8 байт входного блока (big-endian long)
     * @param inLo нижние 8 байт входного блока (big-endian long)
     */
    public void encryptToFields(long inHi, long inLo) {
        long hi = inHi, lo = inLo;
        for (int r = 0; r < 9; r++) {
            long xhi = hi ^ skHi[r];
            long xlo = lo ^ skLo[r];
            hi = lsxHi(xhi, xlo);
            lo = lsxLo(xhi, xlo);
        }
        encBufHi = hi ^ skHi[9];
        encBufLo = lo ^ skLo[9];
    }

    // -----------------------------------------------------------------------
    // Развёртка ключа (Key Schedule) — ГОСТ Р 34.12-2015, §4.3
    //
    // Алгоритм идентичен исходному. Изменено: раундовые ключи хранятся как long-пары
    // (skHi/skLo) вместо byte[][], LSX-шаг функции Фейстеля использует lsxHi/lsxLo.
    // -----------------------------------------------------------------------

    private void generateSubKeys(byte[] key) {
        // K = x || y, каждая половина 16 байт
        long xhi = (long) LONG_BE.get(key, 0);
        long xlo = (long) LONG_BE.get(key, 8);
        long yhi = (long) LONG_BE.get(key, 16);
        long ylo = (long) LONG_BE.get(key, 24);

        skHi[0] = xhi; skLo[0] = xlo;
        skHi[1] = yhi; skLo[1] = ylo;

        // 4 итерации по 8 раундов функции Фейстеля F(C_n, x, y)
        byte[] cBuf = new byte[16];
        for (int i = 1; i <= 4; i++) {
            for (int j = 1; j <= 8; j++) {
                // Константа раунда C_n = L(e_n), где n = 8·(i-1)+j
                Arrays.fill(cBuf, (byte) 0);
                cBuf[15] = (byte) (8 * (i - 1) + j);
                applyL(cBuf, false);
                long chi = (long) LONG_BE.get(cBuf, 0);
                long clo = (long) LONG_BE.get(cBuf, 8);

                // Функция Фейстеля F(C, x, y): tmp = LSX(C XOR x) XOR y; y = x; x = tmp
                long txhi = chi ^ xhi, txlo = clo ^ xlo;
                long tmpHi = lsxHi(txhi, txlo) ^ yhi;
                long tmpLo = lsxLo(txhi, txlo) ^ ylo;
                yhi = xhi; ylo = xlo;
                xhi = tmpHi; xlo = tmpLo;
            }
            skHi[2 * i]     = xhi; skLo[2 * i]     = xlo;
            skHi[2 * i + 1] = yhi; skLo[2 * i + 1] = ylo;
        }
    }
}
