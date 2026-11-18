package org.rssys.gost.digest;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

/**
 * Абстрактный базовый класс хэш-функции ГОСТ Р 34.11-2012 (Стрибог), общий для вариантов
 * 256 и 512 бит.
 *
 * <p>Ссылки: RFC 6986 (https://www.rfc-editor.org/rfc/rfc6986), ГОСТ Р 34.11-2012.
 *
 * <h3>Представление данных</h3>
 *
 * Стандарт записывает 512-битные векторы как числа, у которых младший байт стоит последним, а
 * сообщение читается от младшего байта к старшему. Поэтому блок сообщения и результат читаются и
 * пишутся словами {@code long} в порядке little-endian: слово {@code a₀} стандарта — это
 * первые 8 байт блока. Состояние хранится как {@code long[8]} в этой же нумерации, и никаких
 * разворотов массивов не нужно. В RFC 6986 §10 векторы напечатаны старшим байтом вперёд, а
 * библиотека отдаёт байты младшим вперёд: чтобы сверить с RFC, вход и выход переворачивают.
 *
 * <h3>Таблицы</h3>
 *
 * Преобразование LPS (S-замена, перестановка байт P и линейное L) для одного слова сводится к
 * 8 обращениям к таблицам: {@code T_i[x] = L(π(x) · 256^i)}. Таблицы строятся при загрузке
 * класса из S-блока и матрицы {@code A}, поэтому в коде нет 2048 готовых значений. Обращения к
 * таблицам идут по индексу, зависящему от данных, поэтому время работы тоже зависит от данных.
 *
 * <h3>Затирание</h3>
 *
 * Все промежуточные значения живут в полях объекта и затираются в {@link #destroy()}; после
 * {@link #reset()} остаётся только начальное состояние хэша.
 */
public abstract class Streebog implements Digest {

    private static final int BLOCK_BYTES = 64;
    private static final int WORDS = BLOCK_BYTES / Long.BYTES;
    private static final long BLOCK_BITS = 512L;
    private static final int BYTE_MASK = 0xFF;
    private static final int VALUES_PER_BYTE = 256;

    private static final VarHandle LONG_LE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.LITTLE_ENDIAN);

    // S-блок π' (RFC 6986 §6.2). Совпадает с S-блоком Кузнечика (RFC 7801 §4.1.1).
    private static final byte[] PI = {
        (byte) 0xFC, (byte) 0xEE, (byte) 0xDD, (byte) 0x11, (byte) 0xCF, (byte) 0x6E,
        (byte) 0x31, (byte) 0x16, (byte) 0xFB, (byte) 0xC4, (byte) 0xFA, (byte) 0xDA,
        (byte) 0x23, (byte) 0xC5, (byte) 0x04, (byte) 0x4D, (byte) 0xE9, (byte) 0x77,
        (byte) 0xF0, (byte) 0xDB, (byte) 0x93, (byte) 0x2E, (byte) 0x99, (byte) 0xBA,
        (byte) 0x17, (byte) 0x36, (byte) 0xF1, (byte) 0xBB, (byte) 0x14, (byte) 0xCD,
        (byte) 0x5F, (byte) 0xC1, (byte) 0xF9, (byte) 0x18, (byte) 0x65, (byte) 0x5A,
        (byte) 0xE2, (byte) 0x5C, (byte) 0xEF, (byte) 0x21, (byte) 0x81, (byte) 0x1C,
        (byte) 0x3C, (byte) 0x42, (byte) 0x8B, (byte) 0x01, (byte) 0x8E, (byte) 0x4F,
        (byte) 0x05, (byte) 0x84, (byte) 0x02, (byte) 0xAE, (byte) 0xE3, (byte) 0x6A,
        (byte) 0x8F, (byte) 0xA0, (byte) 0x06, (byte) 0x0B, (byte) 0xED, (byte) 0x98,
        (byte) 0x7F, (byte) 0xD4, (byte) 0xD3, (byte) 0x1F, (byte) 0xEB, (byte) 0x34,
        (byte) 0x2C, (byte) 0x51, (byte) 0xEA, (byte) 0xC8, (byte) 0x48, (byte) 0xAB,
        (byte) 0xF2, (byte) 0x2A, (byte) 0x68, (byte) 0xA2, (byte) 0xFD, (byte) 0x3A,
        (byte) 0xCE, (byte) 0xCC, (byte) 0xB5, (byte) 0x70, (byte) 0x0E, (byte) 0x56,
        (byte) 0x08, (byte) 0x0C, (byte) 0x76, (byte) 0x12, (byte) 0xBF, (byte) 0x72,
        (byte) 0x13, (byte) 0x47, (byte) 0x9C, (byte) 0xB7, (byte) 0x5D, (byte) 0x87,
        (byte) 0x15, (byte) 0xA1, (byte) 0x96, (byte) 0x29, (byte) 0x10, (byte) 0x7B,
        (byte) 0x9A, (byte) 0xC7, (byte) 0xF3, (byte) 0x91, (byte) 0x78, (byte) 0x6F,
        (byte) 0x9D, (byte) 0x9E, (byte) 0xB2, (byte) 0xB1, (byte) 0x32, (byte) 0x75,
        (byte) 0x19, (byte) 0x3D, (byte) 0xFF, (byte) 0x35, (byte) 0x8A, (byte) 0x7E,
        (byte) 0x6D, (byte) 0x54, (byte) 0xC6, (byte) 0x80, (byte) 0xC3, (byte) 0xBD,
        (byte) 0x0D, (byte) 0x57, (byte) 0xDF, (byte) 0xF5, (byte) 0x24, (byte) 0xA9,
        (byte) 0x3E, (byte) 0xA8, (byte) 0x43, (byte) 0xC9, (byte) 0xD7, (byte) 0x79,
        (byte) 0xD6, (byte) 0xF6, (byte) 0x7C, (byte) 0x22, (byte) 0xB9, (byte) 0x03,
        (byte) 0xE0, (byte) 0x0F, (byte) 0xEC, (byte) 0xDE, (byte) 0x7A, (byte) 0x94,
        (byte) 0xB0, (byte) 0xBC, (byte) 0xDC, (byte) 0xE8, (byte) 0x28, (byte) 0x50,
        (byte) 0x4E, (byte) 0x33, (byte) 0x0A, (byte) 0x4A, (byte) 0xA7, (byte) 0x97,
        (byte) 0x60, (byte) 0x73, (byte) 0x1E, (byte) 0x00, (byte) 0x62, (byte) 0x44,
        (byte) 0x1A, (byte) 0xB8, (byte) 0x38, (byte) 0x82, (byte) 0x64, (byte) 0x9F,
        (byte) 0x26, (byte) 0x41, (byte) 0xAD, (byte) 0x45, (byte) 0x46, (byte) 0x92,
        (byte) 0x27, (byte) 0x5E, (byte) 0x55, (byte) 0x2F, (byte) 0x8C, (byte) 0xA3,
        (byte) 0xA5, (byte) 0x7D, (byte) 0x69, (byte) 0xD5, (byte) 0x95, (byte) 0x3B,
        (byte) 0x07, (byte) 0x58, (byte) 0xB3, (byte) 0x40, (byte) 0x86, (byte) 0xAC,
        (byte) 0x1D, (byte) 0xF7, (byte) 0x30, (byte) 0x37, (byte) 0x6B, (byte) 0xE4,
        (byte) 0x88, (byte) 0xD9, (byte) 0xE7, (byte) 0x89, (byte) 0xE1, (byte) 0x1B,
        (byte) 0x83, (byte) 0x49, (byte) 0x4C, (byte) 0x3F, (byte) 0xF8, (byte) 0xFE,
        (byte) 0x8D, (byte) 0x53, (byte) 0xAA, (byte) 0x90, (byte) 0xCA, (byte) 0xD8,
        (byte) 0x85, (byte) 0x61, (byte) 0x20, (byte) 0x71, (byte) 0x67, (byte) 0xA4,
        (byte) 0x2D, (byte) 0x2B, (byte) 0x09, (byte) 0x5B, (byte) 0xCB, (byte) 0x9B,
        (byte) 0x25, (byte) 0xD0, (byte) 0xBE, (byte) 0xE5, (byte) 0x6C, (byte) 0x52,
        (byte) 0x59, (byte) 0xA6, (byte) 0x74, (byte) 0xD2, (byte) 0xE6, (byte) 0xF4,
        (byte) 0xB4, (byte) 0xC0, (byte) 0xD1, (byte) 0x66, (byte) 0xAF, (byte) 0xC2,
        (byte) 0x39, (byte) 0x4B, (byte) 0x63, (byte) 0xB6,
    };

    // Матрица A линейного преобразования L (RFC 6986 §6.4): 64 строки по 64 бита. Строка
    // A[63 - i] соответствует биту i входного слова.
    private static final long[] MATRIX_A = {
        0x8E20FAA72BA0B470L, 0x47107DDD9B505A38L, 0xAD08B0E0C3282D1CL, 0xD8045870EF14980EL,
        0x6C022C38F90A4C07L, 0x3601161CF205268DL, 0x1B8E0B0E798C13C8L, 0x83478B07B2468764L,
        0xA011D380818E8F40L, 0x5086E740CE47C920L, 0x2843FD2067ADEA10L, 0x14AFF010BDD87508L,
        0x0AD97808D06CB404L, 0x05E23C0468365A02L, 0x8C711E02341B2D01L, 0x46B60F011A83988EL,
        0x90DAB52A387AE76FL, 0x486DD4151C3DFDB9L, 0x24B86A840E90F0D2L, 0x125C354207487869L,
        0x092E94218D243CBAL, 0x8A174A9EC8121E5DL, 0x4585254F64090FA0L, 0xACCC9CA9328A8950L,
        0x9D4DF05D5F661451L, 0xC0A878A0A1330AA6L, 0x60543C50DE970553L, 0x302A1E286FC58CA7L,
        0x18150F14B9EC46DDL, 0x0C84890AD27623E0L, 0x0642CA05693B9F70L, 0x0321658CBA93C138L,
        0x86275DF09CE8AAA8L, 0x439DA0784E745554L, 0xAFC0503C273AA42AL, 0xD960281E9D1D5215L,
        0xE230140FC0802984L, 0x71180A8960409A42L, 0xB60C05CA30204D21L, 0x5B068C651810A89EL,
        0x456C34887A3805B9L, 0xAC361A443D1C8CD2L, 0x561B0D22900E4669L, 0x2B838811480723BAL,
        0x9BCF4486248D9F5DL, 0xC3E9224312C8C1A0L, 0xEFFA11AF0964EE50L, 0xF97D86D98A327728L,
        0xE4FA2054A80B329CL, 0x727D102A548B194EL, 0x39B008152ACB8227L, 0x9258048415EB419DL,
        0x492C024284FBAEC0L, 0xAA16012142F35760L, 0x550B8E9E21F7A530L, 0xA48B474F9EF5DC18L,
        0x70A6A56E2440598EL, 0x3853DC371220A247L, 0x1CA76E95091051ADL, 0x0EDD37C48A08A6D8L,
        0x07E095624504536CL, 0x8D70C431AC02A736L, 0xC83862965601DD1BL, 0x641C314B2B8EE083L,
    };

    // Раундовые константы C₁..C₁₂ (RFC 6986 §6.5), слова в нумерации стандарта: a₀ — первое.
    private static final long[][] ROUND_CONSTANTS = {
        {
            0xDD806559F2A64507L, 0x05767436CC744D23L, 0xA2422A08A460D315L, 0x4B7CE09192676901L,
            0x714EB88D7585C4FCL, 0x2F6A76432E45D016L, 0xEBCB2F81C0657C1FL, 0xB1085BDA1ECADAE9L,
        },
        {
            0xE679047021B19BB7L, 0x55DDA21BD7CBCD56L, 0x5CB561C2DB0AA7CAL, 0x9AB5176B12D69958L,
            0x61D55E0F16B50131L, 0xF3FEEA720A232B98L, 0x4FE39D460F70B5D7L, 0x6FA3B58AA99D2F1AL,
        },
        {
            0x991E96F50ABA0AB2L, 0xC2B6F443867ADB31L, 0xC1C93A376062DB09L, 0xD3E20FE490359EB1L,
            0xF2EA7514B1297B7BL, 0x06F15E5F529C1F8BL, 0x0A39FC286A3D8435L, 0xF574DCAC2BCE2FC7L,
        },
        {
            0x220CBEBC84E3D12EL, 0x3453EAA193E837F1L, 0xD8B71333935203BEL, 0xA9D72C82ED03D675L,
            0x9D721CAD685E353FL, 0x488E857E335C3C7DL, 0xF948E1A05D71E4DDL, 0xEF1FDFB3E81566D2L,
        },
        {
            0x601758FD7C6CFE57L, 0x7A56A27EA9EA63F5L, 0xDFFF00B723271A16L, 0xBFCD1747253AF5A3L,
            0x359E35D7800FFFBDL, 0x7F151C1F1686104AL, 0x9A3F410C6CA92363L, 0x4BEA6BACAD474799L,
        },
        {
            0xFA68407A46647D6EL, 0xBF71C57236904F35L, 0x0AF21F66C2BEC6B6L, 0xCFFAA6B71C9AB7B4L,
            0x187F9AB49AF08EC6L, 0x2D66C4F95142A46CL, 0x6FA4C33B7A3039C0L, 0xAE4FAEAE1D3AD3D9L,
        },
        {
            0x8886564D3A14D493L, 0x3517454CA23C4AF3L, 0x06476983284A0504L, 0x0992ABC52D822C37L,
            0xD3473E33197A93C9L, 0x399EC6C7E6BF87C9L, 0x51AC86FEBF240954L, 0xF4C70E16EEAAC5ECL,
        },
        {
            0xA47F0DD4BF02E71EL, 0x36ACC2355951A8D9L, 0x69D18D2BD1A5C42FL, 0xF4892BCB929B0690L,
            0x89B4443B4DDBC49AL, 0x4EB7F8719C36DE1EL, 0x03E7AA020C6E4141L, 0x9B1F5B424D93C9A7L,
        },
        {
            0x7261445183235ADBL, 0x0E38DC92CB1F2A60L, 0x7B2B8A9AA6079C54L, 0x800A440BDBB2CEB1L,
            0x3CD955B7E00D0984L, 0x3A7D3A1B25894224L, 0x944C9AD8EC165FDEL, 0x378F5A541631229BL,
        },
        {
            0x74B4C7FB98459CEDL, 0x3698FAD1153BB6C3L, 0x7A1E6C303B7652F4L, 0x9FE76702AF69334BL,
            0x1FFFE18A1B336103L, 0x8941E71CFF8A78DBL, 0x382AE548B2E4F3F3L, 0xABBEDEA680056F52L,
        },
        {
            0x6BCAA4CD81F32D1BL, 0xDEA2594AC06FD85DL, 0xEFBACD1D7D476E98L, 0x8A1D71EFEA48B9CAL,
            0x2001802114846679L, 0xD8FA6BBBEBAB0761L, 0x3002C6CD635AFE94L, 0x7BCD9ED0EFC889FBL,
        },
        {
            0x48BC924AF11BD720L, 0xFAF417D5D9B21B99L, 0xE71DA4AA88E12852L, 0x5D80EF9D1891CC86L,
            0xF82012D430219F9BL, 0xCDA43C32BCDF1D77L, 0xD21380B00449B17AL, 0x378EE767F11631BAL,
        },
    };

    // Таблицы LPS: T_i[x] = L(π(x) · 256^i). Отдельные поля, а не двумерный массив: на
    // горячем пути JIT не перечитывает ссылку на строку и снимает проверку границ при индексе
    // 0..255.
    private static final long[] T0 = new long[VALUES_PER_BYTE];
    private static final long[] T1 = new long[VALUES_PER_BYTE];
    private static final long[] T2 = new long[VALUES_PER_BYTE];
    private static final long[] T3 = new long[VALUES_PER_BYTE];
    private static final long[] T4 = new long[VALUES_PER_BYTE];
    private static final long[] T5 = new long[VALUES_PER_BYTE];
    private static final long[] T6 = new long[VALUES_PER_BYTE];
    private static final long[] T7 = new long[VALUES_PER_BYTE];

    // Нулевое слагаемое для g₀ (RFC 6986 §9): только читается, не изменяется.
    private static final long[] ZERO_WORDS = new long[WORDS];

    static {
        buildTable(T0, 0);
        buildTable(T1, 1);
        buildTable(T2, 2);
        buildTable(T3, 3);
        buildTable(T4, 4);
        buildTable(T5, 5);
        buildTable(T6, 6);
        buildTable(T7, 7);
    }

    /**
     * Строит таблицу {@code T_i}. Преобразование L линейно над GF(2), поэтому образы всех 256
     * значений байта получаются из 8 базисных строк матрицы за 255 сложений, а не за 256 · 8
     * разборов битов: таблицы строятся при первом обращении к классу, на пути первого
     * рукопожатия.
     */
    private static void buildTable(long[] table, int byteIndex) {
        long[] image = new long[VALUES_PER_BYTE];
        int firstBit = Byte.SIZE * byteIndex;
        for (int value = 1; value < VALUES_PER_BYTE; value++) {
            int lowestBit = Integer.numberOfTrailingZeros(value);
            image[value] =
                    image[value & (value - 1)] ^ MATRIX_A[Long.SIZE - 1 - firstBit - lowestBit];
        }
        for (int x = 0; x < VALUES_PER_BYTE; x++) {
            table[x] = image[PI[x] & BYTE_MASK];
        }
    }

    // Состояние хэша: h — промежуточное значение, n — счётчик обработанных бит, sigma — сумма
    // блоков по модулю 2^512 (RFC 6986 §9).
    private final long[] h = new long[WORDS];
    private final long[] n = new long[WORDS];
    private final long[] sigma = new long[WORDS];

    // Рабочие слова: текущий блок, раундовый ключ и состояние шифра E. Выводятся из входа
    // (в HMAC это K ⊕ ipad), поэтому затираются в destroy().
    private final long[] block = new long[WORDS];
    private final long[] roundKey = new long[WORDS];
    private final long[] cipherState = new long[WORDS];

    // Незавершённый блок. Полный блок обрабатывается сразу, поэтому в doFinal здесь всегда
    // меньше 64 байт.
    private final byte[] pending = new byte[BLOCK_BYTES];
    private int pendingLength;

    // Начальное значение h (RFC 6986 §9): все 64 байта равны 0x01 для 256 бит и 0x00 для 512.
    private final long initialWord;

    /**
     * @param initialByte значение, которым заполнены все 64 байта начального значения {@code h}:
     *     {@code 0x00} для варианта 512 бит и {@code 0x01} для 256 бит
     */
    protected Streebog(byte initialByte) {
        long word = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            word = (word << Byte.SIZE) | (initialByte & BYTE_MASK);
        }
        this.initialWord = word;
        // Остальные поля нулевые по умолчанию, поэтому reset() здесь не нужен.
        Arrays.fill(h, word);
    }

    @Override
    public int getByteLength() {
        return BLOCK_BYTES;
    }

    @Override
    public abstract String getAlgorithmName();

    @Override
    public abstract int getDigestSize();

    @Override
    public void update(byte in) {
        pending[pendingLength++] = in;
        if (pendingLength == BLOCK_BYTES) {
            compressBlock(pending, 0);
            pendingLength = 0;
        }
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        Objects.checkFromIndexSize(inOff, len, in.length);
        int offset = inOff;
        int remaining = len;

        // Сначала дополняем незавершённый блок, иначе порядок байт сообщения нарушится.
        if (pendingLength > 0) {
            int taken = Math.min(BLOCK_BYTES - pendingLength, remaining);
            System.arraycopy(in, offset, pending, pendingLength, taken);
            pendingLength += taken;
            offset += taken;
            remaining -= taken;
            if (pendingLength < BLOCK_BYTES) {
                return;
            }
            compressBlock(pending, 0);
            pendingLength = 0;
        }

        // Полные блоки идут прямо из входного массива, без промежуточной копии.
        while (remaining >= BLOCK_BYTES) {
            compressBlock(in, offset);
            offset += BLOCK_BYTES;
            remaining -= BLOCK_BYTES;
        }

        if (remaining > 0) {
            System.arraycopy(in, offset, pending, 0, remaining);
            pendingLength = remaining;
        }
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        int size = getDigestSize();
        // Проверка до вычислений: при ошибке состояние хэша остаётся нетронутым.
        Objects.checkFromIndexSize(outOff, size, out.length);

        // Дополнение последнего блока по RFC 6986 §9: 0…0‖1‖M. Полные блоки обрабатываются сразу,
        // поэтому pendingLength < 64 и для единицы всегда есть место (при пустом остатке блок
        // состоит из одной единицы).
        int messageLength = pendingLength;
        Arrays.fill(pending, messageLength, BLOCK_BYTES, (byte) 0);
        pending[messageLength] = 1;
        loadBlock(pending, 0);

        compress(n, block);
        addToCounter(n, messageLength * (long) Byte.SIZE);
        addMod512(sigma, block);
        compress(ZERO_WORDS, n);
        compress(ZERO_WORDS, sigma);

        // Результат: старшие size · 8 бит h, то есть последние слова в нумерации стандарта.
        int firstWord = WORDS - size / Long.BYTES;
        for (int i = firstWord; i < WORDS; i++) {
            LONG_LE.set(out, outOff + (i - firstWord) * Long.BYTES, h[i]);
        }

        reset();
        return size;
    }

    @Override
    public void reset() {
        Arrays.fill(h, initialWord);
        Arrays.fill(n, 0L);
        Arrays.fill(sigma, 0L);
        Arrays.fill(pending, (byte) 0);
        pendingLength = 0;
    }

    /**
     * Затирает все рабочие поля и возвращает хэш в начальное состояние.
     *
     * <p>{@link #reset()} рабочие слова не очищает: в {@code block} после обработки остаётся
     * последний блок входа (для HMAC это {@code K ⊕ ipad}), в {@code roundKey} и
     * {@code cipherState} — значения, выведенные из входа. Здесь они затираются, поэтому
     * {@code Hmac.clear()} действительно уничтожает производные от ключа данные. Объект после
     * вызова остаётся пригодным: начальное значение {@code h} — публичная константа алгоритма.
     */
    @Override
    public void destroy() {
        Arrays.fill(block, 0L);
        Arrays.fill(roundKey, 0L);
        Arrays.fill(cipherState, 0L);
        reset();
    }

    /** Обрабатывает полный блок сообщения: g_N, затем N += 512 и Σ += m (RFC 6986 §9, шаг 2). */
    private void compressBlock(byte[] source, int offset) {
        loadBlock(source, offset);
        compress(n, block);
        addToCounter(n, BLOCK_BITS);
        addMod512(sigma, block);
    }

    private void loadBlock(byte[] source, int offset) {
        for (int i = 0; i < WORDS; i++) {
            block[i] = (long) LONG_LE.get(source, offset + i * Long.BYTES);
        }
    }

    /**
     * Функция сжатия g_N(h, m) = E(LPS(h ⊕ N), m) ⊕ h ⊕ m (RFC 6986 §8.1), результат в {@code h}.
     *
     * <p>Шифр E (§8.2) — 12 раундов: состояние сдвигается на раундовый ключ и проходит LPS, а
     * следующий ключ получается как {@code LPS(K ⊕ C)}. Тринадцатый ключ добавляется без LPS.
     * Рабочие слова — поля объекта, чтобы не выделять память на каждый блок.
     */
    private void compress(long[] counter, long[] message) {
        lps(h, counter, roundKey);
        System.arraycopy(message, 0, cipherState, 0, WORDS);
        for (long[] roundConstant : ROUND_CONSTANTS) {
            lps(cipherState, roundKey, cipherState);
            lps(roundKey, roundConstant, roundKey);
        }
        for (int i = 0; i < WORDS; i++) {
            h[i] ^= cipherState[i] ^ roundKey[i] ^ message[i];
        }
    }

    /**
     * Преобразование {@code LPS(a ⊕ b)} (RFC 6986 §6): сложение, S-замена, перестановка P и L.
     *
     * <p>S и P сводятся к выбору байта, L — к таблицам, поэтому слово результата {@code j} равно
     * XOR восьми значений {@code T_i[байт j слова i]}. Входы читаются в локальные переменные
     * до записи, так что {@code out} может совпадать с {@code a} или {@code b}. Цикл по
     * позициям развёрнут вручную: на коротких сообщениях (один блок в HMAC и HKDF) JIT не
     * успевает развернуть его сам.
     */
    private static void lps(long[] a, long[] b, long[] out) {
        long x0 = a[0] ^ b[0];
        long x1 = a[1] ^ b[1];
        long x2 = a[2] ^ b[2];
        long x3 = a[3] ^ b[3];
        long x4 = a[4] ^ b[4];
        long x5 = a[5] ^ b[5];
        long x6 = a[6] ^ b[6];
        long x7 = a[7] ^ b[7];
        out[0] =
                T0[(int) x0 & 0xFF]
                        ^ T1[(int) x1 & 0xFF]
                        ^ T2[(int) x2 & 0xFF]
                        ^ T3[(int) x3 & 0xFF]
                        ^ T4[(int) x4 & 0xFF]
                        ^ T5[(int) x5 & 0xFF]
                        ^ T6[(int) x6 & 0xFF]
                        ^ T7[(int) x7 & 0xFF];
        out[1] =
                T0[(int) (x0 >>> 8) & 0xFF]
                        ^ T1[(int) (x1 >>> 8) & 0xFF]
                        ^ T2[(int) (x2 >>> 8) & 0xFF]
                        ^ T3[(int) (x3 >>> 8) & 0xFF]
                        ^ T4[(int) (x4 >>> 8) & 0xFF]
                        ^ T5[(int) (x5 >>> 8) & 0xFF]
                        ^ T6[(int) (x6 >>> 8) & 0xFF]
                        ^ T7[(int) (x7 >>> 8) & 0xFF];
        out[2] =
                T0[(int) (x0 >>> 16) & 0xFF]
                        ^ T1[(int) (x1 >>> 16) & 0xFF]
                        ^ T2[(int) (x2 >>> 16) & 0xFF]
                        ^ T3[(int) (x3 >>> 16) & 0xFF]
                        ^ T4[(int) (x4 >>> 16) & 0xFF]
                        ^ T5[(int) (x5 >>> 16) & 0xFF]
                        ^ T6[(int) (x6 >>> 16) & 0xFF]
                        ^ T7[(int) (x7 >>> 16) & 0xFF];
        out[3] =
                T0[(int) (x0 >>> 24) & 0xFF]
                        ^ T1[(int) (x1 >>> 24) & 0xFF]
                        ^ T2[(int) (x2 >>> 24) & 0xFF]
                        ^ T3[(int) (x3 >>> 24) & 0xFF]
                        ^ T4[(int) (x4 >>> 24) & 0xFF]
                        ^ T5[(int) (x5 >>> 24) & 0xFF]
                        ^ T6[(int) (x6 >>> 24) & 0xFF]
                        ^ T7[(int) (x7 >>> 24) & 0xFF];
        out[4] =
                T0[(int) (x0 >>> 32) & 0xFF]
                        ^ T1[(int) (x1 >>> 32) & 0xFF]
                        ^ T2[(int) (x2 >>> 32) & 0xFF]
                        ^ T3[(int) (x3 >>> 32) & 0xFF]
                        ^ T4[(int) (x4 >>> 32) & 0xFF]
                        ^ T5[(int) (x5 >>> 32) & 0xFF]
                        ^ T6[(int) (x6 >>> 32) & 0xFF]
                        ^ T7[(int) (x7 >>> 32) & 0xFF];
        out[5] =
                T0[(int) (x0 >>> 40) & 0xFF]
                        ^ T1[(int) (x1 >>> 40) & 0xFF]
                        ^ T2[(int) (x2 >>> 40) & 0xFF]
                        ^ T3[(int) (x3 >>> 40) & 0xFF]
                        ^ T4[(int) (x4 >>> 40) & 0xFF]
                        ^ T5[(int) (x5 >>> 40) & 0xFF]
                        ^ T6[(int) (x6 >>> 40) & 0xFF]
                        ^ T7[(int) (x7 >>> 40) & 0xFF];
        out[6] =
                T0[(int) (x0 >>> 48) & 0xFF]
                        ^ T1[(int) (x1 >>> 48) & 0xFF]
                        ^ T2[(int) (x2 >>> 48) & 0xFF]
                        ^ T3[(int) (x3 >>> 48) & 0xFF]
                        ^ T4[(int) (x4 >>> 48) & 0xFF]
                        ^ T5[(int) (x5 >>> 48) & 0xFF]
                        ^ T6[(int) (x6 >>> 48) & 0xFF]
                        ^ T7[(int) (x7 >>> 48) & 0xFF];
        out[7] =
                T0[(int) (x0 >>> 56) & 0xFF]
                        ^ T1[(int) (x1 >>> 56) & 0xFF]
                        ^ T2[(int) (x2 >>> 56) & 0xFF]
                        ^ T3[(int) (x3 >>> 56) & 0xFF]
                        ^ T4[(int) (x4 >>> 56) & 0xFF]
                        ^ T5[(int) (x5 >>> 56) & 0xFF]
                        ^ T6[(int) (x6 >>> 56) & 0xFF]
                        ^ T7[(int) (x7 >>> 56) & 0xFF];
    }

    /**
     * Прибавляет {@code value} (неотрицательное) к счётчику N по модулю 2^512. N — счётчик длины,
     * его значение не секретно, поэтому перенос можно прекращать, когда он исчерпан.
     */
    static void addToCounter(long[] counter, long value) {
        long word = counter[0];
        long sum = word + value;
        long carry = ((word & value) | ((word | value) & ~sum)) >>> (Long.SIZE - 1);
        counter[0] = sum;
        for (int i = 1; i < WORDS && carry != 0; i++) {
            word = counter[i];
            sum = word + carry;
            carry = (word & ~sum) >>> (Long.SIZE - 1);
            counter[i] = sum;
        }
    }

    /**
     * Прибавляет блок к накопителю Σ по модулю 2^512. В Σ складываются блоки сообщения (в HMAC
     * среди них {@code K ⊕ ipad}), поэтому проход фиксированный, без ветвлений и ранних выходов,
     * а перенос считается побитовой формулой старшего бита сумматора, а не сравнением.
     */
    static void addMod512(long[] accumulator, long[] addend) {
        long carry = 0;
        for (int i = 0; i < WORDS; i++) {
            long a = accumulator[i];
            long b = addend[i];
            long sum = a + b + carry;
            carry = ((a & b) | ((a | b) & ~sum)) >>> (Long.SIZE - 1);
            accumulator[i] = sum;
        }
    }
}
