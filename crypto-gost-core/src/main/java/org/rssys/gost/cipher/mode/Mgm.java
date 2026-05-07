package org.rssys.gost.cipher.mode;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.Pack;

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
 * <p>Ссылки:
 * <ul>
 *   <li>RFC 9058 — Multilinear Galois Mode (MGM)</li>
 *   <li>Р 1323565.1.026-2019 — Режимы аутентифицированного шифрования блочного шифра</li>
 * </ul>
 */
public class Mgm {

    // Полином редукции GF(2^128): f(w) - w^128 = w^7 + w^2 + w + 1
    // RFC 9058 §3, Р 1323565.1.026-2019 §5.1
    private static final byte GF128_REDUCTION_POLY = (byte) 0x87;

    private final BlockCipher cipher;
    private final int blockSize;
    /** Размер тега в байтах (S/8 по RFC 9058). */
    private final int tagSize;

    // Сохранённый ICN для reset()
    private byte[] icn;
    private boolean forEncryption;
    private boolean initialized;
    /** Признак того, что обработка данных начата (AAD больше нельзя добавлять). */
    private boolean aadFinished;

    // Счётчики и аккумулятор инициализируются в init() после определения blockSize
    private byte[] Y;   // счётчик шифрования (blockSize байт)
    private byte[] Z;   // счётчик аутентификации (blockSize байт)
    private byte[] sum; // аккумулятор мультилинейной функции (blockSize байт)

    // Длины обработанных данных в битах (для финального шага MAC)
    private long aadBitLen;
    private long ctBitLen;

    // Состояние
    private boolean finished;

    // Переиспользуемый scratch-буфер для initCounters (избегаем byte[16] на каждый вызов)
    private final byte[] zInScratch;

    /**
     * Создаёт MGM с тегом размером с блок шифра.
     *
     * @param cipher блочный шифр (Кузнечик: blockSize = 16 байт)
     */
    public Mgm(BlockCipher cipher) {
        this(cipher, cipher.getBlockSize());
    }

    /**
     * Создаёт MGM с тегом заданного размера.
     *
     * @param cipher  блочный шифр
     * @param tagSize размер тега в байтах (1..blockSize)
     */
    public Mgm(BlockCipher cipher, int tagSize) {
        this.cipher    = cipher;
        this.blockSize = cipher.getBlockSize();
        if (tagSize < 8 || tagSize > blockSize) {
            throw new IllegalArgumentException(
                "MGM tag size must be 8.." + blockSize + " bytes, got " + tagSize);
        }
        this.tagSize = tagSize;
        // Выделяем буферы здесь — размер определяется blockSize конкретного шифра
        this.Y          = new byte[blockSize];
        this.Z          = new byte[blockSize];
        this.sum        = new byte[blockSize];
        this.zInScratch = new byte[blockSize];
    }

    /**
     * Инициализирует MGM.
     *
     * @param forEncryption {@code true} — шифрование, {@code false} — расшифрование
     * @param params        {@link ParametersWithIV}: ключ + ICN длиной {@code blockSize - 1} байт
     * @throws IllegalArgumentException если параметры некорректны
     */
    public void init(boolean forEncryption, CipherParameters params) {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("MGM requires ParametersWithIV (key + ICN)");
        }
        ParametersWithIV ivParams = (ParametersWithIV) params;
        byte[] iv = ivParams.getIV();

        // ICN ∈ V_{n-1}: n-1 = 127 бит. В байтах: 16 байт, где старший бит = 0.
        // RFC 9058 §3: ICN хранится как 128-битный вектор с нулём в бите 127.
        if (iv.length != blockSize) {
            throw new IllegalArgumentException(
                "MGM ICN must be " + blockSize + " bytes (with MSB=0), got " + iv.length);
        }
        if ((iv[0] & 0x80) != 0) {
            throw new IllegalArgumentException(
                "MGM ICN must have MSB (bit 127) = 0, per RFC 9058 §3");
        }

        this.forEncryption = forEncryption;
        this.icn           = Arrays.copyOf(iv, iv.length);

        // Инициализируем шифр ключом (E_K используется всегда в режиме шифрования блока)
        cipher.init(true, ivParams.getParameters());

        initCounters();
        this.initialized = true;
        this.aadFinished = false;
        this.finished = false;
    }

    /**
     * Переинициализирует MGM с новым ICN, пропуская дорогостоящий
     * {@code cipher.init()} (ключевое расписание).
     * <p>
     * Симметричный ключ и вычисленные subKeys от предыдущего вызова
     * {@link #init} переиспользуются. Это безопасно, так как subKeys
     * read-only в {@code processBlock}.
     * <p>
     * Все per-message состояние (счётчики Y/Z, аккумулятор MAC, флаги)
     * сбрасывается — идентично поведению {@link #init}.
     * <p>
     * Используется на hot path TLS 1.3 с TLSTREE: 8191/8192 записей
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
        if (newIcn.length != blockSize) {
            throw new IllegalArgumentException(
                "MGM ICN must be " + blockSize + " bytes (with MSB=0), got " + newIcn.length);
        }
        if ((newIcn[0] & 0x80) != 0) {
            throw new IllegalArgumentException(
                "MGM ICN must have MSB (bit 127) = 0, per RFC 9058 §3");
        }

        this.icn = Arrays.copyOf(newIcn, newIcn.length);
        this.aadFinished = false;
        this.finished = false;
        initCounters();
    }

    /**
     * Добавляет ассоциированные данные для аутентификации.
     * <p>
     * AAD не шифруется. Должен вызываться до первого вызова {@link #processBytes}.
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

        // Обрабатываем AAD блоками; неполный последний блок дополняется нулями
        int pos = 0;
        while (pos < len) {
            byte[] block = new byte[blockSize]; // нули — дополнение автоматически
            int blockLen = Math.min(blockSize, len - pos);
            System.arraycopy(aad, offset + pos, block, 0, blockLen);
            processMacBlock(block);
            aadBitLen = Math.addExact(aadBitLen, (long) blockLen * 8);
            pos += blockLen;
        }
    }

    /**
     * Шифрует или расшифровывает данные.
     * <p>
     * При первом вызове AAD автоматически финализируется.
     * Неполный последний блок поддерживается.
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
        aadFinished = true;
        if (len == 0) return 0;

        int pos = 0;
        while (pos < len) {
            int blockLen = Math.min(blockSize, len - pos);

            // Гамма = E(K, Y_i)
            byte[] gamma = new byte[blockSize];
            cipher.processBlock(Y, 0, gamma, 0);
            incrR(Y);

            // XOR гаммой — шифрование/расшифрование симметрично
            for (int i = 0; i < blockLen; i++) {
                output[outOff + pos + i] = (byte) (input[inOff + pos + i] ^ gamma[i]);
            }

            // MAC вычисляется над шифртекстом (EtM: при шифровании над output, при расшифровании над input)
            byte[] ctBlock = new byte[blockSize]; // нули = дополнение неполного блока
            if (forEncryption) {
                System.arraycopy(output, outOff + pos, ctBlock, 0, blockLen);
            } else {
                System.arraycopy(input, inOff + pos, ctBlock, 0, blockLen);
            }
            processMacBlock(ctBlock);
            ctBitLen  = Math.addExact(ctBitLen,  (long) blockLen * 8);

            pos += blockLen;
        }
        return len;
    }

    /**
     * Завершает шифрование и записывает тег аутентификации.
     *
     * @param output выходной буфер
     * @param outOff смещение (должно быть достаточно места для {@link #getTagSize()} байт)
     * @return размер тега в байтах
     * @throws IllegalStateException если MGM не инициализирован
     */
    public int finishEncryption(byte[] output, int outOff) {
        if (finished) throw new IllegalStateException("Already finished; call init() for new message");
        finished = true;
        checkInitialized();
        byte[] tag = computeTag();
        System.arraycopy(tag, 0, output, outOff, tagSize);
        return tagSize;
    }

    /**
     * Завершает расшифрование и проверяет тег аутентификации.
     * <p>
     * Сравнение выполняется за constant-time через {@link java.security.MessageDigest#isEqual}.
     *
     * @param tag    буфер с принятым тегом
     * @param offset смещение тега
     * @throws AuthenticationException если тег не совпадает
     * @throws IllegalStateException   если MGM не инициализирован
     */
    public void finishDecryption(byte[] tag, int offset) throws AuthenticationException {
        if (finished) throw new IllegalStateException("Already finished; call init() for new message");
        finished = true;
        checkInitialized();
        byte[] expectedTag = computeTag();
        byte[] actualTag   = Arrays.copyOfRange(tag, offset, offset + tagSize);
        if (!java.security.MessageDigest.isEqual(expectedTag, actualTag)) {
            // Обнуляем выход перед исключением предотвращает использование поддельных данных
            throw new AuthenticationException("MGM authentication tag mismatch");
        }
    }


    /** @return размер тега в байтах */
    public int getTagSize() {
        return tagSize;
    }

    /** @return имя алгоритма, например {@code "GOST3412-2015/MGM"} */
    public String getAlgorithmName() {
        return cipher.getAlgorithmName() + "/MGM";
    }

    /** @return размер блока шифра в байтах */
    public int getBlockSize() {
        return blockSize;
    }

    // -----------------------------------------------------------------------
    // Внутренние методы
    // -----------------------------------------------------------------------

    /**
     * Инициализирует счётчики Y и Z из ICN.
     * По RFC 9058 §4.1:
     * <pre>
     *   Y_1 = E(K, 0^1 || ICN)  — старший бит = 0 (ICN уже содержит бит 0 в позиции 127)
     *   Z_1 = E(K, 1^1 || ICN)  — выставляем старший бит в 1
     * </pre>
     * ICN = 16 байт, старший бит (бит 127) = 0.
     * {@code 0^1 || ICN} = ICN как есть (старший бит уже 0).
     * {@code 1^1 || ICN} = ICN с выставленным старшим битом (0x80 в первом байте).
     */
    private void initCounters() {
        // Y_1 = E(K, 0^1 || ICN): ICN уже имеет MSB=0, используем как есть
        cipher.processBlock(icn, 0, Y, 0);

        // Z_1 = E(K, 1^1 || ICN): выставляем MSB в 1
        System.arraycopy(icn, 0, zInScratch, 0, blockSize);
        zInScratch[0] |= (byte) 0x80;
        cipher.processBlock(zInScratch, 0, Z, 0);

        Arrays.fill(sum, (byte) 0);
        aadBitLen = 0;
        ctBitLen  = 0;
    }

    /**
     * Обновляет накопитель MAC одним полным (или дополненным нулями) блоком.
     * <p>
     * По RFC 9058 §4.1:
     * <pre>
     *   H_i = E(K, Z_i)
     *   sum = sum XOR (H_i (*) block)   — (*) — умножение в GF(2^128)
     *   Z_{i+1} = incr_l(Z_i)
     * </pre>
     *
     * @param block блок данных длиной {@code blockSize} байт (может быть дополнен нулями)
     */
    private void processMacBlock(byte[] block) {
        // H_i = E(K, Z_i)
        byte[] H = new byte[blockSize];
        cipher.processBlock(Z, 0, H, 0);
        incrL(Z);

        // sum = sum XOR gf128Mul(H, block)
        byte[] product = gf128Mul(H, block);
        Pack.xorBlock(sum, product, blockSize);
    }

    /**
     * Вычисляет финальный тег аутентификации по RFC 9058 §4.1 (финальный шаг):
     * <pre>
     *   H_{h+q+1} = E(K, Z_{h+q+1})
     *   T = MSB_S( E(K, sum XOR (H_{h+q+1} (*) (len(A) || len(C)))) )
     * </pre>
     * len(A) и len(C) — длины в битах, каждая как {@code n/2} байт в big-endian.
     */
    private byte[] computeTag() {
        byte[] lenBlock = buildLengthBlock();

        // H = E(K, Z)
        byte[] H = new byte[blockSize];
        cipher.processBlock(Z, 0, H, 0);

        // finSum = sum XOR (H (*) lenBlock)
        byte[] product = gf128Mul(H, lenBlock);
        byte[] finSum  = Arrays.copyOf(sum, blockSize);
        Pack.xorBlock(finSum, product, blockSize);

        // T = MSB_S(E(K, finSum))
        byte[] tagFull = new byte[blockSize];
        cipher.processBlock(finSum, 0, tagFull, 0);
        return Arrays.copyOf(tagFull, tagSize);
    }

    /**
     * Формирует блок {@code len(A) || len(C)} для финального MAC-шага.
     * Каждая длина в битах кодируется как {@code n/2} байт в big-endian.
     */
    private byte[] buildLengthBlock() {
        int half = blockSize / 2;
        byte[] lenBlock = new byte[blockSize];
        // len(A) в первые half байт (big-endian)
        long a = aadBitLen;
        for (int i = half - 1; i >= 0; i--) {
            lenBlock[i] = (byte) (a & 0xFF);
            a >>= 8;
        }
        // len(C) во вторые half байт (big-endian)
        long c = ctBitLen;
        for (int i = blockSize - 1; i >= half; i--) {
            lenBlock[i] = (byte) (c & 0xFF);
            c >>= 8;
        }
        return lenBlock;
    }

    /**
     * incr_r: инкрементирует правую n/2-битную половину блока (big-endian).
     * Используется для счётчика шифрования Y_i (RFC 9058 §3).
     */
    private void incrR(byte[] block) {
        int half = blockSize / 2;
        for (int i = blockSize - 1; i >= half; i--) {
            if (++block[i] != 0) break;
        }
    }

    /**
     * incr_l: инкрементирует левую n/2-битную половину блока (big-endian).
     * Используется для счётчика аутентификации Z_i (RFC 9058 §3).
     */
    private void incrL(byte[] block) {
        int half = blockSize / 2;
        for (int i = half - 1; i >= 0; i--) {
            if (++block[i] != 0) break;
        }
    }

    /**
     * Умножение двух элементов GF(2^128).
     * <p>
     * Поле GF(2^128) задаётся неприводимым многочленом
     * f(w) = w^128 + w^7 + w^2 + w + 1 (RFC 9058 §3).
     * <p>
     * Представление: big-endian, бит 127 — старший бит первого байта.
     * <p>
     * Алгоритм «right-to-left comb»: итерируем по битам X от младшего (w^0) к старшему (w^127).
     * На каждом шаге: если бит X_i = 1, XOR результата с текущим Y; затем сдвигаем Y влево на w.
     * Этот порядок гарантирует коммутативность, так как оба аргумента обрабатываются симметрично.
     *
     * @param X левый множитель (16 байт, big-endian)
     * @param Y правый множитель (16 байт, big-endian)
     * @return X (*) Y в GF(2^128), 16 байт, big-endian
     */
    public static byte[] gf128Mul(byte[] X, byte[] Y) {
        byte[] result = new byte[16];
        byte[] V      = Arrays.copyOf(Y, 16); // текущая степень: V = Y * w^i

        // Итерируем по 128 битам X от w^0 (младший) к w^127 (старший)
        // В big-endian: бит w^0 — это LSB последнего байта (X[15] & 0x01)
        //               бит w^127 — это MSB первого байта  (X[0]  & 0x80)
        for (int byteIdx = 15; byteIdx >= 0; byteIdx--) {
            int xByte = X[byteIdx] & 0xFF;
            for (int bit = 0; bit <= 7; bit++) {
                // Текущий бит X: w^(byteIdx*8 + bit) ... нет, нужен порядок по возрастанию степени
                // bit=0 → LSB байта → младшая степень в данном байте
                if (((xByte >> bit) & 1) == 1) {
                    // XOR результата с V = Y * w^i
                    Pack.xorBlock(result, V, result.length);
                }
                // V = V * w (умножение на образующий элемент с редукцией)
                multiplyByW(V);
            }
        }
        return result;
    }

    /**
     * Умножает элемент V ∈ GF(2^128) на w (сдвиг влево на 1 бит с редукцией).
     * <p>
     * В big-endian: умножение на w — сдвиг всего 128-битного числа влево на 1.
     * Если выдвигается старший бит (бит 127, т.е. MSB первого байта),
     * XOR с представлением многочлена f(w) без члена w^128:
     * f(w) - w^128 = w^7 + w^2 + w + 1 = 0x87 (в LSB = последнем байте, big-endian).
     */
    private static void multiplyByW(byte[] V) {
        // Запоминаем старший бит (бит 127 = MSB первого байта)
        int msb = (V[0] >>> 7) & 1;

        // Сдвиг всего массива влево на 1 бит (big-endian)
        for (int i = 0; i < 15; i++) {
            V[i] = (byte) (((V[i] & 0xFF) << 1) | ((V[i + 1] & 0xFF) >>> 7));
        }
        V[15] = (byte) ((V[15] & 0xFF) << 1);

        // Редукция: если вышел бит 127, XOR с полиномом (последний байт big-endian)
        if (msb == 1) {
            V[15] ^= GF128_REDUCTION_POLY;
        }
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("MGM not initialized — call init() first");
        }
    }
}
