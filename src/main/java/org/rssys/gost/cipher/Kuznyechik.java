package org.rssys.gost.cipher;

import org.rssys.gost.util.DataLengthException;
import org.rssys.gost.util.OutputLengthException;
import org.rssys.gost.util.Pack;

import java.util.Arrays;

/**
 * Реализация блочного шифра «Кузнечик» (Grasshopper) по ГОСТ Р 34.12-2015.
 *
 * <ul>
 *   <li>Размер блока: 128 бит (16 байт)</li>
 *   <li>Длина ключа: 256 бит (32 байта)</li>
 *   <li>Количество раундов: 10 (9 полных раундов LSX + финальный XOR)</li>
 * </ul>
 */
public class Kuznyechik implements BlockCipher {

    /** Размер блока шифра в байтах (ГОСТ Р 34.12-2015): 128 бит = 16 байт. */
    public static final int BLOCK_SIZE = 16;

    /** Размер ключа в байтах (ГОСТ Р 34.12-2015): 256 бит = 32 байта. */
    public static final int KEY_SIZE = 32;

    // Таблица замен S (Pi) — ГОСТ Р 34.12-2015, приложение А
    private static final byte[] PI = {
            (byte) 0xFC, (byte) 0xEE, (byte) 0xDD, (byte) 0x11, (byte) 0xCF, (byte) 0x6E, (byte) 0x31, (byte) 0x16,
            (byte) 0xFB, (byte) 0xC4, (byte) 0xFA, (byte) 0xDA, (byte) 0x23, (byte) 0xC5, (byte) 0x04, (byte) 0x4D,
            (byte) 0xE9, (byte) 0x77, (byte) 0xF0, (byte) 0xDB, (byte) 0x93, (byte) 0x2E, (byte) 0x99, (byte) 0xBA,
            (byte) 0x17, (byte) 0x36, (byte) 0xF1, (byte) 0xBB, (byte) 0x14, (byte) 0xCD, (byte) 0x5F, (byte) 0xC1,
            (byte) 0xF9, (byte) 0x18, (byte) 0x65, (byte) 0x5A, (byte) 0xE2, (byte) 0x5C, (byte) 0xEF, (byte) 0x21,
            (byte) 0x81, (byte) 0x1C, (byte) 0x3C, (byte) 0x42, (byte) 0x8B, (byte) 0x01, (byte) 0x8E, (byte) 0x4F,
            (byte) 0x05, (byte) 0x84, (byte) 0x02, (byte) 0xAE, (byte) 0xE3, (byte) 0x6A, (byte) 0x8F, (byte) 0xA0,
            (byte) 0x06, (byte) 0x0B, (byte) 0xED, (byte) 0x98, (byte) 0x7F, (byte) 0xD4, (byte) 0xD3, (byte) 0x1F,
            (byte) 0xEB, (byte) 0x34, (byte) 0x2C, (byte) 0x51, (byte) 0xEA, (byte) 0xC8, (byte) 0x48, (byte) 0xAB,
            (byte) 0xF2, (byte) 0x2A, (byte) 0x68, (byte) 0xA2, (byte) 0xFD, (byte) 0x3A, (byte) 0xCE, (byte) 0xCC,
            (byte) 0xB5, (byte) 0x70, (byte) 0x0E, (byte) 0x56, (byte) 0x08, (byte) 0x0C, (byte) 0x76, (byte) 0x12,
            (byte) 0xBF, (byte) 0x72, (byte) 0x13, (byte) 0x47, (byte) 0x9C, (byte) 0xB7, (byte) 0x5D, (byte) 0x87,
            (byte) 0x15, (byte) 0xA1, (byte) 0x96, (byte) 0x29, (byte) 0x10, (byte) 0x7B, (byte) 0x9A, (byte) 0xC7,
            (byte) 0xF3, (byte) 0x91, (byte) 0x78, (byte) 0x6F, (byte) 0x9D, (byte) 0x9E, (byte) 0xB2, (byte) 0xB1,
            (byte) 0x32, (byte) 0x75, (byte) 0x19, (byte) 0x3D, (byte) 0xFF, (byte) 0x35, (byte) 0x8A, (byte) 0x7E,
            (byte) 0x6D, (byte) 0x54, (byte) 0xC6, (byte) 0x80, (byte) 0xC3, (byte) 0xBD, (byte) 0x0D, (byte) 0x57,
            (byte) 0xDF, (byte) 0xF5, (byte) 0x24, (byte) 0xA9, (byte) 0x3E, (byte) 0xA8, (byte) 0x43, (byte) 0xC9,
            (byte) 0xD7, (byte) 0x79, (byte) 0xD6, (byte) 0xF6, (byte) 0x7C, (byte) 0x22, (byte) 0xB9, (byte) 0x03,
            (byte) 0xE0, (byte) 0x0F, (byte) 0xEC, (byte) 0xDE, (byte) 0x7A, (byte) 0x94, (byte) 0xB0, (byte) 0xBC,
            (byte) 0xDC, (byte) 0xE8, (byte) 0x28, (byte) 0x50, (byte) 0x4E, (byte) 0x33, (byte) 0x0A, (byte) 0x4A,
            (byte) 0xA7, (byte) 0x97, (byte) 0x60, (byte) 0x73, (byte) 0x1E, (byte) 0x00, (byte) 0x62, (byte) 0x44,
            (byte) 0x1A, (byte) 0xB8, (byte) 0x38, (byte) 0x82, (byte) 0x64, (byte) 0x9F, (byte) 0x26, (byte) 0x41,
            (byte) 0xAD, (byte) 0x45, (byte) 0x46, (byte) 0x92, (byte) 0x27, (byte) 0x5E, (byte) 0x55, (byte) 0x2F,
            (byte) 0x8C, (byte) 0xA3, (byte) 0xA5, (byte) 0x7D, (byte) 0x69, (byte) 0xD5, (byte) 0x95, (byte) 0x3B,
            (byte) 0x07, (byte) 0x58, (byte) 0xB3, (byte) 0x40, (byte) 0x86, (byte) 0xAC, (byte) 0x1D, (byte) 0xF7,
            (byte) 0x30, (byte) 0x37, (byte) 0x6B, (byte) 0xE4, (byte) 0x88, (byte) 0xD9, (byte) 0xE7, (byte) 0x89,
            (byte) 0xE1, (byte) 0x1B, (byte) 0x83, (byte) 0x49, (byte) 0x4C, (byte) 0x3F, (byte) 0xF8, (byte) 0xFE,
            (byte) 0x8D, (byte) 0x53, (byte) 0xAA, (byte) 0x90, (byte) 0xCA, (byte) 0xD8, (byte) 0x85, (byte) 0x61,
            (byte) 0x20, (byte) 0x71, (byte) 0x67, (byte) 0xA4, (byte) 0x2D, (byte) 0x2B, (byte) 0x09, (byte) 0x5B,
            (byte) 0xCB, (byte) 0x9B, (byte) 0x25, (byte) 0xD0, (byte) 0xBE, (byte) 0xE5, (byte) 0x6C, (byte) 0x52,
            (byte) 0x59, (byte) 0xA6, (byte) 0x74, (byte) 0xD2, (byte) 0xE6, (byte) 0xF4, (byte) 0xB4, (byte) 0xC0,
            (byte) 0xD1, (byte) 0x66, (byte) 0xAF, (byte) 0xC2, (byte) 0x39, (byte) 0x4B, (byte) 0x63, (byte) 0xB6
    };

    private static final byte[] INVERSE_PI = {
            (byte) 0xA5, (byte) 0x2D, (byte) 0x32, (byte) 0x8F, (byte) 0x0E, (byte) 0x30, (byte) 0x38, (byte) 0xC0,
            (byte) 0x54, (byte) 0xE6, (byte) 0x9E, (byte) 0x39, (byte) 0x55, (byte) 0x7E, (byte) 0x52, (byte) 0x91,
            (byte) 0x64, (byte) 0x03, (byte) 0x57, (byte) 0x5A, (byte) 0x1C, (byte) 0x60, (byte) 0x07, (byte) 0x18,
            (byte) 0x21, (byte) 0x72, (byte) 0xA8, (byte) 0xD1, (byte) 0x29, (byte) 0xC6, (byte) 0xA4, (byte) 0x3F,
            (byte) 0xE0, (byte) 0x27, (byte) 0x8D, (byte) 0x0C, (byte) 0x82, (byte) 0xEA, (byte) 0xAE, (byte) 0xB4,
            (byte) 0x9A, (byte) 0x63, (byte) 0x49, (byte) 0xE5, (byte) 0x42, (byte) 0xE4, (byte) 0x15, (byte) 0xB7,
            (byte) 0xC8, (byte) 0x06, (byte) 0x70, (byte) 0x9D, (byte) 0x41, (byte) 0x75, (byte) 0x19, (byte) 0xC9,
            (byte) 0xAA, (byte) 0xFC, (byte) 0x4D, (byte) 0xBF, (byte) 0x2A, (byte) 0x73, (byte) 0x84, (byte) 0xD5,
            (byte) 0xC3, (byte) 0xAF, (byte) 0x2B, (byte) 0x86, (byte) 0xA7, (byte) 0xB1, (byte) 0xB2, (byte) 0x5B,
            (byte) 0x46, (byte) 0xD3, (byte) 0x9F, (byte) 0xFD, (byte) 0xD4, (byte) 0x0F, (byte) 0x9C, (byte) 0x2F,
            (byte) 0x9B, (byte) 0x43, (byte) 0xEF, (byte) 0xD9, (byte) 0x79, (byte) 0xB6, (byte) 0x53, (byte) 0x7F,
            (byte) 0xC1, (byte) 0xF0, (byte) 0x23, (byte) 0xE7, (byte) 0x25, (byte) 0x5E, (byte) 0xB5, (byte) 0x1E,
            (byte) 0xA2, (byte) 0xDF, (byte) 0xA6, (byte) 0xFE, (byte) 0xAC, (byte) 0x22, (byte) 0xF9, (byte) 0xE2,
            (byte) 0x4A, (byte) 0xBC, (byte) 0x35, (byte) 0xCA, (byte) 0xEE, (byte) 0x78, (byte) 0x05, (byte) 0x6B,
            (byte) 0x51, (byte) 0xE1, (byte) 0x59, (byte) 0xA3, (byte) 0xF2, (byte) 0x71, (byte) 0x56, (byte) 0x11,
            (byte) 0x6A, (byte) 0x89, (byte) 0x94, (byte) 0x65, (byte) 0x8C, (byte) 0xBB, (byte) 0x77, (byte) 0x3C,
            (byte) 0x7B, (byte) 0x28, (byte) 0xAB, (byte) 0xD2, (byte) 0x31, (byte) 0xDE, (byte) 0xC4, (byte) 0x5F,
            (byte) 0xCC, (byte) 0xCF, (byte) 0x76, (byte) 0x2C, (byte) 0xB8, (byte) 0xD8, (byte) 0x2E, (byte) 0x36,
            (byte) 0xDB, (byte) 0x69, (byte) 0xB3, (byte) 0x14, (byte) 0x95, (byte) 0xBE, (byte) 0x62, (byte) 0xA1,
            (byte) 0x3B, (byte) 0x16, (byte) 0x66, (byte) 0xE9, (byte) 0x5C, (byte) 0x6C, (byte) 0x6D, (byte) 0xAD,
            (byte) 0x37, (byte) 0x61, (byte) 0x4B, (byte) 0xB9, (byte) 0xE3, (byte) 0xBA, (byte) 0xF1, (byte) 0xA0,
            (byte) 0x85, (byte) 0x83, (byte) 0xDA, (byte) 0x47, (byte) 0xC5, (byte) 0xB0, (byte) 0x33, (byte) 0xFA,
            (byte) 0x96, (byte) 0x6F, (byte) 0x6E, (byte) 0xC2, (byte) 0xF6, (byte) 0x50, (byte) 0xFF, (byte) 0x5D,
            (byte) 0xA9, (byte) 0x8E, (byte) 0x17, (byte) 0x1B, (byte) 0x97, (byte) 0x7D, (byte) 0xEC, (byte) 0x58,
            (byte) 0xF7, (byte) 0x1F, (byte) 0xFB, (byte) 0x7C, (byte) 0x09, (byte) 0x0D, (byte) 0x7A, (byte) 0x67,
            (byte) 0x45, (byte) 0x87, (byte) 0xDC, (byte) 0xE8, (byte) 0x4F, (byte) 0x1D, (byte) 0x4E, (byte) 0x04,
            (byte) 0xEB, (byte) 0xF8, (byte) 0xF3, (byte) 0x3E, (byte) 0x3D, (byte) 0xBD, (byte) 0x8A, (byte) 0x88,
            (byte) 0xDD, (byte) 0xCD, (byte) 0x0B, (byte) 0x13, (byte) 0x98, (byte) 0x02, (byte) 0x93, (byte) 0x80,
            (byte) 0x90, (byte) 0xD0, (byte) 0x24, (byte) 0x34, (byte) 0xCB, (byte) 0xED, (byte) 0xF4, (byte) 0xCE,
            (byte) 0x99, (byte) 0x10, (byte) 0x44, (byte) 0x40, (byte) 0x92, (byte) 0x3A, (byte) 0x01, (byte) 0x26,
            (byte) 0x12, (byte) 0x1A, (byte) 0x48, (byte) 0x68, (byte) 0xF5, (byte) 0x81, (byte) 0x8B, (byte) 0xC7,
            (byte) 0xD6, (byte) 0x20, (byte) 0x0A, (byte) 0x08, (byte) 0x00, (byte) 0x4C, (byte) 0xD7, (byte) 0x74
    };

    private static final int SUB_LENGTH = KEY_SIZE / 2; // 16

    // Коэффициенты линейного преобразования L — ГОСТ Р 34.12-2015, таблица А.2
    private static final byte[] L_FACTORS = {
            (byte) 0x94, (byte) 0x20, (byte) 0x85, (byte) 0x10, (byte) 0xC2, (byte) 0xC0, (byte) 0x01, (byte) 0xFB,
            (byte) 0x01, (byte) 0xC0, (byte) 0xC2, (byte) 0x10, (byte) 0x85, (byte) 0x20, (byte) 0x94, (byte) 0x01
    };

    // Неприводимый полином GF(2^8): x^8+x^7+x^6+x+1 — ГОСТ Р 34.12-2015, таблица А.2
    private static final byte GF_POLY = (byte) 0xC3;

    // Срезы GF по фиксированным коэффициентам L_FACTORS — 16×256 = 4 KB вместо 64 KB
    private static final byte[][] GF_MUL_L = buildLFactorTables();

    // Размер каждой: 16 × 256 × 16 байт = 64 KB

    // T[i][x]     = L(e_i * PI[x])      — для шифрования
    private static final byte[][][] T = buildTTables(false);
    // T_INV[i][x] = L^-1(e_i * PI^-1[x]) — для расшифрования
    private static final byte[][][] T_INV = buildTTables(true);

    private static byte[][][] buildTTables(boolean inverse) {
        byte[][][] t = new byte[16][256][16];
        byte[] tmp = new byte[16];
        for (int i = 0; i < 16; i++) {
            for (int x = 0; x < 256; x++) {
                Arrays.fill(tmp, (byte) 0);
                tmp[i] = (byte) x;          // ← просто байт x, без S-замены
                applyLStatic(tmp, inverse);
                t[i][x] = Arrays.copyOf(tmp, 16);
            }
        }
        return t;
    }


    private static byte computeLfeedbackStatic(byte[] a) {
        byte result = a[15];
        for (int i = 14; i >= 0; i--) {
            result ^= GF_MUL_L[i][a[i] & 0xFF];
        }
        return result;
    }

    private static byte[][] buildLFactorTables() {
        byte[][] t = new byte[16][256];
        for (int i = 0; i < 16; i++) {
            int factor = L_FACTORS[i] & 0xFF;
            for (int x = 0; x < 256; x++) {
                t[i][x] = gfMulSlow((byte) x, (byte) factor);
            }
        }
        return t;
    }

    private static byte gfMulSlow(byte a, byte b) {
        byte result = 0;
        byte x = a;
        byte y = b;
        for (int n = 0; n < 8 && x != 0 && y != 0; n++, y = (byte) (y >> 1)) {
            if ((y & 1) != 0) result ^= x;
            byte hi = (byte) (x & 0x80);
            x = (byte) (x << 1);
            if (hi != 0) x ^= GF_POLY;
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Состояние экземпляра
    // -----------------------------------------------------------------------

    private byte[][] subKeys = null;
    private boolean forEncryption;
    private boolean keyInitialized;
    private final byte[] scratchBlock = new byte[BLOCK_SIZE];
    private final byte[] scratchTmp = new byte[BLOCK_SIZE];

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
        if (!(params instanceof SymmetricKey)) {
            throw new IllegalArgumentException("invalid parameter passed to Kuznyechik.init - " + params.getClass().getName());
        }
        this.forEncryption = forEncryption;
        this.keyInitialized = true;
        byte[] key = ((SymmetricKey) params).getKey();
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("invalid key size: " + key.length + " bytes, required " + KEY_SIZE + " bytes");
        }
        generateSubKeys(key);
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException {
        if (!keyInitialized) {
            throw new IllegalStateException("Kuznyechik not initialized");
        }
        if (inOff + BLOCK_SIZE > in.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (outOff + BLOCK_SIZE > out.length) {
            throw new OutputLengthException("output buffer too short");
        }
        processKuznyechik(in, inOff, out, outOff);
        return BLOCK_SIZE;
    }

    @Override
    public void reset() {
        // subKeys не изменяются при обработке блоков — сброс не требуется
    }

    private void generateSubKeys(byte[] key) {
        subKeys = new byte[10][SUB_LENGTH];

        byte[] x = Arrays.copyOfRange(key, 0, SUB_LENGTH);
        byte[] y = Arrays.copyOfRange(key, SUB_LENGTH, KEY_SIZE);

        System.arraycopy(x, 0, subKeys[0], 0, SUB_LENGTH);
        System.arraycopy(y, 0, subKeys[1], 0, SUB_LENGTH);

        byte[] c = new byte[SUB_LENGTH];
        for (int i = 1; i <= 4; i++) {
            for (int j = 1; j <= 8; j++) {
                computeC(c, 8 * (i - 1) + j);
                applyF(c, x, y);
            }
            System.arraycopy(x, 0, subKeys[2 * i], 0, SUB_LENGTH);
            System.arraycopy(y, 0, subKeys[2 * i + 1], 0, SUB_LENGTH);
        }
    }

    /**
     * Константа раунда: C[n] = L(e_n), где e_n имеет 1 в позиции 15
     */
    private void computeC(byte[] out, int n) {
        Arrays.fill(out, (byte) 0);
        out[15] = (byte) n;
        applyLStatic(out,false);
    }

    /**
     * Функция Фейстеля F(c, x, y): x <- LSX(c XOR x) XOR y, y <- старый x
     */
    private void applyF(byte[] c, byte[] x, byte[] y) {
        System.arraycopy(c, 0, scratchTmp, 0, SUB_LENGTH);
        Pack.xorBlock(scratchTmp, x, SUB_LENGTH);
        // applyS inline через PI:
        for (int i = 0; i < 16; i++) scratchTmp[i] = PI[scratchTmp[i] & 0xFF];
        applyLStatic(scratchTmp, false);
        Pack.xorBlock(scratchTmp, y, SUB_LENGTH);
        System.arraycopy(x,          0, y, 0, SUB_LENGTH);
        System.arraycopy(scratchTmp, 0, x, 0, SUB_LENGTH);
    }

    /**
     * LSX: XOR ключа с блоком → S-преобразование → L-преобразование
     */
    private void applyLSXInPlace(byte[] key, byte[] block) {
        Arrays.fill(scratchTmp, (byte) 0);
        for (int i = 0; i < 16; i++) {
            int b = PI[(block[i] ^ key[i]) & 0xFF] & 0xFF; // XOR → S-замена → T
            byte[] row = T[i][b];
            for (int j = 0; j < 16; j++) scratchTmp[j] ^= row[j];
        }
        System.arraycopy(scratchTmp, 0, block, 0, 16);
    }

    /**
     * XSLinverse (обратное): XOR ключа с блоком → L^-1 → S^-1
     */
    private void applyXSLinverseInPlace(byte[] key, byte[] block) {
        Arrays.fill(scratchTmp, (byte) 0);
        for (int i = 0; i < 16; i++) {
            int b = (block[i] ^ key[i]) & 0xFF;           // только XOR, без S⁻¹
            byte[] row = T_INV[i][b];
            for (int j = 0; j < 16; j++) scratchTmp[j] ^= row[j];
        }
        // S⁻¹ применяем ко всему результату L⁻¹ целиком
        for (int i = 0; i < 16; i++) scratchTmp[i] = INVERSE_PI[scratchTmp[i] & 0xFF];
        System.arraycopy(scratchTmp, 0, block, 0, 16);
    }


    private static void applyLStatic(byte[] a, boolean inverse) {
        if (inverse) {
            for (int i = 0; i < BLOCK_SIZE; i++) applyRinverseStatic(a);
        } else {
            for (int i = 0; i < BLOCK_SIZE; i++) applyRStatic(a);
        }
    }

    private static void applyRStatic(byte[] a) {
        byte feedback = computeLfeedbackStatic(a);
        System.arraycopy(a, 0, a, 1, 15);
        a[0] = feedback;
    }

    private static void applyRinverseStatic(byte[] a) {
        byte[] tmp = new byte[16]; // только при инициализации — аллокация допустима
        System.arraycopy(a, 1, tmp, 0, 15);
        tmp[15] = a[0];
        byte feedback = computeLfeedbackStatic(tmp);
        System.arraycopy(a, 1, a, 0, 15);
        a[15] = feedback;
    }

    private void processKuznyechik(byte[] in, int inOff, byte[] out, int outOff) {
        System.arraycopy(in, inOff, scratchBlock, 0, BLOCK_SIZE); // копируем в поле
        if (forEncryption) {
            for (int i = 0; i < 9; i++) {
                applyLSXInPlace(subKeys[i], scratchBlock);        // in-place, без аллокации
            }
            Pack.xorBlock(scratchBlock, subKeys[9], BLOCK_SIZE);
        } else {
            for (int i = 9; i > 0; i--) {
                applyXSLinverseInPlace(subKeys[i], scratchBlock); // in-place, без аллокации
            }
            Pack.xorBlock(scratchBlock, subKeys[0], BLOCK_SIZE);
        }
        System.arraycopy(scratchBlock, 0, out, outOff, BLOCK_SIZE);
    }
}
