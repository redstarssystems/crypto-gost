package org.rssys.gost.mac;

import static org.rssys.gost.util.Pack.xorBlock;

import org.rssys.gost.cipher.BlockCipher;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.util.ISO7816d4Padding;
import org.rssys.gost.util.Pack;

/**
 * Реализация CMAC (OMAC1) согласно ГОСТ Р 34.13-2015.
 * Использует стандартный CBC-режим ({@link Cbc}) с нулевым IV.
 */
public class Cmac implements Mac {

    private final byte[] poly; // неприводимый полином поля GF(2^blockSize*8)
    private final byte[] ZEROES;
    private byte[] mac;
    private byte[] buf;
    private int bufOff;
    private final Cbc cipher; // CBC с нулевым IV (ГОСТ Р 34.13-2015 §5.1)
    private final int blockSize;
    private final int macSize;
    private byte[] Lu;
    private byte[] Lu2;

    public Cmac(BlockCipher blockCipher) {
        this(blockCipher, blockCipher.getBlockSize() * 8);
    }

    public Cmac(BlockCipher blockCipher, int macSizeBits) {
        if (macSizeBits % 8 != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }
        if (macSizeBits > blockCipher.getBlockSize() * 8) {
            throw new IllegalArgumentException(
                    "MAC size must be <= " + (blockCipher.getBlockSize() * 8));
        }
        this.blockSize = blockCipher.getBlockSize();
        // CBC с нулевым IV — стандартное начальное состояние CMAC (ГОСТ Р 34.13-2015 §5.1)
        this.cipher = new Cbc(blockCipher);
        this.macSize = macSizeBits / 8;
        this.poly = lookupPoly(blockSize);
        this.mac = new byte[blockSize];
        this.buf = new byte[blockSize];
        this.ZEROES = new byte[blockSize];
        this.bufOff = 0;
    }

    @Override
    public String getAlgorithmName() {
        return cipher.getAlgorithmName();
    }

    @Override
    public void init(CipherParameters params) {
        validate(params);
        // Инициализируем Cbc с нулевым IV
        // ParametersWithIV с нулевым вектором гарантирует чистое состояние регистра
        byte[] zeroIV = new byte[blockSize];
        cipher.init(true, new ParametersWithIV((SymmetricKey) params, zeroIV));
        // Вычисляем L = E(K, 0^n) для генерации подключей Lu и Lu2
        byte[] l = new byte[blockSize];
        cipher.processBlock(ZEROES, 0, l, 0);
        Lu = doubleLu(l);
        Lu2 = doubleLu(Lu);
        reset();
    }

    /**
     * Проверяет, что параметры содержат {@link SymmetricKey}.
     *
     * @throws IllegalArgumentException если параметры {@code null} или не являются {@link SymmetricKey}
     */
    private void validate(CipherParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("CMac requires SymmetricKey, got null");
        }
        if (!(params instanceof SymmetricKey)) {
            throw new IllegalArgumentException(
                    "CMac requires SymmetricKey, got " + params.getClass().getName());
        }
    }

    @Override
    public int getMacSize() {
        return macSize;
    }

    @Override
    public void update(byte in) {
        if (bufOff == buf.length) {
            cipher.processBlock(buf, 0, mac, 0);
            bufOff = 0;
        }
        buf[bufOff++] = in;
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        if (len < 0) throw new IllegalArgumentException("Can't have a negative input length!");

        int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);
            cipher.processBlock(buf, 0, mac, 0);
            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize) {
                cipher.processBlock(in, inOff, mac, 0);
                len -= blockSize;
                inOff += blockSize;
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);
        bufOff += len;
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        byte[] lu;
        if (bufOff == blockSize) {
            lu = Lu;
        } else {
            new ISO7816d4Padding().addPadding(buf, bufOff);
            lu = Lu2;
        }

        // buf = buf XOR lu (XOR с подключом Lu или Lu2 по ГОСТ Р 34.13-2015 §5.1)
        xorBlock(buf, lu, mac.length);

        cipher.processBlock(buf, 0, mac, 0);
        System.arraycopy(mac, 0, out, outOff, macSize);
        reset();
        return macSize;
    }

    @Override
    public void reset() {
        java.util.Arrays.fill(buf, (byte) 0);
        bufOff = 0;
        cipher.reset();
    }

    /**
     * Сдвиг массива влево на 1 бит.
     * Возвращает старший бит (перенос).
     */
    private static int shiftLeft(byte[] in, byte[] out) {
        int carry = 0;
        for (int i = in.length - 1; i >= 0; i--) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b << 1) | carry);
            carry = b >>> 7;
        }
        return carry;
    }

    /**
     * Удвоение в GF(2^n): если MSB=0 -> сдвиг влево, иначе сдвиг влево XOR poly.
     */
    private byte[] doubleLu(byte[] in) {
        byte[] out = new byte[in.length];
        int carry = shiftLeft(in, out);
        // Применяем poly только к последним 3 байтам (где ненулевые коэффициенты)
        int mask = -(carry) & 0xFF; // 0xFF если carry=1, иначе 0x00
        int n = in.length;
        out[n - 3] ^= (byte) (poly[1] & mask);
        out[n - 2] ^= (byte) (poly[2] & mask);
        out[n - 1] ^= (byte) (poly[3] & mask);
        return out;
    }

    // Неприводимые полиномы GF(2^n) для разных размеров блока.
    // Источник: NIST SP 800-38B, таблица 1; BouncyCastle CMac.lookupPoly.
    // Значение p задаёт ненулевые члены полинома (кроме x^n и x^0, которые подразумеваются).
    private static final int POLY_64 = 27;
    private static final int POLY_128 = 135; // Кузнечик: x^128 + x^7 + x^2 + x + 1
    private static final int POLY_160 = 45;
    private static final int POLY_192 = 135;
    private static final int POLY_224 = 777;
    private static final int POLY_256 = 1061;
    private static final int POLY_320 = 27;
    private static final int POLY_384 = 4109;
    private static final int POLY_448 = 2129;
    private static final int POLY_512 = 293;
    private static final int POLY_768 = 655377;
    private static final int POLY_1024 = 524355;
    private static final int POLY_2048 = 548865;

    /**
     * Возвращает неприводимый полином GF(2^n) для заданного размера блока.
     * Используется для вычисления подключей Lu, Lu2 в CMAC (ГОСТ Р 34.13-2015 §5.1).
     */
    private static byte[] lookupPoly(int blockSizeBytes) {
        int p;
        switch (blockSizeBytes * 8) {
            case 64:
                p = POLY_64;
                break;
            case 128:
                p = POLY_128;
                break;
            case 160:
                p = POLY_160;
                break;
            case 192:
                p = POLY_192;
                break;
            case 224:
                p = POLY_224;
                break;
            case 256:
                p = POLY_256;
                break;
            case 320:
                p = POLY_320;
                break;
            case 384:
                p = POLY_384;
                break;
            case 448:
                p = POLY_448;
                break;
            case 512:
                p = POLY_512;
                break;
            case 768:
                p = POLY_768;
                break;
            case 1024:
                p = POLY_1024;
                break;
            case 2048:
                p = POLY_2048;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unknown block size for CMAC: " + (blockSizeBytes * 8) + " bits");
        }
        byte[] result = new byte[4];
        Pack.intToBigEndian(p, result, 0);
        return result;
    }
}
