package org.rssys.gost.mac;

import static org.rssys.gost.util.Pack.xorBlock;

import java.util.Arrays;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.util.ISO7816d4Padding;

/**
 * Реализация CMAC (OMAC1) на шифре Кузнечик согласно ГОСТ Р 34.13-2015 (режим выработки
 * имитовставки). Использует CBC-режим ({@link Cbc}) с нулевым IV.
 *
 * <p>Принимает только {@link Kuznyechik}, как и остальные режимы ({@code Cfb}, {@code Ctr},
 * {@code Ofb}, {@code Mgm}): прочих блочных шифров в библиотеке нет, а передача режима вместо
 * шифра отказывала бы поздно и невнятно, уже в {@link #init}.</p>
 */
public final class Cmac implements Mac {

    /**
     * Остаток неприводимого многочлена поля GF(2^128): x^128 + x^7 + x^2 + x + 1, то есть
     * {@code 0x87} в последнем байте при удвоении подключа (RFC 4493 §2.3).
     */
    private static final int R_128 = 0x87;

    private final byte[] ZEROES;
    private byte[] mac;
    private byte[] buf;
    private int bufOff;
    private final Cbc cipher; // CBC с нулевым IV, начальное состояние CMAC
    private final String algorithmName; // имя исходного шифра: внутренний Cbc наружу не виден
    private final int blockSize;
    private final int macSize;
    private byte[] Lu;
    private byte[] Lu2;

    /**
     * CMAC с полным тегом (размер блока Кузнечика, 16 байт).
     *
     * @param cipher шифр Кузнечик
     */
    public Cmac(Kuznyechik cipher) {
        this(cipher, cipher.getBlockSize() * 8);
    }

    /**
     * CMAC с усечённым тегом.
     *
     * <p>Пустой тег ничего не защищает, а отрицательный размер вскрылся бы только в
     * {@code doFinal}, поэтому оба значения отвергаются при создании.
     *
     * @param cipher      шифр Кузнечик
     * @param macSizeBits размер тега в битах: кратен 8, от 8 до размера блока в битах
     * @throws IllegalArgumentException если размер тега неположителен, некратен 8 или больше блока
     */
    public Cmac(Kuznyechik cipher, int macSizeBits) {
        if (macSizeBits <= 0) {
            throw new IllegalArgumentException("MAC size must be positive");
        }
        if (macSizeBits % 8 != 0) {
            throw new IllegalArgumentException("MAC size must be multiple of 8");
        }
        if (macSizeBits > cipher.getBlockSize() * 8) {
            throw new IllegalArgumentException(
                    "MAC size must be <= " + (cipher.getBlockSize() * 8));
        }
        this.blockSize = cipher.getBlockSize();
        // CBC с нулевым IV — стандартное начальное состояние CMAC
        this.cipher = new Cbc(cipher);
        this.algorithmName = cipher.getAlgorithmName() + "/CMAC";
        this.macSize = macSizeBits / 8;
        this.mac = new byte[blockSize];
        this.buf = new byte[blockSize];
        this.ZEROES = new byte[blockSize];
        this.bufOff = 0;
    }

    @Override
    public String getAlgorithmName() {
        return algorithmName;
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
        byte[] newLu;
        byte[] newLu2;
        try {
            cipher.processBlock(ZEROES, 0, l, 0);
            newLu = doubleLu(l);
            newLu2 = doubleLu(newLu);
        } finally {
            // L выводит оба подключа, поэтому в куче его оставлять нельзя
            Arrays.fill(l, (byte) 0);
        }
        // Старые подключи затираем только после успешного вычисления новых: при исключении выше
        // объект не должен остаться с нулевыми подключами и молча считать неверный CMAC.
        if (Lu != null) {
            Arrays.fill(Lu, (byte) 0);
        }
        if (Lu2 != null) {
            Arrays.fill(Lu2, (byte) 0);
        }
        Lu = newLu;
        Lu2 = newLu2;
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
            ISO7816d4Padding.writePadding(buf, bufOff);
            lu = Lu2;
        }

        // buf = buf XOR lu (XOR с подключом Lu или Lu2 в зависимости от полноты последнего блока)
        xorBlock(buf, lu, mac.length);

        cipher.processBlock(buf, 0, mac, 0);
        System.arraycopy(mac, 0, out, outOff, macSize);
        reset();
        return macSize;
    }

    @Override
    public void reset() {
        Arrays.fill(buf, (byte) 0);
        // mac содержит последний вычисленный блок — затираем для консистентности с destroy().
        if (mac != null) {
            Arrays.fill(mac, (byte) 0);
        }
        bufOff = 0;
        cipher.reset();
    }

    @Override
    public void destroy() {
        cipher.destroy();
        if (mac != null) {
            Arrays.fill(mac, (byte) 0);
        }
        if (Lu != null) {
            Arrays.fill(Lu, (byte) 0);
        }
        if (Lu2 != null) {
            Arrays.fill(Lu2, (byte) 0);
        }
        Arrays.fill(buf, (byte) 0);
        bufOff = 0;
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
     * Удвоение в GF(2^128): если старший бит равен 0 — сдвиг влево, иначе сдвиг влево и XOR
     * {@link #R_128} в последнем байте.
     *
     * <p>Вход (подключ) секретный, поэтому перенос не должен давать ветвления: XOR применяется
     * через маску {@code 0xFF}/{@code 0x00}, чтобы время не зависело от значения старшего бита.</p>
     */
    private byte[] doubleLu(byte[] in) {
        byte[] out = new byte[in.length];
        int carry = shiftLeft(in, out);
        int mask = -carry & 0xFF; // 0xFF если carry=1, иначе 0x00
        out[in.length - 1] ^= (byte) (R_128 & mask);
        return out;
    }
}
