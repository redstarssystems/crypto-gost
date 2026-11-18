package org.rssys.gost.util;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Вспомогательные операции над массивами байт: XOR блоков, реверс порядка байт, запись и чтение
 * целых в big-endian и строгое преобразование {@link BigInteger} в массив фиксированной длины.
 */
public final class Pack {

    private static final VarHandle INT_BE =
            MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);
    private static final VarHandle LONG_BE =
            MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

    private Pack() {}

    /**
     * Записывает {@code value} в {@code out[off..off+3]} в порядке big-endian.
     *
     * @throws IndexOutOfBoundsException если в {@code out} нет четырёх байт с позиции {@code off}
     */
    public static void writeInt(int value, byte[] out, int off) {
        INT_BE.set(out, off, value);
    }

    /**
     * Читает {@code int} из {@code in[off..off+3]} в порядке big-endian.
     *
     * @throws IndexOutOfBoundsException если в {@code in} нет четырёх байт с позиции {@code off}
     */
    public static int readInt(byte[] in, int off) {
        return (int) INT_BE.get(in, off);
    }

    /**
     * Записывает {@code value} в {@code out[off..off+7]} в порядке big-endian.
     *
     * @throws IndexOutOfBoundsException если в {@code out} нет восьми байт с позиции {@code off}
     */
    public static void writeLong(long value, byte[] out, int off) {
        LONG_BE.set(out, off, value);
    }

    /**
     * Читает {@code long} из {@code in[off..off+7]} в порядке big-endian.
     *
     * @throws IndexOutOfBoundsException если в {@code in} нет восьми байт с позиции {@code off}
     */
    public static long readLong(byte[] in, int off) {
        return (long) LONG_BE.get(in, off);
    }

    /**
     * XOR блока {@code src} в {@code dst} (in-place), первые {@code len} байт.
     * Используется в {@code Cmac} вместо инлайн-цикла.
     */
    public static void xorBlock(byte[] dst, byte[] src, int len) {
        for (int i = 0; i < len; i++) {
            dst[i] ^= src[i];
        }
    }

    /**
     * Реверс порядка байт массива (big-endian <-> little-endian).
     * Используется для интерпретации хэша по RFC 7091 §5.3 (LSB first).
     */
    public static byte[] reverseBytes(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }

    /**
     * Строгое преобразование неотрицательного {@link BigInteger} в big-endian массив ровно
     * {@code len} байт: слева дополняется нулями.
     *
     * <p>Значение, не помещающееся в {@code len} байт, и отрицательное значение отвергаются, а не
     * усекаются: молчаливая потеря старших байт превращает {@code 2^(8·len) + 5} в {@code 5}, а
     * потеря знака превращает {@code -1} в {@code 255}, и ключ или координата становятся
     * другим числом без какой-либо ошибки. Проверка идёт по {@link BigInteger#bitLength()}, а не
     * по длине {@link BigInteger#toByteArray()}: тот добавляет знаковый нуль только при
     * установленном старшем бите.
     *
     * <p>Временная копия {@code toByteArray()} затирается. Сам {@code BigInteger} неизменяем и
     * его содержимое очистить нельзя, поэтому для секретных значений затирать нужно ещё и
     * возвращённый массив, а на долгоживущее хранение секрета лучше держать массив, а не число.
     *
     * @param value неотрицательное значение
     * @param len   длина результата в байтах, положительная
     * @throws IllegalArgumentException если {@code len <= 0}, значение отрицательно или не
     *                                  помещается в {@code len} байт
     */
    public static byte[] toFixedLengthBigEndian(BigInteger value, int len) {
        if (len <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        byte[] result = new byte[len];
        writeFixedLengthBigEndian(value, result, 0, len);
        return result;
    }

    /**
     * То же, что {@link #toFixedLengthBigEndian}, но пишет в готовый буфер: на горячем пути
     * (кодирование подписи) это убирает промежуточный массив и лишнее копирование. Диапазон
     * {@code [outOff, outOff + len)} перед записью обнуляется целиком.
     *
     * @param value  неотрицательное значение
     * @param out    буфер назначения
     * @param outOff смещение записи
     * @param len    длина записи в байтах, положительная
     * @throws IllegalArgumentException если {@code len <= 0}, диапазон выходит за {@code out},
     *                                  значение отрицательно или не помещается в {@code len} байт
     */
    public static void writeFixedLengthBigEndian(
            BigInteger value, byte[] out, int outOff, int len) {
        if (len <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        if (outOff < 0 || len > out.length - outOff) {
            throw new IllegalArgumentException(
                    "Range out of bounds: outOff=" + outOff + ", len=" + len);
        }
        if (value.signum() < 0 || value.bitLength() > Byte.SIZE * len) {
            throw new IllegalArgumentException(
                    "value must be non-negative and fit " + len + " bytes");
        }
        byte[] raw = value.toByteArray();
        try {
            Arrays.fill(out, outOff, outOff + len, (byte) 0);
            // значимые байты: без возможного знакового нуля впереди
            int significant = Math.min(raw.length, len);
            System.arraycopy(
                    raw, raw.length - significant, out, outOff + len - significant, significant);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
}
