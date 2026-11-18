package org.rssys.gost.util;

import java.util.Arrays;

/**
 * Дополнение ISO/IEC 7816-4: за данными следует байт {@code 0x80}, затем нули до конца блока.
 *
 * <p>Дополнение всегда добавляется и всегда лежит в последнем блоке (1..{@code blockSize}
 * байт, в том числе целый блок для данных, кратных блоку). Снятие проверяет это строго:
 * маркер обязан находиться в последнем блоке, а всё после него быть нулевым. Иначе
 * расшифрованный текст, оканчивающийся длинной цепочкой нулей после {@code 0x80}, принимался бы
 * за дополнение произвольной длины.
 *
 * <p>Класс не хранит состояния и потокобезопасен.
 */
public final class ISO7816d4Padding {

    private static final int MARKER = 0x80;

    private ISO7816d4Padding() {}

    /**
     * Добавляет дополнение к данным и возвращает новый массив, длина которого кратна
     * {@code blockSize} (данные, кратные блоку, получают целый блок дополнения).
     *
     * @param data      исходные данные
     * @param blockSize размер блока в байтах, положительный
     * @return новый массив с дополнением
     * @throws IllegalArgumentException если {@code data == null} или {@code blockSize < 1}
     */
    public static byte[] pad(byte[] data, int blockSize) {
        if (data == null || blockSize < 1) {
            throw new IllegalArgumentException(
                    "Data must not be null and blockSize must be positive");
        }
        int padLen = blockSize - (data.length % blockSize);
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        writePadding(padded, data.length);
        return padded;
    }

    /**
     * Записывает дополнение в уже выделенный буфер: байт {@code 0x80} на позицию {@code len} и
     * нули до конца буфера. Без выделения памяти: нужен {@code Cmac.doFinal}, где дополняется
     * последний блок на месте.
     *
     * @param buffer буфер, в начале которого лежат {@code len} байт данных; дополнение занимает
     *               оставшиеся байты
     * @param len    длина данных в {@code buffer}; должна быть меньше длины буфера (место под
     *               маркер)
     * @throws IllegalArgumentException если {@code buffer == null}, {@code len < 0} или
     *     {@code len >= buffer.length}
     */
    public static void writePadding(byte[] buffer, int len) {
        if (buffer == null) {
            throw new IllegalArgumentException("Buffer must not be null");
        }
        if (len < 0 || len >= buffer.length) {
            throw new IllegalArgumentException(
                    "Data length "
                            + len
                            + " leaves no room for the padding marker in a buffer of "
                            + buffer.length
                            + " bytes");
        }
        buffer[len] = (byte) MARKER;
        for (int i = len + 1; i < buffer.length; i++) {
            buffer[i] = 0;
        }
    }

    /**
     * Снимает дополнение и возвращает новый массив с данными.
     *
     * @param data      данные с дополнением; длина кратна {@code blockSize} и не меньше его
     * @param blockSize размер блока в байтах, положительный
     * @return новый массив без дополнения
     * @throws IllegalArgumentException если аргументы не соответствуют условиям выше или
     *     дополнение испорчено (маркер должен быть в последнем блоке, после него только нули)
     */
    public static byte[] unpad(byte[] data, int blockSize) {
        int padCount = padCount(data, blockSize);
        return Arrays.copyOf(data, data.length - padCount);
    }

    /**
     * Возвращает количество байт дополнения в последнем блоке расшифрованных данных.
     *
     * <p>Проверяется только последний блок фиксированной длины {@code blockSize}: маркер
     * {@code 0x80} должен быть в нём, а все байты после последнего маркера нулевыми. Проход по блоку
     * не зависит от положения маркера и без ветвлений по данным (best-effort constant-time, см.
     * crypto-gost-core/doc/adr/adr-04.md). Длина результата раскрывает длину дополнения, это
     * неустранимо на уровне API.
     *
     * @param in        расшифрованные данные; длина кратна {@code blockSize} и не меньше его
     * @param blockSize размер блока в байтах, положительный
     * @return количество байт дополнения, от 1 до {@code blockSize}
     * @throws IllegalArgumentException если аргументы не соответствуют условиям выше или
     *     дополнение испорчено (нет маркера в последнем блоке или после маркера есть ненулевой
     *     байт): как и {@link Pkcs7Padding#unpad}
     */
    private static int padCount(byte[] in, int blockSize) {
        if (in == null || blockSize <= 0 || in.length < blockSize || in.length % blockSize != 0) {
            throw new IllegalArgumentException(
                    "Padded data must be a non-empty multiple of the block size");
        }
        int blockStart = in.length - blockSize;

        // Позиция последнего байта 0x80 в блоке; -1, если маркера нет. Без ветвлений по данным.
        int markerPos = -1;
        for (int i = 0; i < blockSize; i++) {
            int diff = (in[blockStart + i] & 0xFF) ^ MARKER;
            // isMarker = 0xFFFFFFFF, если байт равен 0x80, иначе 0.
            int isMarker = (diff - 1) >> 31;
            markerPos = (markerPos & ~isMarker) | (i & isMarker);
        }

        // Все байты строго после маркера обязаны быть нулевыми. Если маркера нет (markerPos = -1),
        // «после маркера» оказывается весь блок, и ненулевое содержимое тоже ловится ниже.
        int mismatch = 0;
        for (int i = 0; i < blockSize; i++) {
            // afterMarker = 0xFFFFFFFF, если i > markerPos, иначе 0.
            int afterMarker = (markerPos - i) >> 31;
            mismatch |= (in[blockStart + i] & 0xFF) & afterMarker;
        }
        // markerPos < 0 означает отсутствие маркера: старший бит выставлен.
        int missingMarker = markerPos >> 31;
        if ((mismatch | missingMarker) != 0) {
            throw new IllegalArgumentException("invalid ISO 7816-4 padding");
        }
        return blockSize - markerPos;
    }
}
