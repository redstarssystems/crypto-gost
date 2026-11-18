package org.rssys.gost.util;

/**
 * Padding по схеме PKCS#7 (RFC 5652 §6.3).
 */
public final class Pkcs7Padding {

    private Pkcs7Padding() {}

    /**
     * Добавляет PKCS#7 padding к данным.
     *
     * @param data      исходные данные
     * @param blockSize размер блока в байтах (для Кузнечика — 16)
     * @return новый массив с добавленным padding
     * @throws IllegalArgumentException если blockSize < 1 или > 255
     */
    public static byte[] pad(byte[] data, int blockSize) {
        if (blockSize < 1 || blockSize > 255) {
            throw new IllegalArgumentException("blockSize must be between 1 and 255");
        }
        int padLen = blockSize - (data.length % blockSize);
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    /**
     * Удаляет PKCS#7 padding из данных.
     *
     * @param data      данные с padding
     * @param blockSize размер блока в байтах
     * @return новый массив без padding
     * @throws IllegalArgumentException если blockSize вне диапазона 1..255, padding некорректен
     *                                  или данные пусты
     */
    public static byte[] unpad(byte[] data, int blockSize) {
        if (blockSize < 1 || blockSize > 255) {
            throw new IllegalArgumentException("blockSize must be between 1 and 255");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data must not be null or empty");
        }
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("data length is not a multiple of block size");
        }
        int padLen = data[data.length - 1] & 0xFF;

        // Best-effort constant-time: без early-exit и без data-dependent длины цикла.
        // Полный constant-time в JVM недостижим (JIT, bounds-checks), но убираем
        // явные тайминг-различия «быстрый reject vs медленная проверка» (Vaudenay).
        // Единое решение о валидности принимается один раз в конце по маске bad.
        //
        // Внимание: длина возвращаемого массива всё равно раскрывает padLen — это
        // неустранимо на уровне API и не является утечкой сверх факта расшифрования.
        // см. crypto-gost-core/doc/adr/adr-04.md
        int lastBlockStart = data.length - blockSize;

        // Проверка диапазона padLen в [1, blockSize] без ветвления: bad != 0 при нарушении.
        int bad = ((padLen - 1) | (blockSize - padLen)) >> 31;

        // Сканируем весь последний блок фиксированной длины blockSize.
        // Байт на позиции i относится к padding, если i >= blockSize - padLen.
        int threshold = blockSize - padLen;
        for (int i = 0; i < blockSize; i++) {
            int b = data[lastBlockStart + i] & 0xFF;
            // isPadMask = 0xFFFFFFFF, если i >= threshold, иначе 0.
            int isPadMask = (threshold - i - 1) >> 31;
            bad |= (b ^ padLen) & isPadMask;
        }

        if (bad != 0) {
            throw new IllegalArgumentException("invalid PKCS#7 padding");
        }
        byte[] result = new byte[data.length - padLen];
        System.arraycopy(data, 0, result, 0, result.length);
        return result;
    }
}
