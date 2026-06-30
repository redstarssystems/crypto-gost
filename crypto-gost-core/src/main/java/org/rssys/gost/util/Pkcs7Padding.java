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
    public static byte[] addPadding(byte[] data, int blockSize) {
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
     * @throws IllegalArgumentException если padding некорректен или данные пусты
     */
    public static byte[] removePadding(byte[] data, int blockSize) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data must not be null or empty");
        }
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException(
                    "data length " + data.length + " is not a multiple of blockSize " + blockSize);
        }
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen < 1 || padLen > blockSize) {
            throw new IllegalArgumentException("invalid PKCS#7 padding byte: " + padLen);
        }
        // Проверяем что все padding-байты одинаковы (защита от некорректных данных)
        for (int i = data.length - padLen; i < data.length; i++) {
            if ((data[i] & 0xFF) != padLen) {
                throw new IllegalArgumentException("invalid PKCS#7 padding: inconsistent bytes");
            }
        }
        byte[] result = new byte[data.length - padLen];
        System.arraycopy(data, 0, result, 0, result.length);
        return result;
    }
}
