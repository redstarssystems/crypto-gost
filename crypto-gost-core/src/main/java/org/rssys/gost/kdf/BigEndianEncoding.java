package org.rssys.gost.kdf;

/**
 * Кодирование длины {@code [L]_b} для KDF ГОСТ Р 34.11-2012 (RFC 7836, Р 50.1.113-2016).
 *
 * <p>Класс общий для {@link KdfGostR3411_2012_256} и {@link KdfTreeGostR3411_2012_256}: обе
 * функции дописывают к входу длину результата в битах одним и тем же способом, и расхождение в
 * таком коде тихо давало бы другой ключ. Счётчик итерации кодируется отдельно, одним байтом.
 */
final class BigEndianEncoding {

    private BigEndianEncoding() {}

    /**
     * Кодирует неотрицательное целое в минимальном big-endian без ведущих нулей
     * (RFC 7836: {@code [L]_b} - network byte order переменной длины); ноль кодируется одним
     * нулевым байтом.
     *
     * @param value неотрицательное целое
     * @return big-endian байты
     */
    static byte[] minimal(int value) {
        if (value == 0) {
            return new byte[] {0};
        }
        int bits = Integer.SIZE - Integer.numberOfLeadingZeros(value);
        int bytes = (bits + Byte.SIZE - 1) / Byte.SIZE;
        byte[] result = new byte[bytes];
        for (int i = bytes - 1; i >= 0; i--) {
            result[i] = (byte) value;
            value >>>= Byte.SIZE;
        }
        return result;
    }
}
