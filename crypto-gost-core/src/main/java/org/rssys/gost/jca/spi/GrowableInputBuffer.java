package org.rssys.gost.jca.spi;

import java.util.Arrays;
import java.util.Objects;

/**
 * Растущий буфер накопленного ввода для JCA-шифров, которые обрабатывают сообщение целиком в
 * {@code doFinal} (MGM и CTR-ACPKM-OMAC).
 *
 * <p>Такие шифры не могут отдавать результат из {@code update}: при расшифровании тег стоит в
 * конце, и открытый текст нельзя выдавать до его проверки. Поэтому всё сообщение копится в памяти
 * до {@code doFinal}. Ёмкость растёт удвоением, чтобы общее число копирований было линейным:
 * выделение ровно {@code size + len} на каждый {@code update} давало квадратичное копирование
 * (через {@code CipherOutputStream} блоками по 8 КиБ).
 *
 * <p>Содержимое (открытый текст или шифртекст) остаётся в куче, пока буфер не очищен. Прежний
 * массив при росте и весь массив в {@link #clear()} затираются. Вместимость может превышать размер
 * не более чем вдвое, поэтому пиковое потребление памяти выше размера сообщения.
 *
 * <p>Не потокобезопасен, как и {@code Cipher}.
 */
final class GrowableInputBuffer {

    /** Предел длины массива: часть значения {@code int} занимает заголовок массива в JVM. */
    static final int MAX_SIZE = Integer.MAX_VALUE - 8;

    /** Первая выделяемая ёмкость: короткие сообщения не растут на каждый маленький {@code update}. */
    private static final int MIN_CAPACITY = 64;

    private static final byte[] EMPTY = new byte[0];

    private final int maxSize;
    private byte[] data = EMPTY;
    private int size;

    /**
     * Буфер с заданным пределом размера.
     *
     * <p>Шифры задают предел {@code MAX_SIZE - TAG_LEN}, чтобы длина шифртекста с тегом
     * ({@code size + TAG_LEN}) не переполнила {@code int}; тесты задают малый предел, чтобы не
     * выделять гигабайты.
     *
     * @param maxSize предел размера в байтах, от 0 до {@link #MAX_SIZE}
     */
    GrowableInputBuffer(int maxSize) {
        if (maxSize < 0 || maxSize > MAX_SIZE) {
            throw new IllegalArgumentException("maxSize must be in [0, " + MAX_SIZE + "]");
        }
        this.maxSize = maxSize;
    }

    /**
     * Добавляет байты в конец буфера.
     *
     * @throws IllegalStateException если размер превысил бы предел длины массива
     * @throws IndexOutOfBoundsException если диапазон выходит за границы {@code src}
     */
    void append(byte[] src, int offset, int len) {
        if (len <= 0) {
            return;
        }
        // Сравнение в таком виде не переполняет int: size <= maxSize
        if (len > maxSize - size) {
            throw new IllegalStateException("Buffered input exceeds the maximum array size");
        }
        // Границы проверяются до роста: при ошибке буфер остаётся прежним
        Objects.checkFromIndexSize(offset, len, src.length);
        int required = size + len;
        if (required > data.length) {
            grow(required);
        }
        System.arraycopy(src, offset, data, size, len);
        size = required;
    }

    private void grow(int required) {
        byte[] grown = Arrays.copyOf(data, nextCapacity(data.length, required, maxSize));
        // Прежний массив содержит открытый текст или шифртекст: затираем до отбрасывания
        Arrays.fill(data, (byte) 0);
        data = grown;
    }

    /**
     * Новая ёмкость при росте: удвоение, но не меньше нужного и не больше предела.
     *
     * <p>Вынесено в статический метод, чтобы границы арифметики проверялись без выделения
     * гигабайтных массивов. Удвоение считается в {@code long}: на больших размерах {@code int}
     * переполнился бы раньше предела.
     *
     * @param current  текущая ёмкость
     * @param required нужная ёмкость, не больше {@code maxSize}
     * @param maxSize  предел ёмкости
     */
    static int nextCapacity(int current, int required, int maxSize) {
        long doubled = (long) current * 2;
        return (int) Math.min(Math.max(Math.max(doubled, MIN_CAPACITY), required), maxSize);
    }

    /** Число накопленных байт. */
    int size() {
        return size;
    }

    /**
     * Массив с накопленными данными: значимы только первые {@link #size()} байт, остальное нули.
     * Ссылка недействительна после следующего {@link #append} и {@link #clear()}.
     */
    byte[] array() {
        return data;
    }

    /** Затирает содержимое и возвращает буфер в пустое состояние. */
    void clear() {
        Arrays.fill(data, (byte) 0);
        data = EMPTY;
        size = 0;
    }
}
