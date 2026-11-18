package org.rssys.gost.api;

import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.util.ConstantTime;

/**
 * API для имитовставки CMAC на шифре Кузнечик (ГОСТ Р 34.13-2015 §4.6).
 *
 * <p>CMAC (Cipher-based MAC) — код аутентификации сообщений на основе блочного шифра.
 * Не путать с HMAC ({@link Digest#hmac256}, {@link Digest#hmac512}),
 * который строится на хэш-функции.
 *
 * <p>Параметры:
 * <ul>
 *   <li>Шифр: Кузнечик (ГОСТ Р 34.12-2015), ключ 32 байта</li>
 *   <li>Полный тег: {@value #CMAC_TAG_SIZE} байт (128 бит = размер блока)</li>
 *   <li>Допускается усечение тега до {@code tagBytes} байт</li>
 * </ul>
 *
 * <h3>Два режима работы:</h3>
 *
 * <b>1. Статические методы</b> — для блока данных целиком в памяти:
 * <pre>{@code
 * SymmetricKey key = KeyGenerator.generateSymmetricKey();
 * byte[] tag = CmacApi.cmac(data, key);
 * boolean ok = CmacApi.verifyMac(expected, tag);
 * }</pre>
 *
 * <b>2. Инкрементальный инстанс</b> — для данных, поступающих по частям
 * (из файла, сокета и т.п.), без накопления всего массива в памяти:
 * <pre>{@code
 * CmacApi cmac = new CmacApi(key);
 * byte[] buf = new byte[8192];
 * int n;
 * while ((n = inputStream.read(buf)) != -1) {
 *     cmac.update(buf, 0, n);
 * }
 * byte[] tag = cmac.digest();
 * cmac.destroy();
 * }</pre>
 *
 * <p>Экземпляр хранит расписание ключа: после использования вызовите {@link #destroy()} или
 * используйте его в try-with-resources.
 *
 * <h3>Thread-safety:</h3>
 * Статические методы потокобезопасны.
 * Инстанс {@code CmacApi} <b>не является</b> потокобезопасным —
 * создавайте отдельный экземпляр на каждый поток.
 */
public final class CmacApi implements AutoCloseable {

    /**
     * Размер полного тега CMAC для Кузнечика в байтах (ГОСТ Р 34.13-2015).
     * Равен размеру блока шифра: 16 байт = 128 бит.
     */
    public static final int CMAC_TAG_SIZE = Kuznyechik.BLOCK_SIZE;

    // -----------------------------------------------------------------------
    // Состояние инстанса (для инкрементального режима)
    // -----------------------------------------------------------------------

    /** Низкоуровневый делегат. */
    private final Cmac cmac;

    /** Экземпляр уничтожен: {@code update}, {@code digest} и {@code reset} бросают исключение. */
    private boolean destroyed;

    // -----------------------------------------------------------------------
    // Конструктор (инкрементальный режим)
    // -----------------------------------------------------------------------

    /**
     * Создаёт инкрементальный экземпляр CMAC с полным тегом ({@value #CMAC_TAG_SIZE} байт).
     *
     * @param key ключ Кузнечика (32 байта)
     */
    public CmacApi(SymmetricKey key) {
        this.cmac = new Cmac(new Kuznyechik());
        this.cmac.init(key);
    }

    // -----------------------------------------------------------------------
    // Инкрементальный API
    // -----------------------------------------------------------------------

    /**
     * Добавляет данные к вычислению.
     *
     * @param data входные данные
     * @return this
     */
    public CmacApi update(byte[] data) {
        return update(data, 0, data.length);
    }

    /**
     * Добавляет часть данных к вычислению.
     *
     * @param data входные данные
     * @param off  смещение в массиве
     * @param len  количество байт
     * @return this
     */
    public CmacApi update(byte[] data, int off, int len) {
        checkNotDestroyed();
        cmac.update(data, off, len);
        return this;
    }

    /**
     * Завершает вычисление и возвращает тег.
     * Сбрасывает внутреннее состояние — экземпляр готов к повторному использованию
     * с тем же ключом.
     *
     * @return тег, {@value #CMAC_TAG_SIZE} байт
     */
    public byte[] digest() {
        checkNotDestroyed();
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0); // doFinal вызывает reset() внутри
        return out;
    }

    /**
     * Сбрасывает внутреннее состояние без вычисления тега.
     * Ключ сохраняется — экземпляр готов к повторному использованию.
     */
    public void reset() {
        checkNotDestroyed();
        cmac.reset();
    }

    /**
     * Вычисляет полный CMAC на Кузнечике (ГОСТ Р 34.13-2015, имитовставка).
     *
     * @param data входные данные
     * @param key  ключ (32 байта для Кузнечика)
     * @return тег, {@value #CMAC_TAG_SIZE} байт
     */
    public static byte[] cmac(byte[] data, SymmetricKey key) {
        return cmac(data, key, CMAC_TAG_SIZE);
    }

    /**
     * Вычисляет усечённый CMAC на Кузнечике (ГОСТ Р 34.13-2015).
     *
     * @param data     входные данные
     * @param key      ключ (32 байта для Кузнечика)
     * @param tagBytes размер тега в байтах (от 1 до {@value #CMAC_TAG_SIZE})
     * @return тег, {@code tagBytes} байт
     * @throws IllegalArgumentException если {@code tagBytes} вне диапазона [1, {@value #CMAC_TAG_SIZE}]
     */
    public static byte[] cmac(byte[] data, SymmetricKey key, int tagBytes) {
        if (tagBytes < 1 || tagBytes > CMAC_TAG_SIZE) {
            throw new IllegalArgumentException(
                    "CMAC tagBytes must be between 1 and " + CMAC_TAG_SIZE + ", got " + tagBytes);
        }
        Cmac c = new Cmac(new Kuznyechik(), tagBytes * 8);
        try {
            c.init(key);
            c.update(data, 0, data.length);
            byte[] out = new byte[tagBytes];
            c.doFinal(out, 0);
            return out;
        } finally {
            // расписание ключа и подключи не должны пережить вызов
            c.destroy();
        }
    }

    /**
     * Затирает расписание ключа и подключи. Идемпотентен. После вызова экземпляр непригоден:
     * {@code update}, {@code digest} и {@code reset} бросают {@link IllegalStateException}.
     * Вызывать, когда экземпляр больше не нужен: он хранит выведенные из ключа подключи.
     */
    public void destroy() {
        if (destroyed) return;
        destroyed = true;
        cmac.destroy();
    }

    /** То же, что {@link #destroy()}: позволяет использовать экземпляр в try-with-resources. */
    @Override
    public void close() {
        destroy();
    }

    /**
     * Сравнивает два MAC-тега за constant-time.
     *
     * <p>Сравнивает за постоянное время через {@link ConstantTime#equals}, чтобы время ответа не
     * раскрывало, сколько байт совпало. Всегда используйте этот метод для сравнения MAC — не
     * {@code Arrays.equals}. Применим для CMAC и HMAC.
     *
     * <p>Возвращает {@code false}, если любой из аргументов {@code null} или пуст:
     * пустой тег не бывает валидным для CMAC и HMAC. Теги разной длины не равны: более длинный
     * тег, начинающийся с ожидаемого, не принимается.
     *
     * @param expected ожидаемый тег
     * @param actual   вычисленный тег
     * @return {@code true} если теги равны по значению
     */
    public static boolean verifyMac(byte[] expected, byte[] actual) {
        // Длины сверяются до сравнения: иначе более длинный тег совпал бы по префиксу, а более
        // короткий дал бы исключение вместо false
        if (expected == null
                || actual == null
                || expected.length == 0
                || actual.length == 0
                || expected.length != actual.length) {
            return false;
        }
        return ConstantTime.equals(expected, 0, actual, 0, expected.length);
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("CmacApi has been destroyed");
        }
    }
}
