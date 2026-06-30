package org.rssys.gost.api;

import java.security.MessageDigest;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.mac.Cmac;

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
 * }</pre>
 *
 * <h3>Thread-safety:</h3>
 * Статические методы потокобезопасны.
 * Инстанс {@code CmacApi} <b>не является</b> потокобезопасным —
 * создавайте отдельный экземпляр на каждый поток.
 */
public final class CmacApi {

    /**
     * Размер полного тега CMAC для Кузнечика в байтах (ГОСТ Р 34.13-2015).
     * Равен размеру блока шифра: 16 байт = 128 бит.
     */
    public static final int CMAC_TAG_SIZE = Kuznyechik.BLOCK_SIZE;

    // -----------------------------------------------------------------------
    // Состояние инстанса (для инкрементального режима)
    // -----------------------------------------------------------------------

    /** Низкоуровневый делегат. {@code null} для статических методов. */
    private final Cmac cmac;

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
        byte[] out = new byte[cmac.getMacSize()];
        cmac.doFinal(out, 0); // doFinal вызывает reset() внутри
        return out;
    }

    /**
     * Сбрасывает внутреннее состояние без вычисления тега.
     * Ключ сохраняется — экземпляр готов к повторному использованию.
     */
    public void reset() {
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
        c.init(key);
        c.update(data, 0, data.length);
        byte[] out = new byte[tagBytes];
        c.doFinal(out, 0);
        return out;
    }

    /**
     * Сравнивает два MAC-тега за constant-time.
     *
     * <p>Использует {@link MessageDigest#isEqual} для защиты от timing-атак.
     * Всегда используйте этот метод для сравнения MAC — не {@code Arrays.equals}.
     * Применим для CMAC и HMAC.
     *
     * <p>Возвращает {@code false} если любой из аргументов {@code null}.
     *
     * @param expected ожидаемый тег
     * @param actual   вычисленный тег
     * @return {@code true} если теги равны по значению
     */
    public static boolean verifyMac(byte[] expected, byte[] actual) {
        return MessageDigest.isEqual(expected, actual);
    }
}
