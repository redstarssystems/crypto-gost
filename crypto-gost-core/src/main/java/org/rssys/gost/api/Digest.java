package org.rssys.gost.api;

import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.mac.Mac;

/**
 * API для хэш-функций Стрибог и HMAC-Стрибог (ГОСТ Р 34.11-2012 / RFC 7836).
 *
 * <p>Поддерживаемые алгоритмы:
 * <ul>
 *   <li>{@link Algorithm#STREEBOG_256} — хэш-функция ГОСТ Р 34.11-2012, 256 бит</li>
 *   <li>{@link Algorithm#STREEBOG_512} — хэш-функция ГОСТ Р 34.11-2012, 512 бит</li>
 *   <li>{@link Algorithm#HMAC_256} — HMAC-Стрибог-256 (RFC 7836)</li>
 *   <li>{@link Algorithm#HMAC_512} — HMAC-Стрибог-512 (RFC 7836)</li>
 * </ul>
 *
 * <p>Для имитовставки CMAC на шифре Кузнечик (ГОСТ Р 34.13-2015) используйте {@link CmacApi}.
 *
 * <h3>Два режима работы:</h3>
 *
 * <b>1. Статические методы</b> — для блока данных целиком в памяти:
 * <pre>{@code
 * byte[] hash = Digest.digest256(data);
 * byte[] mac  = Digest.hmac256(data, key);
 * boolean ok  = CmacApi.verifyMac(expected, Digest.hmac256(data, key));
 * }</pre>
 *
 * <b>2. Инкрементальный инстанс</b> — для данных, поступающих по частям
 * (из файла, сокета и т.п.), без накопления всего массива в памяти:
 * <pre>{@code
 * Digest h = new Digest(Digest.Algorithm.STREEBOG_256);
 * byte[] buf = new byte[8192];
 * int n;
 * while ((n = inputStream.read(buf)) != -1) {
 *     h.update(buf, 0, n);
 * }
 * byte[] hash = h.digest();
 *
 * Digest m = new Digest(Digest.Algorithm.HMAC_256, key);
 * while ((n = inputStream.read(buf)) != -1) {
 *     m.update(buf, 0, n);
 * }
 * byte[] mac = m.digest();
 * m.destroy();
 * }</pre>
 *
 * <p>Экземпляр хранит состояние хэша, а для HMAC и выведенные из ключа значения: после
 * использования вызовите {@link #destroy()} или используйте его в try-with-resources.
 *
 * <h3>Thread-safety:</h3>
 * Статические методы потокобезопасны.
 * Инстанс {@code Digest} <b>не является</b> потокобезопасным —
 * создавайте отдельный экземпляр на каждый поток.
 */
public final class Digest implements AutoCloseable {

    /**
     * Алгоритм хэширования или HMAC.
     */
    public enum Algorithm {
        /** Стрибог-256 (ГОСТ Р 34.11-2012). Выход: 32 байта. */
        STREEBOG_256,
        /** Стрибог-512 (ГОСТ Р 34.11-2012). Выход: 64 байта. */
        STREEBOG_512,
        /** HMAC-Стрибог-256 (RFC 7836). Выход: 32 байта. Требует ключ. */
        HMAC_256,
        /** HMAC-Стрибог-512 (RFC 7836). Выход: 64 байта. Требует ключ. */
        HMAC_512
    }

    // -----------------------------------------------------------------------
    // Состояние инстанса (для инкрементального режима)
    // -----------------------------------------------------------------------

    /**
     * Дайджест для STREEBOG_256 / STREEBOG_512, null для MAC-алгоритмов.
     */
    private final org.rssys.gost.digest.Digest digestImpl;

    /** MAC для HMAC_256 / HMAC_512, null для дайджестов. */
    private final Mac mac;

    /**
     * Экземпляр уничтожен. Ведётся здесь, а не в реализации: дайджест без ключа после
     * {@code destroy()} оставался бы пригодным, а HMAC нет, и один метод вёл бы себя по-разному.
     */
    private boolean destroyed;

    // -----------------------------------------------------------------------
    // Конструкторы (инкрементальный режим)
    // -----------------------------------------------------------------------

    /**
     * Создаёт инкрементальный экземпляр для алгоритмов без ключа (STREEBOG_256, STREEBOG_512).
     *
     * @param algorithm STREEBOG_256 или STREEBOG_512
     * @throws IllegalArgumentException если алгоритм требует ключ
     */
    public Digest(Algorithm algorithm) {
        if (algorithm == Algorithm.HMAC_256 || algorithm == Algorithm.HMAC_512) {
            throw new IllegalArgumentException(
                    algorithm + " requires a key — use Digest(Algorithm, SymmetricKey)");
        }
        this.digestImpl = createDigestImpl(algorithm);
        this.mac = null;
    }

    /**
     * Создаёт инкрементальный экземпляр для алгоритмов с ключом (HMAC_256, HMAC_512).
     *
     * @param algorithm HMAC_256 или HMAC_512
     * @param key       ключ аутентификации
     * @throws IllegalArgumentException если алгоритм не требует ключ
     */
    public Digest(Algorithm algorithm, SymmetricKey key) {
        if (algorithm == Algorithm.STREEBOG_256 || algorithm == Algorithm.STREEBOG_512) {
            throw new IllegalArgumentException(
                    algorithm + " does not use a key — use Digest(Algorithm)");
        }
        this.digestImpl = null;
        this.mac = createHmac(algorithm, key);
    }

    // -----------------------------------------------------------------------
    // Инкрементальный API
    // -----------------------------------------------------------------------

    /**
     * Добавляет данные к вычислению.
     *
     * @return this
     */
    public Digest update(byte[] data) {
        return update(data, 0, data.length);
    }

    /**
     * Добавляет часть данных к вычислению.
     *
     * @return this
     */
    public Digest update(byte[] data, int off, int len) {
        checkNotDestroyed();
        if (digestImpl != null) {
            digestImpl.update(data, off, len);
        } else {
            mac.update(data, off, len);
        }
        return this;
    }

    /**
     * Завершает вычисление и возвращает результат.
     * Сбрасывает внутреннее состояние — экземпляр готов к повторному использованию.
     *
     * @return хэш или MAC в виде byte[]
     */
    public byte[] digest() {
        checkNotDestroyed();
        if (digestImpl != null) {
            byte[] out = new byte[digestImpl.getDigestSize()];
            digestImpl.doFinal(out, 0); // doFinal вызывает reset() внутри
            return out;
        } else {
            byte[] out = new byte[mac.getMacSize()];
            mac.doFinal(out, 0); // doFinal вызывает reset() внутри
            return out;
        }
    }

    /**
     * Сбрасывает внутреннее состояние без вычисления результата.
     */
    public void reset() {
        checkNotDestroyed();
        if (digestImpl != null) {
            digestImpl.reset();
        } else {
            mac.reset();
        }
    }

    /**
     * Затирает внутреннее состояние: хвост входных данных и, для HMAC, ipad и opad, выведенные из
     * ключа. Идемпотентен. После вызова экземпляр непригоден для всех алгоритмов: {@code update},
     * {@code digest} и {@code reset} бросают {@link IllegalStateException}. Нужен, когда
     * хэшируются секретные данные или используется ключ: {@link #reset()} рабочие буферы не
     * очищает.
     */
    public void destroy() {
        if (destroyed) return;
        destroyed = true;
        if (digestImpl != null) {
            digestImpl.destroy();
        } else {
            mac.destroy();
        }
    }

    /** То же, что {@link #destroy()}: позволяет использовать экземпляр в try-with-resources. */
    @Override
    public void close() {
        destroy();
    }

    // -----------------------------------------------------------------------
    // Статические методы (для блока данных в памяти)
    // -----------------------------------------------------------------------

    /**
     * Вычисляет Стрибог-256 (ГОСТ Р 34.11-2012, RFC 6986).
     *
     * @param data входные данные
     * @return хэш, 32 байта, big-endian
     */
    public static byte[] digest256(byte[] data) {
        return digest(data, Algorithm.STREEBOG_256);
    }

    /**
     * Вычисляет Стрибог-512 (ГОСТ Р 34.11-2012).
     *
     * @param data входные данные
     * @return хэш, 64 байта, big-endian
     */
    public static byte[] digest512(byte[] data) {
        return digest(data, Algorithm.STREEBOG_512);
    }

    /**
     * Вычисляет HMAC-Стрибог-256 (RFC 7836).
     *
     * @param data входные данные
     * @param key  ключ аутентификации
     * @return MAC, 32 байта
     */
    public static byte[] hmac256(byte[] data, SymmetricKey key) {
        return hmac(data, key, Algorithm.HMAC_256);
    }

    /**
     * Вычисляет HMAC-Стрибог-512 (RFC 7836).
     *
     * @param data входные данные
     * @param key  ключ аутентификации
     * @return MAC, 64 байта
     */
    public static byte[] hmac512(byte[] data, SymmetricKey key) {
        return hmac(data, key, Algorithm.HMAC_512);
    }

    // -----------------------------------------------------------------------
    // Общие приватные методы (убирают дублирование из публичных статических)
    // -----------------------------------------------------------------------

    private static byte[] digest(byte[] data, Algorithm algorithm) {
        org.rssys.gost.digest.Digest d = createDigestImpl(algorithm);
        try {
            d.update(data, 0, data.length);
            byte[] out = new byte[d.getDigestSize()];
            d.doFinal(out, 0);
            return out;
        } finally {
            // reset() рабочие буферы не очищает: в них остаётся хвост входа (последний неполный
            // блок) и производные от него значения; хешируются в том числе секретные данные
            d.destroy();
        }
    }

    private static byte[] hmac(byte[] data, SymmetricKey key, Algorithm algorithm) {
        Mac m = createHmac(algorithm, key);
        try {
            m.update(data, 0, data.length);
            byte[] out = new byte[m.getMacSize()];
            m.doFinal(out, 0);
            return out;
        } finally {
            // ipad/opad выведены из ключа и не должны пережить вызов
            m.destroy();
        }
    }

    // -----------------------------------------------------------------------
    // Внутренние фабричные методы
    // -----------------------------------------------------------------------

    private static org.rssys.gost.digest.Digest createDigestImpl(Algorithm algorithm) {
        return switch (algorithm) {
            case STREEBOG_256 -> new Streebog256();
            case STREEBOG_512 -> new Streebog512();
            case HMAC_256, HMAC_512 ->
                    throw new IllegalArgumentException("Not a digest algorithm: " + algorithm);
        };
    }

    private static Mac createHmac(Algorithm algorithm, SymmetricKey key) {
        Mac m =
                switch (algorithm) {
                    case HMAC_256 -> new Hmac(new Streebog256());
                    case HMAC_512 -> new Hmac(new Streebog512());
                    case STREEBOG_256, STREEBOG_512 ->
                            throw new IllegalArgumentException(
                                    "Not an HMAC algorithm: " + algorithm);
                };
        m.init(key);
        return m;
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("Digest has been destroyed");
        }
    }
}
