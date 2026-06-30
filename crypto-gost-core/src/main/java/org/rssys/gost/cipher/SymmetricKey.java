package org.rssys.gost.cipher;

import java.util.Arrays;
import javax.security.auth.Destroyable;

/**
 * Симметричный ключ шифрования в виде защищённой обёртки над {@code byte[]}.
 *
 * <p>Используется как ключ для Кузнечика (ГОСТ Р 34.12-2015, 256 бит = 32 байта),
 * а также как ключ для производных алгоритмов: CMAC (ГОСТ Р 34.13-2015),
 * HMAC-Стрибог (RFC 7836), MGM (RFC 9058).
 *
 * <p>Гарантии безопасности:
 * <ul>
 *   <li>Конструктор делает defensive copy входного массива — изменение оригинала
 *       не влияет на хранимый ключ.</li>
 *   <li>{@link #getKey()} возвращает defensive copy — изменение результата
 *       не влияет на внутреннее состояние.</li>
 *   <li>Реализует {@link Destroyable}: {@link #destroy()} обнуляет ключевой материал
 *       в памяти; после вызова объект непригоден для использования.</li>
 * </ul>
 *
 * <p>Для использования через JCA/JCE предназначен {@link org.rssys.gost.jca.key.GostSecretKey},
 * который реализует {@link javax.crypto.SecretKey} и содержит метод
 * {@code toSymmetricKey()} для конвертации в этот тип.
 */
public class SymmetricKey implements CipherParameters, Destroyable {

    private byte[] key;
    private boolean destroyed = false;

    /**
     * Создаёт ключ из байтового массива.
     *
     * @param key ключевой материал (копируется)
     * @throws IllegalArgumentException если {@code key} равен {@code null} или пустой
     */
    public SymmetricKey(byte[] key) {
        if (key == null) throw new IllegalArgumentException("Key must not be null");
        if (key.length == 0) throw new IllegalArgumentException("Key must not be empty");
        this.key = Arrays.copyOf(key, key.length);
    }

    /**
     * Возвращает defensive copy ключевого материала.
     * Изменение возвращённого массива не влияет на внутреннее состояние.
     *
     * @throws IllegalStateException если ключ уже уничтожен
     */
    public byte[] getKey() {
        if (destroyed) throw new IllegalStateException("SymmetricKey has been destroyed");
        return Arrays.copyOf(key, key.length);
    }

    /**
     * Обнуляет ключевой материал в памяти.
     * После вызова объект непригоден для использования.
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(key, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
