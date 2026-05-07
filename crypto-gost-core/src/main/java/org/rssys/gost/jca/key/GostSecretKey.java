package org.rssys.gost.jca.key;

import org.rssys.gost.cipher.SymmetricKey;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

/**
 * Симметричный ключ ГОСТ-алгоритмов, реализующий {@link SecretKey}.
 * <p>
 * Используется для алгоритмов:
 * <ul>
 *   <li>Кузнечик (ГОСТ Р 34.12-2015) — 32 байта</li>
 *   <li>HMAC-Стрибог-256/512 — произвольная длина</li>
 *   <li>CMAC-Кузнечик — 32 байта</li>
 * </ul>
 * <p>
 * Является JCA-адаптером над низкоуровневым {@link SymmetricKey}: конструктор
 * {@link #GostSecretKey(String, SymmetricKey)} принимает {@link SymmetricKey},
 * а {@link #toSymmetricKey()} конвертирует обратно для передачи в низкоуровневые
 * алгоритмы ({@code Kuznyechik}, {@code Cmac}, {@code HmacStreebog} и др.).
 * <p>
 * Реализует {@link Destroyable}: вызов {@link #destroy()} обнуляет внутренний
 * байтовый массив. После уничтожения методы {@link #getEncoded()} и
 * {@link #toSymmetricKey()} бросают {@link IllegalStateException}.
 * <p>
 * {@link #getFormat()} возвращает {@code "RAW"} — стандартный формат для
 * симметричных ключей в JCE.
 * <p>
 * <b>Безопасность:</b> сериализация объекта запрещена — {@link #writeObject} и
 * {@link #readObject} бросают {@link NotSerializableException}. Ключевой материал
 * не должен попадать в поток сериализации.
 */
public final class GostSecretKey implements SecretKey, Destroyable {

    private static final long serialVersionUID = 1L;

    /** Название алгоритма: "Kuznyechik", "HmacGOST3411-2012-256" и т.п. */
    private final String algorithm;

    /** Ключевой материал. Обнуляется при вызове {@link #destroy()}. */
    private byte[] keyBytes;

    /** Признак уничтожения ключа. */
    private boolean destroyed = false;

    /**
     * Создаёт ключ из сырых байт.
     *
     * @param algorithm имя алгоритма: {@code "Kuznyechik"}, {@code "HmacGOST3411-2012-256"},
     *                  {@code "HmacGOST3411-2012-512"} или {@code "CMAC-Kuznyechik"}
     * @param keyBytes  байты ключа, копируются внутрь
     * @throws IllegalArgumentException если {@code algorithm} пустой или {@code keyBytes} пустой
     */
    public GostSecretKey(String algorithm, byte[] keyBytes) {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("Algorithm name must not be null or empty");
        }
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("Key bytes must not be null or empty");
        }
        this.algorithm = algorithm;
        this.keyBytes  = Arrays.copyOf(keyBytes, keyBytes.length);
    }

    /**
     * Создаёт ключ из {@link SymmetricKey}.
     *
     * @param algorithm имя алгоритма: {@code "Kuznyechik"}, {@code "HmacGOST3411-2012-256"},
     *                  {@code "HmacGOST3411-2012-512"} или {@code "CMAC-Kuznyechik"}
     * @param keyParam  низкоуровневый симметричный ключ
     * @throws IllegalStateException если {@code keyParam} уже уничтожен
     */
    public GostSecretKey(String algorithm, SymmetricKey keyParam) {
        this(algorithm, keyParam.getKey());
    }

    /** @return имя алгоритма, например {@code "Kuznyechik"} */
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    /** @return {@code "RAW"} — формат хранения ключевых байт */
    @Override
    public String getFormat() {
        return "RAW";
    }

    /**
     * Возвращает копию ключевых байт.
     *
     * @throws IllegalStateException если ключ уничтожен
     */
    @Override
    public byte[] getEncoded() {
        checkNotDestroyed();
        return Arrays.copyOf(keyBytes, keyBytes.length);
    }


    /**
     * Обнуляет ключевой материал в памяти.
     * После вызова объект непригоден для использования.
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(keyBytes, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * Конвертирует ключ в низкоуровневый {@link SymmetricKey}.
     *
     * @return новый {@link SymmetricKey} с копией ключевых байт
     * @throws IllegalStateException если ключ уничтожен
     */
    public SymmetricKey toSymmetricKey() {
        checkNotDestroyed();
        return new SymmetricKey(keyBytes);
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("GostSecretKey has been destroyed");
        }
    }

    /**
     * Запрещает сериализацию — ключевой материал не должен попадать в поток.
     *
     * @throws NotSerializableException всегда
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException("GostSecretKey must not be serialized");
    }

    /**
     * Запрещает десериализацию — ключевой материал не должен восстанавливаться из потока.
     *
     * @throws NotSerializableException всегда
     */
    private void readObject(ObjectInputStream in) throws IOException {
        throw new NotSerializableException("GostSecretKey must not be deserialized");
    }
}
