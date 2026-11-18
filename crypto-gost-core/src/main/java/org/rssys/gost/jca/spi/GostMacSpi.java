package org.rssys.gost.jca.spi;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.mac.Cmac;
import org.rssys.gost.mac.Hmac;
import org.rssys.gost.mac.Mac;

/**
 * Реализация {@link MacSpi} для MAC-алгоритмов ГОСТ.
 * <p>
 * Предоставляет три конкретных подкласса:
 * <ul>
 *   <li>{@link HmacStreebog256Spi} — HMAC-Стрибог-256
 *       OID {@code 1.2.643.7.1.1.4.1}, вывод 32 байта</li>
 *   <li>{@link HmacStreebog512Spi} — HMAC-Стрибог-512
 *       OID {@code 1.2.643.7.1.1.4.2}, вывод 64 байта</li>
 *   <li>{@link CmacKuznyechikSpi} — CMAC-Кузнечик
 *       вывод 16 байт</li>
 * </ul>
 * <p>
 * Принимает как {@link GostSecretKey}, так и {@link javax.crypto.spec.SecretKeySpec}
 * с форматом {@code "RAW"}.
 */
public abstract class GostMacSpi extends MacSpi {

    /** Делегат — низкоуровневая реализация MAC. */
    private Mac delegate;

    /**
     * Фабричный метод, вызываемый подклассами для создания конкретного делегата.
     * Вызывается при каждой инициализации, чтобы получить свежий экземпляр.
     */
    protected abstract Mac createDelegate();

    /**
     * Возвращает длину тега MAC в байтах для данного алгоритма.
     * Реализуется подклассом как константа — не требует создания делегата.
     */
    protected abstract int getMacLength();

    /**
     * Требуемая длина ключа в байтах. По умолчанию любая непустая (HMAC-Стрибог принимает ключ
     * произвольной длины); подкласс с фиксированной длиной ключа переопределяет метод, чтобы
     * неверная длина давала {@link InvalidKeyException}, а не исключение из шифра.
     */
    protected int requiredKeyLength() {
        return SymmetricKeyExtractor.ANY_LENGTH;
    }

    /**
     * Инициализирует MAC ключом.
     * <p>
     * Принимает {@link GostSecretKey} или {@link javax.crypto.spec.SecretKeySpec}
     * с форматом {@code "RAW"}.
     *
     * <p>После неудачного {@code init} MAC считается неинициализированным: прежний ключ
     * не сохраняется, {@code update} и {@code doFinal} бросают {@link IllegalStateException}
     * до успешной повторной инициализации.
     *
     * @param key   ключ аутентификации
     * @param params параметры алгоритма (не используются, должны быть {@code null})
     * @throws InvalidKeyException если ключ имеет неподдерживаемый тип или формат
     * @throws InvalidAlgorithmParameterException если переданы ненулевые параметры
     */
    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Старый делегат уничтожается до любых проверок: неудачный init не должен оставлять
        // рабочим прежний ключ (fail-closed).
        if (delegate != null) {
            delegate.destroy();
            delegate = null;
        }
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "No algorithm parameters supported for GOST MAC");
        }
        SymmetricKey keyParam = SymmetricKeyExtractor.forMac(key, requiredKeyLength(), "GOST MAC");
        // Свежий делегат при каждой инициализации; полю присваивается только после успеха,
        // чтобы не оставить неинициализированный делегат.
        Mac newDelegate = null;
        boolean initialized = false;
        try {
            newDelegate = createDelegate();
            newDelegate.init(keyParam);
            initialized = true;
        } finally {
            // Копия ключа нужна только на время init; делегат хранит собственные pads.
            // Создание делегата внутри try: сбой в нём тоже не оставляет копию ключа в куче.
            keyParam.destroy();
            if (!initialized && newDelegate != null) {
                newDelegate.destroy();
            }
        }
        delegate = newDelegate;
    }

    /** Добавляет один байт к вычислению MAC. */
    @Override
    protected void engineUpdate(byte input) {
        checkInitialized();
        delegate.update(input);
    }

    /** Добавляет часть массива к вычислению MAC. */
    @Override
    protected void engineUpdate(byte[] input, int inputOffset, int len) {
        checkInitialized();
        delegate.update(input, inputOffset, len);
    }

    /**
     * Завершает вычисление MAC и возвращает тег.
     * Внутреннее состояние сбрасывается после вызова.
     */
    @Override
    protected byte[] engineDoFinal() {
        checkInitialized();
        byte[] out = new byte[delegate.getMacSize()];
        delegate.doFinal(out, 0); // doFinal вызывает reset() внутри
        return out;
    }

    /** Сбрасывает внутреннее состояние MAC без вычисления тега. */
    @Override
    protected void engineReset() {
        if (delegate != null) {
            delegate.reset();
        }
    }

    /** @return длина тега MAC в байтах */
    @Override
    protected int engineGetMacLength() {
        return getMacLength();
    }

    private void checkInitialized() {
        if (delegate == null) {
            throw new IllegalStateException("MAC not initialized — call init() first");
        }
    }

    /**
     * HMAC-Стрибог-256
     * <p>
     * OID: {@code 1.2.643.7.1.1.4.1}.
     * Регистрируется в провайдере как {@code "HmacGOST3411-2012-256"}.
     */
    public static final class HmacStreebog256Spi extends GostMacSpi {
        @Override
        protected Mac createDelegate() {
            return new Hmac(new Streebog256());
        }

        @Override
        protected int getMacLength() {
            return Streebog256.DIGEST_SIZE;
        }
    }

    /**
     * HMAC-Стрибог-512
     * <p>
     * OID: {@code 1.2.643.7.1.1.4.2}.
     * Регистрируется в провайдере как {@code "HmacGOST3411-2012-512"}.
     */
    public static final class HmacStreebog512Spi extends GostMacSpi {
        @Override
        protected Mac createDelegate() {
            return new Hmac(new Streebog512());
        }

        @Override
        protected int getMacLength() {
            return Streebog512.DIGEST_SIZE;
        }
    }

    /**
     * CMAC-Кузнечик
     * <p>
     * Регистрируется в провайдере как {@code "CMAC-Kuznyechik"}.
     */
    public static final class CmacKuznyechikSpi extends GostMacSpi {
        @Override
        protected Mac createDelegate() {
            return new Cmac(new Kuznyechik());
        }

        @Override
        protected int getMacLength() {
            return Kuznyechik.BLOCK_SIZE;
        }

        @Override
        protected int requiredKeyLength() {
            return Kuznyechik.KEY_SIZE;
        }
    }
}
