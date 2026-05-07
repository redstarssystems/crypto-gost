package org.rssys.gost.jca.spi;

import org.rssys.gost.jca.key.GostSecretKey;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Реализация {@link SecretKeyFactorySpi} для симметричных ключей алгоритма Кузнечик.
 * <p>
 * Позволяет создавать {@link GostSecretKey} из сырых байт через стандартный JCE API:
 * <pre>{@code
 * SecretKeyFactory skf =
 *     SecretKeyFactory.getInstance("Kuznyechik", provider);
 * SecretKey key = skf.generateSecret(new SecretKeySpec(keyBytes, "Kuznyechik"));
 * }</pre>
 * <p>
 * Поддерживаемые спецификации:
 * <ul>
 *   <li>{@link SecretKeySpec} с алгоритмом {@code "Kuznyechik"} → {@link GostSecretKey}</li>
 * </ul>
 * <p>
 * Регистрируется в провайдере как {@code "Kuznyechik"}.
 */
public final class GostSecretKeyFactorySpi extends SecretKeyFactorySpi {

    /**
     * Генерирует симметричный ключ по спецификации.
     *
     * @param keySpec {@link SecretKeySpec} с алгоритмом "Kuznyechik" и 32 байтами ключа
     * @throws InvalidKeySpecException если спецификация неподдерживаемого типа
     *         или содержит неверную длину ключа
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SecretKeySpec) {
            SecretKeySpec spec = (SecretKeySpec) keySpec;
            byte[] raw = spec.getEncoded();
            if (raw == null || raw.length == 0) {
                throw new InvalidKeySpecException("SecretKeySpec contains null or empty key bytes");
            }
            if (raw.length != 32) {
                throw new InvalidKeySpecException(
                    "Kuznyechik requires 32-byte key, got " + raw.length);
            }
            return new GostSecretKey("Kuznyechik", raw);
        }
        throw new InvalidKeySpecException(
            "Unsupported KeySpec type: " + keySpec.getClass().getName()
            + ". Expected SecretKeySpec");
    }

    /**
     * Возвращает спецификацию ключа в запрошенном формате.
     * <p>
     * Принимает {@code Class<?>} согласно контракту {@link SecretKeyFactorySpi}.
     *
     * @param key      симметричный ключ
     * @param keySpec  запрошенный класс спецификации
     * @throws InvalidKeySpecException если класс не поддерживается
     */
    @SuppressWarnings("unchecked")
    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec)
            throws InvalidKeySpecException {
        if (!SecretKeySpec.class.isAssignableFrom(keySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec class: " + keySpec.getName()
                + ". Supported: SecretKeySpec");
        }
        byte[] raw = key.getEncoded();
        if (raw == null) {
            throw new InvalidKeySpecException("Key encoding is not available");
        }
        return new SecretKeySpec(raw, "Kuznyechik");
    }

    /**
     * Транслирует ключ в ключ провайдера.
     * <p>
     * Если ключ уже {@link GostSecretKey} — возвращается как есть.
     * Иначе — создаётся {@link GostSecretKey} из RAW-байт ключа.
     *
     * @throws InvalidKeyException если ключ имеет неподдерживаемый формат
     */
    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof GostSecretKey) {
            return key;
        }
        if ("RAW".equals(key.getFormat())) {
            byte[] raw = key.getEncoded();
            if (raw == null || raw.length == 0) {
                throw new InvalidKeyException("Key encoding is null or empty");
            }
            if (raw.length != 32) {
                throw new InvalidKeyException(
                    "Kuznyechik requires 32-byte key, got " + raw.length);
            }
            return new GostSecretKey("Kuznyechik", raw);
        }
        throw new InvalidKeyException(
            "Cannot translate key with format '" + key.getFormat()
            + "'. Expected RAW format");
    }
}
