package org.rssys.gost.jca.spi;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

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
 *   <li>{@link SecretKeySpec} с алгоритмом {@code "Kuznyechik"} или {@code "GOST3412-2015"}
 *       -> {@link GostSecretKey}; спецификация с другим именем алгоритма отвергается</li>
 * </ul>
 * <p>
 * Регистрируется в провайдере как {@code "Kuznyechik"}.
 */
public final class GostSecretKeyFactorySpi extends SecretKeyFactorySpi {

    /**
     * Генерирует симметричный ключ по спецификации.
     *
     * @param keySpec {@link SecretKeySpec} с алгоритмом "Kuznyechik" и 32 байтами ключа
     * @throws InvalidKeySpecException если спецификация неподдерживаемого типа, с другим именем
     *         алгоритма или с неверной длиной ключа
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof SecretKeySpec spec)) {
            throw new InvalidKeySpecException(
                    "Unsupported KeySpec type: "
                            + (keySpec == null ? "null" : keySpec.getClass().getName())
                            + ". Expected SecretKeySpec");
        }
        try {
            return toGostSecretKey(spec);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    /**
     * Возвращает спецификацию ключа в запрошенном формате.
     * <p>
     * Принимает {@code Class<?>} согласно контракту {@link SecretKeyFactorySpi}.
     *
     * @param key      симметричный ключ Кузнечика
     * @param keySpec  запрошенный класс спецификации
     * @throws InvalidKeySpecException если класс не поддерживается, ключ уничтожен, неверной длины
     *         или принадлежит другому алгоритму
     */
    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec)
            throws InvalidKeySpecException {
        if (!SecretKeySpec.class.isAssignableFrom(keySpec)) {
            throw new InvalidKeySpecException(
                    "Unsupported KeySpec class: "
                            + keySpec.getName()
                            + ". Supported: SecretKeySpec");
        }
        SymmetricKey symmetricKey;
        try {
            symmetricKey = SymmetricKeyExtractor.forCipher(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
        byte[] raw = symmetricKey.getKey();
        try {
            return new SecretKeySpec(raw, GostSecretKey.KUZNYECHIK);
        } finally {
            Arrays.fill(raw, (byte) 0);
            symmetricKey.destroy();
        }
    }

    /**
     * Транслирует ключ в ключ провайдера.
     * <p>
     * Ключ Кузнечика, уже являющийся {@link GostSecretKey}, возвращается как есть. Иначе создаётся
     * {@link GostSecretKey} из RAW-байт ключа. Ключ с другим именем алгоритма (например,
     * {@code AES}) отвергается: иначе он молча стал бы ключом Кузнечика.
     *
     * @throws InvalidKeyException если ключ уничтожен, неподдерживаемого формата, с другим именем
     *         алгоритма или неверной длины
     */
    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        // Проверка имени (без учёта регистра), длины и состояния выполняется для обоих путей.
        // Как есть возвращается только ключ с каноническим именем: ключ с алиасом или другим
        // регистром пересобирается, чтобы у ключа провайдера имя было единым.
        if (key instanceof GostSecretKey gostKey
                && GostSecretKey.KUZNYECHIK.equals(gostKey.getAlgorithm())) {
            requireValidCipherKey(key);
            return key;
        }
        return toGostSecretKey(key);
    }

    /** Проверяет состояние, имя алгоритма и длину ключа; извлечённая для этого копия затирается. */
    private static void requireValidCipherKey(SecretKey key) throws InvalidKeyException {
        SymmetricKeyExtractor.forCipher(key).destroy();
    }

    private static GostSecretKey toGostSecretKey(SecretKey key) throws InvalidKeyException {
        SymmetricKey symmetricKey = SymmetricKeyExtractor.forCipher(key);
        try {
            return new GostSecretKey(GostSecretKey.KUZNYECHIK, symmetricKey);
        } finally {
            symmetricKey.destroy();
        }
    }
}
