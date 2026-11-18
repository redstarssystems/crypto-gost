package org.rssys.gost.jca.spi;

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.jca.key.GostSecretKey;

/**
 * Единственная точка извлечения низкоуровневого {@link SymmetricKey} из JCA-ключа для SPI шифров,
 * MAC и фабрик ключей.
 *
 * <p>Временная копия ключевых байт, возвращённая {@link Key#getEncoded()}, затирается сразу после
 * того, как конструктор {@link SymmetricKey} сделал собственную. Уничтоженный ключ даёт
 * {@link InvalidKeyException}, а не непроверяемое исключение из {@code getEncoded()}.
 *
 * <p>Принимаются {@link GostSecretKey} и любой {@link SecretKey} с форматом {@code RAW}.
 */
final class SymmetricKeyExtractor {

    /** Любая непустая длина ключа (HMAC-Стрибог принимает ключ произвольной длины). */
    static final int ANY_LENGTH = 0;

    private SymmetricKeyExtractor() {}

    /**
     * Извлекает ключ шифра Кузнечик. Имя алгоритма ключа обязано быть {@code Kuznyechik} или
     * {@code GOST3412-2015}: иначе ключ другого назначения (например, {@code AES}) молча стал бы
     * ключом Кузнечика. Так же ведёт себя шифр AES в SunJCE. Ключ с именем {@code RAW} или
     * любым другим, кроме двух названных, отвергается: прежняя версия принимала любой RAW-ключ из
     * 32 байт.
     *
     * @param key JCA-ключ
     * @return {@link SymmetricKey} длиной {@link Kuznyechik#KEY_SIZE} с собственной копией байт
     * @throws InvalidKeyException если ключ отсутствует, уничтожен, неподдерживаемого типа, с
     *                             чужим именем алгоритма или неверной длины
     */
    static SymmetricKey forCipher(Key key) throws InvalidKeyException {
        requireNotNull(key);
        requireCipherAlgorithm(key.getAlgorithm());
        return extract(key, Kuznyechik.KEY_SIZE, "Kuznyechik");
    }

    /**
     * Извлекает ключ MAC. Имя алгоритма не проверяется: {@code SecretKeySpec(bytes, "RAW")} и
     * {@code GostSecretKey("Kuznyechik")} для CMAC - обычные для JCA случаи.
     *
     * @param key            JCA-ключ
     * @param requiredLength требуемая длина в байтах или {@link #ANY_LENGTH}
     * @param algorithm      имя алгоритма для сообщения об ошибке
     * @throws InvalidKeyException если ключ отсутствует, уничтожен, неподдерживаемого типа или
     *                             неверной длины
     */
    static SymmetricKey forMac(Key key, int requiredLength, String algorithm)
            throws InvalidKeyException {
        requireNotNull(key);
        return extract(key, requiredLength, algorithm);
    }

    private static void requireNotNull(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
    }

    private static void requireCipherAlgorithm(String algorithm) throws InvalidKeyException {
        if (!GostSecretKey.KUZNYECHIK.equalsIgnoreCase(algorithm)
                && !GostSecretKey.GOST3412_2015.equalsIgnoreCase(algorithm)) {
            throw new InvalidKeyException(
                    "Key algorithm must be "
                            + GostSecretKey.KUZNYECHIK
                            + " or "
                            + GostSecretKey.GOST3412_2015
                            + ", got: "
                            + algorithm);
        }
    }

    private static SymmetricKey extract(Key key, int requiredLength, String algorithm)
            throws InvalidKeyException {
        if (!(key instanceof GostSecretKey)
                && !(key instanceof SecretKey && "RAW".equals(key.getFormat()))) {
            throw new InvalidKeyException(
                    "Unsupported key type: "
                            + key.getClass().getName()
                            + ". Expected GostSecretKey or SecretKey with RAW format");
        }
        byte[] encoded;
        try {
            encoded = key.getEncoded();
        } catch (IllegalStateException e) {
            throw new InvalidKeyException("Key has been destroyed", e);
        }
        try {
            if (encoded == null || encoded.length == 0) {
                throw new InvalidKeyException("Key encoding is null or empty");
            }
            if (requiredLength != ANY_LENGTH && encoded.length != requiredLength) {
                throw new InvalidKeyException(
                        algorithm
                                + " requires a "
                                + requiredLength
                                + "-byte key, got "
                                + encoded.length);
            }
            // Конструктор SymmetricKey делает собственную копию, поэтому копию из getEncoded()
            // затираем сразу после использования.
            return new SymmetricKey(encoded);
        } finally {
            if (encoded != null) {
                Arrays.fill(encoded, (byte) 0);
            }
        }
    }
}
