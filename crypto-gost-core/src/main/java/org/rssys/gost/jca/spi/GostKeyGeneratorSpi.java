package org.rssys.gost.jca.spi;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Реализация {@link KeyGeneratorSpi} для генерации симметричных ключей Кузнечика.
 * <p>
 * Генерирует случайный ключ длиной 256 бит (32 байта) согласно ГОСТ Р 34.12-2015
 * <p>
 * Использование через JCA:
 * <pre>{@code
 * javax.crypto.KeyGenerator kg =
 *     javax.crypto.KeyGenerator.getInstance("Kuznyechik", provider);
 * SecretKey key = kg.generateKey();
 * }</pre>
 * <p>
 */
public final class GostKeyGeneratorSpi extends KeyGeneratorSpi {

    private static final int KEY_SIZE_BITS = 256;

    /** Генератор случайных чисел. Устанавливается через {@link #engineInit}. */
    private SecureRandom random;

    public GostKeyGeneratorSpi() {
        this.random = CryptoRandom.INSTANCE;
    }

    /**
     * Инициализирует генератор с заданным генератором случайных чисел.
     */
    @Override
    protected void engineInit(SecureRandom random) {
        this.random = (random != null) ? random : CryptoRandom.INSTANCE;
    }

    /**
     * Инициализирует генератор с параметрами алгоритма.
     * <p>
     * Параметры не поддерживаются — для Кузнечика длина ключа фиксирована (256 бит).
     *
     * @throws InvalidAlgorithmParameterException всегда, так как параметры не применимы
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "Kuznyechik key generator does not accept AlgorithmParameterSpec. "
                        + "Key size is fixed at 256 bits");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != KEY_SIZE_BITS) {
            throw new InvalidParameterException(
                    "Kuznyechik key size must be 256 bits, got " + keysize);
        }
        this.random = (random != null) ? random : CryptoRandom.INSTANCE;
    }

    /**
     * Генерирует новый случайный ключ Кузнечика.
     *
     * @return {@link GostSecretKey} с алгоритмом {@code "Kuznyechik"}, 32 байта
     */
    @Override
    protected SecretKey engineGenerateKey() {
        return new GostSecretKey("Kuznyechik", KeyGenerator.generateSymmetricKey(random));
    }

    private static final class InvalidParameterException extends RuntimeException {
        InvalidParameterException(String msg) {
            super(msg);
        }
    }
}
